package policy

import (
	"context"
	"crypto/ed25519"
	"io"
	"log"
	"os"
	"testing"
	"time"
)

// stubEngine is a minimal Engine that returns a fixed decision and records nothing
// else. The Reason field is used as a sentinel so tests can tell which engine served.
type stubEngine struct {
	reason string
}

func (s *stubEngine) Evaluate(_ context.Context, _ Input) (*Decision, error) {
	return &Decision{Allow: true, StatusCode: 200, Reason: s.reason}, nil
}

func quietLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// newWatcherWithFakeStat builds a HotWatcher whose stat source is controlled by the
// returned setMod function, so reloads can be driven deterministically without touching
// the real clock or filesystem mtime resolution.
func newWatcherWithFakeStat(initial Engine, reload ReloadFunc) (*HotWatcher, func(time.Time)) {
	cur := time.Unix(1000, 0)
	w := NewHotWatcher("fake.wasm", time.Second, initial, reload, quietLogger())
	w.stat = func(string) (time.Time, error) { return cur, nil }
	// Reset lastMod to the seeded value (NewHotWatcher seeded via the default stat,
	// which errored on the nonexistent path and left lastMod zero).
	w.lastMod = cur
	return w, func(t time.Time) { cur = t }
}

func TestHotWatcherNoChangeNoReload(t *testing.T) {
	reloads := 0
	reload := func() (Engine, error) {
		reloads++
		return &stubEngine{reason: "new"}, nil
	}
	w, _ := newWatcherWithFakeStat(&stubEngine{reason: "initial"}, reload)

	if swapped := w.checkAndReload(); swapped {
		t.Fatal("expected no swap when mtime is unchanged")
	}
	if reloads != 0 {
		t.Fatalf("expected 0 reload calls, got %d", reloads)
	}
	dec, _ := w.Evaluate(context.Background(), Input{})
	if dec.Reason != "initial" {
		t.Fatalf("expected initial engine to serve, got %q", dec.Reason)
	}
}

func TestHotWatcherReloadsOnChange(t *testing.T) {
	reload := func() (Engine, error) { return &stubEngine{reason: "new"}, nil }
	w, setMod := newWatcherWithFakeStat(&stubEngine{reason: "initial"}, reload)

	setMod(time.Unix(2000, 0)) // simulate a file write with a newer mtime
	if swapped := w.checkAndReload(); !swapped {
		t.Fatal("expected swap when mtime changed and reload succeeded")
	}
	dec, _ := w.Evaluate(context.Background(), Input{})
	if dec.Reason != "new" {
		t.Fatalf("expected new engine to serve after reload, got %q", dec.Reason)
	}
}

func TestHotWatcherFailedReloadRetainsLastGood(t *testing.T) {
	failNext := true
	reload := func() (Engine, error) {
		if failNext {
			return nil, os.ErrInvalid // simulate bad compile / read / signature failure
		}
		return &stubEngine{reason: "new"}, nil
	}
	w, setMod := newWatcherWithFakeStat(&stubEngine{reason: "initial"}, reload)

	// First change: reload fails -> last-good retained, no deny-all.
	setMod(time.Unix(2000, 0))
	if swapped := w.checkAndReload(); swapped {
		t.Fatal("expected no swap when reload fails")
	}
	dec, _ := w.Evaluate(context.Background(), Input{})
	if dec.Reason != "initial" {
		t.Fatalf("expected last-good (initial) engine to keep serving after failed reload, got %q", dec.Reason)
	}
	// Critically: must NOT be a deny-all state.
	if !dec.Allow {
		t.Fatal("failed reload must not enter deny-all; last-good must keep allowing per its policy")
	}

	// lastMod must NOT have advanced, so a later fix is retried even at the same mtime.
	failNext = false
	if swapped := w.checkAndReload(); !swapped {
		t.Fatal("expected retry to swap once reload succeeds (lastMod must not have advanced on failure)")
	}
	dec, _ = w.Evaluate(context.Background(), Input{})
	if dec.Reason != "new" {
		t.Fatalf("expected new engine after recovery, got %q", dec.Reason)
	}
}

func TestHotWatcherStatErrorRetainsLastGood(t *testing.T) {
	reload := func() (Engine, error) { return &stubEngine{reason: "new"}, nil }
	w := NewHotWatcher("fake.wasm", time.Second, &stubEngine{reason: "initial"}, reload, quietLogger())
	w.lastMod = time.Unix(1000, 0)
	w.stat = func(string) (time.Time, error) { return time.Time{}, os.ErrNotExist }

	if swapped := w.checkAndReload(); swapped {
		t.Fatal("expected no swap when stat fails")
	}
	dec, _ := w.Evaluate(context.Background(), Input{})
	if dec.Reason != "initial" {
		t.Fatalf("expected last-good engine on stat error, got %q", dec.Reason)
	}
}

// TestHotWatcherEndToEndReloadViaLoader exercises the real reload path: a signed WASM
// bundle is loaded via BundleLoader, then rewritten+resigned, and a reload tick swaps it
// in. It also asserts that signatures are re-verified on reload (a bad-signature rewrite
// is rejected and the last-good bundle is retained).
func TestHotWatcherEndToEndReloadViaLoader(t *testing.T) {
	dir := t.TempDir()
	pubPEM, priv := genEd25519PEM(t)

	wasm := minimalWASM()
	bundlePath := writeBundle(t, dir, wasm)
	writeSig(t, bundlePath, ed25519.Sign(priv, wasm))

	loader := NewBundleLoader(DefaultFallbackDeny, pubPEM)
	initial, err := loader.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	reload := func() (Engine, error) { return loader.LoadBundle(bundlePath) }
	w := NewHotWatcher(bundlePath, time.Second, initial, reload, quietLogger())

	// Case 1: rewrite the bundle with a VALID signature and a newer mtime -> reload swaps.
	wasm2 := minimalWASM() // structurally identical but rewritten file (new mtime)
	if err := os.WriteFile(bundlePath, wasm2, 0o644); err != nil {
		t.Fatalf("rewrite bundle: %v", err)
	}
	writeSig(t, bundlePath, ed25519.Sign(priv, wasm2))
	bumpMtime(t, bundlePath, 2*time.Second)

	if swapped := w.checkAndReload(); !swapped {
		t.Fatal("expected reload to swap a validly re-signed bundle")
	}
	if !w.Loaded() {
		t.Fatal("expected watcher to report Loaded after successful reload")
	}

	// Case 2: rewrite with a BAD signature and a newer mtime -> reload rejected, last-good kept.
	wasm3 := minimalWASM()
	if err := os.WriteFile(bundlePath, wasm3, 0o644); err != nil {
		t.Fatalf("rewrite bundle: %v", err)
	}
	badSig := ed25519.Sign(priv, wasm3)
	badSig[0] ^= 0xff // corrupt: signature no longer validates
	writeSig(t, bundlePath, badSig)
	bumpMtime(t, bundlePath, 4*time.Second)

	if swapped := w.checkAndReload(); swapped {
		t.Fatal("expected reload to reject a bad-signature bundle (signature re-verified on reload)")
	}
	// Still serving (last-good), not deny-all.
	if !w.Loaded() {
		t.Fatal("expected watcher to keep serving last-good bundle after bad-signature reload")
	}
}

// bumpMtime sets the mtime of path to now+delta so mtime-based change detection fires
// deterministically regardless of filesystem timestamp granularity.
func bumpMtime(t *testing.T, path string, delta time.Duration) {
	t.Helper()
	ts := time.Now().Add(delta)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

func TestHotWatcherStartStopReloads(t *testing.T) {
	reloadCh := make(chan struct{}, 1)
	reload := func() (Engine, error) {
		select {
		case reloadCh <- struct{}{}:
		default:
		}
		return &stubEngine{reason: "new"}, nil
	}
	w, setMod := newWatcherWithFakeStat(&stubEngine{reason: "initial"}, reload)
	// Tighten the real ticker so the background loop fires quickly.
	w.interval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	setMod(time.Unix(2000, 0)) // make the next tick observe a change

	select {
	case <-reloadCh:
	case <-time.After(2 * time.Second):
		t.Fatal("expected background loop to invoke reload after an mtime change")
	}

	w.Stop()
	w.Stop() // idempotent

	// After Stop, the new engine should be the one serving.
	dec, _ := w.Evaluate(context.Background(), Input{})
	if dec.Reason != "new" {
		t.Fatalf("expected new engine to serve after background reload, got %q", dec.Reason)
	}
}

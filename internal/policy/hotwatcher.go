package policy

import (
	"context"
	"log"
	"os"
	"sync"
	"time"
)

// ReloadFunc produces a fresh policy Engine by (re)loading the bundle from disk.
//
// It is supplied by the caller and MUST perform the same load path used at startup,
// including signature re-verification (fail-closed) where a public key is configured.
// For WASM bundles this is typically BundleLoader.LoadBundle (which re-verifies the
// detached Ed25519 signature on every changed mtime); for Rego it is RegoEngine.Load
// followed by returning the same engine.
//
// A non-nil error means the reload failed (bad read, bad compile, or bad signature):
// HotWatcher treats this as fail-closed-to-last-good — it keeps serving the previously
// loaded engine and never swaps in a broken one.
type ReloadFunc func() (Engine, error)

// HotWatcher wraps a policy Engine and periodically reloads it from disk WITHOUT a
// process restart. It polls the bundle file's mtime on a fixed interval (stdlib
// time.Ticker, no fsnotify dependency); when the mtime changes it invokes the
// configured ReloadFunc and, on success, atomically swaps in the new engine.
//
// Fail-closed-to-last-good semantics (SECURITY-CRITICAL):
//   - A reload that fails for any reason (read error, compile error, or signature
//     verification failure) is logged and discarded. The last successfully loaded
//     engine continues to serve traffic. The watcher NEVER drops into a deny-all
//     state on a bad reload — the previously verified policy remains authoritative.
//   - Signature re-verification is delegated to ReloadFunc (e.g. BundleLoader), so a
//     bundle whose signature no longer validates is rejected and the prior good
//     bundle is retained.
//
// HotWatcher itself satisfies the Engine interface (and EngineWithStatus when the
// wrapped engine does), so it can be dropped in wherever the proxy expects an Engine.
type HotWatcher struct {
	path     string
	interval time.Duration
	reload   ReloadFunc
	logger   *log.Logger

	mu      sync.RWMutex
	current Engine
	// lastMod is the mtime of the bundle file as of the last successful load (or the
	// last observed mtime). It is compared on each tick to detect changes.
	lastMod time.Time

	// stat is the file-stat function used to read mtime. It is a field so tests can
	// inject a deterministic clock/source; defaults to os.Stat-backed modTime.
	stat func(path string) (time.Time, error)

	stopOnce sync.Once
	stopped  chan struct{}
}

// NewHotWatcher wraps initial with periodic disk reloading.
//
//   - path is the bundle file whose mtime is polled.
//   - interval is the poll period; it must be > 0 (callers validate config; a
//     non-positive interval is clamped to a safe minimum here as defense in depth).
//   - initial is the already-loaded, verified engine to serve until the first
//     successful reload. It must be non-nil.
//   - reload re-loads the bundle from disk (with signature re-verification).
//   - logger receives reload diagnostics; nil uses a stderr-backed default.
func NewHotWatcher(path string, interval time.Duration, initial Engine, reload ReloadFunc, logger *log.Logger) *HotWatcher {
	if logger == nil {
		logger = log.New(os.Stderr, "[accessgate-proxy][policy-hotwatch] ", log.LstdFlags|log.LUTC)
	}
	if interval <= 0 {
		interval = time.Second
	}
	w := &HotWatcher{
		path:     path,
		interval: interval,
		reload:   reload,
		logger:   logger,
		current:  initial,
		stopped:  make(chan struct{}),
		stat:     statModTime,
	}
	// Seed lastMod with the current file mtime so the first tick only reloads on an
	// actual change. A stat error here is non-fatal: lastMod stays zero, so the first
	// observable mtime is treated as a change and triggers a (harmless) reload attempt.
	if mod, err := w.stat(path); err == nil {
		w.lastMod = mod
	}
	return w
}

// statModTime returns the mtime of the file at path.
func statModTime(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Evaluate delegates to the currently active engine (atomic, lock-guarded read).
func (w *HotWatcher) Evaluate(ctx context.Context, input Input) (*Decision, error) {
	w.mu.RLock()
	eng := w.current
	w.mu.RUnlock()
	return eng.Evaluate(ctx, input)
}

// Loaded reports whether the active engine has a bundle loaded (EngineWithStatus).
func (w *HotWatcher) Loaded() bool {
	w.mu.RLock()
	eng := w.current
	w.mu.RUnlock()
	if s, ok := eng.(EngineWithStatus); ok {
		return s.Loaded()
	}
	return eng != nil
}

// BundlePath reports the active engine's bundle path (EngineWithStatus), falling
// back to the watched path.
func (w *HotWatcher) BundlePath() string {
	w.mu.RLock()
	eng := w.current
	w.mu.RUnlock()
	if s, ok := eng.(EngineWithStatus); ok {
		if p := s.BundlePath(); p != "" {
			return p
		}
	}
	return w.path
}

// Start launches the background polling loop. It returns immediately; the loop runs
// until ctx is cancelled or Stop is called. Calling Start more than once spawns
// additional loops and should be avoided.
func (w *HotWatcher) Start(ctx context.Context) {
	go w.run(ctx)
}

func (w *HotWatcher) run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopped:
			return
		case <-ticker.C:
			w.checkAndReload()
		}
	}
}

// Stop terminates the polling loop. It is safe to call multiple times and from any
// goroutine. Stop does not affect the currently active engine; the last-good policy
// remains served by whatever holds a reference to this watcher.
func (w *HotWatcher) Stop() {
	w.stopOnce.Do(func() { close(w.stopped) })
}

// checkAndReload performs a single mtime check and, if the bundle changed, attempts a
// reload. It is the unit of work executed on every ticker tick and is exported to the
// package for deterministic, wall-clock-free testing.
//
// Returns true when a new engine was successfully swapped in; false otherwise (no
// change, or a failed reload that retained the last-good engine).
func (w *HotWatcher) checkAndReload() bool {
	mod, err := w.stat(w.path)
	if err != nil {
		// Cannot stat the bundle (e.g. transient unlink during an atomic rename, or a
		// permissions blip). Keep last-good; do not reset lastMod so a later successful
		// stat with a new mtime still triggers a reload.
		w.logger.Printf("reload check: stat %q failed, keeping last-good policy: %v", w.path, err)
		return false
	}

	w.mu.RLock()
	unchanged := mod.Equal(w.lastMod)
	w.mu.RUnlock()
	if unchanged {
		return false
	}

	newEng, err := w.reload()
	if err != nil {
		// Fail-closed-to-last-good: a bad compile, bad read, or bad/absent signature is
		// rejected. We DO NOT advance lastMod, so a subsequent fix (new mtime) is retried
		// and we never enter a deny-all state.
		w.logger.Printf("reload of %q failed, retaining last-good policy (fail-closed, no deny-all): %v", w.path, err)
		return false
	}
	if newEng == nil {
		w.logger.Printf("reload of %q returned nil engine, retaining last-good policy", w.path)
		return false
	}

	w.mu.Lock()
	w.current = newEng
	w.lastMod = mod
	w.mu.Unlock()
	w.logger.Printf("reloaded policy bundle %q (mtime %s)", w.path, mod.UTC().Format(time.RFC3339Nano))
	return true
}

// ensure HotWatcher satisfies the engine interfaces.
var (
	_ Engine           = (*HotWatcher)(nil)
	_ EngineWithStatus = (*HotWatcher)(nil)
)

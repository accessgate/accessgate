package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverFromDirEmpty(t *testing.T) {
	reg := New()
	dir := t.TempDir()
	if err := DiscoverFromDir(context.Background(), reg, dir, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverFromDirLoadsJSONManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"id":"test.plugin","kind":"pipeline","name":"T","version":"1","capabilities":["pipeline:x"]}`
	writeManifest(t, dir, "p.json", manifest)
	reg := New()
	if err := DiscoverFromDir(context.Background(), reg, dir, nil); err != nil {
		t.Fatal(err)
	}
	regd, ok := reg.RegistrationFor(PluginID("test.plugin"))
	if !ok || regd.Descriptor.ID != "test.plugin" {
		t.Fatalf("registration missing: ok=%v", ok)
	}
}

func TestDiscoverFromDirNonexistentRoot(t *testing.T) {
	reg := New()
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	if err := DiscoverFromDir(context.Background(), reg, dir, nil); err != nil {
		t.Fatalf("expected nil error for missing root, got %v", err)
	}
}

func TestDiscoverFromDirInvalidManifests(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		wantSub  string
	}{
		{
			name:     "missing id",
			contents: `{"kind":"pipeline","capabilities":["pipeline:x"]}`,
			wantSub:  `missing required field "id"`,
		},
		{
			name:     "missing kind",
			contents: `{"id":"a.b","capabilities":["pipeline:x"]}`,
			wantSub:  `missing required field "kind"`,
		},
		{
			name:     "unknown kind",
			contents: `{"id":"a.b","kind":"wizard","capabilities":["pipeline:x"]}`,
			wantSub:  `unknown kind "wizard"`,
		},
		{
			name:     "missing capabilities",
			contents: `{"id":"a.b","kind":"pipeline"}`,
			wantSub:  `missing required field "capabilities"`,
		},
		{
			name:     "empty capability entry",
			contents: `{"id":"a.b","kind":"pipeline","capabilities":[""]}`,
			wantSub:  `empty capability at index 0`,
		},
		{
			name:     "empty depends_on entry",
			contents: `{"id":"a.b","kind":"pipeline","capabilities":["pipeline:x"],"depends_on":[""]}`,
			wantSub:  `empty depends_on entry at index 0`,
		},
		{
			name:     "malformed json",
			contents: `{"id":`,
			wantSub:  `unmarshal manifest`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeManifest(t, dir, "p.json", tt.contents)
			reg := New()
			err := DiscoverFromDir(context.Background(), reg, dir, nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !containsSub(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
			if len(reg.AllPluginIDs()) != 0 {
				t.Fatalf("invalid manifest must not register: got %v", reg.AllPluginIDs())
			}
		})
	}
}

// TestBuildDependencyGraphUnresolvableDependsOn ensures a depends_on capability with no
// provider in the registry is reported as an error by BuildDependencyGraph.
func TestBuildDependencyGraphUnresolvableDependsOn(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"id":"a.b","kind":"pipeline","capabilities":["pipeline:a"],"depends_on":["pipeline:missing"]}`
	writeManifest(t, dir, "p.json", manifest)
	reg := New()
	if err := DiscoverFromDir(context.Background(), reg, dir, nil); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	err := reg.BuildDependencyGraph()
	if err == nil {
		t.Fatal("expected unresolvable depends_on error, got nil")
	}
	if !containsSub(err.Error(), "no providers") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildDependencyGraphResolvableDependsOn(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "a.json", `{"id":"a","kind":"pipeline","capabilities":["pipeline:a"]}`)
	writeManifest(t, dir, "b.json", `{"id":"b","kind":"pipeline","capabilities":["pipeline:b"],"depends_on":["pipeline:a"]}`)
	reg := New()
	if err := DiscoverFromDir(context.Background(), reg, dir, nil); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if err := reg.BuildDependencyGraph(); err != nil {
		t.Fatalf("build graph: %v", err)
	}
	order := reg.StartupOrder()
	if len(order) != 2 {
		t.Fatalf("expected 2 plugins in startup order, got %v", order)
	}
	// a must precede b.
	var ia, ib int
	for i, id := range order {
		switch id {
		case "a":
			ia = i
		case "b":
			ib = i
		}
	}
	if ia > ib {
		t.Fatalf("expected a before b, got %v", order)
	}
}

// signedManifest produces a manifest JSON with a valid inline Ed25519 signature.
func signedManifest(t *testing.T, priv ed25519.PrivateKey, m Manifest) string {
	t.Helper()
	m.Signature = nil
	payload, err := json.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	m.Signature = &ManifestSignature{
		Algorithm: ManifestSignatureAlgorithm,
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	out, err := json.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func pemPublicKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return string(block)
}

func TestEd25519VerifierValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m := Manifest{ID: "signed.plugin", Kind: "pipeline", Name: "S", Capabilities: []string{"pipeline:x"}}
	writeManifest(t, dir, "p.json", signedManifest(t, priv, m))

	verifier, err := NewEd25519Verifier(pemPublicKey(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	reg := New()
	if err := DiscoverFromDir(context.Background(), reg, dir, verifier); err != nil {
		t.Fatalf("discovery with valid signature: %v", err)
	}
	if _, ok := reg.RegistrationFor("signed.plugin"); !ok {
		t.Fatal("signed plugin not registered")
	}
}

func TestEd25519VerifierTamperedManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m := Manifest{ID: "signed.plugin", Kind: "pipeline", Name: "S", Capabilities: []string{"pipeline:x"}}
	contents := signedManifest(t, priv, m)

	// Tamper: change the name after signing.
	var parsed Manifest
	if err := json.Unmarshal([]byte(contents), &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Name = "tampered"
	tampered, err := json.Marshal(&parsed)
	if err != nil {
		t.Fatal(err)
	}
	writeManifest(t, dir, "p.json", string(tampered))

	verifier, err := NewEd25519Verifier(pemPublicKey(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	reg := New()
	err = DiscoverFromDir(context.Background(), reg, dir, verifier)
	if err == nil {
		t.Fatal("expected verification failure for tampered manifest, got nil")
	}
	if !containsSub(err.Error(), "signature verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reg.AllPluginIDs()) != 0 {
		t.Fatalf("tampered manifest must not register: %v", reg.AllPluginIDs())
	}
}

func TestEd25519VerifierMissingSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeManifest(t, dir, "p.json", `{"id":"a","kind":"pipeline","capabilities":["pipeline:x"]}`)

	verifier, err := NewEd25519Verifier(pemPublicKey(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	reg := New()
	err = DiscoverFromDir(context.Background(), reg, dir, verifier)
	if err == nil {
		t.Fatal("expected missing-signature failure, got nil")
	}
	if !errors.Is(err, ErrManifestSignatureMissing) {
		t.Fatalf("expected ErrManifestSignatureMissing, got %v", err)
	}
}

func TestEd25519VerifierWrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m := Manifest{ID: "signed.plugin", Kind: "pipeline", Name: "S", Capabilities: []string{"pipeline:x"}}
	writeManifest(t, dir, "p.json", signedManifest(t, priv, m))

	verifier, err := NewEd25519Verifier(pemPublicKey(t, otherPub))
	if err != nil {
		t.Fatal(err)
	}
	reg := New()
	err = DiscoverFromDir(context.Background(), reg, dir, verifier)
	if err == nil {
		t.Fatal("expected verification failure with wrong key, got nil")
	}
	if !containsSub(err.Error(), "signature verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEd25519VerifierUnsupportedAlgorithm(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeManifest(t, dir, "p.json",
		`{"id":"a","kind":"pipeline","capabilities":["pipeline:x"],"signature":{"algorithm":"rsa","value":"AA=="}}`)

	verifier, err := NewEd25519Verifier(pemPublicKey(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	reg := New()
	err = DiscoverFromDir(context.Background(), reg, dir, verifier)
	if err == nil {
		t.Fatal("expected unsupported-algorithm failure, got nil")
	}
	if !containsSub(err.Error(), "unsupported signature algorithm") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewEd25519VerifierBadKey(t *testing.T) {
	if _, err := NewEd25519Verifier("not a key"); err == nil {
		t.Fatal("expected error for invalid public key")
	}
	if _, err := NewEd25519Verifier(""); err == nil {
		t.Fatal("expected error for empty public key")
	}
}

func containsSub(s, sub string) bool {
	return strings.Contains(s, sub)
}

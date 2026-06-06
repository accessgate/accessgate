package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleLoaderMissingFile(t *testing.T) {
	b := NewBundleLoader(DefaultFallbackDeny, "")
	_, err := b.LoadBundle(filepath.Join(t.TempDir(), "missing.wasm"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// minimalWASM returns a tiny but valid WASM module that exports linear "memory" and an
// "evaluate(i32,i32)->(i32,i32)" function (returning 0,0). It is sufficient for the
// BundleLoader to compile and instantiate successfully.
func minimalWASM() []byte {
	sec := func(id byte, body []byte) []byte {
		return append([]byte{id, byte(len(body))}, body...)
	}
	header := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	typeBody := []byte{0x01, 0x60, 0x02, 0x7f, 0x7f, 0x02, 0x7f, 0x7f}
	funcBody := []byte{0x01, 0x00}
	memBody := []byte{0x01, 0x00, 0x01}
	exp := []byte{0x02}
	exp = append(exp, 0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00)
	exp = append(exp, 0x08, 'e', 'v', 'a', 'l', 'u', 'a', 't', 'e', 0x00, 0x00)
	fnbody := []byte{0x00, 0x41, 0x00, 0x41, 0x00, 0x0b}
	codeBody := append([]byte{0x01, byte(len(fnbody))}, fnbody...)

	wasm := append([]byte{}, header...)
	wasm = append(wasm, sec(0x01, typeBody)...)
	wasm = append(wasm, sec(0x03, funcBody)...)
	wasm = append(wasm, sec(0x05, memBody)...)
	wasm = append(wasm, sec(0x07, exp)...)
	wasm = append(wasm, sec(0x0a, codeBody)...)
	return wasm
}

// genEd25519PEM creates an ephemeral keypair and returns the PKIX PEM public key plus the
// raw private key for signing.
func genEd25519PEM(t *testing.T) (pubPEM string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return string(pemBytes), priv
}

// writeBundle writes the WASM bytes to a temp file and returns its path.
func writeBundle(t *testing.T, dir string, wasm []byte) string {
	t.Helper()
	p := filepath.Join(dir, "policy.wasm")
	if err := os.WriteFile(p, wasm, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return p
}

// writeSig writes a base64-encoded detached signature for bundlePath.
func writeSig(t *testing.T, bundlePath string, sig []byte) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString(sig)
	if err := os.WriteFile(bundlePath+SignatureSuffix, []byte(encoded+"\n"), 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
}

func TestBundleLoaderValidSignatureLoads(t *testing.T) {
	dir := t.TempDir()
	pubPEM, priv := genEd25519PEM(t)
	wasm := minimalWASM()
	bundlePath := writeBundle(t, dir, wasm)
	writeSig(t, bundlePath, ed25519.Sign(priv, wasm))

	b := NewBundleLoader(DefaultFallbackDeny, pubPEM)
	eng, err := b.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("expected valid signed bundle to load, got: %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestBundleLoaderTamperedBundleRejected(t *testing.T) {
	dir := t.TempDir()
	pubPEM, priv := genEd25519PEM(t)
	wasm := minimalWASM()
	// Sign the original bytes...
	sig := ed25519.Sign(priv, wasm)
	// ...but write a tampered bundle (flip the last code byte).
	tampered := append([]byte{}, wasm...)
	tampered[len(tampered)-1] ^= 0xff
	bundlePath := writeBundle(t, dir, tampered)
	writeSig(t, bundlePath, sig)

	b := NewBundleLoader(DefaultFallbackDeny, pubPEM)
	if _, err := b.LoadBundle(bundlePath); err == nil {
		t.Fatal("expected tampered bundle to be rejected (fail closed)")
	}
}

func TestBundleLoaderTamperedSignatureRejected(t *testing.T) {
	dir := t.TempDir()
	pubPEM, priv := genEd25519PEM(t)
	wasm := minimalWASM()
	bundlePath := writeBundle(t, dir, wasm)
	sig := ed25519.Sign(priv, wasm)
	sig[0] ^= 0xff // corrupt the signature
	writeSig(t, bundlePath, sig)

	b := NewBundleLoader(DefaultFallbackDeny, pubPEM)
	if _, err := b.LoadBundle(bundlePath); err == nil {
		t.Fatal("expected tampered signature to be rejected (fail closed)")
	}
}

func TestBundleLoaderWrongKeyRejected(t *testing.T) {
	dir := t.TempDir()
	pubPEM, _ := genEd25519PEM(t)    // configure with key A
	_, otherPriv := genEd25519PEM(t) // sign with key B
	wasm := minimalWASM()
	bundlePath := writeBundle(t, dir, wasm)
	writeSig(t, bundlePath, ed25519.Sign(otherPriv, wasm))

	b := NewBundleLoader(DefaultFallbackDeny, pubPEM)
	if _, err := b.LoadBundle(bundlePath); err == nil {
		t.Fatal("expected bundle signed by a different key to be rejected (fail closed)")
	}
}

func TestBundleLoaderMissingSignatureRejected(t *testing.T) {
	dir := t.TempDir()
	pubPEM, _ := genEd25519PEM(t)
	bundlePath := writeBundle(t, dir, minimalWASM())
	// Intentionally do NOT write a .sig file.

	b := NewBundleLoader(DefaultFallbackDeny, pubPEM)
	_, err := b.LoadBundle(bundlePath)
	if err == nil {
		t.Fatal("expected missing signature to be rejected when a public key is configured")
	}
	if !errors.Is(err, ErrSignatureMissing) {
		t.Fatalf("expected ErrSignatureMissing, got: %v", err)
	}
}

func TestBundleLoaderNoKeyLoadsUnsigned(t *testing.T) {
	// With no public key configured, an unsigned bundle (no .sig) still loads — preserving
	// prior unsigned behavior.
	dir := t.TempDir()
	bundlePath := writeBundle(t, dir, minimalWASM())

	b := NewBundleLoader(DefaultFallbackDeny, "")
	if _, err := b.LoadBundle(bundlePath); err != nil {
		t.Fatalf("expected unsigned bundle to load when no key configured, got: %v", err)
	}
}

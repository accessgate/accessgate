package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenkeySignVerifyRoundTrip exercises the full CLI surface: generate a keypair, sign a
// bundle, and verify the produced signature validates against the generated public key.
func TestGenkeySignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "key.pem")
	pub := filepath.Join(dir, "key.pub.pem")

	if err := run([]string{"-genkey", "-priv", priv, "-pub", pub}, os.Stderr); err != nil {
		t.Fatalf("genkey: %v", err)
	}

	bundle := filepath.Join(dir, "policy.wasm")
	content := []byte("not-real-wasm-but-bytes-to-sign")
	if err := os.WriteFile(bundle, content, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	if err := run([]string{"-priv", priv, "-bundle", bundle}, os.Stderr); err != nil {
		t.Fatalf("sign: %v", err)
	}

	sigBytes, err := os.ReadFile(bundle + signatureSuffix)
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBytes)))
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}

	pubKey := loadPublicKeyForTest(t, pub)
	if !ed25519.Verify(pubKey, content, sig) {
		t.Fatal("signature produced by CLI does not verify against generated public key")
	}
}

func TestSignExplicitOutPath(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "key.pem")
	pub := filepath.Join(dir, "key.pub.pem")
	if err := run([]string{"-genkey", "-priv", priv, "-pub", pub}, os.Stderr); err != nil {
		t.Fatalf("genkey: %v", err)
	}
	bundle := filepath.Join(dir, "policy.wasm")
	if err := os.WriteFile(bundle, []byte("abc"), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	out := filepath.Join(dir, "custom.sig")
	if err := run([]string{"-priv", priv, "-bundle", bundle, "-out", out}, os.Stderr); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected signature at %s: %v", out, err)
	}
}

func TestRunErrors(t *testing.T) {
	cases := [][]string{
		{},                                // no args
		{"-genkey", "-priv", "only-priv"}, // genkey missing -pub
		{"-bundle", "x.wasm"},             // sign missing -priv
		{"-priv", "nope.pem", "-bundle", "x.wasm"}, // missing files
	}
	for i, args := range cases {
		if err := run(args, os.Stderr); err == nil {
			t.Fatalf("case %d: expected error for args %v", i, args)
		}
	}
}

func loadPublicKeyForTest(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	// Reuse the same parsing the proxy uses by going through PEM decode here.
	key, err := parsePublicKeyPEM(data)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	return key
}

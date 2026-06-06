package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// signatureSuffix mirrors policy.SignatureSuffix: the proxy expects "<bundle>.sig".
const signatureSuffix = ".sig"

// defaultSignaturePath returns the conventional detached signature path for a bundle.
func defaultSignaturePath(bundlePath string) string {
	return bundlePath + signatureSuffix
}

// generateKeypair creates a fresh Ed25519 keypair and writes the private key (PKCS#8 PEM)
// and public key (PKIX PEM) to the given paths. The private key file is written with 0600
// permissions.
func generateKeypair(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// parsePublicKeyPEM parses a PKIX PEM-encoded Ed25519 public key. It mirrors the parsing
// the proxy performs at load time, so the CLI and proxy agree on the key format.
func parsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("public key is not valid PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519 (got %T)", key)
	}
	return edKey, nil
}

// loadPrivateKey reads and parses a PEM-encoded Ed25519 private key (PKCS#8).
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not valid PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519 (got %T)", key)
	}
	return edKey, nil
}

// signBundle reads the bundle at bundlePath, signs its raw bytes with the Ed25519 private
// key at privPath, and writes the base64-encoded detached signature to sigPath.
func signBundle(privPath, bundlePath, sigPath string) error {
	key, err := loadPrivateKey(privPath)
	if err != nil {
		return err
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	sig := ed25519.Sign(key, bundle)
	encoded := base64.StdEncoding.EncodeToString(sig)
	if err := os.WriteFile(sigPath, []byte(encoded+"\n"), 0o644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	return nil
}

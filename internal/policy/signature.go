package policy

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// SignatureSuffix is appended to a bundle path to locate its detached signature file.
//
// Signature convention (SECURITY-CRITICAL):
//   - A policy bundle at "<bundle>.wasm" is signed by a detached signature file at
//     "<bundle>.wasm.sig".
//   - The signature is an Ed25519 signature computed over the exact, raw bytes of the
//     bundle file.
//   - The .sig file content is the signature encoded as standard base64 (optionally with
//     surrounding whitespace/newlines). For convenience a raw 64-byte binary signature is
//     also accepted.
//   - Verification fails closed: a missing .sig, an unparuseable key, a malformed signature,
//     or a signature that does not validate all result in an error and the bundle is NOT
//     loaded.
const SignatureSuffix = ".sig"

// ErrSignatureMissing indicates the detached signature file does not exist while a public
// key is configured. This is treated as a verification failure (fail closed).
var ErrSignatureMissing = errors.New("policy: bundle signature file is missing")

// signaturePath returns the detached signature file path for a given bundle path.
func signaturePath(bundlePath string) string {
	return bundlePath + SignatureSuffix
}

// parseEd25519PublicKey parses a PEM-encoded Ed25519 public key.
//
// It accepts a PKIX/SubjectPublicKeyInfo PEM block (the form produced by
// x509.MarshalPKIXPublicKey, "BEGIN PUBLIC KEY"). As a convenience it also accepts a raw
// 32-byte Ed25519 public key supplied without PEM framing.
func parseEd25519PublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(string(pemBytes))
	if trimmed == "" {
		return nil, errors.New("policy: empty public key")
	}

	block, _ := pem.Decode([]byte(trimmed))
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("policy: parse PKIX public key: %w", err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("policy: public key is not Ed25519 (got %T)", pub)
		}
		return edPub, nil
	}

	// Fallback: a raw base64-encoded 32-byte key without PEM framing.
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}

	return nil, errors.New("policy: public key is not a valid PEM-encoded Ed25519 key")
}

// decodeSignature interprets the raw content of a .sig file as an Ed25519 signature.
// It accepts base64 (preferred) or raw 64-byte binary content.
func decodeSignature(sig []byte) ([]byte, error) {
	if len(sig) == ed25519.SignatureSize {
		// Raw binary signature.
		return sig, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil {
		return nil, fmt.Errorf("policy: signature is neither raw 64 bytes nor valid base64: %w", err)
	}
	if len(decoded) != ed25519.SignatureSize {
		return nil, fmt.Errorf("policy: signature has wrong length: got %d, want %d", len(decoded), ed25519.SignatureSize)
	}
	return decoded, nil
}

// verifyBundleSignature verifies that signature is a valid Ed25519 signature over bundle
// using the supplied PEM-encoded public key. It returns nil only when verification
// succeeds; every other path returns a non-nil error (fail closed).
func verifyBundleSignature(publicKeyPEM string, bundle, signature []byte) error {
	pub, err := parseEd25519PublicKey([]byte(publicKeyPEM))
	if err != nil {
		return err
	}
	sig, err := decodeSignature(signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, bundle, sig) {
		return errors.New("policy: bundle signature verification failed")
	}
	return nil
}

// verifyBundleFile reads the detached signature for bundlePath and verifies it against the
// already-read bundle bytes using publicKeyPEM. It fails closed: a missing signature file
// returns ErrSignatureMissing, and any other problem returns a descriptive error.
func verifyBundleFile(publicKeyPEM, bundlePath string, bundle []byte) error {
	sigPath := signaturePath(bundlePath)
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: expected %q", ErrSignatureMissing, sigPath)
		}
		return fmt.Errorf("policy: read bundle signature: %w", err)
	}
	if err := verifyBundleSignature(publicKeyPEM, bundle, sig); err != nil {
		return err
	}
	return nil
}

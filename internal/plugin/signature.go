package plugin

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Manifest signature convention (SECURITY-CRITICAL):
//
//   - A manifest may carry an inline "signature" object: {"algorithm":"ed25519","value":"<base64>"}.
//   - The signature is an Ed25519 signature computed over the canonical JSON bytes of the
//     manifest with its "signature" field removed (see signingPayload). Canonical here means
//     the manifest is re-marshalled with encoding/json after clearing Signature, yielding a
//     deterministic byte sequence both signer and verifier agree on.
//   - The "value" is standard base64. A raw 64-byte binary signature is also accepted.
//   - Verification fails closed: a missing signature, an unparseable key, a malformed
//     signature, an unsupported algorithm, or a signature that does not validate all result
//     in an error and the manifest is NOT registered.
//
// To produce the signing payload offline, marshal the manifest JSON without the "signature"
// field (or with it set to null) and sign those exact bytes with the Ed25519 private key.

// ManifestSignatureAlgorithm is the only signature algorithm currently supported.
const ManifestSignatureAlgorithm = "ed25519"

// ErrManifestSignatureMissing indicates a manifest carried no signature while a public key
// is configured. This is treated as a verification failure (fail closed).
var ErrManifestSignatureMissing = errors.New("plugin: manifest signature is missing")

// Ed25519Verifier verifies inline Ed25519 manifest signatures against a configured public key.
// It implements the Verifier interface.
type Ed25519Verifier struct {
	publicKey ed25519.PublicKey
}

// NewEd25519Verifier parses a PEM-encoded (or raw base64) Ed25519 public key and returns a
// Verifier. It returns an error if the key cannot be parsed.
func NewEd25519Verifier(publicKeyPEM string) (*Ed25519Verifier, error) {
	pub, err := parseEd25519PublicKey([]byte(publicKeyPEM))
	if err != nil {
		return nil, err
	}
	return &Ed25519Verifier{publicKey: pub}, nil
}

// NewEd25519VerifierFromFile reads a PEM-encoded Ed25519 public key from path and returns a
// Verifier.
func NewEd25519VerifierFromFile(path string) (*Ed25519Verifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plugin: read manifest public key %q: %w", path, err)
	}
	return NewEd25519Verifier(string(data))
}

// Verify checks the inline signature on m. It fails closed: a missing signature, an
// unsupported algorithm, a malformed value, or an invalid signature all return an error.
func (v *Ed25519Verifier) Verify(manifestPath string, m *Manifest) error {
	if v == nil || v.publicKey == nil {
		return errors.New("plugin: nil Ed25519 verifier")
	}
	if m == nil {
		return errors.New("plugin: nil manifest")
	}
	if m.Signature == nil || strings.TrimSpace(m.Signature.Value) == "" {
		return fmt.Errorf("%w: manifest %s (id=%q)", ErrManifestSignatureMissing, manifestPath, m.ID)
	}
	if alg := strings.ToLower(strings.TrimSpace(m.Signature.Algorithm)); alg != ManifestSignatureAlgorithm {
		return fmt.Errorf("plugin: manifest %s (id=%q) unsupported signature algorithm %q (want %q)", manifestPath, m.ID, m.Signature.Algorithm, ManifestSignatureAlgorithm)
	}
	payload, err := signingPayload(m)
	if err != nil {
		return fmt.Errorf("plugin: manifest %s (id=%q): %w", manifestPath, m.ID, err)
	}
	sig, err := decodeManifestSignature([]byte(m.Signature.Value))
	if err != nil {
		return fmt.Errorf("plugin: manifest %s (id=%q): %w", manifestPath, m.ID, err)
	}
	if !ed25519.Verify(v.publicKey, payload, sig) {
		return fmt.Errorf("plugin: manifest %s (id=%q) signature verification failed", manifestPath, m.ID)
	}
	return nil
}

// signingPayload returns the canonical bytes that an inline manifest signature is computed
// over: the manifest re-marshalled with its Signature field cleared.
func signingPayload(m *Manifest) ([]byte, error) {
	clone := *m
	clone.Signature = nil
	payload, err := json.Marshal(&clone)
	if err != nil {
		return nil, fmt.Errorf("marshal signing payload: %w", err)
	}
	return payload, nil
}

// parseEd25519PublicKey parses a PEM-encoded Ed25519 public key. It accepts a
// PKIX/SubjectPublicKeyInfo PEM block ("BEGIN PUBLIC KEY") and, as a convenience, a raw
// base64-encoded 32-byte key supplied without PEM framing. Mirrors the approach in
// internal/policy/signature.go.
func parseEd25519PublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(string(pemBytes))
	if trimmed == "" {
		return nil, errors.New("plugin: empty public key")
	}

	block, _ := pem.Decode([]byte(trimmed))
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("plugin: parse PKIX public key: %w", err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("plugin: public key is not Ed25519 (got %T)", pub)
		}
		return edPub, nil
	}

	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}

	return nil, errors.New("plugin: public key is not a valid PEM-encoded Ed25519 key")
}

// decodeManifestSignature interprets the inline signature value as an Ed25519 signature.
// It accepts standard base64 (preferred) or raw 64-byte binary content.
func decodeManifestSignature(value []byte) ([]byte, error) {
	if len(value) == ed25519.SignatureSize {
		return value, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(value)))
	if err != nil {
		return nil, fmt.Errorf("signature is neither raw 64 bytes nor valid base64: %w", err)
	}
	if len(decoded) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature has wrong length: got %d, want %d", len(decoded), ed25519.SignatureSize)
	}
	return decoded, nil
}

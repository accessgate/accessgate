package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// GeneratePKCE returns code_verifier, code_challenge (S256), and nonce.
func GeneratePKCE() (verifier, challenge, nonce string, err error) {
	const verifierLen = 32
	b := make([]byte, verifierLen)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	digest := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(digest[:])
	nonceB := make([]byte, 16)
	if _, err := rand.Read(nonceB); err != nil {
		return "", "", "", err
	}
	nonce = base64.RawURLEncoding.EncodeToString(nonceB)
	return verifier, challenge, nonce, nil
}

// GenerateState returns a random state value for the auth flow.
func GenerateState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

const (
	aesGCMNonceSize = 12
	aesGCMTagSize   = 16
	aesKeySize      = 32
)

var (
	ErrDecrypt = errors.New("cookie: decrypt failed")
)

// Encrypt encrypts plaintext with AES-256-GCM. key is used to derive a 32-byte key via SHA-256 if needed.
// Output format: nonce (12 bytes) || ciphertext || tag (16 bytes).
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	k := deriveKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext produced by Encrypt. key must match the one used to encrypt.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) <= aesGCMNonceSize+aesGCMTagSize {
		return nil, ErrDecrypt
	}
	k := deriveKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plain, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

func deriveKey(key []byte) []byte {
	if len(key) == aesKeySize {
		return key
	}
	h := sha256.Sum256(key)
	return h[:]
}

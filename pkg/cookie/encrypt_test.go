package cookie

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("hello")
	key := []byte("dummy-key")

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("Encrypt should not return plaintext as-is")
	}

	out, err := decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if string(out) != string(plaintext) {
		t.Fatalf("expected %q, got %q", string(plaintext), string(out))
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key := []byte("encryption-key-32-bytes-long!!!!!")
	plain := []byte("secret")
	ct, err := encrypt(plain, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrongKey := []byte("wrong-key-32-bytes-long!!!!!!!!!")
	_, err = decrypt(ct, wrongKey)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
	if err != ErrDecrypt {
		t.Errorf("expected ErrDecrypt, got %v", err)
	}
}

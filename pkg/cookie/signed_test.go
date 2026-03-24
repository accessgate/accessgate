package cookie

import (
	"bytes"
	"testing"
)

func TestSignedManagerWithKeysRotation(t *testing.T) {
	oldSecret := "old-secret"
	newSecret := "new-secret"
	m := NewSignedManagerWithKeys(newSecret, oldSecret)

	val, err := m.Encode("session-123")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var s string
	if err := m.Decode(val, &s); err != nil {
		t.Fatalf("Decode (new): %v", err)
	}
	if s != "session-123" {
		t.Fatalf("expected session-123, got %q", s)
	}

	mOld := NewSignedManager(oldSecret)
	valOld, _ := mOld.Encode("session-old")
	if err := m.Decode(valOld, &s); err != nil {
		t.Fatalf("Decode (old key): %v", err)
	}
	if s != "session-old" {
		t.Fatalf("expected session-old, got %q", s)
	}
}

func TestSignedManager_Decode_TamperedValue(t *testing.T) {
	m := NewSignedManager("secret")
	val, err := m.Encode("session-123")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tampered := val
	if idx := bytes.IndexByte([]byte(val), '.'); idx > 0 {
		b := []byte(val)
		b[0] ^= 0x01
		tampered = string(b)
	}
	var s string
	err = m.Decode(tampered, &s)
	if err == nil {
		t.Fatal("expected error when decoding tampered signed value")
	}
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestSignedCodecRoundTrip(t *testing.T) {
	c := NewSignedCodec(NewSignedManager("x"))
	raw, err := c.Encode("id1")
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Decode(raw)
	if err != nil || id != "id1" {
		t.Fatalf("%q %v", id, err)
	}
}

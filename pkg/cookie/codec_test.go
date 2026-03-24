package cookie

import (
	"encoding/base64"
	"testing"
)

func TestEncodeDecodeValueRoundTrip(t *testing.T) {
	type payload struct {
		Foo string
		Bar int
	}

	src := payload{Foo: "baz", Bar: 42}
	key := []byte("test-secret-32-bytes-long enough!!")

	encoded, err := EncodeValue(src, key)
	if err != nil {
		t.Fatalf("EncodeValue returned error: %v", err)
	}

	var dst payload
	if err := DecodeValue(encoded, &dst, key); err != nil {
		t.Fatalf("DecodeValue returned error: %v", err)
	}
	if dst.Foo != src.Foo || dst.Bar != src.Bar {
		t.Fatalf("expected %+v, got %+v", src, dst)
	}
}

func TestEncodeDecodeValueRoundTripNoKey(t *testing.T) {
	type payload struct {
		Foo string
	}
	src := payload{Foo: "baz"}
	encoded, err := EncodeValue(src, nil)
	if err != nil {
		t.Fatalf("EncodeValue returned error: %v", err)
	}
	var dst payload
	if err := DecodeValue(encoded, &dst, nil); err != nil {
		t.Fatalf("DecodeValue returned error: %v", err)
	}
	if dst.Foo != src.Foo {
		t.Fatalf("expected %+v, got %+v", src, dst)
	}
}

func TestDecodeValue_WrongKey(t *testing.T) {
	type payload struct{ Foo string }
	key := []byte("test-secret-32-bytes-long enough!!")
	encoded, err := EncodeValue(payload{Foo: "secret"}, key)
	if err != nil {
		t.Fatalf("EncodeValue: %v", err)
	}
	wrongKey := []byte("other-secret-32-bytes-long enough!!")
	var dst payload
	err = DecodeValue(encoded, &dst, wrongKey)
	if err == nil {
		t.Fatal("expected error when decoding with wrong key")
	}
	if err != ErrDecrypt && err != ErrCodecDecode {
		t.Errorf("expected ErrDecrypt or ErrCodecDecode, got %v", err)
	}
}

func TestDecodeValue_TamperedPayload(t *testing.T) {
	key := []byte("test-secret-32-bytes-long enough!!")
	encoded, err := EncodeValue(struct{ X int }{42}, key)
	if err != nil {
		t.Fatalf("EncodeValue: %v", err)
	}
	raw, _ := base64.URLEncoding.DecodeString(encoded)
	if len(raw) < 2 {
		t.Fatal("encoded value too short to tamper")
	}
	raw[0] ^= 0x01
	tampered := base64.URLEncoding.EncodeToString(raw)
	var dst struct{ X int }
	err = DecodeValue(tampered, &dst, key)
	if err == nil {
		t.Fatal("expected error when decoding tampered payload")
	}
}

func TestDecodeValue_InvalidBase64(t *testing.T) {
	key := []byte("test-secret-32-bytes-long enough!!")
	var dst struct{ Foo string }
	err := DecodeValue("not-valid-base64!!!", &dst, key)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if err != ErrCodecDecode {
		t.Errorf("expected ErrCodecDecode, got %v", err)
	}
}

package cookie

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrCodecEncode = errors.New("cookie: encode failed")
	ErrCodecDecode = errors.New("cookie: decode failed")
)

// Codec encodes and decodes session IDs to and from cookie-safe strings.
type Codec interface {
	Encode(sessionID string) (string, error)
	Decode(raw string) (string, error)
}

// RotatingCodec selects the appropriate Codec for a given timestamp, enabling key rotation.
type RotatingCodec interface {
	Current() Codec
	ForTimestamp(ts time.Time) (Codec, error)
}

// EncodeValue serializes v to JSON, encrypts with key, and returns a base64-URL cookie-safe string.
// key can be nil for unencrypted base64-only encoding (not recommended for sensitive data).
func EncodeValue(v any, key []byte) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if len(key) > 0 {
		data, err = Encrypt(data, key)
		if err != nil {
			return "", err
		}
	} else {
		data = []byte(base64.URLEncoding.EncodeToString(data))
	}
	return base64.URLEncoding.EncodeToString(data), nil
}

// DecodeValue decodes a cookie value produced by EncodeValue into dst.
// key must match the one used for EncodeValue; use nil if value was encoded without encryption.
func DecodeValue(raw string, dst any, key []byte) error {
	data, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return ErrCodecDecode
	}
	if len(key) > 0 {
		data, err = Decrypt(data, key)
		if err != nil {
			return err
		}
	} else {
		data, err = base64.URLEncoding.DecodeString(string(data))
		if err != nil {
			return ErrCodecDecode
		}
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return ErrCodecDecode
	}
	return nil
}

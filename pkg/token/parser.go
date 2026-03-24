package token

import (
	"encoding/base64"
	"strings"
)

// ParseJWT splits a raw JWT into header, payload, and signature segments (base64url decoded).
// It does not verify the signature.
func ParseJWT(raw string) (header, payload, signature []byte, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, nil, nil
	}
	header, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, err
	}
	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, err
	}
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, err
	}
	return header, payload, signature, nil
}

package token

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ValidateIDToken verifies the ID token signature using JWKSSource, then validates exp, iss, aud, and optional nonce.
// Returns a Principal with claims from the token.
func ValidateIDToken(ctx context.Context, raw string, jwksSource JWKSSource, issuer, audience, expectedNonce string) (*Principal, error) {
	if jwksSource == nil {
		return nil, fmt.Errorf("token: JWKSSource is nil")
	}
	jwksData, err := jwksSource.GetJWKS(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("token: get jwks: %w", err)
	}
	keyfunc := keyFuncFromJWKS(jwksData)
	token, err := jwt.Parse(raw, keyfunc, jwt.WithIssuer(issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, fmt.Errorf("token: parse: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token: invalid claims")
	}
	if audience != "" {
		audValid := false
		switch v := claims["aud"].(type) {
		case string:
			audValid = v == audience
		case []interface{}:
			for _, a := range v {
				if s, ok := a.(string); ok && s == audience {
					audValid = true
					break
				}
			}
		}
		if !audValid {
			return nil, fmt.Errorf("token: audience mismatch")
		}
	}
	if expectedNonce != "" {
		nonce, _ := claims["nonce"].(string)
		if nonce != expectedNonce {
			return nil, fmt.Errorf("token: nonce mismatch")
		}
	}
	sub, _ := claims["sub"].(string)
	exp := time.Time{}
	if v, ok := claims["exp"]; ok {
		switch t := v.(type) {
		case float64:
			exp = time.Unix(int64(t), 0)
		case json.Number:
			n, _ := t.Int64()
			exp = time.Unix(n, 0)
		}
	}
	claimsMap := make(map[string]any)
	for k, v := range claims {
		claimsMap[k] = v
	}
	var roles []string
	if r, ok := claims["realm_access"].(map[string]any); ok {
		if arr, ok := r["roles"].([]interface{}); ok {
			for _, x := range arr {
				if s, ok := x.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}
	if len(roles) == 0 {
		if r, ok := claims["roles"].([]interface{}); ok {
			for _, x := range r {
				if s, ok := x.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}
	return &Principal{
		Subject:   sub,
		Roles:     roles,
		Claims:    claimsMap,
		ExpiresAt: exp,
	}, nil
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func keyFuncFromJWKS(jwksData []byte) jwt.Keyfunc {
	var set struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := json.Unmarshal(jwksData, &set); err != nil {
		return func(t *jwt.Token) (interface{}, error) { return nil, err }
	}
	return func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token: missing kid in header")
		}
		for _, k := range set.Keys {
			if k.Kid != kid {
				continue
			}
			switch k.Kty {
			case "RSA":
				if k.N == "" || k.E == "" {
					continue
				}
				nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
				if err != nil {
					return nil, err
				}
				eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
				if err != nil {
					return nil, err
				}
				n := new(big.Int).SetBytes(nBytes)
				if n.BitLen() < 2048 {
					return nil, fmt.Errorf("token: RSA key too small: %d bits (minimum 2048)", n.BitLen())
				}
				eBig := new(big.Int).SetBytes(eBytes)
				if !eBig.IsInt64() || eBig.Int64() > 1<<31-1 {
					return nil, fmt.Errorf("token: exponent too large")
				}
				return &rsa.PublicKey{N: n, E: int(eBig.Int64())}, nil
			case "EC":
				if k.Crv == "" || k.X == "" || k.Y == "" {
					continue
				}
				pub, err := ecPubKeyFromJWK(k.Crv, k.X, k.Y)
				if err != nil {
					return nil, err
				}
				return pub, nil
			}
		}
		return nil, fmt.Errorf("token: no key found for kid %s", kid)
	}
}

func ecPubKeyFromJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var fieldBytes int
	var ecdhCurve ecdh.Curve
	var ellipticCurve elliptic.Curve
	switch crv {
	case "P-256":
		fieldBytes = 32
		ecdhCurve = ecdh.P256()
		ellipticCurve = elliptic.P256()
	case "P-384":
		fieldBytes = 48
		ecdhCurve = ecdh.P384()
		ellipticCurve = elliptic.P384()
	case "P-521":
		fieldBytes = 66
		ecdhCurve = ecdh.P521()
		ellipticCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("token: unsupported EC curve %s", crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, err
	}
	if len(xBytes) > fieldBytes || len(yBytes) > fieldBytes {
		return nil, fmt.Errorf("token: EC coordinate too large for %s", crv)
	}
	xP := make([]byte, fieldBytes)
	yP := make([]byte, fieldBytes)
	copy(xP[fieldBytes-len(xBytes):], xBytes)
	copy(yP[fieldBytes-len(yBytes):], yBytes)
	sec1 := make([]byte, 1+2*fieldBytes)
	sec1[0] = 4
	copy(sec1[1:], xP)
	copy(sec1[1+fieldBytes:], yP)
	pubECDH, err := ecdhCurve.NewPublicKey(sec1)
	if err != nil {
		return nil, fmt.Errorf("token: EC public key point is not on curve %s: %w", crv, err)
	}
	raw := pubECDH.Bytes()
	if len(raw) != len(sec1) || raw[0] != 4 {
		return nil, fmt.Errorf("token: unexpected EC public key encoding for %s", crv)
	}
	x := new(big.Int).SetBytes(raw[1 : 1+fieldBytes])
	y := new(big.Int).SetBytes(raw[1+fieldBytes:])
	return &ecdsa.PublicKey{Curve: ellipticCurve, X: x, Y: y}, nil
}

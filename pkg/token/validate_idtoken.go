package token

import (
	"context"
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
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
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
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("token: EC public key point is not on curve %s", crv)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

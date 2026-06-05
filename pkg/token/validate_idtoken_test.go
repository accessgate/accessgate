package token

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "client-app"
)

func TestValidateIDToken_NilSource(t *testing.T) {
	_, err := ValidateIDToken(context.Background(), "x", nil, testIssuer, testAudience, "")
	if err == nil || !strings.Contains(err.Error(), "JWKSSource is nil") {
		t.Fatalf("expected nil-source error, got %v", err)
	}
}

func TestValidateIDToken_Valid(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}
	raw := signRS256(t, key, testKID, validClaims(testIssuer, testAudience))

	p, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, "")
	if err != nil {
		t.Fatalf("ValidateIDToken: %v", err)
	}
	if p.Subject != "user-123" {
		t.Fatalf("subject = %q", p.Subject)
	}
	if p.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero ExpiresAt")
	}
	if p.Claims["iss"] != testIssuer {
		t.Fatalf("claims iss = %v", p.Claims["iss"])
	}
}

func TestValidateIDToken_ValidEC(t *testing.T) {
	key := ecTestKey(t)
	src := &staticJWKSSource{data: ecJWKS(t, key, testKID)}
	raw := signES256(t, key, testKID, validClaims(testIssuer, testAudience))

	p, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, "")
	if err != nil {
		t.Fatalf("ValidateIDToken (EC): %v", err)
	}
	if p.Subject != "user-123" {
		t.Fatalf("subject = %q", p.Subject)
	}
}

func TestValidateIDToken_AudienceAsArray(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}
	claims := validClaims(testIssuer, "")
	claims["aud"] = []interface{}{"other-app", testAudience}
	raw := signRS256(t, key, testKID, claims)

	if _, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, ""); err != nil {
		t.Fatalf("expected array audience to match, got %v", err)
	}
}

func TestValidateIDToken_NonceMatch(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}
	claims := validClaims(testIssuer, testAudience)
	claims["nonce"] = "n-123"
	raw := signRS256(t, key, testKID, claims)

	if _, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, "n-123"); err != nil {
		t.Fatalf("expected nonce match, got %v", err)
	}
}

func TestValidateIDToken_Roles(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}

	t.Run("realm_access roles", func(t *testing.T) {
		claims := validClaims(testIssuer, testAudience)
		claims["realm_access"] = map[string]any{"roles": []interface{}{"admin", "user"}}
		raw := signRS256(t, key, testKID, claims)
		p, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Roles) != 2 || p.Roles[0] != "admin" || p.Roles[1] != "user" {
			t.Fatalf("roles = %v", p.Roles)
		}
	})

	t.Run("top-level roles", func(t *testing.T) {
		claims := validClaims(testIssuer, testAudience)
		claims["roles"] = []interface{}{"editor"}
		raw := signRS256(t, key, testKID, claims)
		p, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Roles) != 1 || p.Roles[0] != "editor" {
			t.Fatalf("roles = %v", p.Roles)
		}
	})
}

func TestValidateIDToken_Rejections(t *testing.T) {
	key := rsaTestKey(t)
	jwks := rsaJWKS(t, key, testKID)

	tests := []struct {
		name       string
		mutate     func(jwt.MapClaims)
		kid        string
		issuer     string
		audience   string
		nonce      string
		wantSubstr string
	}{
		{
			name:       "wrong issuer",
			issuer:     "https://evil.example.com",
			audience:   testAudience,
			wantSubstr: "parse",
		},
		{
			name:       "wrong audience",
			audience:   "different-app",
			issuer:     testIssuer,
			wantSubstr: "audience mismatch",
		},
		{
			name:       "nonce mismatch",
			mutate:     func(c jwt.MapClaims) { c["nonce"] = "actual" },
			nonce:      "expected",
			issuer:     testIssuer,
			audience:   testAudience,
			wantSubstr: "nonce mismatch",
		},
		{
			name:       "missing nonce when expected",
			nonce:      "expected",
			issuer:     testIssuer,
			audience:   testAudience,
			wantSubstr: "nonce mismatch",
		},
		{
			name:       "expired token",
			mutate:     func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
			issuer:     testIssuer,
			audience:   testAudience,
			wantSubstr: "parse",
		},
		{
			name:       "missing exp (expiration required)",
			mutate:     func(c jwt.MapClaims) { delete(c, "exp") },
			issuer:     testIssuer,
			audience:   testAudience,
			wantSubstr: "parse",
		},
		{
			name:       "unknown kid",
			kid:        "other-kid",
			issuer:     testIssuer,
			audience:   testAudience,
			wantSubstr: "parse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims(testIssuer, testAudience)
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			kid := testKID
			if tc.kid != "" {
				kid = tc.kid
			}
			raw := signRS256(t, key, kid, claims)
			src := &staticJWKSSource{data: jwks}
			_, err := ValidateIDToken(context.Background(), raw, src, tc.issuer, tc.audience, tc.nonce)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

func TestValidateIDToken_SignatureMismatch(t *testing.T) {
	signingKey := rsaTestKey(t)
	otherKey := rsaTestKey(t)
	// JWKS advertises a DIFFERENT key than the one used to sign.
	src := &staticJWKSSource{data: rsaJWKS(t, otherKey, testKID)}
	raw := signRS256(t, signingKey, testKID, validClaims(testIssuer, testAudience))

	_, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, "")
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestValidateIDToken_MissingKidHeader(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}
	// Sign without a kid header.
	raw := signRS256(t, key, "", validClaims(testIssuer, testAudience))

	_, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, "")
	if err == nil {
		t.Fatal("expected error for missing kid header")
	}
}

func TestValidateIDToken_NoneAlg(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}
	// Craft an alg=none token manually.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims(testIssuer, testAudience))
	tok.Header["kid"] = testKID
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, ""); err == nil {
		t.Fatal("expected alg=none to be rejected")
	}
}

func TestValidateIDToken_Malformed(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}
	for _, raw := range []string{"", "not-a-jwt", "a.b.c"} {
		if _, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, ""); err == nil {
			t.Fatalf("expected error for malformed token %q", raw)
		}
	}
}

func TestValidateIDToken_JWKSSourceError(t *testing.T) {
	src := &staticJWKSSource{err: context.DeadlineExceeded}
	_, err := ValidateIDToken(context.Background(), "a.b.c", src, testIssuer, testAudience, "")
	if err == nil || !strings.Contains(err.Error(), "get jwks") {
		t.Fatalf("expected get jwks error, got %v", err)
	}
}

func TestValidateIDToken_InvalidJWKSData(t *testing.T) {
	// keyFuncFromJWKS returns a keyfunc that errors when the JWKS is unparsable;
	// jwt.Parse should then fail.
	src := &staticJWKSSource{data: []byte("not json")}
	key := rsaTestKey(t)
	raw := signRS256(t, key, testKID, validClaims(testIssuer, testAudience))
	if _, err := ValidateIDToken(context.Background(), raw, src, testIssuer, testAudience, ""); err == nil {
		t.Fatal("expected error for unparsable JWKS data")
	}
}

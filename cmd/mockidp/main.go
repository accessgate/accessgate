package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type authCodeInfo struct {
	CodeChallenge string
	Nonce         string
	ClientID      string
	RedirectURI   string
	State         string
	CreatedAt     time.Time
}

type refreshInfo struct {
	ClientID string
}

func main() {
	addr := envOrDefault("MOCKIDP_LISTEN_ADDR", ":8082")
	issuer := envOrDefault("MOCKIDP_ISSUER", "http://mockidp:8082")

	authorizationEndpoint := envOrDefault("MOCKIDP_AUTHORIZATION_ENDPOINT", "http://localhost:8082/authorize")
	tokenEndpoint := envOrDefault("MOCKIDP_TOKEN_ENDPOINT", "http://mockidp:8082/token")
	jwksURI := envOrDefault("MOCKIDP_JWKS_URI", "http://mockidp:8082/jwks")
	endSessionEndpoint := envOrDefault("MOCKIDP_END_SESSION_ENDPOINT", "http://localhost:8082/logout")

	idTokenSub := envOrDefault("MOCKIDP_SUB", "test-user")
	idTokenEmail := envOrDefault("MOCKIDP_EMAIL", "u@example.com")
	expiresInSeconds := envOrDefaultInt("MOCKIDP_EXPIRES_IN_SECONDS", 10)

	log.Printf("[mockidp] listen=%s issuer=%s auth=%s token=%s jwks=%s end_session=%s", addr, issuer, authorizationEndpoint, tokenEndpoint, jwksURI, endSessionEndpoint)

	key := mustGenerateRSAKey()
	kid := envOrDefault("MOCKIDP_KID", "mock-kid")

	var (
		codesMu    sync.Mutex
		authCodes  = make(map[string]authCodeInfo)
		refreshMu  sync.Mutex
		refreshMap = make(map[string]refreshInfo)
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": authorizationEndpoint,
			"token_endpoint":         tokenEndpoint,
			"jwks_uri":               jwksURI,
			"end_session_endpoint":   endSessionEndpoint,
		})
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		q := r.URL.Query()
		clientID := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		codeChallenge := q.Get("code_challenge")
		nonce := q.Get("nonce")
		if redirectURI == "" || state == "" || codeChallenge == "" || nonce == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing required authorize params"))
			return
		}

		code := randomCode()
		codesMu.Lock()
		authCodes[code] = authCodeInfo{
			CodeChallenge: codeChallenge,
			Nonce:         nonce,
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			State:         state,
			CreatedAt:     time.Now(),
		}
		codesMu.Unlock()

		// Redirect back to agent callback with code + state.
		u, err := url.Parse(redirectURI)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		qq := u.Query()
		qq.Set("code", code)
		qq.Set("state", state)
		u.RawQuery = qq.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()

		grantType := r.FormValue("grant_type")
		w.Header().Set("Content-Type", "application/json")

		switch grantType {
		case "authorization_code":
			handleAuthCodeToken(w, r, &codesMu, authCodes, &refreshMu, refreshMap, expiresInSeconds, issuer, kid, idTokenSub, idTokenEmail, expiresInSeconds)
		case "refresh_token":
			handleRefreshToken(w, r, &refreshMu, refreshMap, expiresInSeconds, issuer, kid, idTokenSub, idTokenEmail, expiresInSeconds)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
		}
	})

	// Minimal end-session endpoint for logout.
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		nBytes := key.N.Bytes()
		e := key.E
		// RFC7517 base64url without padding.
		n := base64.RawURLEncoding.EncodeToString(nBytes)
		eBig := big.NewInt(int64(e)).Bytes()
		eStr := base64.RawURLEncoding.EncodeToString(eBig)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": kid,
					"n":   n,
					"e":   eStr,
				},
			},
		})
	})

	log.Printf("[mockidp] serving on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleAuthCodeToken(
	w http.ResponseWriter,
	r *http.Request,
	codesMu *sync.Mutex,
	authCodes map[string]authCodeInfo,
	refreshMu *sync.Mutex,
	refreshMap map[string]refreshInfo,
	expiresIn int,
	issuer string,
	kid string,
	sub string,
	email string,
	expiresInSeconds int,
) {
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	// redirect_uri is sent by agent but we don't validate it in the mock.
	_ = r.FormValue("redirect_uri")

	codesMu.Lock()
	info, ok := authCodes[code]
	codesMu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_code"}`))
		return
	}

	expected := s256Challenge(codeVerifier)
	if expected != info.CodeChallenge {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_code_verifier"}`))
		return
	}

	accessToken := "access-" + code
	refreshToken := "refresh-" + randomCode()

	refreshMu.Lock()
	refreshMap[refreshToken] = refreshInfo{ClientID: info.ClientID}
	refreshMu.Unlock()

	idToken := signIDToken(issuer, info.ClientID, info.Nonce, sub, email, time.Now().Add(time.Duration(expiresInSeconds)*time.Second), kid)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"id_token":      idToken,
		"expires_in":    expiresInSeconds,
		"token_type":    "Bearer",
	})
}

func handleRefreshToken(
	w http.ResponseWriter,
	r *http.Request,
	refreshMu *sync.Mutex,
	refreshMap map[string]refreshInfo,
	expiresIn int,
	issuer string,
	kid string,
	sub string,
	email string,
	expiresInSeconds int,
) {
	refreshToken := r.FormValue("refresh_token")
	refreshMu.Lock()
	info, ok := refreshMap[refreshToken]
	refreshMu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_refresh_token"}`))
		return
	}

	accessToken := "access-refresh-" + refreshToken
	newRefreshToken := "refresh-" + randomCode()

	refreshMu.Lock()
	refreshMap[newRefreshToken] = refreshInfo{ClientID: info.ClientID}
	refreshMu.Unlock()

	idToken := signIDToken(issuer, info.ClientID, "", sub, email, time.Now().Add(time.Duration(expiresInSeconds)*time.Second), kid)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"id_token":      idToken,
		"expires_in":    expiresInSeconds,
		"token_type":    "Bearer",
	})
}

func signIDToken(issuer, audience, nonce, sub, email string, exp time.Time, kid string) string {
	claims := jwt.MapClaims{
		"iss":   issuer,
		"aud":   audience,
		"sub":   sub,
		"exp":   exp.Unix(),
		"iat":   time.Now().Unix(),
		"email": email,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid

	// We sign with the global key created in main; to keep the file small,
	// we use a package-level variable is avoided. Instead, this function
	// uses the default global key by re-generating would be expensive, so
	// we rely on a closure in main. For simplicity, we embed the signing key
	// via a global variable.
	//
	// NOTE: This is a mock IdP; in v1 it's acceptable for the signing key
	// to be stored globally.
	return mustSign(tok)
}

var signingKey *rsa.PrivateKey

func mustSign(tok *jwt.Token) string {
	if signingKey == nil {
		// should never happen
		panic("mockidp signingKey is nil")
	}
	s, err := tok.SignedString(signingKey)
	if err != nil {
		panic(err)
	}
	return s
}

func mustGenerateRSAKey() *rsa.PrivateKey {
	// 2048-bit RSA is sufficient for this mock.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// store global signing key for signIDToken
	signingKey = key
	return key
}

func randomCode() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.TrimSpace(base64.RawURLEncoding.EncodeToString(b))
}

func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func envOrDefault(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envOrDefaultInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil {
		return def
	}
	return n
}

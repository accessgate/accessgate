package cookie

import "net/http"

// Manager is responsible for encoding, decoding and managing HTTP cookies.
type Manager interface {
	Encode(v any) (string, error)
	Decode(raw string, dst any) error
	Set(w http.ResponseWriter, name string, value string, opts CookieOptions)
	Clear(w http.ResponseWriter, name string, opts CookieOptions)
}

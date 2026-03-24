package errormap

import (
	"errors"
	"net/http"
	"strings"
)

// StatusFor returns an appropriate HTTP status code for the given error.
// Used by agent HTTP handlers to map service errors to responses.
func StatusFor(err error) int {
	if err == nil {
		return http.StatusOK
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "missing") || strings.Contains(s, "required"):
		return http.StatusBadRequest
	case strings.Contains(s, "invalid") || strings.Contains(s, "redirect"):
		return http.StatusBadRequest
	case strings.Contains(s, "not found") || strings.Contains(s, "NotFound"):
		return http.StatusNotFound
	case strings.Contains(s, "unauthorized") || strings.Contains(s, "Unauthorized"):
		return http.StatusUnauthorized
	case strings.Contains(s, "forbidden"):
		return http.StatusForbidden
	case errors.Is(err, errBadRequest):
		return http.StatusBadRequest
	case errors.Is(err, errNotFound):
		return http.StatusNotFound
	case errors.Is(err, errUnauthorized):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

var (
	errBadRequest   = errors.New("bad request")
	errNotFound     = errors.New("not found")
	errUnauthorized = errors.New("unauthorized")
)

// BadRequest returns an error that maps to 400.
func BadRequest(msg string) error { return errors.Join(errBadRequest, errors.New(msg)) }

// NotFound returns an error that maps to 404.
func NotFound(msg string) error { return errors.Join(errNotFound, errors.New(msg)) }

// Unauthorized returns an error that maps to 401.
func Unauthorized(msg string) error { return errors.Join(errUnauthorized, errors.New(msg)) }

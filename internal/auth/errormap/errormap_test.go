package errormap

import (
	"errors"
	"net/http"
	"testing"
)

func TestStatusForNil(t *testing.T) {
	if got := StatusFor(nil); got != http.StatusOK {
		t.Fatalf("got %d", got)
	}
}

func TestStatusForSentinelErrors(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{BadRequest("x"), http.StatusBadRequest},
		{NotFound("x"), http.StatusNotFound},
		{Unauthorized("x"), http.StatusUnauthorized},
	}
	for _, tc := range tests {
		if got := StatusFor(tc.err); got != tc.want {
			t.Fatalf("StatusFor(%v)=%d want %d", tc.err, got, tc.want)
		}
	}
}

func TestStatusForStringHeuristics(t *testing.T) {
	tests := []struct {
		msg  string
		want int
	}{
		{"missing token", http.StatusBadRequest},
		{"field required", http.StatusBadRequest},
		{"invalid state", http.StatusBadRequest},
		{"bad redirect", http.StatusBadRequest},
		{"user not found", http.StatusNotFound},
		{"NotFound resource", http.StatusNotFound},
		{"unauthorized access", http.StatusUnauthorized},
		{"Unauthorized", http.StatusUnauthorized},
		{"forbidden by policy", http.StatusForbidden},
		{"something else blew up", http.StatusInternalServerError},
	}
	for _, tc := range tests {
		if got := StatusFor(errors.New(tc.msg)); got != tc.want {
			t.Fatalf("msg %q: got %d want %d", tc.msg, got, tc.want)
		}
	}
}

package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDenyBodyEscapesJSON(t *testing.T) {
	b := DenyBody(403, `say "hi" and \`)
	var wrap struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		t.Fatal(err)
	}
	if len(wrap.Errors) != 1 || !strings.Contains(wrap.Errors[0].Message, "hi") {
		t.Fatalf("%s", string(b))
	}
}

func TestWriteDenyResponse(t *testing.T) {
	w := httptest.NewRecorder()
	WriteDenyResponse(w, 401, "nope")
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatal(ct)
	}
}

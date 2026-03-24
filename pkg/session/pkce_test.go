package session

import (
	"encoding/json"
	"testing"
)

func TestPKCEStateJSON(t *testing.T) {
	p := PKCEState{
		State: "st", CodeVerifier: "v", CodeChallenge: "c",
		Nonce: "n", RedirectTo: "/app",
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got PKCEState
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.State != p.State || got.RedirectTo != p.RedirectTo {
		t.Fatalf("%+v", got)
	}
}

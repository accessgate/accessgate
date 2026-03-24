package oidcprovider

import (
	"encoding/json"
	"testing"
)

func TestScopesUnmarshalString(t *testing.T) {
	var s Scopes
	if err := json.Unmarshal([]byte(`"openid profile email"`), &s); err != nil {
		t.Fatal(err)
	}
	if len(s) != 3 {
		t.Fatalf("%v", s)
	}
}

func TestScopesUnmarshalArray(t *testing.T) {
	var s Scopes
	if err := json.Unmarshal([]byte(`["a","b"]`), &s); err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 {
		t.Fatal(s)
	}
}

func TestPluginDescriptor(t *testing.T) {
	p := New()
	d := p.Descriptor()
	if d.ID != "provider:oidc" {
		t.Fatal(d.ID)
	}
}

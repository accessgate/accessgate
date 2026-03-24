package authz

import (
	"net/url"
	"testing"
)

func TestValidateUpstreamURL_RejectsFileScheme(t *testing.T) {
	u, _ := url.Parse("file:///etc/passwd")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("file:// scheme should be rejected")
	}
}

func TestValidateUpstreamURL_RejectsGopherScheme(t *testing.T) {
	u, _ := url.Parse("gopher://127.0.0.1:70/")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("gopher:// scheme should be rejected")
	}
}

func TestValidateUpstreamURL_RejectsLoopback(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/admin")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("loopback address should be rejected")
	}
}

func TestValidateUpstreamURL_RejectsIPv6Loopback(t *testing.T) {
	u, _ := url.Parse("http://[::1]/admin")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("IPv6 loopback should be rejected")
	}
}

func TestValidateUpstreamURL_RejectsPrivateRFC1918(t *testing.T) {
	for _, addr := range []string{
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://192.168.1.1/",
	} {
		u, _ := url.Parse(addr)
		if err := validateUpstreamURL(u); err == nil {
			t.Errorf("private address %s should be rejected", addr)
		}
	}
}

func TestValidateUpstreamURL_RejectsLinkLocal(t *testing.T) {
	u, _ := url.Parse("http://169.254.169.254/latest/meta-data/")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("link-local (metadata) address should be rejected")
	}
}

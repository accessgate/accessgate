package healthcheck

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newServerOnLoopback starts an httptest server bound to 127.0.0.1 and returns
// the port it listened on. Run() always dials 127.0.0.1, so the test server
// must too.
func newServerOnLoopback(t *testing.T, h http.Handler) (port string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)

	_, p, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	return p
}

func TestRun_Healthy(t *testing.T) {
	port := newServerOnLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_HC_PORT", port)
	if err := Run("TEST_HC_PORT", "0", "/healthz"); err != nil {
		t.Fatalf("expected healthy, got error: %v", err)
	}
}

func TestRun_UnhealthyStatus(t *testing.T) {
	port := newServerOnLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	t.Setenv("TEST_HC_PORT", port)
	err := Run("TEST_HC_PORT", "0", "/healthz")
	if err == nil {
		t.Fatal("expected error for 503 status, got nil")
	}
	if !strings.Contains(err.Error(), "unhealthy status 503") {
		t.Fatalf("expected unhealthy status error, got: %v", err)
	}
}

func TestRun_ConnectionRefused(t *testing.T) {
	// Bind+close to obtain a port nothing is listening on.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()

	t.Setenv("TEST_HC_PORT", port)
	if err := Run("TEST_HC_PORT", "0", "/healthz"); err == nil {
		t.Fatal("expected error for refused connection, got nil")
	}
}

func TestRun_DefaultPortWhenEnvUnset(t *testing.T) {
	port := newServerOnLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Env var unset -> falls back to defaultPort.
	if err := Run("DEFINITELY_UNSET_HC_PORT", port, "/healthz"); err != nil {
		t.Fatalf("expected healthy via default port, got error: %v", err)
	}
}

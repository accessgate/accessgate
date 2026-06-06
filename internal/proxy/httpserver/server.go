package httpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	pkgproxy "github.com/accessgate/accessgate/internal/authz"
	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/internal/proxy/config"
)

// Server is the HTTP server for the Proxy app.
type Server struct {
	mux            *http.ServeMux
	cfg            *config.Config
	engine         pkgproxy.Engine
	registry       *plugin.Registry
	metricsHandler http.Handler
}

// New constructs a new Server with the given config and prebuilt proxy engine.
// registry is optional; when set it holds discovered/registered plugins for pipeline use and admin.
// metricsHandler is optional; when set, GET /metrics is registered (e.g. promhttp.HandlerFor(reg, ...)).
func New(cfg *config.Config, engine pkgproxy.Engine, registry *plugin.Registry, metricsHandler http.Handler) *Server {
	s := &Server{
		mux:            http.NewServeMux(),
		cfg:            cfg,
		engine:         engine,
		registry:       registry,
		metricsHandler: metricsHandler,
	}
	s.routes()
	return s
}

// routes performs route assembly and request pipeline assembly: health/ready/live, admin, then proxy path prefix with engine middleware.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.mux.HandleFunc("GET /livez", s.handleLivez)
	if s.cfg.AdminSecret != "" {
		s.mux.HandleFunc("GET /admin", s.handleAdmin)
	}
	if s.metricsHandler != nil {
		s.mux.Handle("GET /metrics", s.metricsHandler)
	}
	prefix := s.cfg.ProxyPathPrefix
	if prefix == "" {
		prefix = "/"
	}
	handler := pkgproxy.Middleware(s.engine, s.cfg.UpstreamURL)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if !strings.HasSuffix(prefix, "/") {
		s.mux.Handle(prefix, handler)
	}
	s.mux.Handle(prefix+"/", handler)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleLivez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Admin-Secret")), []byte(s.cfg.AdminSecret)) != 1 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	out := map[string]any{
		"config_summary": s.proxyConfigSummary(),
		"plugins":        s.pluginsList(),
		"plugin_health":  s.pluginHealthList(r.Context()),
		"policy_bundle":  s.policyBundleStatus(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) proxyConfigSummary() map[string]any {
	return map[string]any{
		"upstream_url":      s.cfg.UpstreamURL,
		"proxy_path_prefix": s.cfg.ProxyPathPrefix,
		"require_auth":      bool(s.cfg.RequireAuth),
		"auth_url":          s.cfg.AuthURL,
		"cookie_name":       s.cfg.CookieName,
		"http_port":         s.cfg.HTTPPort,
	}
}

func (s *Server) pluginsList() []map[string]any {
	if s.registry == nil {
		return nil
	}
	order := s.registry.StartupOrder()
	if len(order) == 0 {
		order = s.registry.AllPluginIDs()
	}
	var list []map[string]any
	for _, id := range order {
		reg, ok := s.registry.RegistrationFor(id)
		if !ok {
			continue
		}
		list = append(list, map[string]any{
			"id": string(reg.Descriptor.ID), "kind": string(reg.Descriptor.Kind), "name": reg.Descriptor.Name,
			"enabled": reg.Enabled, "state": string(reg.State),
		})
	}
	return list
}

func (s *Server) pluginHealthList(ctx context.Context) []map[string]any {
	if s.registry == nil {
		return nil
	}
	order := s.registry.StartupOrder()
	if len(order) == 0 {
		order = s.registry.AllPluginIDs()
	}
	var out []map[string]any
	for _, id := range order {
		reg, ok := s.registry.RegistrationFor(id)
		if !ok {
			continue
		}
		entry := map[string]any{"plugin_id": string(id), "state": string(reg.State)}
		if reg.Error != nil {
			entry["error"] = reg.Error.Error()
		}
		out = append(out, entry)
	}
	return out
}

func (s *Server) policyBundleStatus() map[string]any {
	eng, ok := s.engine.(*pkgproxy.DefaultEngine)
	if !ok || eng == nil || eng.Policy == nil {
		return map[string]any{"loaded": false, "message": "no policy engine"}
	}
	st, ok := eng.Policy.(policy.EngineWithStatus)
	if !ok {
		return map[string]any{"loaded": false, "message": "engine does not report status"}
	}
	return map[string]any{
		"loaded":      st.Loaded(),
		"bundle_path": st.BundlePath(),
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

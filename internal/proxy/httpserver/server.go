package httpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	pkgproxy "github.com/accessgate/accessgate/internal/authz"
	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/internal/proxy/config"
	"github.com/accessgate/accessgate/pkg/observability"
)

// Route binds one configured route to its prebuilt engine.
type Route struct {
	Config config.RouteConfig
	Engine pkgproxy.Engine
}

// Server is the HTTP server for the Proxy app.
type Server struct {
	mux            *http.ServeMux
	cfg            *config.Config
	routes         []Route
	registry       *plugin.Registry
	metricsHandler http.Handler
	metrics        observability.Metrics
}

// SetMetrics installs an optional metrics sink used to record per-route proxy outcomes.
func (s *Server) SetMetrics(m observability.Metrics) { s.metrics = m }

func (s *Server) recordOutcome(route, outcome string) {
	// ProxyRouteOutcome is an optional, additive metrics extension (see observability.ConnectorMetrics).
	if cm, ok := s.metrics.(observability.ConnectorMetrics); ok {
		cm.ProxyRouteOutcome(route, outcome)
	}
}

// New constructs a Server from a single prebuilt engine (legacy/single-route path). The route
// is synthesized from the legacy top-level UpstreamURL/ProxyPathPrefix fields.
// registry is optional; when set it holds discovered/registered plugins for pipeline use and admin.
// metricsHandler is optional; when set, GET /metrics is registered (e.g. promhttp.HandlerFor(reg, ...)).
func New(cfg *config.Config, engine pkgproxy.Engine, registry *plugin.Registry, metricsHandler http.Handler) *Server {
	rc := config.RouteConfig{
		ID:                  "default",
		PathPrefix:          s_orDefault(cfg.ProxyPathPrefix, "/"),
		UpstreamURL:         cfg.UpstreamURL,
		UnauthenticatedMode: config.UnauthModeAPI401,
	}
	return NewWithRoutes(cfg, []Route{{Config: rc, Engine: engine}}, registry, metricsHandler)
}

// NewWithRoutes constructs a Server that dispatches across multiple routes, each with its own
// engine and upstream. Used by the proxy bootstrap for multi-route configs.
func NewWithRoutes(cfg *config.Config, routes []Route, registry *plugin.Registry, metricsHandler http.Handler) *Server {
	s := &Server{
		mux:            http.NewServeMux(),
		cfg:            cfg,
		routes:         routes,
		registry:       registry,
		metricsHandler: metricsHandler,
	}
	s.installRoutes()
	return s
}

func s_orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// installRoutes assembles the request pipeline: health/ready/live and admin/metrics are
// registered as explicit (more specific) patterns so they take precedence over the catch-all
// proxy handler, which matches every other path against the route table.
func (s *Server) installRoutes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.mux.HandleFunc("GET /livez", s.handleLivez)
	if s.cfg.AdminSecret != "" {
		s.mux.HandleFunc("GET /admin", s.handleAdmin)
	}
	if s.metricsHandler != nil {
		s.mux.Handle("GET /metrics", s.metricsHandler)
	}
	s.mux.HandleFunc("/", s.handleProxy)
}

// handleProxy matches the request to a route and runs that route's engine, then either
// redirects (html_redirect mode), forwards to the route's upstream, or writes the deny response.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	rt, ok := s.matchRoute(r.Host, r.URL.Path)
	if !ok {
		s.recordOutcome("", "route_miss")
		http.Error(w, `{"errors":[{"message":"no route"}]}`, http.StatusNotFound)
		return
	}
	req, err := pkgproxy.RequestFromHTTP(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := rt.Engine.Handle(r.Context(), req)
	if err != nil {
		s.recordOutcome(rt.Config.ID, "auth_failure")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if resp.RedirectTo != "" {
		s.recordOutcome(rt.Config.ID, "auth_failure")
		http.Redirect(w, r, resp.RedirectTo, http.StatusFound)
		return
	}
	if resp.Allow && rt.Config.UpstreamURL != "" {
		s.recordOutcome(rt.Config.ID, "allow")
		_ = pkgproxy.ProxyToUpstream(r.Context(), w, r, rt.Config.UpstreamURL, resp.UpstreamHeaders, req.Body)
		return
	}
	s.recordOutcome(rt.Config.ID, "auth_failure")
	pkgproxy.WriteResponse(w, resp)
}

// matchRoute selects the route with the longest matching path prefix whose host constraint is
// satisfied (a route with no Hosts matches any host; host comparison ignores the port).
func (s *Server) matchRoute(host, path string) (Route, bool) {
	hostOnly := host
	if i := strings.IndexByte(hostOnly, ':'); i >= 0 {
		hostOnly = hostOnly[:i]
	}
	best := -1
	var match Route
	for _, rt := range s.routes {
		if !hostMatches(rt.Config.Hosts, host, hostOnly) {
			continue
		}
		if !pathMatches(path, rt.Config.PathPrefix) {
			continue
		}
		if n := len(rt.Config.PathPrefix); n > best {
			best = n
			match = rt
		}
	}
	return match, best >= 0
}

func hostMatches(hosts []string, host, hostOnly string) bool {
	if len(hosts) == 0 {
		return true
	}
	for _, h := range hosts {
		if h == host || h == hostOnly {
			return true
		}
	}
	return false
}

func pathMatches(path, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
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
	routes := make([]map[string]any, 0, len(s.routes))
	for _, rt := range s.routes {
		routes = append(routes, map[string]any{
			"id":                   rt.Config.ID,
			"hosts":                []string(rt.Config.Hosts),
			"path_prefix":          rt.Config.PathPrefix,
			"upstream_url":         rt.Config.UpstreamURL,
			"require_auth":         bool(rt.Config.RequireAuth),
			"unauthenticated_mode": rt.Config.UnauthenticatedMode,
			"connector_id":         rt.Config.ConnectorID,
		})
	}
	return map[string]any{
		"auth_url":    s.cfg.AuthURL,
		"cookie_name": s.cfg.CookieName,
		"http_port":   s.cfg.HTTPPort,
		"routes":      routes,
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
	// Report per-route policy bundle status (routes may share or override the engine).
	out := make([]map[string]any, 0, len(s.routes))
	for _, rt := range s.routes {
		entry := map[string]any{"route": rt.Config.ID, "loaded": false}
		if eng, ok := rt.Engine.(*pkgproxy.DefaultEngine); ok && eng != nil && eng.Policy != nil {
			if st, ok := eng.Policy.(policy.EngineWithStatus); ok {
				entry["loaded"] = st.Loaded()
				entry["bundle_path"] = st.BundlePath()
			} else {
				entry["message"] = "engine does not report status"
			}
		} else {
			entry["message"] = "no policy engine"
		}
		out = append(out, entry)
	}
	return map[string]any{"routes": out}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// FlexibleBool allows configuration values to be provided either as JSON booleans
// (e.g. `true`) or as JSON strings (e.g. `"true"`), which is helpful for env->config loaders.
type FlexibleBool bool

func (b *FlexibleBool) UnmarshalJSON(data []byte) error {
	// First try normal bool.
	var v bool
	if err := json.Unmarshal(data, &v); err == nil {
		*b = FlexibleBool(v)
		return nil
	}
	// Then accept string forms.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true", "1", "yes", "y":
			*b = FlexibleBool(true)
			return nil
		case "false", "0", "no", "n":
			*b = FlexibleBool(false)
			return nil
		default:
			return fmt.Errorf("invalid flexible bool %q", s)
		}
	}
	return fmt.Errorf("flexible bool: unsupported value %s", string(data))
}

// CommaStrings is a []string that unmarshals from a JSON string (comma-separated) or a JSON array.
// Used for env vars and YAML/JSON arrays (e.g. per-route host lists).
type CommaStrings []string

// UnmarshalJSON implements json.Unmarshaler.
func (c *CommaStrings) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*c = nil
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		out := make([]string, 0)
		for p := range strings.SplitSeq(s, ",") {
			if t := strings.TrimSpace(p); t != "" {
				out = append(out, t)
			}
		}
		*c = out
		return nil
	}
	var slice []string
	if err := json.Unmarshal(data, &slice); err != nil {
		return err
	}
	*c = slice
	return nil
}

// Unauthenticated-handling modes for a route.
const (
	// UnauthModeAPI401 returns a JSON 401 when no principal is present (default, API style).
	UnauthModeAPI401 = "api_401"
	// UnauthModeHTMLRedirect issues a 302 to LoginRedirectURL when no principal is present (browser style).
	UnauthModeHTMLRedirect = "html_redirect"
)

type PolicyEngine string

const (
	PolicyEngineWASM PolicyEngine = "wasm"
	PolicyEngineRego PolicyEngine = "rego"
)

// MinPolicyReloadInterval is the smallest accepted policy_reload_interval. A floor
// avoids pathologically tight polling that would hammer the filesystem and starve
// other work; sub-second mtime resolution on some filesystems also makes very small
// intervals unreliable.
const MinPolicyReloadInterval = time.Second

// DefaultPolicyReloadInterval is the default poll period when hot-reload is enabled
// and no interval is configured.
const DefaultPolicyReloadInterval = 10 * time.Second

// Config holds configuration for the Proxy app (loaded via go-config from file + env).
type Config struct {
	UpstreamURL     string       `json:"upstream_url"`
	ProxyPathPrefix string       `json:"proxy_path_prefix"`
	RequireAuth     FlexibleBool `json:"require_auth"`
	// AuthURL is the accessgate-auth base URL (session resolve, login flows).
	AuthURL    string `json:"auth_url" yaml:"auth_url"`
	CookieName string `json:"cookie_name"`
	HTTPPort   string `json:"http_port"`

	// GRPCListenAddr, when non-empty, enables the optional proxy gRPC server.
	// It is a "host:port" listen address (e.g. ":9091"). The gRPC server runs
	// alongside the HTTP server and installs the AccessGate authz interceptors
	// on every call. An empty value (the default) disables the gRPC server.
	GRPCListenAddr string `json:"grpc_listen_addr"`

	// GRPCUpstreamAddr is the "host:port" address of the upstream gRPC backend
	// that authorized calls are transparently forwarded to. When non-empty (and
	// the gRPC server is enabled via GRPCListenAddr), the proxy terminates,
	// authorizes, and then forwards each call to this upstream over a shared
	// client connection, injecting the authz identity headers as outbound gRPC
	// metadata. An empty value (the default) keeps the legacy behavior:
	// authorized calls return codes.Unimplemented. The address is SSRF-validated
	// at startup like upstream_url (honoring allow_private_upstreams).
	GRPCUpstreamAddr string `json:"grpc_upstream_addr"`

	// GRPCUpstreamInsecure controls the transport security used to dial the
	// upstream gRPC backend. When false (the default), the proxy dials with TLS.
	// When true, the proxy dials with an insecure (plaintext) transport, which
	// is intended only for local development or trusted in-cluster networks.
	GRPCUpstreamInsecure FlexibleBool `json:"grpc_upstream_insecure"`

	// PolicyEngine selects the policy execution backend. Supported: "wasm" (default), "rego".
	PolicyEngine PolicyEngine `json:"policy_engine"`
	// PolicyBundlePath is the path to the policy bundle for the selected engine.
	// For wasm: path to a .wasm file implementing the evaluate ABI.
	// For rego: path to a .rego file.
	PolicyBundlePath string `json:"policy_bundle_path"`
	// PolicyFallbackAllow configures behavior when no policy is loaded or evaluation fails.
	// When true fallback is allow; when false (the default) fallback is deny with 503.
	// It is fail-closed by default: an unset/empty value is equivalent to false (deny).
	PolicyFallbackAllow FlexibleBool `json:"policy_fallback_allow"`

	// PolicyReloadEnabled enables local policy hot-reload: the proxy polls the bundle
	// file's mtime and reloads it in place (re-verifying the signature, fail-closed)
	// without a restart. A failed reload (bad compile/signature/read) retains the
	// last-good policy and never enters a deny-all state. Requires policy_bundle_path
	// to be set; when false (the default) the bundle is loaded once at startup.
	PolicyReloadEnabled bool `json:"policy_reload_enabled"`
	// PolicyReloadInterval is the poll period for hot-reload, as a Go duration string
	// (e.g. "10s", "1m"). Only consulted when policy_reload_enabled is true. It must be
	// parseable and at least MinPolicyReloadInterval. Defaults to "10s".
	PolicyReloadInterval string `json:"policy_reload_interval"`

	// PipelinePlugins lists pipeline plugin configs (id, type, raw config). Used by proxy startup to configure and enable pipeline plugins from the registry.
	PipelinePlugins []PipelinePluginEntry `json:"pipeline_plugins"`
	// PluginsManifestDir optional directory to discover plugin manifests (JSON). Empty disables filesystem discovery.
	PluginsManifestDir string `json:"plugins_manifest_dir"`
	// PluginsManifestStrict controls how manifest discovery and dependency-graph errors are
	// handled at startup. When true, any discovery or dependency-graph error fails startup
	// (fail-closed). When false (default, for backward compatibility) such errors are logged
	// clearly but do not abort startup.
	PluginsManifestStrict bool `json:"plugins_manifest_strict"`
	// PluginsManifestPublicKeyPath is an optional path to a PEM-encoded Ed25519 public key
	// used to verify plugin manifest signatures. When set, every discovered manifest must
	// carry a valid Ed25519 signature or discovery fails (fail-closed). When empty, manifest
	// signatures are not verified.
	PluginsManifestPublicKeyPath string `json:"plugins_manifest_public_key_path"`

	// AdminSecret if set guards /admin; requests must include header X-Admin-Secret: <value>. Empty disables admin endpoint.
	AdminSecret string `json:"admin_secret"`

	// BundlePublicKeyPath is the path to a PEM-encoded public key used to verify policy bundle signatures.
	// When set, LoadBundle will verify the bundle signature before instantiating it.
	// When empty, a warning is logged and bundles are loaded without integrity verification.
	BundlePublicKeyPath string `json:"bundle_public_key_path"`

	// AllowPrivateUpstreams disables SSRF IP-range validation for the upstream URL.
	// Set to true only in local development or test environments where the upstream
	// intentionally runs on a loopback or private address. Never enable in production.
	AllowPrivateUpstreams bool `json:"allow_private_upstreams"`

	// Routes lists the protected routes served by this proxy instance. When empty,
	// Normalize() synthesizes a single "default" route from the legacy top-level
	// UpstreamURL/ProxyPathPrefix/RequireAuth fields (backward compat).
	Routes []RouteConfig `json:"routes"`

	// Header claim mapping
	HeaderUserIDClaim            string `json:"headers_user_id_claim"`
	HeaderEmailClaim             string `json:"headers_email_claim"`
	HeaderNameClaim              string `json:"headers_name_claim"`
	HeaderPreferredUsernameClaim string `json:"headers_preferred_username_claim"`
	HeaderRolesClaim             string `json:"headers_roles_claim"`
	HeaderGroupsClaim            string `json:"headers_groups_claim"`
	HeaderTenantIDClaim          string `json:"headers_tenant_id_claim"`
	HeaderAdminRole              string `json:"headers_admin_role"`
}

// RouteConfig describes a single protected route served by this proxy instance.
// Each route selects its own upstream, auth policy, unauthenticated behavior, and the
// auth connector its sessions resolve against.
type RouteConfig struct {
	// ID is a stable identifier used as a metrics label and in admin output.
	ID string `json:"id"`
	// Hosts optionally restricts the route to specific request hosts (exact match). Empty = any host.
	Hosts CommaStrings `json:"hosts"`
	// PathPrefix is the URL path prefix this route serves (e.g. "/graphql", "/api"). Required.
	PathPrefix string `json:"path_prefix"`
	// UpstreamURL is the backend this route forwards authorized requests to. Required.
	UpstreamURL string `json:"upstream_url"`
	// RequireAuth enforces a resolved principal before the request is allowed through.
	RequireAuth FlexibleBool `json:"require_auth"`
	// UnauthenticatedMode controls the response when no principal is present:
	// UnauthModeAPI401 (default) or UnauthModeHTMLRedirect.
	UnauthenticatedMode string `json:"unauthenticated_mode"`
	// LoginRedirectURL is the location for html_redirect mode. Required when that mode is set.
	LoginRedirectURL string `json:"login_redirect_url"`
	// ConnectorID names the auth connector this route's sessions resolve against. Empty = default.
	ConnectorID string `json:"connector_id"`
	// PolicyBundlePath optionally overrides the policy bundle for this route. Empty = shared engine.
	PolicyBundlePath string `json:"policy_bundle_path"`
}

// blockedUpstreamCIDRs lists private/loopback/link-local ranges forbidden as upstream targets (SSRF).
var blockedUpstreamCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"::1/128",        // IPv6 loopback
		"10.0.0.0/8",     // RFC-1918
		"172.16.0.0/12",  // RFC-1918
		"192.168.0.0/16", // RFC-1918
		"169.254.0.0/16", // link-local / AWS metadata
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique-local
		"0.0.0.0/8",      // "this" network
	} {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedUpstreamCIDRs = append(blockedUpstreamCIDRs, ipnet)
		}
	}
}

// validateUpstreamSSRF returns an error if the URL targets a private/loopback address.
func validateUpstreamSSRF(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("upstream_url: invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("upstream_url: scheme %q not allowed (must be http or https)", u.Scheme)
	}
	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("upstream_url: no host")
	}
	ips, err := net.LookupHost(hostname)
	if err != nil {
		if ip := net.ParseIP(hostname); ip != nil {
			ips = []string{ip.String()}
		} else {
			return fmt.Errorf("upstream_url: host %q could not be resolved: %w", hostname, err)
		}
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, blocked := range blockedUpstreamCIDRs {
			if blocked.Contains(ip) {
				return fmt.Errorf("upstream_url: host %q resolves to blocked address %s (SSRF protection; set allow_private_upstreams: true only for local dev)", hostname, ip)
			}
		}
	}
	return nil
}

// validateGRPCUpstreamSSRF returns an error if the "host:port" gRPC upstream
// address targets a private/loopback address. It reuses the same blocked-CIDR
// set as validateUpstreamSSRF; the only difference is the input form (a bare
// host:port rather than a URL with a scheme).
func validateGRPCUpstreamSSRF(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("grpc_upstream_addr: invalid host:port %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("grpc_upstream_addr: no host in %q", addr)
	}
	if port == "" {
		return fmt.Errorf("grpc_upstream_addr: no port in %q", addr)
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		if ip := net.ParseIP(host); ip != nil {
			ips = []string{ip.String()}
		} else {
			return fmt.Errorf("grpc_upstream_addr: host %q could not be resolved: %w", host, err)
		}
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, blocked := range blockedUpstreamCIDRs {
			if blocked.Contains(ip) {
				return fmt.Errorf("grpc_upstream_addr: host %q resolves to blocked address %s (SSRF protection; set allow_private_upstreams: true only for local dev)", host, ip)
			}
		}
	}
	return nil
}

// Validate returns an error if required configuration is missing.
//
// When Routes is empty it validates the legacy single-upstream top-level fields (so existing
// configs and callers that invoke Validate() without Normalize() keep working). When Routes is
// non-empty it validates each route and the top-level UpstreamURL becomes optional.
func (c *Config) Validate() error {
	if c.AuthURL == "" {
		return errMissing("AUTH_URL")
	}
	if c.PolicyEngine != "" && c.PolicyEngine != PolicyEngineWASM && c.PolicyEngine != PolicyEngineRego {
		return configError("POLICY_ENGINE (must be \"wasm\" or \"rego\")")
	}
	if c.PolicyReloadInterval != "" {
		d, err := time.ParseDuration(c.PolicyReloadInterval)
		if err != nil {
			return fmt.Errorf("config: policy_reload_interval %q is not a valid duration: %w", c.PolicyReloadInterval, err)
		}
		if d < MinPolicyReloadInterval {
			return fmt.Errorf("config: policy_reload_interval %q is below the minimum of %s", c.PolicyReloadInterval, MinPolicyReloadInterval)
		}
	}
	if c.PolicyReloadEnabled && c.PolicyBundlePath == "" {
		return fmt.Errorf("config: policy_reload_enabled requires policy_bundle_path to be set")
	}
	if !strings.HasPrefix(c.ProxyPathPrefix, "/") {
		c.ProxyPathPrefix = "/" + c.ProxyPathPrefix
	}
	if c.GRPCUpstreamAddr != "" && !c.AllowPrivateUpstreams {
		if err := validateGRPCUpstreamSSRF(c.GRPCUpstreamAddr); err != nil {
			return err
		}
	}

	if len(c.Routes) == 0 {
		// Legacy single-upstream mode.
		if c.UpstreamURL == "" {
			return errMissing("UPSTREAM_URL")
		}
		if !c.AllowPrivateUpstreams {
			if err := validateUpstreamSSRF(c.UpstreamURL); err != nil {
				return err
			}
		}
		return nil
	}
	return c.validateRoutes()
}

// validateRoutes validates the multi-route configuration. It assumes Normalize() has
// already filled per-route defaults.
func (c *Config) validateRoutes() error {
	seen := make(map[string]bool, len(c.Routes))
	for i := range c.Routes {
		rt := &c.Routes[i]
		if rt.ID == "" {
			return fmt.Errorf("config: route[%d] missing id", i)
		}
		if seen[rt.ID] {
			return fmt.Errorf("config: duplicate route id %q", rt.ID)
		}
		seen[rt.ID] = true
		if rt.PathPrefix == "" {
			return fmt.Errorf("config: route %q missing path_prefix", rt.ID)
		}
		if rt.UpstreamURL == "" {
			return fmt.Errorf("config: route %q missing upstream_url", rt.ID)
		}
		switch rt.UnauthenticatedMode {
		case UnauthModeAPI401, UnauthModeHTMLRedirect:
		default:
			return fmt.Errorf("config: route %q invalid unauthenticated_mode %q (must be %q or %q)", rt.ID, rt.UnauthenticatedMode, UnauthModeAPI401, UnauthModeHTMLRedirect)
		}
		if rt.UnauthenticatedMode == UnauthModeHTMLRedirect && rt.LoginRedirectURL == "" {
			return fmt.Errorf("config: route %q with unauthenticated_mode=html_redirect requires login_redirect_url", rt.ID)
		}
		if !c.AllowPrivateUpstreams {
			if err := validateUpstreamSSRF(rt.UpstreamURL); err != nil {
				return fmt.Errorf("config: route %q: %w", rt.ID, err)
			}
		}
	}
	return nil
}

// Normalize synthesizes and fills defaults for the route list. When no routes are configured
// it creates a single "default" route from the legacy top-level fields, preserving the existing
// path prefix and upstream. It is idempotent and should be called after ApplyDefaults() and
// before Validate() (Load does this). Direct callers of Validate() that skip Normalize() get
// legacy single-upstream validation.
func (c *Config) Normalize() {
	if len(c.Routes) == 0 {
		c.Routes = []RouteConfig{{
			ID:                  "default",
			PathPrefix:          c.ProxyPathPrefix,
			UpstreamURL:         c.UpstreamURL,
			RequireAuth:         c.RequireAuth,
			UnauthenticatedMode: UnauthModeAPI401,
		}}
	}
	for i := range c.Routes {
		rt := &c.Routes[i]
		if rt.PathPrefix != "" && !strings.HasPrefix(rt.PathPrefix, "/") {
			rt.PathPrefix = "/" + rt.PathPrefix
		}
		if rt.UnauthenticatedMode == "" {
			rt.UnauthenticatedMode = UnauthModeAPI401
		}
	}
}

// ApplyDefaults sets default values for optional fields when not set.
func (c *Config) ApplyDefaults() {
	if c.ProxyPathPrefix == "" {
		c.ProxyPathPrefix = "/graphql"
	}
	if c.CookieName == "" {
		c.CookieName = "__Host-ess_session"
	}
	if c.HTTPPort == "" {
		c.HTTPPort = "8081"
	}
	if c.PolicyEngine == "" {
		c.PolicyEngine = PolicyEngineWASM
	}
	if c.PolicyReloadInterval == "" {
		c.PolicyReloadInterval = DefaultPolicyReloadInterval.String()
	}
	// PolicyFallbackAllow is fail-closed by default: the zero value (false) means deny.
	// No defaulting is needed — an unset key already yields deny. Allowing unevaluated
	// requests requires an explicit policy_fallback_allow: true.
	if c.HeaderUserIDClaim == "" {
		c.HeaderUserIDClaim = "sub"
	}
	if c.HeaderEmailClaim == "" {
		c.HeaderEmailClaim = "email"
	}
	if c.HeaderNameClaim == "" {
		c.HeaderNameClaim = "name"
	}
	if c.HeaderPreferredUsernameClaim == "" {
		c.HeaderPreferredUsernameClaim = "preferred_username"
	}
	if c.HeaderRolesClaim == "" {
		c.HeaderRolesClaim = "realm_access.roles"
	}
	if c.HeaderGroupsClaim == "" {
		c.HeaderGroupsClaim = "groups"
	}
	if c.HeaderAdminRole == "" {
		c.HeaderAdminRole = "admin"
	}
}

// PolicyReloadIntervalDuration returns the parsed policy_reload_interval. It assumes
// the value has already passed Validate (and ApplyDefaults has run); if the field is
// somehow empty or unparseable it falls back to DefaultPolicyReloadInterval so callers
// never receive a zero duration.
func (c *Config) PolicyReloadIntervalDuration() time.Duration {
	if c.PolicyReloadInterval == "" {
		return DefaultPolicyReloadInterval
	}
	d, err := time.ParseDuration(c.PolicyReloadInterval)
	if err != nil || d < MinPolicyReloadInterval {
		return DefaultPolicyReloadInterval
	}
	return d
}

// PipelinePluginEntry is a single pipeline plugin config entry (id, type, raw map for go-config / pluginconfig).
type PipelinePluginEntry struct {
	ID   string         `json:"id"`
	Type string         `json:"type"`
	Raw  map[string]any `json:"raw"`
}

type configError string

func (e configError) Error() string { return "config: missing " + string(e) }

func errMissing(name string) error { return configError(name) }

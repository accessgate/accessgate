package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ArmanAvanesyan/accessgate/internal/authz"
	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
	"github.com/ArmanAvanesyan/accessgate/internal/policy"
	"github.com/ArmanAvanesyan/accessgate/pkg/token"
)

// Config matches schemas/plugins/pipeline/ratelimit.schema.json.
type Config struct {
	Name              string `json:"name"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	Burst             int    `json:"burst"`
	KeyStrategy       string `json:"key_strategy"` // ip|principal|header
	HeaderName        string `json:"header_name"`
	// TrustedProxies is a list of CIDR ranges whose X-Forwarded-For / X-Real-IP headers are trusted.
	// When empty, forwarded-IP headers are ignored and the connection RemoteAddr is used instead.
	TrustedProxies []string `json:"trusted_proxies"`
}

type bucket struct {
	tokens float64
	last   time.Time
}

type Plugin struct {
	mu sync.Mutex

	cfg          Config
	trustedCIDRs []*net.IPNet
	// buckets are keyed by derived limit key.
	buckets map[string]*bucket
}

var _ plugin.PipelinePlugin = (*Plugin)(nil)
var _ plugin.ConfigurablePlugin = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{buckets: make(map[string]*bucket)}
}

func (p *Plugin) Descriptor() plugin.PluginDescriptor {
	return plugin.PluginDescriptor{
		ID:              plugin.PluginID("pipeline:ratelimit"),
		Kind:            plugin.PluginKindPipeline,
		Name:            "RateLimit",
		Description:     "Rate limiting pipeline plugin",
		Version:         "v1",
		Capabilities:    []plugin.Capability{"pipeline:ratelimit"},
		ConfigSchemaRef: "plugins/pipeline/ratelimit",
		VersionInfo: plugin.VersionInfo{
			APIVersion:        "",
			MinRuntimeVersion: "",
			MaxRuntimeVersion: "",
		},
	}
}

func (p *Plugin) Configure(ctx context.Context, cfg any) error {
	// cfg is expected to be a map[string]any produced by go-config.
	b, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("ratelimit: marshal config: %w", err)
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("ratelimit: decode config: %w", err)
	}
	if out.RequestsPerMinute < 1 {
		return fmt.Errorf("ratelimit: requests_per_minute must be >= 1")
	}
	if out.Burst < 1 {
		return fmt.Errorf("ratelimit: burst must be >= 1")
	}
	out.KeyStrategy = strings.ToLower(strings.TrimSpace(out.KeyStrategy))
	switch out.KeyStrategy {
	case "ip", "principal", "header":
	default:
		return fmt.Errorf("ratelimit: key_strategy must be one of: ip, principal, header")
	}
	if out.KeyStrategy == "header" && strings.TrimSpace(out.HeaderName) == "" {
		return fmt.Errorf("ratelimit: header_name is required when key_strategy=header")
	}

	var cidrs []*net.IPNet
	for _, cidr := range out.TrustedProxies {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("ratelimit: invalid trusted_proxy CIDR %q: %w", cidr, err)
		}
		cidrs = append(cidrs, ipnet)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = out
	p.trustedCIDRs = cidrs
	if p.buckets == nil {
		p.buckets = make(map[string]*bucket)
	}
	return nil
}

func (p *Plugin) Health(ctx context.Context) plugin.PluginHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cfg.RequestsPerMinute == 0 || p.cfg.Burst == 0 {
		return plugin.PluginHealth{
			State:   plugin.PluginStateDegraded,
			Message: "not configured",
		}
	}
	return plugin.PluginHealth{
		State:   plugin.PluginStateHealthy,
		Message: fmt.Sprintf("configured (%s)", p.cfg.KeyStrategy),
		Details: map[string]any{"buckets": len(p.buckets)},
	}
}

func (p *Plugin) Handle(ctx context.Context, req *authz.Request, principal *token.Principal) (*policy.Decision, error) {
	key := p.deriveKey(req, principal)

	now := time.Now()
	rate := float64(p.cfg.RequestsPerMinute) / 60.0 // tokens per second
	capacity := float64(p.cfg.Burst)

	p.mu.Lock()
	defer p.mu.Unlock()

	bkt := p.buckets[key]
	if bkt == nil {
		bkt = &bucket{tokens: capacity, last: now}
		p.buckets[key] = bkt
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(bkt.last).Seconds()
	if elapsed > 0 {
		bkt.tokens += elapsed * rate
		if bkt.tokens > capacity {
			bkt.tokens = capacity
		}
	}
	bkt.last = now

	if bkt.tokens >= 1 {
		bkt.tokens -= 1
		return nil, nil
	}

	return &policy.Decision{
		Allow:      false,
		StatusCode: 429,
		Reason:     "rate limit exceeded",
	}, nil
}

func (p *Plugin) deriveKey(req *authz.Request, principal *token.Principal) string {
	switch p.cfg.KeyStrategy {
	case "principal":
		if principal == nil || strings.TrimSpace(principal.Subject) == "" {
			return "anonymous"
		}
		return principal.Subject
	case "header":
		if req == nil || req.Headers == nil {
			return "anonymous"
		}
		if v := strings.TrimSpace(req.Headers[p.cfg.HeaderName]); v != "" {
			return v
		}
		return "anonymous"
	case "ip":
		if req == nil {
			return "anonymous"
		}
		// Only trust X-Forwarded-For / X-Real-IP when the connection comes from a trusted proxy CIDR.
		if len(p.trustedCIDRs) > 0 && req.RemoteAddr != "" && p.remoteAddrTrusted(req.RemoteAddr) {
			if req.Headers != nil {
				if v := strings.TrimSpace(firstHeader(req.Headers, "X-Forwarded-For")); v != "" {
					if ip := firstIP(v); ip != "" {
						return ip
					}
				}
				if v := strings.TrimSpace(firstHeader(req.Headers, "X-Real-IP")); v != "" {
					if ip := firstIP(v); ip != "" {
						return ip
					}
				}
			}
		}
		// Fall back to connection remote address.
		if req.RemoteAddr != "" {
			host, _, err := net.SplitHostPort(req.RemoteAddr)
			if err == nil && host != "" {
				return host
			}
			// Bare IP without port.
			if ip := net.ParseIP(req.RemoteAddr); ip != nil {
				return ip.String()
			}
		}
		return "anonymous"
	default:
		return "anonymous"
	}
}

// remoteAddrTrusted returns true if the remote address falls within any configured trusted CIDR.
func (p *Plugin) remoteAddrTrusted(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range p.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func firstHeader(m map[string]string, key string) string {
	// net/http lowercases header keys. req.Headers is populated from r.Header iteration,
	// preserving canonical keys as stored in the map. Normalize defensively.
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func firstIP(v string) string {
	// X-Forwarded-For may contain a comma-separated list.
	parts := strings.Split(v, ",")
	if len(parts) == 0 {
		return ""
	}
	ip := strings.TrimSpace(parts[0])
	// Validate/canonicalize if possible.
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}

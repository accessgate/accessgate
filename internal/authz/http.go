package authz

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/accessgate/accessgate/pkg/cookie"
)

// blockedCIDRs lists private/loopback/link-local ranges that are forbidden as upstream targets (SSRF).
var blockedCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"::1/128",        // IPv6 loopback
		"10.0.0.0/8",     // RFC-1918
		"172.16.0.0/12",  // RFC-1918
		"192.168.0.0/16", // RFC-1918
		"169.254.0.0/16", // link-local
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique-local (fd00::/8 subset)
		"0.0.0.0/8",      // "this" network
	} {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, ipnet)
		}
	}
}

// validateUpstreamURL rejects schemes other than http/https and blocks SSRF-prone hosts.
func validateUpstreamURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("proxy: upstream scheme %q not allowed (must be http or https)", u.Scheme)
	}
	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("proxy: upstream URL has no host")
	}
	// Resolve to IPs and reject private/loopback ranges.
	ips, err := net.LookupHost(hostname)
	if err != nil {
		// If the hostname looks like a bare IP, parse it directly.
		if ip := net.ParseIP(hostname); ip != nil {
			ips = []string{ip.String()}
		} else {
			return fmt.Errorf("proxy: upstream host %q could not be resolved: %w", hostname, err)
		}
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, blocked := range blockedCIDRs {
			if blocked.Contains(ip) {
				return fmt.Errorf("proxy: upstream host %q resolves to blocked address %s", hostname, ip)
			}
		}
	}
	return nil
}

// RequestFromHTTP builds a Request from http.Request and normalizes it.
func RequestFromHTTP(r *http.Request) (*Request, error) {
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	cookies := make(map[string]string)
	for _, c := range r.Cookies() {
		cookies[c.Name] = c.Value
	}
	var body []byte
	if r.Body != nil {
		const maxBodyBytes = 32 * 1024 * 1024 // 32 MB
		r.Body = http.MaxBytesReader(nil, r.Body, maxBodyBytes)
		body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}
	protocol := "http"
	if r.TLS != nil {
		protocol = "https"
	}
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path = r.URL.Path + "?" + r.URL.RawQuery
	}
	req := NormalizeRequest(protocol, r.Method, path, headers, cookies, body)
	req.RemoteAddr = r.RemoteAddr
	return req, nil
}

// WriteResponse writes the proxy Response to the HTTP response writer (status, SetCookies, body).
// Use for deny/error responses. For Allow, use ProxyToUpstream with resp.UpstreamHeaders.
func WriteResponse(w http.ResponseWriter, resp *Response) {
	for _, c := range resp.SetCookies {
		cookie.WriteOutCookie(w, c)
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	if len(resp.Body) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(resp.StatusCode)
	if len(resp.Body) > 0 {
		_, _ = w.Write(resp.Body)
	}
}

// ProxyToUpstream proxies the request to upstreamURL, adding upstreamHeaders to the outgoing request.
// body is the request body (already read from r); pass the same body used to build Request.
// The caller is responsible for SSRF validation of the upstream URL at configuration load time
// (e.g. via validateUpstreamURL called from Config.Validate).
func ProxyToUpstream(ctx context.Context, w http.ResponseWriter, r *http.Request, upstreamURL string, upstreamHeaders map[string]string, body []byte) error {
	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		return err
	}
	// Scheme-only check at request time; IP-range SSRF validation is performed at startup (Config.Validate).
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return fmt.Errorf("proxy: upstream scheme %q not allowed (must be http or https)", upstream.Scheme)
	}
	path := singleJoiningSlash(upstream.Path, r.URL.Path)
	if path != "" && path[0] != '/' {
		path = "/" + path
	}
	if r.URL.RawQuery != "" {
		path = path + "?" + r.URL.RawQuery
	}
	targetURL := upstream.Scheme + "://" + upstream.Host + path
	outReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, nil)
	if err != nil {
		return err
	}
	if len(body) > 0 {
		outReq.Body = io.NopCloser(strings.NewReader(string(body)))
		outReq.ContentLength = int64(len(body))
	}
	for k, v := range r.Header {
		if strings.EqualFold(k, "Cookie") {
			continue
		}
		outReq.Header[k] = v
	}
	for k, v := range upstreamHeaders {
		outReq.Header.Set(k, v)
	}
	outReq.Host = upstream.Host
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ServeHTTP(w, outReq)
	return nil
}

func singleJoiningSlash(a, b string) string {
	a = strings.TrimSuffix(a, "/")
	b = strings.TrimPrefix(b, "/")
	if a == "" {
		return "/" + b
	}
	if b == "" {
		return a
	}
	return a + "/" + b
}

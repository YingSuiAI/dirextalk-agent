package mcphttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var deniedAddressRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func parseTrustedEndpoint(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, fmt.Errorf("%w: invalid endpoint", ErrInvalidConfig)
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Opaque != "" {
		return nil, fmt.Errorf("%w: endpoint must use HTTPS", ErrInvalidConfig)
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("%w: endpoint cannot carry credentials or query state", ErrInvalidConfig)
	}
	host := endpoint.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return nil, fmt.Errorf("%w: invalid endpoint host", ErrInvalidConfig)
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("%w: invalid endpoint port", ErrInvalidConfig)
		}
	}
	return endpoint, nil
}

type publicEndpointPolicy struct {
	resolver *net.Resolver
}

func newPublicEndpointPolicy() EndpointPolicy {
	return &publicEndpointPolicy{resolver: net.DefaultResolver}
}

func (p *publicEndpointPolicy) Validate(ctx context.Context, endpoint *url.URL) error {
	if endpoint == nil || endpoint.Scheme != "https" {
		return ErrEndpointDenied
	}
	host := strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), ".")
	if host == "" || deniedHostName(host) {
		return ErrEndpointDenied
	}
	addresses, err := lookupEndpointAddresses(ctx, p.resolver, host)
	if err != nil || len(addresses) == 0 {
		return ErrEndpointDenied
	}
	for _, address := range addresses {
		if !publicAddress(address) {
			return ErrEndpointDenied
		}
	}
	return nil
}

func deniedHostName(host string) bool {
	if host == "localhost" {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func lookupEndpointAddresses(ctx context.Context, resolver *net.Resolver, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	if resolver == nil {
		return nil, ErrEndpointDenied
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.Unmap())
	}
	return result, nil
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedAddressRanges {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func newSecureTransport() http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&publicDialer{
		resolver: net.DefaultResolver,
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}).DialContext
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return transport
}

type publicDialer struct {
	resolver *net.Resolver
	dialer   *net.Dialer
}

func (d *publicDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || deniedHostName(strings.TrimSuffix(strings.ToLower(host), ".")) {
		return nil, ErrEndpointDenied
	}
	addresses, err := lookupEndpointAddresses(ctx, d.resolver, host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrEndpointDenied
	}
	for _, candidate := range addresses {
		if !publicAddress(candidate) {
			return nil, ErrEndpointDenied
		}
	}
	var lastErr error
	for _, candidate := range addresses {
		connection, dialErr := d.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrEndpointDenied
}

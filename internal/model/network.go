package model

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

var (
	errUnsafeModelEndpoint = errors.New("model endpoint is not publicly routable")
	errModelDialFailed     = errors.New("model endpoint dial failed")
	errModelRedirect       = errors.New("model provider redirects are forbidden")
)

const endpointResolutionTimeout = 10 * time.Second

var deniedModelEndpointPrefixes = []netip.Prefix{
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
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

type networkResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type networkDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type endpointPolicy struct {
	host     string
	resolver networkResolver
	dialer   networkDialer
}

func newDefaultHTTPClient(policy *endpointPolicy, tlsConfig *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Credentials must never be sent through a process-wide HTTP(S)_PROXY.
	transport.Proxy = nil
	transport.DialContext = policy.dialContext
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig.Clone()
	}
	return &http.Client{
		Timeout:   defaultHTTPTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errModelRedirect
		},
	}
}

func (policy *endpointPolicy) preflight(ctx context.Context) error {
	if policy == nil || policy.resolver == nil || policy.dialer == nil {
		return errUnsafeModelEndpoint
	}
	lookupCtx, cancel := context.WithTimeout(ctx, endpointResolutionTimeout)
	defer cancel()
	_, err := policy.resolvePublic(lookupCtx, policy.host)
	return err
}

func (policy *endpointPolicy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !sameEndpointHost(host, policy.host) {
		return nil, errUnsafeModelEndpoint
	}
	lookupCtx, cancel := context.WithTimeout(ctx, endpointResolutionTimeout)
	addresses, err := policy.resolvePublic(lookupCtx, host)
	cancel()
	if err != nil {
		return nil, errUnsafeModelEndpoint
	}
	for _, address := range addresses {
		dialNetwork := network
		if network == "tcp" {
			if address.Is4() {
				dialNetwork = "tcp4"
			} else {
				dialNetwork = "tcp6"
			}
		}
		connection, dialErr := policy.dialer.DialContext(ctx, dialNetwork, net.JoinHostPort(address.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
	}
	return nil, errModelDialFailed
}

func (policy *endpointPolicy) resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	host = normalizeEndpointHost(host)
	if host == "" || forbiddenEndpointName(host) {
		return nil, errUnsafeModelEndpoint
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !publicModelAddress(address) {
			return nil, errUnsafeModelEndpoint
		}
		return []netip.Addr{address}, nil
	}
	addresses, err := policy.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errUnsafeModelEndpoint
	}
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !publicModelAddress(address) {
			return nil, errUnsafeModelEndpoint
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	if len(result) == 0 {
		return nil, errUnsafeModelEndpoint
	}
	return result, nil
}

func validateLiteralEndpointHost(host string) error {
	host = normalizeEndpointHost(host)
	if host == "" || forbiddenEndpointName(host) {
		return errUnsafeModelEndpoint
	}
	if address, err := netip.ParseAddr(host); err == nil && !publicModelAddress(address.Unmap()) {
		return errUnsafeModelEndpoint
	}
	return nil
}

func publicModelAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedModelEndpointPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func forbiddenEndpointName(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") ||
		host == "metadata.google.internal"
}

func normalizeEndpointHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
}

func sameEndpointHost(left, right string) bool {
	return normalizeEndpointHost(left) == normalizeEndpointHost(right)
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (function resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return function(ctx, network, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (function dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return function(ctx, network, address)
}

func defaultEndpointPolicy(host string) *endpointPolicy {
	return &endpointPolicy{
		host: host, resolver: net.DefaultResolver,
		dialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
	}
}

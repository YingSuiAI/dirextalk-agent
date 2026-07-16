package publicweb

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
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
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var errDNSResolution = errors.New("official source DNS resolution failed")

type netIPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type publicDialer struct {
	resolver netIPResolver
	dialer   contextDialer
}

func newSecureTransport(resolver netIPResolver) http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&publicDialer{
		resolver: resolver,
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}).DialContext
	transport.DialTLSContext = nil
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return transport
}

func validateResolvedHost(ctx context.Context, resolver netIPResolver, host string) error {
	_, err := resolvePublicAddresses(ctx, resolver, host)
	return err
}

func resolvePublicAddresses(ctx context.Context, resolver netIPResolver, host string) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !publicAddress(address) {
			return nil, ErrURLDenied
		}
		return []netip.Addr{address}, nil
	}
	if deniedHostName(host) {
		return nil, ErrURLDenied
	}
	if !validDNSName(host) || resolver == nil {
		return nil, ErrURLDenied
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errDNSResolution
	}
	if len(addresses) == 0 {
		return nil, errDNSResolution
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !publicAddress(address) {
			return nil, ErrURLDenied
		}
		result = append(result, address)
	}
	return result, nil
}

func (dialer *publicDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if dialer == nil || dialer.resolver == nil || dialer.dialer == nil || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, ErrURLDenied
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrURLDenied
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, ErrURLDenied
	}
	addresses, err := resolvePublicAddresses(ctx, dialer.resolver, host)
	if err != nil {
		return nil, err
	}
	for _, candidate := range addresses {
		connection, dialErr := dialer.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, ErrFetchFailed
}

func deniedHostName(host string) bool {
	if host == "" || strings.Contains(host, "%") || !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{"localhost", ".localhost", ".local", ".internal", ".home", ".lan", ".test", ".invalid", ".example"} {
		if host == suffix || strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return host == "metadata.google.internal" || host == "instance-data.ec2.internal"
}

func validDNSName(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
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

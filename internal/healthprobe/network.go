package healthprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxResponseBytes = 64 << 10

type resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type NetworkTransport struct {
	resolver resolver
	dialer   dialer
	now      func() time.Time
	rootCAs  *x509.CertPool
}

func NewNetworkTransport() *NetworkTransport {
	return &NetworkTransport{resolver: net.DefaultResolver, dialer: &net.Dialer{}, now: time.Now}
}

func newNetworkTransport(resolver resolver, dialer dialer, now func() time.Time) (*NetworkTransport, error) {
	if resolver == nil || dialer == nil || now == nil {
		return nil, ErrInvalidTransport
	}
	return &NetworkTransport{resolver: resolver, dialer: dialer, now: now}, nil
}

func (transport *NetworkTransport) Probe(ctx context.Context, request Request) (Observation, error) {
	if transport == nil || transport.resolver == nil || transport.dialer == nil || transport.now == nil || ctx == nil ||
		request.Timeout < 250*time.Millisecond || request.Timeout > time.Minute {
		return Observation{}, &TransportError{Code: FailureTargetRejected}
	}
	switch request.Protocol {
	case ProtocolHTTPS:
		if validateHTTPS(request.Target) != nil {
			return Observation{}, &TransportError{Code: FailureTargetRejected}
		}
		return transport.probeHTTPS(ctx, request)
	case ProtocolTCP:
		if validateTCP(request.Target) != nil {
			return Observation{}, &TransportError{Code: FailureTargetRejected}
		}
		return transport.probeTCP(ctx, request)
	default:
		return Observation{}, &TransportError{Code: FailureTargetRejected}
	}
}

func (transport *NetworkTransport) probeHTTPS(ctx context.Context, request Request) (Observation, error) {
	parsed, _ := url.Parse(request.Target)
	host, port := parsed.Hostname(), parsed.Port()
	if port == "" {
		port = "443"
	}
	target, err := transport.resolve(ctx, host, port)
	if err != nil {
		return Observation{}, err
	}
	expectedAddress := net.JoinHostPort(host, port)
	httpTransport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, &TransportError{Code: FailureTargetRejected}
			}
			if !sameAddress(address, expectedAddress) {
				return nil, &TransportError{Code: FailureTargetRejected}
			}
			connection, dialErr := transport.dialer.DialContext(ctx, network, target)
			if dialErr != nil {
				return nil, &TransportError{Code: classifyNetworkError(dialErr), Cause: dialErr}
			}
			return connection, nil
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host, RootCAs: transport.rootCAs},
		TLSHandshakeTimeout:    request.Timeout,
		ResponseHeaderTimeout:  request.Timeout,
		ExpectContinueTimeout:  0,
		IdleConnTimeout:        request.Timeout,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	defer httpTransport.CloseIdleConnections()
	client := &http.Client{
		Transport: httpTransport,
		Timeout:   request.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, request.Target, nil)
	if err != nil {
		return Observation{}, &TransportError{Code: FailureTargetRejected}
	}
	httpRequest.Header.Set("Accept", "application/octet-stream")
	httpRequest.Header.Set("User-Agent", "dirextalk-agent-healthprobe/1")
	started := transport.now()
	response, err := client.Do(httpRequest)
	latency := transport.now().Sub(started)
	if err != nil {
		return Observation{}, &TransportError{Code: classifyHTTPError(err), Cause: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		clear(body)
		return Observation{}, &TransportError{Code: classifyNetworkError(err), Cause: err}
	}
	if len(body) > maxResponseBytes {
		clear(body)
		return Observation{}, &TransportError{Code: FailureResponseTooLarge}
	}
	digest := sha256.Sum256(body)
	clear(body)
	return Observation{StatusCode: response.StatusCode, SummaryDigest: digestString(digest), Latency: latency}, nil
}

func (transport *NetworkTransport) probeTCP(ctx context.Context, request Request) (Observation, error) {
	host, port, _ := net.SplitHostPort(request.Target)
	target, err := transport.resolve(ctx, host, port)
	if err != nil {
		return Observation{}, err
	}
	started := transport.now()
	connection, err := transport.dialer.DialContext(ctx, "tcp", target)
	latency := transport.now().Sub(started)
	if err != nil {
		return Observation{}, &TransportError{Code: classifyNetworkError(err), Cause: err}
	}
	if err := connection.Close(); err != nil {
		return Observation{}, &TransportError{Code: FailureConnect, Cause: err}
	}
	digest := sha256.Sum256([]byte("dirextalk.external-tcp-connect/v1"))
	return Observation{SummaryDigest: digestString(digest), Latency: latency}, nil
}

func (transport *NetworkTransport) resolve(ctx context.Context, host, port string) (string, error) {
	plainHost := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if ip := net.ParseIP(plainHost); ip != nil {
		if !publicIP(ip) {
			return "", &TransportError{Code: FailureTargetRejected}
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	addresses, err := transport.resolver.LookupIP(ctx, "ip", plainHost)
	if err != nil || len(addresses) == 0 || len(addresses) > 32 {
		return "", &TransportError{Code: FailureResolve, Cause: err}
	}
	resolved := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if !publicIP(address) {
			return "", &TransportError{Code: FailureTargetRejected}
		}
		resolved = append(resolved, address.String())
	}
	sort.Strings(resolved)
	return net.JoinHostPort(resolved[0], port), nil
}

func sameAddress(actual, expected string) bool {
	actualHost, actualPort, actualErr := net.SplitHostPort(actual)
	expectedHost, expectedPort, expectedErr := net.SplitHostPort(expected)
	return actualErr == nil && expectedErr == nil && strings.EqualFold(actualHost, expectedHost) && actualPort == expectedPort
}

func classifyNetworkError(err error) FailureCode {
	if errors.Is(err, context.Canceled) {
		return FailureCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return FailureTimeout
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return FailureTimeout
	}
	return FailureConnect
}

func classifyHTTPError(err error) FailureCode {
	if code := classifyNetworkError(err); code != FailureConnect {
		return code
	}
	var certificateInvalid x509.CertificateInvalidError
	var hostnameInvalid x509.HostnameError
	var unknownAuthority x509.UnknownAuthorityError
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &certificateInvalid) || errors.As(err, &hostnameInvalid) || errors.As(err, &unknownAuthority) || errors.As(err, &recordHeader) {
		return FailureTLS
	}
	return FailureConnect
}

func digestString(value [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(value[:])
}

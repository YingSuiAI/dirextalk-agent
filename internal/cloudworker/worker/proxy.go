package worker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OutboundProxyBinding struct {
	URL               string `json:"url"`
	ServerName        string `json:"server_name"`
	TrustBundleSHA256 string `json:"trust_bundle_sha256"`
	BindingSHA256     string `json:"binding_digest"`
}

func (binding OutboundProxyBinding) Validate() error {
	parsed, err := url.Parse(binding.URL)
	if err != nil || binding.URL == "" || parsed.Scheme != "https" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.Port() == "" ||
		parsed.Hostname() != binding.ServerName ||
		binding.ServerName != strings.ToLower(binding.ServerName) ||
		!hostnamePattern.MatchString(binding.ServerName) || net.ParseIP(binding.ServerName) != nil ||
		!validDigest(binding.TrustBundleSHA256) || !validDigest(binding.BindingSHA256) ||
		parsed.String() != binding.URL {
		return ErrInvalid
	}
	canonical, err := json.Marshal(struct {
		URL               string `json:"url"`
		ServerName        string `json:"server_name"`
		TrustBundleSHA256 string `json:"trust_bundle_sha256"`
	}{binding.URL, binding.ServerName, binding.TrustBundleSHA256})
	if err != nil {
		return ErrInvalid
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	if hex.EncodeToString(digest[:]) != binding.BindingSHA256 {
		return ErrInvalid
	}
	return nil
}

type OutboundProxy struct {
	binding      OutboundProxyBinding
	proxyRoots   *x509.CertPool
	targetRoots  *x509.CertPool
	dialProxyTLS func(context.Context, string, *tls.Config) (net.Conn, error)
}

func NewOutboundProxy(
	binding OutboundProxyBinding,
	proxyRoots *x509.CertPool,
	targetRoots *x509.CertPool,
) (*OutboundProxy, error) {
	if binding.Validate() != nil || proxyRoots == nil || targetRoots == nil {
		return nil, ErrInvalid
	}
	return &OutboundProxy{
		binding: binding, proxyRoots: proxyRoots.Clone(), targetRoots: targetRoots.Clone(),
		dialProxyTLS: defaultProxyTLSDial,
	}, nil
}

func ProxyBindingFromBootstrap(document BootstrapDocument) OutboundProxyBinding {
	return OutboundProxyBinding{
		URL: document.OutboundProxyURL, ServerName: document.OutboundProxyServerName,
		TrustBundleSHA256: document.OutboundProxyTrustSHA256,
		BindingSHA256:     document.OutboundProxyBindingSHA256,
	}
}

func (proxy *OutboundProxy) URL() string {
	if proxy == nil {
		return ""
	}
	return proxy.binding.URL
}

func (proxy *OutboundProxy) parsedURL() (*url.URL, error) {
	if proxy == nil || proxy.binding.Validate() != nil || proxy.proxyRoots == nil ||
		proxy.targetRoots == nil || proxy.dialProxyTLS == nil {
		return nil, ErrInvalid
	}
	parsed, err := url.Parse(proxy.binding.URL)
	if err != nil {
		return nil, ErrInvalid
	}
	return parsed, nil
}

// DialTunnel establishes TLS to the sealed proxy and then an unauthenticated
// HTTP CONNECT tunnel to the exact requested authority. The caller performs
// the inner target TLS handshake; no direct-connect fallback exists.
func (proxy *OutboundProxy) DialTunnel(
	ctx context.Context,
	targetAuthority string,
) (net.Conn, error) {
	parsed, err := proxy.parsedURL()
	if ctx == nil || err != nil || !validAuthority(targetAuthority) {
		return nil, ErrInvalid
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: proxy.proxyRoots.Clone(), ServerName: proxy.binding.ServerName,
		NextProtos: []string{"http/1.1"},
	}
	connection, err := proxy.dialProxyTLS(ctx, parsed.Host, tlsConfig)
	if err != nil {
		return nil, ErrUnavailable
	}
	request := &http.Request{
		Method: http.MethodConnect, URL: &url.URL{Opaque: targetAuthority},
		Host: targetAuthority, Header: make(http.Header),
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	} else {
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if err := request.Write(connection); err != nil {
		_ = connection.Close()
		return nil, ErrUnavailable
	}
	reader := bufio.NewReaderSize(connection, 16<<10)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response == nil || response.StatusCode != http.StatusOK ||
		reader.Buffered() != 0 || len(response.TransferEncoding) != 0 || response.ContentLength > 0 {
		if response != nil && response.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
			_ = response.Body.Close()
		}
		_ = connection.Close()
		return nil, ErrUnavailable
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, nil
}

func defaultProxyTLSDial(
	ctx context.Context,
	address string,
	config *tls.Config,
) (net.Conn, error) {
	if ctx == nil || address == "" || config == nil {
		return nil, ErrInvalid
	}
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second},
		Config:    config,
	}
	return tlsDialer.DialContext(ctx, "tcp", address)
}

func (proxy *OutboundProxy) HTTPTransport() (*http.Transport, error) {
	if _, err := proxy.parsedURL(); err != nil {
		return nil, err
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) {
			return proxy.DialTunnel(ctx, address)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: proxy.targetRoots.Clone(),
		},
		TLSHandshakeTimeout: 5 * time.Second, ForceAttemptHTTP2: true,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}, nil
}

func validAuthority(value string) bool {
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	host, port, err := net.SplitHostPort(value)
	return err == nil && port != "" && strings.ToLower(host) == host &&
		hostnamePattern.MatchString(host) && net.ParseIP(host) == nil
}

package worker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
)

func TestOutboundProxyDialsOnlySealedProxyAndConnectsExactTarget(t *testing.T) {
	t.Parallel()
	binding := outboundProxyBindingForTest(t)
	proxy, err := NewOutboundProxy(binding, x509.NewCertPool(), x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	target := "api.example.test:443"
	serverErr := make(chan error, 1)
	dialed := make(chan string, 1)
	proxy.dialProxyTLS = func(
		_ context.Context,
		address string,
		config *tls.Config,
	) (net.Conn, error) {
		dialed <- address
		if address != "proxy.example.test:443" || config.ServerName != binding.ServerName ||
			config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
			len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" {
			return nil, errors.New("unexpected proxy TLS binding")
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			request, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				serverErr <- err
				return
			}
			if request.Method != http.MethodConnect || request.Host != target ||
				request.RequestURI != target {
				serverErr <- fmt.Errorf("CONNECT request = method %q host %q uri %q", request.Method, request.Host, request.RequestURI)
				return
			}
			_, err = server.Write([]byte("HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n"))
			serverErr <- err
		}()
		return client, nil
	}
	connection, err := proxy.DialTunnel(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if address := <-dialed; address != "proxy.example.test:443" {
		t.Fatalf("dialed address = %q", address)
	}
}

func TestOutboundProxyPreservesSquidConnectTunnelWithoutContentLength(t *testing.T) {
	t.Parallel()
	binding := outboundProxyBindingForTest(t)
	proxy, err := NewOutboundProxy(binding, x509.NewCertPool(), x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	target := "worker-control.example.test:443"
	received := make(chan string, 1)
	proxy.dialProxyTLS = func(context.Context, string, *tls.Config) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if _, readErr := http.ReadRequest(bufio.NewReader(server)); readErr != nil {
				received <- "read request: " + readErr.Error()
				return
			}
			if _, writeErr := server.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); writeErr != nil {
				received <- "write response: " + writeErr.Error()
				return
			}
			buffer := make([]byte, 4)
			if _, readErr := io.ReadFull(server, buffer); readErr != nil {
				received <- "read tunnel: " + readErr.Error()
				return
			}
			received <- string(buffer)
		}()
		return client, nil
	}
	connection, err := proxy.DialTunnel(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if value := <-received; value != "ping" {
		t.Fatalf("tunnel payload = %q", value)
	}
}

func TestOutboundProxyTransportHasNoDirectConnectFallback(t *testing.T) {
	t.Parallel()
	proxy, err := NewOutboundProxy(
		outboundProxyBindingForTest(t), x509.NewCertPool(), x509.NewCertPool(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var addresses []string
	proxy.dialProxyTLS = func(
		_ context.Context,
		address string,
		_ *tls.Config,
	) (net.Conn, error) {
		addresses = append(addresses, address)
		return nil, errors.New("sealed proxy unavailable")
	}
	transport, err := proxy.HTTPTransport()
	if err != nil {
		t.Fatal(err)
	}
	if transport.Proxy != nil {
		t.Fatal("transport installed an environment/direct proxy selector")
	}
	_, err = transport.DialContext(t.Context(), "tcp", "provider.example.test:443")
	if !errors.Is(err, ErrUnavailable) || len(addresses) != 1 ||
		addresses[0] != "proxy.example.test:443" {
		t.Fatalf("addresses=%v error=%v", addresses, err)
	}
}

func TestOutboundProxyBindingRejectsTrustAndEndpointDrift(t *testing.T) {
	t.Parallel()
	binding := outboundProxyBindingForTest(t)
	for name, mutate := range map[string]func(*OutboundProxyBinding){
		"trust": func(value *OutboundProxyBinding) {
			value.TrustBundleSHA256 = proxyTestDigest([]byte("other-ca"))
		},
		"endpoint": func(value *OutboundProxyBinding) {
			value.URL = "https://other-proxy.example.test:443"
			value.ServerName = "other-proxy.example.test"
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatalf("%s drift retained old binding digest", name)
			}
		})
	}
}

func outboundProxyBindingForTest(t *testing.T) OutboundProxyBinding {
	t.Helper()
	binding := OutboundProxyBinding{
		URL: "https://proxy.example.test:443", ServerName: "proxy.example.test",
		TrustBundleSHA256: proxyTestDigest([]byte("proxy-ca")),
	}
	raw, err := json.Marshal(struct {
		URL               string `json:"url"`
		ServerName        string `json:"server_name"`
		TrustBundleSHA256 string `json:"trust_bundle_sha256"`
	}{binding.URL, binding.ServerName, binding.TrustBundleSHA256})
	if err != nil {
		t.Fatal(err)
	}
	binding.BindingSHA256 = proxyTestDigest(raw)
	return binding
}

func proxyTestDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

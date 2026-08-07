package worker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

type recordingPiTunnelDialer struct {
	mu          sync.Mutex
	authorities []string
	serve       func(net.Conn)
}

func (dialer *recordingPiTunnelDialer) DialTunnel(
	_ context.Context,
	authority string,
) (net.Conn, error) {
	client, server := net.Pipe()
	dialer.mu.Lock()
	dialer.authorities = append(dialer.authorities, authority)
	serve := dialer.serve
	dialer.mu.Unlock()
	go func() {
		defer server.Close()
		if serve != nil {
			serve(server)
		}
	}()
	return client, nil
}

func (dialer *recordingPiTunnelDialer) snapshot() []string {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]string(nil), dialer.authorities...)
}

func TestPiCONNECTBridgeUsesOnlySealedTunnelForHostname443(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingPiTunnelDialer{serve: func(connection net.Conn) {
		payload := make([]byte, 4)
		if _, err := io.ReadFull(connection, payload); err != nil || string(payload) != "ping" {
			return
		}
		_, _ = connection.Write([]byte("pong"))
	}}
	bridge, err := startPiCONNECTBridge(t.Context(), listener, dialer, "model-relay.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridge.Close() })
	if err := bridge.AuthorizeRelay("https://model-relay.example.test/v1"); err != nil {
		t.Fatal(err)
	}
	if err := bridge.AuthorizeRelay("https://model-relay.example.test/v1"); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("second relay authorization error = %v", err)
	}

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	authority := "model-relay.example.test:443"
	if _, err := fmt.Fprintf(
		client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority,
	); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "pong" {
		t.Fatalf("tunnel payload=%q err=%v", payload, err)
	}
	if got := dialer.snapshot(); len(got) != 1 || got[0] != authority {
		t.Fatalf("upstream authorities = %v", got)
	}
}

func TestPiCONNECTBridgeRejectsHTTPIPAndNon443WithoutUpstream(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingPiTunnelDialer{}
	bridge, err := startPiCONNECTBridge(t.Context(), listener, dialer, "model-relay.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridge.Close() })

	for name, raw := range map[string]string{
		"before_claim":  "CONNECT model-relay.example.test:443 HTTP/1.1\r\nHost: model-relay.example.test:443\r\n\r\n",
		"ordinary_http": "GET http://model-relay.example.test/v1 HTTP/1.1\r\nHost: model-relay.example.test\r\n\r\n",
		"ip_authority":  "CONNECT 203.0.113.7:443 HTTP/1.1\r\nHost: 203.0.113.7:443\r\n\r\n",
		"wrong_port":    "CONNECT model-relay.example.test:80 HTTP/1.1\r\nHost: model-relay.example.test:80\r\n\r\n",
		"uppercase":     "CONNECT Model-Relay.example.test:443 HTTP/1.1\r\nHost: Model-Relay.example.test:443\r\n\r\n",
	} {
		name, raw := name, raw
		t.Run(name, func(t *testing.T) {
			if status := piProxyStatus(t, listener.Addr().String(), raw); status == http.StatusOK {
				t.Fatalf("unsafe request received %d", status)
			}
		})
	}
	if got := dialer.snapshot(); len(got) != 0 {
		t.Fatalf("rejected requests reached upstream: %v", got)
	}
	if err := bridge.AuthorizeRelay("https://other-relay.example.test/v1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bootstrap/claim relay mismatch error = %v", err)
	}
	if err := bridge.AuthorizeRelay("https://model-relay.example.test/v1"); err != nil {
		t.Fatal(err)
	}
	extra := "CONNECT other-relay.example.test:443 HTTP/1.1\r\nHost: other-relay.example.test:443\r\n\r\n"
	if status := piProxyStatus(t, listener.Addr().String(), extra); status == http.StatusOK {
		t.Fatalf("extra hostname received %d", status)
	}
	if got := dialer.snapshot(); len(got) != 0 {
		t.Fatalf("extra hostname reached upstream: %v", got)
	}
}

func piProxyStatus(t *testing.T, address, raw string) int {
	t.Helper()
	client, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := io.WriteString(client, raw); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	return response.StatusCode
}

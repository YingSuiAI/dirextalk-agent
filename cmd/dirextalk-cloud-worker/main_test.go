package main

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/worker"
)

type recordingWorkerControlTunnel struct {
	addresses chan string
}

func (tunnel *recordingWorkerControlTunnel) DialTunnel(
	_ context.Context,
	address string,
) (net.Conn, error) {
	select {
	case tunnel.addresses <- address:
	default:
	}
	return nil, worker.ErrUnavailable
}

func TestConnectWorkerControlPreservesHostnameForProxyCONNECT(t *testing.T) {
	tunnel := &recordingWorkerControlTunnel{addresses: make(chan string, 1)}
	document := worker.BootstrapDocument{
		ControlPlaneEndpoint:   "https://control.example.test:8443",
		ControlPlaneServerName: "control.example.test",
	}
	connection, err := connectWorkerControl(
		t.Context(), document,
		worker.Installation{TrustRoots: x509.NewCertPool()}, tunnel,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	connection.Connect()

	select {
	case address := <-tunnel.addresses:
		if address != "control.example.test:8443" {
			t.Fatalf("proxy CONNECT authority = %q", address)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC did not invoke the controlled-proxy dialer")
	}
}

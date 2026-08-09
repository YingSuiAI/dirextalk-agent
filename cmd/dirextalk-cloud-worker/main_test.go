package main

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/worker"
)

type recordingWorkerControlTunnel struct {
	addresses chan string
}

func TestValidateCurrentProcessCapabilitiesRequiresExactCompleteSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const exact = "00000000000000c0"
	write("Name:\tworker\nCapInh:\t" + exact + "\nCapPrm:\t" + exact + "\nCapEff:\t" + exact + "\nCapBnd:\t" + exact + "\nCapAmb:\t" + exact + "\n")
	if err := validateCurrentProcessCapabilities(path, exact); err != nil {
		t.Fatalf("exact capability set rejected: %v", err)
	}
	write("CapInh:\t" + exact + "\nCapPrm:\t" + exact + "\nCapEff:\t00000000002000c0\nCapBnd:\t" + exact + "\nCapAmb:\t" + exact + "\n")
	if err := validateCurrentProcessCapabilities(path, exact); err == nil {
		t.Fatal("capability drift accepted")
	}
	write("CapInh:\t" + exact + "\nCapPrm:\t" + exact + "\nCapEff:\t" + exact + "\nCapBnd:\t" + exact + "\n")
	if err := validateCurrentProcessCapabilities(path, exact); err == nil {
		t.Fatal("missing capability field accepted")
	}
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

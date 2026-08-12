package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const noProxyChildMarker = "DIREXTALK_TEST_PRODUCT_CAPABILITY_NO_PROXY_CHILD"

type noProxyProductCapabilityServer struct {
	capv1.UnimplementedProductCapabilityServiceServer
}

func (noProxyProductCapabilityServer) DescribeCapabilities(context.Context, *capv1.DescribeCapabilitiesRequest) (*capv1.DescribeCapabilitiesResponse, error) {
	return &capv1.DescribeCapabilitiesResponse{}, nil
}

func TestProductCapabilityClientBypassesAmbientProxy(t *testing.T) {
	if os.Getenv(noProxyChildMarker) == "1" {
		runNoProxyChild(t)
		return
	}

	root := t.TempDir()
	ca, caKey, caPEM := makeNoProxyTestCA(t)
	serverCert, _, _ := makeNoProxyTestLeaf(t, ca, caKey, "dirextalk-message-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	_, clientCertPEM, clientKeyPEM := makeNoProxyTestLeaf(t, ca, caKey, "dirextalk-agent", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	caFile := writeNoProxyTestFile(t, root, "ca.pem", caPEM)
	clientCertFile := writeNoProxyTestFile(t, root, "client.pem", clientCertPEM)
	clientKeyFile := writeNoProxyTestFile(t, root, "client.key", clientKeyPEM)
	tokenRaw := make([]byte, capv1.CapabilityTokenBytes)
	if _, err := rand.Read(tokenRaw); err != nil {
		t.Fatal(err)
	}
	token, err := capv1.EncodeCapabilityToken(tokenRaw)
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := writeNoProxyTestFile(t, root, "token", []byte(token))

	listener, target := listenNoProxyTestBackend(t)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse test CA")
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS13,
	})))
	capv1.RegisterProductCapabilityServiceServer(server, noProxyProductCapabilityServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxyListener.Close() })
	proxyURL := "http://" + proxyListener.Addr().String()

	command := exec.Command(os.Args[0], "-test.run=^TestProductCapabilityClientBypassesAmbientProxy$")
	command.Env = noProxyTestEnvironment(os.Environ(), map[string]string{
		noProxyChildMarker:                         "1",
		"DIREXTALK_TEST_PRODUCT_CAPABILITY_TARGET": target,
		"DIREXTALK_TEST_PRODUCT_CAPABILITY_CA":     caFile,
		"DIREXTALK_TEST_PRODUCT_CAPABILITY_CERT":   clientCertFile,
		"DIREXTALK_TEST_PRODUCT_CAPABILITY_KEY":    clientKeyFile,
		"DIREXTALK_TEST_PRODUCT_CAPABILITY_TOKEN":  tokenFile,
		"HTTPS_PROXY": proxyURL,
		"https_proxy": proxyURL,
		"HTTP_PROXY":  proxyURL,
		"http_proxy":  proxyURL,
		"ALL_PROXY":   proxyURL,
		"all_proxy":   proxyURL,
		"NO_PROXY":    "",
		"no_proxy":    "",
	})
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("no-proxy child failed: %v\n%s", err, output)
	}
	if err := proxyListener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := proxyListener.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Product Capability client connected to the ambient proxy")
	}
	if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("check ambient proxy connection: %v", err)
	}
}

func runNoProxyChild(t *testing.T) {
	target := os.Getenv("DIREXTALK_TEST_PRODUCT_CAPABILITY_TARGET")
	proxy, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: target}})
	if err != nil {
		t.Fatalf("resolve configured proxy: %v", err)
	}
	if proxy == nil || proxy.String() != os.Getenv("HTTPS_PROXY") {
		t.Fatalf("test precondition failed: target %q does not resolve through configured proxy", target)
	}
	productClient, err := New(&Config{
		ServerAddr:        target,
		CACertFile:        os.Getenv("DIREXTALK_TEST_PRODUCT_CAPABILITY_CA"),
		ClientCertFile:    os.Getenv("DIREXTALK_TEST_PRODUCT_CAPABILITY_CERT"),
		ClientKeyFile:     os.Getenv("DIREXTALK_TEST_PRODUCT_CAPABILITY_KEY"),
		TokenFile:         os.Getenv("DIREXTALK_TEST_PRODUCT_CAPABILITY_TOKEN"),
		InstanceID:        uuid.NewString(),
		AccountGeneration: 1,
		ServerName:        "dirextalk-message-server",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer productClient.Close()
	parent := capv1.NewCallContext(uuid.NewString(), uuid.NewString(), time.Now().Add(5*time.Second).UnixMilli())
	parent, err = capv1.AppendCallNode(parent, capv1.NodeMessage)
	if err != nil {
		t.Fatal(err)
	}
	parent, err = capv1.AppendCallNode(parent, capv1.NodeAgent)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := productClient.DescribeCapabilities(ctx, parent); err != nil {
		t.Fatalf("direct Product Capability call failed: %v", err)
	}
}

func listenNoProxyTestBackend(t *testing.T) (net.Listener, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, addressErr := iface.Addrs()
		if addressErr != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip.To4() != nil && !ip.IsLoopback() {
				return listener, net.JoinHostPort(ip.String(), fmt.Sprint(port))
			}
		}
	}
	_ = listener.Close()
	t.Skip("non-loopback IPv4 address is required to exercise HTTP proxy selection")
	return nil, ""
}

func makeNoProxyTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "no-proxy-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func makeNoProxyTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, usages []x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certPEM, keyPEM
}

func writeNoProxyTestFile(t *testing.T, root, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func noProxyTestEnvironment(current []string, replacements map[string]string) []string {
	replaced := make(map[string]struct{}, len(replacements))
	for key := range replacements {
		replaced[strings.ToUpper(key)] = struct{}{}
	}
	result := make([]string, 0, len(current)+len(replacements))
	for _, entry := range current {
		key, _, found := strings.Cut(entry, "=")
		if _, ok := replaced[strings.ToUpper(key)]; found && ok {
			continue
		}
		result = append(result, entry)
	}
	for key, value := range replacements {
		result = append(result, key+"="+value)
	}
	return result
}

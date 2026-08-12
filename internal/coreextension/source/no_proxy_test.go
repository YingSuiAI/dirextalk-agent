package source

import (
	"net/http"
	"testing"
)

func TestProductionProviderClientsIgnoreAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")

	client, err := newProviderClient(HTTPConfig{}, NPMRegistryAuthority)
	if err != nil {
		t.Fatalf("new production provider client: %v", err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("provider transport = %T, want *http.Transport", client.http.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("production provider transport inherited an ambient proxy")
	}
}

func TestProductionNodeResolverIgnoresAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")

	resolver, err := NewProductionNodeDependencyResolver(NodeDependencyResolverConfig{})
	if err != nil {
		t.Fatalf("new production Node resolver: %v", err)
	}
	transport, ok := resolver.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("resolver transport = %T, want *http.Transport", resolver.http.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("production Node resolver inherited an ambient proxy")
	}
}

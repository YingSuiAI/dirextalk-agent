package model

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDefaultClientRejectsUnsafeLiteralEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		baseURL  string
		insecure bool
	}{
		{name: "loopback IPv4", baseURL: "https://127.0.0.1/v1"},
		{name: "metadata IPv4", baseURL: "https://169.254.169.254/latest"},
		{name: "loopback IPv6", baseURL: "https://[::1]/v1"},
		{name: "private IPv4", baseURL: "https://10.1.2.3/v1"},
		{name: "localhost name", baseURL: "https://localhost/v1"},
		{name: "insecure flag alone", baseURL: "http://8.8.8.8/v1", insecure: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewClient(Profile{
				Provider: ProviderOpenAICompatible, Model: "test-model", BaseURL: test.baseURL,
				SecretRef: "secret:model", AllowInsecureHTTP: test.insecure,
			}, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
				t.Fatal("secret resolver must not run while parsing an unsafe endpoint")
				return nil, nil
			}))
			if !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("NewClient() error = %v, want ErrInvalidProfile", err)
			}
		})
	}
}

func TestAllowInsecureHTTPRequiresExplicitHTTPClientInjection(t *testing.T) {
	t.Parallel()

	profile := Profile{
		Provider: ProviderOpenAICompatible, Model: "test-model", BaseURL: "http://127.0.0.1/v1",
		SecretRef: "secret:model", AllowInsecureHTTP: true,
	}
	resolver := SecretResolverFunc(func(context.Context, string) ([]byte, error) { return []byte("test-only"), nil })
	if _, err := NewClient(profile, resolver); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("profile flag opened default private transport: %v", err)
	}
	if _, err := NewClient(profile, resolver, WithHTTPClient(httpClientFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("test transport")
	}))); err != nil {
		t.Fatalf("explicit test HTTP client was rejected: %v", err)
	}
}

func TestDefaultClientRejectsPrivateDNSBeforeResolvingCredential(t *testing.T) {
	t.Parallel()

	var secretCalls atomic.Int32
	var dialCalls atomic.Int32
	client, err := NewClient(publicTestProfile(), SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		secretCalls.Add(1)
		return []byte("must-not-be-resolved"), nil
	}), withNetworkResolverForTest(resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})), withNetworkDialerForTest(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("must not dial")
	})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Generate() error = %v, want ErrProviderUnavailable", err)
	}
	if secretCalls.Load() != 0 || dialCalls.Load() != 0 {
		t.Fatalf("unsafe DNS crossed boundary: secret_calls=%d dial_calls=%d", secretCalls.Load(), dialCalls.Load())
	}
}

func TestDefaultClientRejectsDNSRebindingBeforeDialOrCredentialSend(t *testing.T) {
	t.Parallel()

	secret := generatedCredential(t)
	resolverBuffer := append([]byte(nil), secret...)
	var lookups atomic.Int32
	var dialCalls atomic.Int32
	client, err := NewClient(publicTestProfile(), SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return resolverBuffer, nil
	}), withNetworkResolverForTest(resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	})), withNetworkDialerForTest(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("must not dial rebound address")
	})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Generate() error = %v, want ErrProviderUnavailable", err)
	}
	if lookups.Load() < 2 || dialCalls.Load() != 0 {
		t.Fatalf("DNS rebinding was not stopped at dial: lookups=%d dial_calls=%d", lookups.Load(), dialCalls.Load())
	}
	if strings.Contains(err.Error(), string(secret)) {
		t.Fatal("DNS rebinding error exposed model credential")
	}
	for _, value := range resolverBuffer {
		if value != 0 {
			t.Fatal("credential buffer was not zeroed after rejected dial")
		}
	}
}

func TestDefaultClientDoesNotFollowRedirectWithCredential(t *testing.T) {
	t.Parallel()

	var targetRequests atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests.Add(1)
	}))
	defer target.Close()

	secret := generatedCredential(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+string(secret) {
			t.Error("origin did not receive its provider credential")
		}
		http.Redirect(w, request, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	tlsConfig := origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	var dialer net.Dialer
	client, err := NewClient(publicTestProfile(), SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return append([]byte(nil), secret...), nil
	}), withNetworkResolverForTest(publicResolver()), withNetworkDialerForTest(dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, origin.Listener.Addr().String())
	})), withTLSConfigForTest(tlsConfig))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("redirect error = %v, want ErrProviderUnavailable", err)
	}
	if targetRequests.Load() != 0 {
		t.Fatalf("redirect target received %d credential-bearing requests", targetRequests.Load())
	}
}

func TestDefaultTransportIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:65534")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:65534")

	clientValue, err := NewClient(publicTestProfile(), SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte("unused"), nil
	}), withNetworkResolverForTest(publicResolver()))
	if err != nil {
		t.Fatal(err)
	}
	implementation := clientValue.(*client)
	httpClient, ok := implementation.http.(*http.Client)
	if !ok {
		t.Fatalf("default HTTP client type = %T", implementation.http)
	}
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport type = %T", httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("default model transport retained an environment proxy callback")
	}
}

func TestEndpointResolutionErrorsAreCollapsedWithoutSecretLeak(t *testing.T) {
	t.Parallel()

	canary := string(generatedCredential(t))
	var secretCalls atomic.Int32
	client, err := NewClient(publicTestProfile(), SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		secretCalls.Add(1)
		return []byte("unreachable"), nil
	}), withNetworkResolverForTest(resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("resolver leaked " + canary)
	})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), canary) {
		t.Fatalf("resolution error = %v", err)
	}
	if secretCalls.Load() != 0 {
		t.Fatal("credential was resolved after endpoint resolution failed")
	}
}

func publicTestProfile() Profile {
	return Profile{
		Provider: ProviderOpenAICompatible, Model: "test-model",
		BaseURL: "https://model.example/v1", SecretRef: "secret:model",
	}
}

func publicResolver() networkResolver {
	return resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
}

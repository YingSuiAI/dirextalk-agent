package websearch

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/searchprofile"
)

const searchTestSecret = "search-provider-secret-1234567890"

func TestProviderUsesCatalogBoundRequestsAndNormalizesResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		provider   searchprofile.Provider
		endpoint   string
		method     string
		authHeader string
		response   string
	}{
		{
			name: "tavily", provider: searchprofile.ProviderTavily,
			endpoint: "https://api.tavily.com/search", method: http.MethodPost,
			authHeader: "Authorization",
			response:   `{"results":[{"title":"Official result","url":"https://docs.example.org/a#section","content":"api_key=` + searchTestSecret + `"}]}`,
		},
		{
			name: "brave", provider: searchprofile.ProviderBrave,
			endpoint: "https://api.search.brave.com/res/v1/web/search", method: http.MethodGet,
			authHeader: "X-Subscription-Token",
			response:   `{"web":{"results":[{"title":"Official result","url":"https://docs.example.org/a#section","description":"api_key=` + searchTestSecret + `"}]}}`,
		},
		{
			name: "exa", provider: searchprofile.ProviderExa,
			endpoint: "https://api.exa.ai/search", method: http.MethodPost,
			authHeader: "x-api-key",
			response:   `{"results":[{"title":"Official result","url":"https://docs.example.org/a#section","highlights":["api_key=` + searchTestSecret + `"]}]}`,
		},
		{
			name: "serper", provider: searchprofile.ProviderSerper,
			endpoint: "https://google.serper.dev/search", method: http.MethodPost,
			authHeader: "X-API-KEY",
			response:   `{"organic":[{"title":"Official result","link":"https://docs.example.org/a#section","snippet":"api_key=` + searchTestSecret + `"}]}`,
		},
		{
			name: "deepseek_native", provider: searchprofile.ProviderDeepSeekNative,
			endpoint: "https://api.deepseek.com/anthropic/v1/messages", method: http.MethodPost,
			authHeader: "x-api-key",
			response: `{
				"content":[
					{"type":"thinking","thinking":"must not be returned"},
					{"type":"server_tool_use","name":"web_search","input":{"query":"current Dirextalk architecture"}},
					{"type":"web_search_tool_result","content":[{"type":"web_search_result","title":"Official result","url":"https://docs.example.org/a#section","encrypted_content":"must-not-be-returned"}]},
					{"type":"text","text":"Verified summary. api_key=` + searchTestSecret + `"}
				],
				"stop_reason":"end_turn"
			}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			secret := []byte(searchTestSecret)
			resolver := &recordingSecretResolver{secret: secret}
			client := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method != test.method || request.URL.Scheme != "https" || request.URL.Host == "" {
					t.Fatalf("provider request = %s %s", request.Method, request.URL)
				}
				if test.provider == searchprofile.ProviderBrave {
					if request.URL.Scheme+"://"+request.URL.Host+request.URL.Path != test.endpoint ||
						request.URL.Query().Get("q") != "current Dirextalk architecture" ||
						request.URL.Query().Get("count") != "2" || request.URL.Query().Get("safesearch") != "strict" {
						t.Fatalf("Brave request URL = %s", request.URL)
					}
				} else if request.URL.String() != test.endpoint {
					t.Fatalf("provider endpoint = %s", request.URL)
				}
				wantAuth := searchTestSecret
				if test.provider == searchprofile.ProviderTavily {
					wantAuth = "Bearer " + wantAuth
				}
				if request.Header.Get(test.authHeader) != wantAuth {
					t.Fatalf("provider auth header is missing")
				}
				if test.method == http.MethodPost {
					body, err := io.ReadAll(request.Body)
					if err != nil || !json.Valid(body) || !strings.Contains(string(body), "current Dirextalk architecture") {
						t.Fatalf("provider request body = %q, %v", body, err)
					}
					if test.provider == searchprofile.ProviderDeepSeekNative &&
						(!strings.Contains(string(body), `"type":"web_search_20250305"`) ||
							!strings.Contains(string(body), `"model":"deepseek-v4-flash"`)) {
						t.Fatalf("DeepSeek native search request = %s", body)
					}
				}
				return jsonResponse(test.response), nil
			})
			provider := mustProvider(t, test.provider, test.endpoint, resolver, client)
			request := validToolRequest(test.provider, test.endpoint)
			tools, err := provider.Tools(context.Background(), request)
			if err != nil || len(tools) != 1 || tools[0].Definition.Name != runtimeapi.SearchToolName {
				t.Fatalf("Tools() = %#v, %v", tools, err)
			}
			result, err := tools[0].Run(context.Background(), runtimeapi.ToolInvocation{
				RequestID: request.RequestID, OwnerID: request.OwnerID,
				ConversationID: request.ConversationID, ToolCallID: "call-1",
				Name:      runtimeapi.SearchToolName,
				Arguments: json.RawMessage(`{"query":"current Dirextalk architecture"}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			var normalized normalizedResponse
			if err := json.Unmarshal([]byte(result.Content), &normalized); err != nil ||
				normalized.Provider != string(test.provider) || normalized.Query != "current Dirextalk architecture" ||
				!normalized.Untrusted || len(normalized.Results) != 1 ||
				normalized.Results[0].URL != "https://docs.example.org/a" ||
				strings.Contains(result.Content, searchTestSecret) || !strings.Contains(result.Content, "[redacted]") ||
				strings.Contains(result.Content, "must-not-be-returned") ||
				(test.provider == searchprofile.ProviderDeepSeekNative && normalized.Summary == "") {
				t.Fatalf("normalized result = %s, %v", result.Content, err)
			}
			if resolver.reference != "mounted:"+test.name+"-token" || resolver.calls != 1 {
				t.Fatalf("secret resolution = %q calls=%d", resolver.reference, resolver.calls)
			}
			for _, value := range secret {
				if value != 0 {
					t.Fatal("resolved secret bytes were not cleared")
				}
			}
		})
	}
}

func TestDeepSeekNativeResponseRequiresActualServerSearchEvidence(t *testing.T) {
	t.Parallel()
	for _, response := range []string{
		`{"content":[{"type":"text","text":"unsupported answer"}],"stop_reason":"end_turn"}`,
		`{"content":[{"type":"server_tool_use","name":"other_tool"}],"stop_reason":"end_turn"}`,
		`{"content":[{"type":"server_tool_use","name":"web_search"},{"type":"web_search_tool_result","content":[]}],"stop_reason":"end_turn"}`,
	} {
		if _, err := parseProviderResponse(
			searchprofile.ProviderDeepSeekNative,
			[]byte(response),
		); !errors.Is(err, ErrResponseRejected) {
			t.Fatalf("unsafe DeepSeek response error = %v", err)
		}
	}
}

func TestDeepSeekNativeResponseAcceptsMaxTokenSearchEvidence(t *testing.T) {
	t.Parallel()
	parsed, err := parseProviderResponse(
		searchprofile.ProviderDeepSeekNative,
		[]byte(`{
			"content":[
				{"type":"text","text":"unsupported pre-search answer"},
				{"type":"server_tool_use","name":"web_search"},
				{"type":"web_search_tool_result","content":[{"type":"web_search_result","title":"Official result","url":"https://docs.example.org/current"}]},
				{"type":"text","text":"supported post-search summary"}
			],
			"stop_reason":"max_tokens"
		}`),
	)
	if err != nil || len(parsed.items) != 1 || parsed.items[0].url != "https://docs.example.org/current" ||
		parsed.summary != "supported post-search summary" || strings.Contains(parsed.summary, "unsupported") {
		t.Fatalf("max-token search response = %#v, %v", parsed, err)
	}
}

func TestProviderFailsClosedBeforeCredentialOrNetworkAccess(t *testing.T) {
	t.Parallel()
	resolver := &recordingSecretResolver{secret: []byte(searchTestSecret)}
	clientCalls := 0
	provider := mustProvider(t, searchprofile.ProviderTavily, "https://api.tavily.com/search", resolver, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		clientCalls++
		return nil, errors.New("network must not be reached")
	}))

	withoutProfile := validToolRequest(searchprofile.ProviderTavily, "https://api.tavily.com/search")
	withoutProfile.SearchProfile = nil
	tools, err := provider.Tools(context.Background(), withoutProfile)
	if err != nil || len(tools) != 0 {
		t.Fatalf("profile-less tools = %#v, %v", tools, err)
	}

	tampered := validToolRequest(searchprofile.ProviderTavily, "https://api.tavily.com/search")
	tampered.SearchProfile.BaseURL = "https://attacker.invalid/search"
	if _, err := provider.Tools(context.Background(), tampered); !errors.Is(err, ErrProfileUnavailable) {
		t.Fatalf("tampered profile error = %v", err)
	}

	request := validToolRequest(searchprofile.ProviderTavily, "https://api.tavily.com/search")
	tools, err = provider.Tools(context.Background(), request)
	if err != nil || len(tools) != 1 {
		t.Fatalf("Tools() = %#v, %v", tools, err)
	}
	for _, invocation := range []runtimeapi.ToolInvocation{
		{
			RequestID: "wrong", OwnerID: request.OwnerID, ConversationID: request.ConversationID,
			ToolCallID: "call-1", Name: runtimeapi.SearchToolName, Arguments: json.RawMessage(`{"query":"safe"}`),
		},
		{
			RequestID: request.RequestID, OwnerID: request.OwnerID, ConversationID: request.ConversationID,
			ToolCallID: "call-2", Name: runtimeapi.SearchToolName, Arguments: json.RawMessage(`{"query":"safe","endpoint":"https://attacker.invalid"}`),
		},
		{
			RequestID: request.RequestID, OwnerID: request.OwnerID, ConversationID: request.ConversationID,
			ToolCallID: "call-3", Name: runtimeapi.SearchToolName, Arguments: json.RawMessage(`{"query":"api_key=sk-abcdefghijklmnopqrstuvwxyz"}`),
		},
	} {
		if _, err := tools[0].Run(context.Background(), invocation); err == nil {
			t.Fatalf("invalid invocation unexpectedly succeeded: %#v", invocation)
		}
	}
	if resolver.calls != 0 || clientCalls != 0 {
		t.Fatalf("invalid calls reached secrets=%d network=%d", resolver.calls, clientCalls)
	}
}

func TestProviderBoundsAndRejectsExternalResponse(t *testing.T) {
	t.Parallel()
	resolver := &recordingSecretResolver{secret: []byte(searchTestSecret)}
	provider := mustProvider(t, searchprofile.ProviderTavily, "https://api.tavily.com/search", resolver, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBytes+1))),
		}, nil
	}))
	request := validToolRequest(searchprofile.ProviderTavily, "https://api.tavily.com/search")
	tools, err := provider.Tools(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tools[0].Run(context.Background(), runtimeapi.ToolInvocation{
		RequestID: request.RequestID, OwnerID: request.OwnerID,
		ConversationID: request.ConversationID, ToolCallID: "call-1",
		Name: runtimeapi.SearchToolName, Arguments: json.RawMessage(`{"query":"safe"}`),
	})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
}

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (function httpDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type recordingSecretResolver struct {
	secret    []byte
	reference string
	calls     int
}

func (resolver *recordingSecretResolver) ResolveSecret(_ context.Context, reference string) ([]byte, error) {
	resolver.calls++
	resolver.reference = reference
	return resolver.secret, nil
}

func mustProvider(t *testing.T, provider searchprofile.Provider, endpoint string, secrets runtimeapi.SecretResolver, client httpDoer) *Provider {
	t.Helper()
	catalog, err := searchprofile.NewCatalog([]searchprofile.Profile{{
		ProfileID: string(provider) + "-default", Provider: provider,
		BaseURL: endpoint, SecretRef: "mounted:" + string(provider) + "-token",
		MaxResults: 2, TimeoutSeconds: 10,
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := newProvider(catalog, secrets, client)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func validToolRequest(provider searchprofile.Provider, endpoint string) runtimeapi.ToolRequest {
	return runtimeapi.ToolRequest{
		RequestID: "request-1", OwnerID: "owner-1", ConversationID: "conversation-1",
		SearchProfile: &searchprofile.Profile{
			ProfileID: string(provider) + "-default", Provider: provider,
			BaseURL: endpoint, SecretRef: "mounted:" + string(provider) + "-token",
			MaxResults: 2, TimeoutSeconds: 10,
		},
	}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

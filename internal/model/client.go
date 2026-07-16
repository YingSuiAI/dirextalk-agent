package model

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultHTTPTimeout = 90 * time.Second
	responseBodyLimit  = 4 << 20
)

type client struct {
	profile         Profile
	baseURL         string
	resolver        SecretResolver
	http            HTTPClient
	customHTTP      bool
	endpointPolicy  *endpointPolicy
	networkResolver networkResolver
	networkDialer   networkDialer
	tlsConfig       *tls.Config
}

type Option func(*client)

func WithHTTPClient(httpClient HTTPClient) Option {
	return func(client *client) {
		if httpClient != nil {
			client.http = httpClient
			client.customHTTP = true
		}
	}
}

// The following options are intentionally package-private. They make DNS and
// dial behavior deterministic in tests without creating a production escape
// hatch around the default endpoint policy.
func withNetworkResolverForTest(resolver networkResolver) Option {
	return func(client *client) {
		if resolver != nil {
			client.networkResolver = resolver
		}
	}
}

func withNetworkDialerForTest(dialer networkDialer) Option {
	return func(client *client) {
		if dialer != nil {
			client.networkDialer = dialer
		}
	}
}

func withTLSConfigForTest(config *tls.Config) Option {
	return func(client *client) {
		if config != nil {
			client.tlsConfig = config.Clone()
		}
	}
}

func NewClient(profile Profile, resolver SecretResolver, options ...Option) (Client, error) {
	profile.Provider = Provider(strings.ToLower(strings.TrimSpace(string(profile.Provider))))
	profile.Model = strings.TrimSpace(profile.Model)
	profile.BaseURL = strings.TrimSpace(profile.BaseURL)
	profile.SecretRef = strings.TrimSpace(profile.SecretRef)
	if resolver == nil || profile.Model == "" || profile.SecretRef == "" {
		return nil, ErrInvalidProfile
	}

	baseURL := profile.BaseURL
	switch profile.Provider {
	case ProviderDeepSeek:
		if baseURL == "" {
			baseURL = "https://api.deepseek.com"
		}
	case ProviderAnthropic:
		if baseURL == "" {
			baseURL = "https://api.anthropic.com"
		}
	case ProviderOpenAICompatible:
		if baseURL == "" {
			return nil, fmt.Errorf("%w: openai-compatible base URL is required", ErrInvalidProfile)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported provider", ErrInvalidProfile)
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: invalid base URL", ErrInvalidProfile)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""

	result := &client{
		profile: profile, baseURL: strings.TrimRight(parsed.String(), "/"), resolver: resolver,
		networkResolver: net.DefaultResolver,
		networkDialer:   &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
	}
	for _, option := range options {
		if option != nil {
			option(result)
		}
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && profile.AllowInsecureHTTP && result.customHTTP) {
		return nil, fmt.Errorf("%w: base URL must use HTTPS", ErrInvalidProfile)
	}
	if !result.customHTTP {
		if err := validateLiteralEndpointHost(parsed.Hostname()); err != nil {
			return nil, fmt.Errorf("%w: base URL host is not allowed", ErrInvalidProfile)
		}
		policy := defaultEndpointPolicy(parsed.Hostname())
		policy.resolver = result.networkResolver
		policy.dialer = result.networkDialer
		result.endpointPolicy = policy
		result.http = newDefaultHTTPClient(policy, result.tlsConfig)
	}
	return result, nil
}

func (c *client) Generate(ctx context.Context, request CompletionRequest) (Completion, error) {
	payload, err := c.requestPayload(request, false)
	if err != nil {
		return Completion{}, err
	}
	response, credential, err := c.do(ctx, payload)
	if err != nil {
		return Completion{}, err
	}
	defer zeroBytes(credential)
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, readErr := readLimited(response.Body, providerErrorBodyLimit)
		if readErr != nil && readErr != ErrResponseTooLarge {
			return Completion{}, readErr
		}
		return Completion{}, providerError(c.profile.Provider, response.StatusCode, response.Header, body, credential)
	}
	body, err := readLimited(response.Body, responseBodyLimit)
	if err != nil {
		return Completion{}, err
	}
	return c.decodeCompletion(body)
}

func (c *client) requestPayload(request CompletionRequest, stream bool) (map[string]any, error) {
	if c.profile.Provider == ProviderAnthropic {
		return c.anthropicRequestPayload(request, stream)
	}
	return c.openAIRequestPayload(request, stream)
}

func (c *client) decodeCompletion(body []byte) (Completion, error) {
	if c.profile.Provider == ProviderAnthropic {
		return c.decodeAnthropicCompletion(body)
	}
	return c.decodeOpenAICompletion(body)
}

func (c *client) decodeDelta(data json.RawMessage) (Delta, bool, error) {
	if c.profile.Provider == ProviderAnthropic {
		return c.decodeAnthropicDelta(data)
	}
	return c.decodeOpenAIDelta(data)
}

func (c *client) Stream(ctx context.Context, request CompletionRequest) (Stream, error) {
	payload, err := c.requestPayload(request, true)
	if err != nil {
		return nil, err
	}
	response, credential, err := c.do(ctx, payload)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(credential)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		defer response.Body.Close()
		body, readErr := readLimited(response.Body, providerErrorBodyLimit)
		if readErr != nil && readErr != ErrResponseTooLarge {
			return nil, readErr
		}
		return nil, providerError(c.profile.Provider, response.StatusCode, response.Header, body, credential)
	}
	return newSSEStream(response.Body, c.decodeDelta), nil
}

func (c *client) do(ctx context.Context, payload map[string]any) (*http.Response, []byte, error) {
	if c.endpointPolicy != nil {
		if err := c.endpointPolicy.preflight(ctx); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			return nil, nil, ErrProviderUnavailable
		}
	}
	credential, err := c.resolver.ResolveSecret(ctx, c.profile.SecretRef)
	if err != nil || len(credential) == 0 {
		zeroBytes(credential)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, ErrSecretUnavailable
	}

	data, err := json.Marshal(payload)
	if err != nil {
		zeroBytes(credential)
		return nil, nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), strings.NewReader(string(data)))
	if err != nil {
		zeroBytes(credential)
		return nil, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if c.profile.Provider == ProviderAnthropic {
		request.Header.Set("x-api-key", string(credential))
		request.Header.Set("anthropic-version", anthropicVersion)
	} else {
		request.Header.Set("Authorization", "Bearer "+string(credential))
	}
	response, err := c.http.Do(request)
	if err != nil {
		zeroBytes(credential)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, ErrProviderUnavailable
	}
	return response, credential, nil
}

func (c *client) endpoint() string {
	if c.profile.Provider == ProviderAnthropic {
		return c.baseURL + "/v1/messages"
	}
	return c.baseURL + "/chat/completions"
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return body[:limit], ErrResponseTooLarge
	}
	return body, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

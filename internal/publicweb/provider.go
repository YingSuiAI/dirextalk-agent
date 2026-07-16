// Package publicweb exposes a single credential-free HTTPS research tool.
// It is intentionally not a general HTTP client: the model controls only the
// public URL, while method, headers, network policy, limits, and provenance are
// fixed by this package.
package publicweb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	ToolName = "official_source_fetch"

	maxArgumentsBytes = 8 << 10
	maxURLBytes       = 2048
	maxResponseBytes  = 1 << 20
	maxTextBytes      = 48 << 10
	maxResultBytes    = 60 << 10
	requestTimeout    = 15 * time.Second
)

var (
	ErrInvocationScopeMismatch = errors.New("official source fetch invocation scope mismatch")
	ErrInvalidArguments        = errors.New("official source fetch arguments are invalid")
	ErrURLDenied               = errors.New("official source URL is not allowed")
	ErrFetchFailed             = errors.New("official source request failed")
	ErrResponseRejected        = errors.New("official source response was rejected")
	ErrResponseTooLarge        = errors.New("official source response exceeds size limit")
	ErrUnsupportedContentType  = errors.New("official source response content type is unsupported")
)

type Provider struct {
	resolver netIPResolver
	client   *http.Client
	now      func() time.Time
	timeout  time.Duration
}

var _ runtimeapi.ToolProvider = (*Provider)(nil)

func New() *Provider {
	resolver := net.DefaultResolver
	return &Provider{
		resolver: resolver,
		client: &http.Client{
			Transport: newSecureTransport(resolver),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now:     time.Now,
		timeout: requestTimeout,
	}
}

func (provider *Provider) Tools(ctx context.Context, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	if provider == nil || provider.resolver == nil || provider.client == nil || provider.now == nil || provider.timeout <= 0 {
		return nil, ErrFetchFailed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validScopeValue(request.RequestID) || !validScopeValue(request.OwnerID) || !validScopeValue(request.ConversationID) {
		return nil, ErrInvocationScopeMismatch
	}
	binding := request
	return []runtimeapi.Tool{{
		Definition: modelapi.Tool{
			Name:        ToolName,
			Description: "Fetch one public official HTTPS source without credentials and return de-secreted plain text with retrieval provenance.",
			InputSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"url"},
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"format":      "uri",
						"maxLength":   maxURLBytes,
						"description": "Absolute public HTTPS URL for an official document or repository page. Credential-bearing URLs are rejected.",
					},
				},
			},
		},
		Run: func(runCtx context.Context, invocation runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
			if !matchesBinding(binding, invocation) {
				return runtimeapi.ToolResult{}, ErrInvocationScopeMismatch
			}
			rawURL, err := decodeArguments(invocation.Arguments)
			if err != nil {
				return runtimeapi.ToolResult{}, err
			}
			result, err := provider.fetch(runCtx, rawURL)
			if err != nil {
				return runtimeapi.ToolResult{}, err
			}
			return runtimeapi.ToolResult{Content: result}, nil
		},
	}}, nil
}

type fetchResult struct {
	URL           string `json:"url"`
	RetrievedAt   string `json:"retrieved_at"`
	ContentDigest string `json:"content_digest"`
	Content       string `json:"content"`
}

// Evidence is the immutable, non-content provenance that may be bound to a
// planning Task. The fetched text remains in the durable tool receipt and is
// never copied into planning tables or task events.
type Evidence struct {
	URL           string
	RetrievedAt   time.Time
	ContentDigest string
}

// ParseEvidenceResult validates the server-produced tool result before its
// provenance is accepted by another durable boundary.
func ParseEvidenceResult(raw string) (Evidence, error) {
	if raw == "" || len(raw) > maxResultBytes {
		return Evidence{}, ErrResponseRejected
	}
	var result fetchResult
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return Evidence{}, ErrResponseRejected
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Evidence{}, ErrResponseRejected
	}
	target, err := parsePublicHTTPSURL(result.URL)
	if err != nil || target.String() != result.URL || !validPublicHostIdentity(target.Hostname()) {
		return Evidence{}, ErrResponseRejected
	}
	retrievedAt, err := time.Parse(time.RFC3339Nano, result.RetrievedAt)
	if err != nil || retrievedAt.IsZero() || !retrievedAt.Equal(retrievedAt.Truncate(time.Microsecond)) ||
		result.RetrievedAt != retrievedAt.UTC().Format(time.RFC3339Nano) {
		return Evidence{}, ErrResponseRejected
	}
	if !validSHA256Digest(result.ContentDigest) || strings.TrimSpace(result.Content) == "" || len([]byte(result.Content)) > maxTextBytes {
		return Evidence{}, ErrResponseRejected
	}
	return Evidence{URL: result.URL, RetrievedAt: retrievedAt.UTC(), ContentDigest: result.ContentDigest}, nil
}

func (provider *Provider) fetch(ctx context.Context, rawURL string) (string, error) {
	target, err := parsePublicHTTPSURL(rawURL)
	if err != nil {
		return "", err
	}
	fetchCtx, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	if err := validateResolvedHost(fetchCtx, provider.resolver, target.Hostname()); err != nil {
		if errors.Is(err, ErrURLDenied) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		return "", ErrFetchFailed
	}

	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", ErrURLDenied
	}
	request.Header.Set("Accept", "text/html, text/plain, text/markdown, application/json")
	request.Header.Set("User-Agent", "Dirextalk-Agent-Official-Source-Fetch/1")

	response, err := provider.client.Do(request)
	if err != nil {
		if fetchCtx.Err() != nil {
			return "", fetchCtx.Err()
		}
		return "", ErrFetchFailed
	}
	if response == nil || response.Body == nil {
		return "", ErrFetchFailed
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", ErrResponseRejected
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !acceptedMediaType(mediaType) {
		return "", ErrUnsupportedContentType
	}
	if response.ContentLength > maxResponseBytes {
		return "", ErrResponseTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		if fetchCtx.Err() != nil {
			return "", fetchCtx.Err()
		}
		return "", ErrFetchFailed
	}
	if len(body) > maxResponseBytes {
		return "", ErrResponseTooLarge
	}
	digest := sha256.Sum256(body)
	content, err := extractSafeText(mediaType, body)
	if err != nil {
		return "", err
	}
	content = redactFetchedText(content)
	if content == "" {
		return "", ErrResponseRejected
	}
	if len([]byte(content)) > maxTextBytes {
		return "", ErrResponseTooLarge
	}

	retrievedAt := provider.now().UTC().Truncate(time.Microsecond)
	encoded, err := json.Marshal(fetchResult{
		URL:           target.String(),
		RetrievedAt:   retrievedAt.Format(time.RFC3339Nano),
		ContentDigest: "sha256:" + hex.EncodeToString(digest[:]),
		Content:       content,
	})
	if err != nil {
		return "", ErrFetchFailed
	}
	if len(encoded) > maxResultBytes {
		return "", ErrResponseTooLarge
	}
	return string(encoded), nil
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validPublicHostIdentity(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if address, err := netip.ParseAddr(host); err == nil {
		return publicAddress(address.Unmap())
	}
	return !deniedHostName(host) && validDNSName(host)
}

func decodeArguments(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || len(raw) > maxArgumentsBytes {
		return "", ErrInvalidArguments
	}
	var input struct {
		URL string `json:"url"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return "", ErrInvalidArguments
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", ErrInvalidArguments
	}
	input.URL = strings.TrimSpace(input.URL)
	if input.URL == "" || len(input.URL) > maxURLBytes {
		return "", ErrInvalidArguments
	}
	return input.URL, nil
}

func matchesBinding(request runtimeapi.ToolRequest, invocation runtimeapi.ToolInvocation) bool {
	return invocation.RequestID == request.RequestID &&
		invocation.OwnerID == request.OwnerID &&
		invocation.ConversationID == request.ConversationID &&
		invocation.Name == ToolName &&
		validScopeValue(invocation.ToolCallID)
}

func validScopeValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed == value && len(value) <= 255 && !strings.ContainsAny(value, "\r\n\x00") && !security.ContainsLikelySecret(value)
}

func acceptedMediaType(mediaType string) bool {
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case "text/html", "text/plain", "text/markdown", "application/json":
		return true
	default:
		return false
	}
}

func parsePublicHTTPSURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) != raw || raw == "" || len(raw) > maxURLBytes || strings.ContainsAny(raw, "\r\n\x00") || security.ContainsLikelySecret(raw) {
		return nil, ErrURLDenied
	}
	target, err := url.Parse(raw)
	if err != nil || !target.IsAbs() || !strings.EqualFold(target.Scheme, "https") || target.Opaque != "" || target.Host == "" || target.User != nil || target.Fragment != "" {
		return nil, ErrURLDenied
	}
	if target.Hostname() == "" || sensitiveQuery(target) {
		return nil, ErrURLDenied
	}
	return target, nil
}

func sensitiveQuery(target *url.URL) bool {
	if target.RawQuery == "" {
		return false
	}
	if security.ContainsLikelySecret(target.RawQuery) {
		return true
	}
	values, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return true
	}
	for key := range values {
		normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(key))
		if strings.HasPrefix(normalized, "xamz") || strings.Contains(normalized, "token") || strings.Contains(normalized, "signature") || strings.Contains(normalized, "credential") || strings.Contains(normalized, "secret") || strings.Contains(normalized, "password") || strings.Contains(normalized, "authorization") || strings.Contains(normalized, "apikey") || strings.Contains(normalized, "accesskey") || normalized == "key" {
			return true
		}
	}
	return false
}

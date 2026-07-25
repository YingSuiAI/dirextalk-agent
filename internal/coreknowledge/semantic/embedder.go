package semantic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

// HTTPEmbedderConfig controls the transport boundary. Endpoint and model are
// taken from the immutable model profile; no request field can select a remote
// host. HTTPClient is injectable for tests and for a service's pinned egress
// transport.
type HTTPEmbedderConfig struct {
	HTTPClient   *http.Client
	Timeout      time.Duration
	Dimension    int
	MaxBodyBytes int64
	MaxInputs    int
}

type HTTPEmbedder struct {
	client       *http.Client
	timeout      time.Duration
	dimension    int
	maxBodyBytes int64
	maxInputs    int
}

func NewHTTPEmbedder(cfg HTTPEmbedderConfig) (*HTTPEmbedder, error) {
	if cfg.Dimension < 0 || cfg.MaxBodyBytes < 0 || cfg.MaxInputs < 0 {
		return nil, ErrInvalid
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout * time.Second
	}
	if cfg.Timeout < time.Second || cfg.Timeout > 10*time.Minute {
		return nil, ErrInvalid
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.MaxInputs == 0 {
		cfg.MaxInputs = MaxInputs
	}
	return &HTTPEmbedder{client: cfg.HTTPClient, timeout: cfg.Timeout, dimension: cfg.Dimension,
		maxBodyBytes: cfg.MaxBodyBytes, maxInputs: cfg.MaxInputs}, nil
}

type openAIEmbeddingRequest struct {
	Input []string `json:"input"`
	Model string   `json:"model"`
}

type openAIEmbeddingResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
		Index     *int      `json:"index"`
	} `json:"data"`
}

type geminiEmbedContentRequest struct {
	Content struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"content"`
}

type geminiEmbedContentResponse struct {
	Embedding struct {
		Values []float32 `json:"values"`
	} `json:"embedding"`
}

func (e *HTTPEmbedder) Embed(ctx context.Context, profile coremodel.Profile, inputs []string) (vectors [][]float32, err error) {
	if e == nil || len(inputs) == 0 || len(inputs) > e.maxInputs || strings.TrimSpace(profile.Model) == "" || profile.APIKey == "" {
		return nil, ErrInvalid
	}
	for _, input := range inputs {
		if err := validateText(input, 1<<20, false); err != nil {
			return nil, ErrInvalid
		}
	}
	provider := coremodel.ModelProvider(strings.ToLower(strings.TrimSpace(string(profile.Provider))))
	switch provider {
	case coremodel.ProviderOpenAICompatible:
		return e.embedOpenAI(ctx, profile, inputs)
	case coremodel.ProviderGemini:
		return e.embedGemini(ctx, profile, inputs)
	case coremodel.ProviderAnthropic:
		return nil, ErrProvider
	default:
		return nil, ErrProvider
	}
}

func (e *HTTPEmbedder) embedOpenAI(ctx context.Context, profile coremodel.Profile, inputs []string) ([][]float32, error) {
	payload := openAIEmbeddingRequest{Input: append([]string(nil), inputs...), Model: profile.Model}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalid
	}
	defer zeroBytes(body)
	endpoint, err := embeddingEndpoint(profile.BaseURL, "/embeddings")
	if err != nil {
		return nil, ErrInvalid
	}
	response, err := e.doJSON(ctx, endpoint, profile.APIKey, body, false)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(response)
	var decoded openAIEmbeddingResponse
	if err := decodeBounded(response, &decoded); err != nil || len(decoded.Data) != len(inputs) {
		return nil, ErrResponse
	}
	result := make([][]float32, len(inputs))
	seen := make([]bool, len(inputs))
	for i, item := range decoded.Data {
		idx := i
		if item.Index != nil {
			idx = *item.Index
		}
		if idx < 0 || idx >= len(inputs) || seen[idx] || validateVector(item.Embedding, e.dimension) != nil {
			return nil, ErrResponse
		}
		seen[idx] = true
		result[idx] = append([]float32(nil), item.Embedding...)
	}
	for _, ok := range seen {
		if !ok {
			return nil, ErrResponse
		}
	}
	return result, nil
}

func (e *HTTPEmbedder) embedGemini(ctx context.Context, profile coremodel.Profile, inputs []string) ([][]float32, error) {
	model := strings.TrimPrefix(strings.TrimSpace(profile.Model), "models/")
	if model == "" || strings.ContainsAny(model, "\r\n?&#") {
		return nil, ErrInvalid
	}
	result := make([][]float32, len(inputs))
	for i, input := range inputs {
		var payload geminiEmbedContentRequest
		payload.Content.Parts = []struct {
			Text string `json:"text"`
		}{{Text: input}}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, ErrInvalid
		}
		endpoint, err := embeddingEndpoint(profile.BaseURL, path.Join("/v1beta/models", model+":embedContent"))
		if err != nil {
			zeroBytes(body)
			return nil, ErrInvalid
		}
		response, callErr := e.doJSON(ctx, endpoint, profile.APIKey, body, true)
		zeroBytes(body)
		if callErr != nil {
			return nil, callErr
		}
		var decoded geminiEmbedContentResponse
		decodeErr := decodeBounded(response, &decoded)
		zeroBytes(response)
		if decodeErr != nil || validateVector(decoded.Embedding.Values, e.dimension) != nil {
			return nil, ErrResponse
		}
		result[i] = append([]float32(nil), decoded.Embedding.Values...)
	}
	return result, nil
}

func embeddingEndpoint(base, suffix string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", ErrInvalid
	}
	u, err := url.Parse(base)
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(base, "\r\n\x00") {
		return "", ErrInvalid
	}
	suffix = "/" + strings.TrimLeft(suffix, "/")
	u.Path = strings.TrimRight(u.Path, "/") + suffix
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func (e *HTTPEmbedder) doJSON(ctx context.Context, endpoint, apiKey string, body []byte, gemini bool) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	if gemini {
		request.Header.Set("x-goog-api-key", apiKey)
	} else {
		request.Header.Set("Authorization", "Bearer "+apiKey)
	}
	response, err := e.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("embedding request failed: %w", redactNetworkError(err))
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, e.maxBodyBytes+1)
	data, readErr := io.ReadAll(limited)
	if readErr != nil {
		zeroBytes(data)
		return nil, fmt.Errorf("embedding response read failed: %w", redactNetworkError(readErr))
	}
	if int64(len(data)) > e.maxBodyBytes {
		zeroBytes(data)
		return nil, ErrBodyTooLarge
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		zeroBytes(data)
		return nil, fmt.Errorf("embedding provider returned status %d", response.StatusCode)
	}
	return data, nil
}

func decodeBounded(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrResponse
	}
	return nil
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func redactNetworkError(err error) error {
	if err == nil {
		return nil
	}
	// URL and HTTP errors may echo request URLs. Return only a stable category.
	return fmt.Errorf("%s", strings.TrimSpace(strings.SplitN(err.Error(), ":", 2)[0]))
}

// DigestVector is useful for deterministic test fixtures without persisting
// input text. It is not used as a security primitive.
func DigestVector(v []float32) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

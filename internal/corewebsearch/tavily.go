package corewebsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	tavilyEndpoint   = "https://api.tavily.com/search"
	tavilyTimeout    = 15 * time.Second
	maxResponseBytes = 2 << 20
	MaxQueryRunes    = 1000
	maxResults       = 10
	maxAnswerBytes   = 3000
	maxTitleBytes    = 300
	maxContentBytes  = 2000
)

type TavilyClient struct {
	client   *http.Client
	endpoint string
}

func NewTavilyClient() *TavilyClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &TavilyClient{
		client: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		endpoint: tavilyEndpoint,
	}
}

func newTavilyClientForTest(client *http.Client, endpoint string) *TavilyClient {
	return &TavilyClient{client: client, endpoint: endpoint}
}

func (c *TavilyClient) Search(ctx context.Context, apiKey, query string, requestedResults int) (SearchResult, error) {
	apiKey = strings.TrimSpace(apiKey)
	query = strings.TrimSpace(query)
	if c == nil || c.client == nil || apiKey == "" || query == "" || !utf8.ValidString(query) || utf8.RuneCountInString(query) > MaxQueryRunes {
		return SearchResult{}, ErrInvalid
	}
	if requestedResults <= 0 {
		requestedResults = 5
	}
	if requestedResults > maxResults {
		requestedResults = maxResults
	}
	payload, err := json.Marshal(map[string]any{"query": query, "search_depth": "basic", "max_results": requestedResults})
	if err != nil {
		return SearchResult{}, ErrProvider
	}
	requestCtx, cancel := context.WithTimeout(ctx, tavilyTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return SearchResult{}, ErrProvider
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+apiKey)
	client := *c.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
			return SearchResult{}, requestCtx.Err()
		}
		return SearchResult{}, ErrProvider
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return SearchResult{}, ErrProvider
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return SearchResult{}, ErrProvider
	}
	var decoded struct {
		Answer  string `json:"answer"`
		Results []struct {
			Title   string  `json:"title"`
			URL     string  `json:"url"`
			Content string  `json:"content"`
			Score   float64 `json:"score"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return SearchResult{}, ErrProvider
	}
	items := make([]SearchItem, 0, min(len(decoded.Results), requestedResults))
	for _, item := range decoded.Results {
		if len(items) == requestedResults {
			break
		}
		url := strings.TrimSpace(item.URL)
		if url == "" {
			continue
		}
		items = append(items, SearchItem{Title: redact(preview(item.Title, maxTitleBytes), apiKey), URL: redact(preview(url, 4096), apiKey), Content: redact(preview(item.Content, maxContentBytes), apiKey), Score: item.Score})
	}
	return SearchResult{Provider: ProviderTavily, Query: redact(query, apiKey), Answer: redact(preview(decoded.Answer, maxAnswerBytes), apiKey), Results: items}, nil
}

func redact(value, secret string) string {
	if secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, "[redacted]")
}

func preview(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[:len(value)-1]
	}
	return strings.TrimSpace(value)
}

func (c *TavilyClient) String() string { return fmt.Sprintf("TavilyClient(%s)", tavilyEndpoint) }

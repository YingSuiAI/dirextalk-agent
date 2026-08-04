package skills

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// WebSearchTool implements web search capability
type WebSearchTool struct {
	apiKey     string
	httpClient *http.Client
}

func NewWebSearchTool(apiKey string) *WebSearchTool {
	return &WebSearchTool{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

// Search performs a web search
func (t *WebSearchTool) Search(ctx context.Context, query string, maxResults int) ([]SearchResult, error) {
	if maxResults == 0 {
		maxResults = 5
	}

	// Use Brave Search API or similar
	endpoint := "https://api.search.brave.com/res/v1/web/search"

	params := url.Values{}
	params.Add("q", query)
	params.Add("count", fmt.Sprintf("%d", maxResults))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", t.apiKey)

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Web struct {
			Results []struct {
				Title       string `json:"title"`
				URL         string `json:"url"`
				Description string `json:"description"`
			} `json:"results"`
		} `json:"web"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	results := make([]SearchResult, 0, len(result.Web.Results))
	for _, r := range result.Web.Results {
		results = append(results, SearchResult{
			Title:       r.Title,
			URL:         r.URL,
			Description: r.Description,
		})
	}

	return results, nil
}

type SearchResult struct {
	Title       string
	URL         string
	Description string
}

// RegisterWebSearchTool registers web search as a skill
func RegisterWebSearchTool(store *SkillStore, apiKey string) {
	tool := NewWebSearchTool(apiKey)

	skill := &Skill{
		ID:          "skill_web_search",
		Name:        "web_search",
		Description: "Search the web for information",
		Type:        "builtin",
		Enabled:     true,
		Config: map[string]interface{}{
			"max_results": 5,
		},
	}

	// Register handler
	store.RegisterHandler("web_search", func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
		query, ok := params["query"].(string)
		if !ok {
			return nil, fmt.Errorf("query parameter required")
		}

		maxResults := 5
		if mr, ok := params["max_results"].(float64); ok {
			maxResults = int(mr)
		}

		results, err := tool.Search(ctx, query, maxResults)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"results": results,
		}, nil
	})

	_ = skill // Store in database
}

// SkillStore additions for handler registration
func (s *SkillStore) RegisterHandler(name string, handler func(context.Context, map[string]interface{}) (map[string]interface{}, error)) {
	// TODO: Store handler in registry
}

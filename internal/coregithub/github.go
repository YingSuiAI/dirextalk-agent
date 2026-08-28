package coregithub

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const identityEndpoint = "https://api.github.com/user"

// GitHubClient only verifies a credential. Repository discovery resolves this
// credential again immediately before each individual source request.
type GitHubClient struct {
	client   *http.Client
	endpoint string
}

func NewGitHubClient() *GitHubClient {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &GitHubClient{client: &http.Client{Transport: t, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint: identityEndpoint}
}

func (c *GitHubClient) Identity(ctx context.Context, token string) error {
	if c == nil || c.client == nil || strings.TrimSpace(token) == "" {
		return ErrInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return ErrProvider
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client.Do(req)
	if err != nil {
		return ErrProvider
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrProvider
	}
	return nil
}

func (c *GitHubClient) String() string { return "GitHubClient" }

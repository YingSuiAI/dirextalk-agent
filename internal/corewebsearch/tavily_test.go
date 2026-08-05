package corewebsearch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTavilySearchIsBoundedAndRedactsCredential(t *testing.T) {
	const secret = "tvly-test-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatalf("request method/auth = %s/%q", r.Method, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"answer":%q,"results":[{"title":%q,"url":"https://example.test/%s","content":%q,"score":0.9}]}`, "answer "+secret, "title "+secret, secret, "content "+secret)
	}))
	defer server.Close()
	client := newTavilyClientForTest(server.Client(), server.URL)
	result, err := client.Search(context.Background(), secret, "current facts", 99)
	if err != nil {
		t.Fatal(err)
	}
	encoded := fmt.Sprintf("%#v", result)
	if strings.Contains(encoded, secret) || len(result.Results) != 1 || result.Provider != ProviderTavily {
		t.Fatalf("unsafe/invalid result: %s", encoded)
	}
}

func TestTavilySearchRejectsRedirectStatusOversizeAndTimeout(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		followed := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/target" {
				followed = true
				w.Write([]byte(`{"results":[]}`))
				return
			}
			http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
		}))
		defer server.Close()
		_, err := newTavilyClientForTest(server.Client(), server.URL).Search(context.Background(), "key", "q", 1)
		if !errors.Is(err, ErrProvider) || followed {
			t.Fatalf("redirect err=%v followed=%v", err, followed)
		}
	})
	t.Run("provider status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("secret provider body"))
		}))
		defer server.Close()
		_, err := newTavilyClientForTest(server.Client(), server.URL).Search(context.Background(), "key", "q", 1)
		if !errors.Is(err, ErrProvider) || strings.Contains(err.Error(), "provider body") {
			t.Fatalf("status error=%v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
		}))
		defer server.Close()
		_, err := newTavilyClientForTest(server.Client(), server.URL).Search(context.Background(), "key", "q", 1)
		if !errors.Is(err, ErrProvider) {
			t.Fatalf("oversize error=%v", err)
		}
	})
	t.Run("caller deadline", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := newTavilyClientForTest(server.Client(), server.URL).Search(ctx, "key", "q", 1)
		close(release)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline error=%v", err)
		}
	})
}

func TestTavilySearchValidatesQuery(t *testing.T) {
	client := newTavilyClientForTest(http.DefaultClient, "http://example.invalid")
	for _, query := range []string{"", strings.Repeat("x", maxQueryRunes+1)} {
		if _, err := client.Search(context.Background(), "key", query, 1); !errors.Is(err, ErrInvalid) {
			t.Fatalf("query length=%d err=%v", len(query), err)
		}
	}
}

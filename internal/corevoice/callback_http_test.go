package corevoice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCallbackHandlerRejectsForgedAndOversizedRequests(t *testing.T) {
	service, _, _ := newVoiceTestService(t, true)
	defer service.Close()
	ctx := context.Background()
	created, err := service.Create(ctx, "owner-a", 9, CreateRequest{ConversationID: "conversation"}, "create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(ctx, "owner-a", 9, created.SessionID, "start"); err != nil {
		t.Fatal(err)
	}
	handler, err := NewCallbackHandler(CallbackHandlerConfig{Service: service, AccountGeneration: 9, RelayToken: "relay-secret", MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/agent/voice/volc/custom-llm?session_id="+created.SessionID, strings.NewReader(`{"session_id":"`+created.SessionID+`","text":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer forged")
	request.Header.Set("X-Dirextalk-Agent-Voice-Relay-Token", "relay-secret")
	request.Header.Set("X-Dirextalk-Account-Generation", "9")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged callback status=%d", response.StatusCode)
	}
	for name, value := range map[string]string{
		"X-Dirextalk-Agent-Voice-Relay-Token": "wrong-relay",
		"X-Dirextalk-Account-Generation":      "10",
	} {
		request, err = http.NewRequest(http.MethodPost, server.URL+"/agent/voice/volc/custom-llm?session_id="+created.SessionID, strings.NewReader(`{"session_id":"`+created.SessionID+`","text":"hello"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+callbackHMAC("callback-secret", created.SessionID, timeFromRFC3339(t, created.ExpiresAt)))
		request.Header.Set("X-Dirextalk-Agent-Voice-Relay-Token", "relay-secret")
		request.Header.Set("X-Dirextalk-Account-Generation", "9")
		request.Header.Set(name, value)
		response, err = http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("invalid relay header %s=%q status=%d", name, value, response.StatusCode)
		}
	}
	request, err = http.NewRequest(http.MethodPost, server.URL+"/agent/voice/volc/custom-llm?session_id="+created.SessionID, strings.NewReader(`{"session_id":"`+created.SessionID+`","text":"`+strings.Repeat("x", 2048)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+callbackHMAC("callback-secret", created.SessionID, timeFromRFC3339(t, created.ExpiresAt)))
	request.Header.Set("X-Dirextalk-Agent-Voice-Relay-Token", "relay-secret")
	request.Header.Set("X-Dirextalk-Account-Generation", "9")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized callback status=%d", response.StatusCode)
	}
}

package corevoice

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type voiceRoundTrip func(*http.Request) (*http.Response, error)

func (f voiceRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSignRTCTokenLimitsPrivileges(t *testing.T) {
	const appID = "123456781234567812345678"
	token, err := signRTCToken(appID, "rtc-secret", "room", "user", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(token[3+len(appID):])
	if err != nil || len(raw) < 2 {
		t.Fatalf("token encoding: %v", err)
	}
	bodyLen := int(binary.LittleEndian.Uint16(raw[:2]))
	body := raw[2 : 2+bodyLen]
	if len(body) < 14 {
		t.Fatal("token body too short")
	}
	offset := 12
	for range 2 {
		if len(body) < offset+2 {
			t.Fatal("identity framing missing")
		}
		offset += 2 + int(binary.LittleEndian.Uint16(body[offset:]))
	}
	count := int(binary.LittleEndian.Uint16(body[offset:]))
	offset += 2
	if count != 2 || len(body) != offset+count*6 || binary.LittleEndian.Uint16(body[offset:]) != 1 || binary.LittleEndian.Uint16(body[offset+6:]) != 4 {
		t.Fatalf("unexpected privileges count=%d body=%d", count, len(body))
	}
}

func TestVolcProviderStartUsesHTTPSBoundCallbackAndSignedRequest(t *testing.T) {
	var requestBody map[string]any
	client := &http.Client{Transport: voiceRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") == "" || r.Header.Get("X-Date") == "" {
			t.Error("missing Volc signature headers")
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &requestBody); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	provider := NewVolcProvider()
	provider.Host, provider.HTTPClient = "https://rtc.example.test", client
	binding := ProfileBinding{Provider: "volc_voice", AppID: "123456781234567812345678", RTCAppKey: "rtc-secret", AccessKeyID: "ak", SecretAccessKey: "sk", WebhookURL: "https://agent.example.test/events", WebhookSecret: "callback-secret", CustomLLMURL: "https://agent.example.test/custom"}
	session := Session{ID: "voice_1", ProviderTaskID: "provider-task-fixed", VoiceChatAppID: binding.AppID, RoomID: "room", UserID: "user", AIUserID: "ai", ExpiresAt: time.Now().Add(time.Minute)}
	if err := provider.Start(context.Background(), "owner", session, binding); err != nil {
		t.Fatal(err)
	}
	config := requestBody["Config"].(map[string]any)
	llm := config["LLMConfig"].(map[string]any)
	if !strings.HasPrefix(llm["Url"].(string), "https://agent.example.test/custom") || llm["APIKey"].(string) == "" {
		t.Fatalf("unexpected LLM config=%v", llm)
	}
	if got := requestBody["TaskId"].(string); got != session.ProviderTaskID {
		t.Fatalf("task id=%q", got)
	}
}

func TestBoundVolcProviderStartInterruptStopAgainstFakeEndpoint(t *testing.T) {
	actions := make([]string, 0, 3)
	client := &http.Client{Transport: voiceRoundTrip(func(r *http.Request) (*http.Response, error) {
		action, _ := urlQueryAction(r.URL.RawQuery)
		actions = append(actions, action)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	binding := ProfileBinding{Provider: "volc_voice", AppID: "123456781234567812345678", RTCAppKey: "rtc-secret", AccessKeyID: "ak", SecretAccessKey: "sk", WebhookURL: "https://agent.example.test/events", WebhookSecret: "callback-secret", CustomLLMURL: "https://agent.example.test/custom"}
	provider, err := NewVolcBoundProvider(binding)
	if err != nil {
		t.Fatal(err)
	}
	provider.base.HTTPClient, provider.base.Host = client, "https://rtc.example.test"
	session := Session{ID: "voice_1", VoiceChatAppID: binding.AppID, RoomID: "room", UserID: "user", AIUserID: "ai", ExpiresAt: time.Now().Add(time.Minute)}
	if err := provider.Start(context.Background(), "owner", session, binding); err != nil {
		t.Fatal(err)
	}
	if err := provider.Interrupt(context.Background(), "owner", session, binding); err != nil {
		t.Fatal(err)
	}
	if err := provider.End(context.Background(), "owner", session, binding); err != nil {
		t.Fatal(err)
	}
	if strings.Join(actions, ",") != "StartVoiceChat,UpdateVoiceChat,StopVoiceChat" {
		t.Fatalf("provider action sequence=%v", actions)
	}
}

func urlQueryAction(raw string) (string, bool) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", false
	}
	return values.Get("Action"), values.Get("Action") != ""
}

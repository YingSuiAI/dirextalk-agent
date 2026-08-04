package corevoice

// VolcProvider is the Agent-owned VolcEngine RTC voice adapter. It mirrors the
// former message-server provider boundary but receives a request-local profile
// binding, so access keys and RTC secrets never enter the durable voice store.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type VolcProvider struct {
	HTTPClient *http.Client
	Host       string
	Region     string
}

func NewVolcProvider() *VolcProvider {
	return &VolcProvider{HTTPClient: &http.Client{Timeout: 15 * time.Second}, Host: "https://rtc.volcengineapi.com", Region: "cn-north-1"}
}

func (p *VolcProvider) Create(_ context.Context, _ string, session Session, binding ProfileBinding) (ProviderSession, error) {
	if !strings.EqualFold(strings.TrimSpace(binding.Provider), "volc_voice") {
		return ProviderSession{}, ErrUnavailable
	}
	if strings.TrimSpace(binding.AppID) == "" || strings.TrimSpace(binding.RTCAppKey) == "" || strings.TrimSpace(binding.AccessKeyID) == "" || strings.TrimSpace(binding.SecretAccessKey) == "" {
		return ProviderSession{}, fmt.Errorf("volc voice credentials and app_id are required")
	}
	if !httpsURL(binding.WebhookURL) || !httpsURL(binding.CustomLLMURL) || strings.TrimSpace(binding.WebhookSecret) == "" {
		return ProviderSession{}, fmt.Errorf("voice HTTPS callback configuration is required")
	}
	room := "dirextalk_voice_" + randomHex(12)
	user := "owner_" + randomHex(12)
	ai := strings.TrimSpace(binding.AIUserID)
	if ai == "" {
		ai = "dirextalk_ai_" + randomHex(8)
	}
	expires := session.ExpiresAt.UTC()
	token, err := signRTCToken(binding.AppID, binding.RTCAppKey, room, user, expires)
	if err != nil {
		return ProviderSession{}, err
	}
	return ProviderSession{AppID: binding.AppID, VoiceChatAppID: fallbackString(binding.VoiceChatAppID, binding.AppID), AIUserID: ai, RoomID: room, UserID: user, Token: token, ProviderHandle: binding.AppID + ":" + room + ":" + session.ID, ExpiresAt: expires}, nil
}

func (p *VolcProvider) Start(ctx context.Context, _ string, session Session, binding ProfileBinding) error {
	if p == nil {
		return ErrUnavailable
	}
	return startVolc(ctx, p, session, binding)
}

func (p *VolcProvider) Interrupt(ctx context.Context, _ string, session Session, binding ProfileBinding) error {
	if p == nil {
		return ErrUnavailable
	}
	return p.call(ctx, "UpdateVoiceChat", map[string]any{"AppId": session.VoiceChatAppID, "RoomId": session.RoomID, "TaskId": providerTaskID(session), "Command": "interrupt"}, binding.AccessKeyID, binding.SecretAccessKey)
}

func (p *VolcProvider) End(ctx context.Context, _ string, session Session, binding ProfileBinding) error {
	if p == nil {
		return ErrUnavailable
	}
	return p.call(ctx, "StopVoiceChat", map[string]any{"AppId": session.VoiceChatAppID, "RoomId": session.RoomID, "TaskId": providerTaskID(session)}, binding.AccessKeyID, binding.SecretAccessKey)
}

// NewVolcBoundProvider returns a provider with request-independent endpoint
// and credential/callback material. Credentials stay in memory only. The
// profile resolver should create one per authenticated owner generation.
func NewVolcBoundProvider(binding ProfileBinding) (*BoundVolcProvider, error) {
	if !strings.EqualFold(strings.TrimSpace(binding.Provider), "volc_voice") || binding.AppID == "" || binding.AccessKeyID == "" || binding.SecretAccessKey == "" || binding.RTCAppKey == "" || !httpsURL(binding.WebhookURL) || !httpsURL(binding.CustomLLMURL) || binding.WebhookSecret == "" {
		return nil, ErrUnavailable
	}
	return &BoundVolcProvider{binding: binding, base: NewVolcProvider()}, nil
}

type BoundVolcProvider struct {
	binding ProfileBinding
	base    *VolcProvider
}

func (p *BoundVolcProvider) Create(ctx context.Context, owner string, session Session, binding ProfileBinding) (ProviderSession, error) {
	if p == nil {
		return ProviderSession{}, ErrUnavailable
	}
	// The constructor binding is authoritative; a caller cannot swap a
	// credential/profile bundle between Create and Start.
	return p.base.createWithBinding(ctx, owner, session, p.binding)
}
func (p *BoundVolcProvider) Start(ctx context.Context, _ string, session Session, _ ProfileBinding) error {
	if p == nil {
		return ErrUnavailable
	}
	return startVolc(ctx, p.base, session, p.binding)
}

func startVolc(ctx context.Context, base *VolcProvider, session Session, binding ProfileBinding) error {
	if base == nil {
		return ErrUnavailable
	}
	callback, err := callbackURL(binding.WebhookURL, session.ID)
	if err != nil {
		return err
	}
	customURL, err := callbackURL(binding.CustomLLMURL, session.ID)
	if err != nil {
		return err
	}
	custom, _ := json.Marshal(map[string]string{"session_id": session.ID})
	resource := fallbackString(binding.TTSResourceID, "seed-tts-1.0")
	speaker := fallbackString(binding.TTSSpeaker, "zh_female_qingxinnvsheng_mars_bigtts")
	rate := binding.TTSSpeechRate
	if rate == 0 {
		rate = 18
	}
	loudness := binding.TTSSpeechLoudness
	if loudness == 0 {
		loudness = 2
	}
	pitch := binding.TTSPitch
	if pitch == 0 {
		pitch = 1
	}
	ttsParams := map[string]any{"Credential": map[string]any{"ResourceId": resource}}
	ttsConfig, _ := json.Marshal(map[string]any{"req_params": map[string]any{"speaker": speaker, "audio_params": map[string]any{"speech_rate": rate, "loudness_rate": loudness}, "additions": map[string]any{"post_process": map[string]any{"pitch": pitch}}}})
	ttsParams["VolcanoTTSParameters"] = string(ttsConfig)
	callbackToken := callbackHMAC(binding.WebhookSecret, session.ID, session.ExpiresAt)
	config := map[string]any{"ASRConfig": map[string]any{"Provider": "volcano", "ProviderParams": map[string]any{"Mode": "bigmodel", "ApiResourceId": "volc.seedasr.sauc.duration", "StreamMode": 2, "VolcanoASRParameters": `{"request":{"enable_nonstream":true}}`}, "VADConfig": map[string]any{"SilenceTime": 900}, "InterruptConfig": map[string]any{"InterruptSpeechDuration": 700}}, "LLMConfig": map[string]any{"Mode": "CustomLLM", "Url": customURL, "APIKey": callbackToken, "Custom": string(custom)}, "TTSConfig": map[string]any{"Provider": "volcano_bidirection", "ProviderParams": ttsParams}}
	payload := map[string]any{"AppId": session.VoiceChatAppID, "RoomId": session.RoomID, "TaskId": providerTaskID(session), "Config": config, "AgentConfig": map[string]any{"TargetUserId": []string{session.UserID}, "UserId": session.AIUserID, "EnableConversationStateCallback": true, "ServerMessageURLForRTS": callback, "ServerMessageSignatureForRTS": callbackToken}}
	return base.call(ctx, "StartVoiceChat", payload, binding.AccessKeyID, binding.SecretAccessKey)
}
func (p *BoundVolcProvider) Interrupt(ctx context.Context, _ string, session Session, _ ProfileBinding) error {
	return p.call(ctx, "UpdateVoiceChat", map[string]any{"AppId": session.VoiceChatAppID, "RoomId": session.RoomID, "TaskId": providerTaskID(session), "Command": "interrupt"})
}
func (p *BoundVolcProvider) End(ctx context.Context, _ string, session Session, _ ProfileBinding) error {
	return p.call(ctx, "StopVoiceChat", map[string]any{"AppId": session.VoiceChatAppID, "RoomId": session.RoomID, "TaskId": providerTaskID(session)})
}
func (p *BoundVolcProvider) call(ctx context.Context, action string, payload map[string]any) error {
	if p == nil || p.base == nil {
		return ErrUnavailable
	}
	return p.base.call(ctx, action, payload, p.binding.AccessKeyID, p.binding.SecretAccessKey)
}

func (p *VolcProvider) createWithBinding(_ context.Context, _ string, session Session, binding ProfileBinding) (ProviderSession, error) {
	room := "dirextalk_voice_" + randomHex(12)
	user := "owner_" + randomHex(12)
	ai := fallbackString(binding.AIUserID, "dirextalk_ai_"+randomHex(8))
	token, err := signRTCToken(binding.AppID, binding.RTCAppKey, room, user, session.ExpiresAt)
	if err != nil {
		return ProviderSession{}, err
	}
	return ProviderSession{AppID: binding.AppID, VoiceChatAppID: fallbackString(binding.VoiceChatAppID, binding.AppID), AIUserID: ai, RoomID: room, UserID: user, Token: token, ProviderHandle: binding.AppID + ":" + room + ":" + session.ID, ExpiresAt: session.ExpiresAt}, nil
}

func (p *VolcProvider) call(ctx context.Context, action string, payload map[string]any, accessKey, secret string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	host := strings.TrimRight(strings.TrimSpace(p.Host), "/")
	if host == "" {
		host = "https://rtc.volcengineapi.com"
	}
	if !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	endpoint := host + "/?Action=" + url.QueryEscape(action) + "&Version=2024-12-01"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	signVolcRequest(req, body, accessKey, secret, fallbackString(p.Region, "cn-north-1"), "rtc")
	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, MaxEventBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("voice provider returned status %d", resp.StatusCode)
	}
	var result struct {
		ResponseMetadata struct {
			Error *struct {
				Code string `json:"Code"`
			} `json:"Error"`
		} `json:"ResponseMetadata"`
	}
	if json.Unmarshal(raw, &result) == nil && result.ResponseMetadata.Error != nil {
		return fmt.Errorf("voice provider request failed: %s", result.ResponseMetadata.Error.Code)
	}
	return nil
}

func signRTCToken(appID, appKey, roomID, userID string, expiry time.Time) (string, error) {
	if appID == "" || appKey == "" || roomID == "" || userID == "" || len(appID) != 24 || !expiry.After(time.Now().UTC()) || expiry.Unix() > int64(^uint32(0)) {
		return "", ErrInvalid
	}
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	issued, expires := uint32(time.Now().Unix()), uint32(expiry.Unix())
	buf := make([]byte, 0, 256)
	for _, n := range []uint32{binary.LittleEndian.Uint32(nonce[:]), issued, expires} {
		var x [4]byte
		binary.LittleEndian.PutUint32(x[:], n)
		buf = append(buf, x[:]...)
	}
	for _, value := range []string{roomID, userID} {
		if len(value) > 65535 {
			return "", ErrInvalid
		}
		var x [2]byte
		binary.LittleEndian.PutUint16(x[:], uint16(len(value)))
		buf = append(buf, x[:]...)
		buf = append(buf, value...)
	}
	var count [2]byte
	binary.LittleEndian.PutUint16(count[:], 2)
	buf = append(buf, count[:]...)
	for _, privilege := range []uint16{1, 4} {
		var x [6]byte
		binary.LittleEndian.PutUint16(x[:2], privilege)
		binary.LittleEndian.PutUint32(x[2:], expires)
		buf = append(buf, x[:]...)
	}
	h := hmac.New(sha256.New, []byte(appKey))
	_, _ = h.Write(buf)
	wrap := func(value []byte) []byte {
		var x [2]byte
		binary.LittleEndian.PutUint16(x[:], uint16(len(value)))
		return append(x[:], value...)
	}
	content := append(wrap(buf), wrap(h.Sum(nil))...)
	return "001" + appID + base64.StdEncoding.EncodeToString(content), nil
}

func signVolcRequest(req *http.Request, body []byte, accessKey, secret, region, service string) {
	date := time.Now().UTC().Format("20060102T150405Z")
	hash := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(hash[:])
	req.Header.Set("X-Date", date)
	req.Header.Set("X-Content-Sha256", bodyHash)
	req.Header.Set("Host", req.Host)
	canonical := req.Method + "\n/\n" + req.URL.RawQuery + "\ncontent-type:" + req.Header.Get("Content-Type") + "\nhost:" + req.Host + "\nx-content-sha256:" + bodyHash + "\nx-date:" + date + "\n\ncontent-type;host;x-content-sha256;x-date\n" + bodyHash
	sum := sha256.Sum256([]byte(canonical))
	scope := date[:8] + "/" + region + "/" + service + "/request"
	toSign := "HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	key := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte(secret), []byte(date[:8])), []byte(region)), []byte(service)), []byte("request"))
	sig := hex.EncodeToString(hmacSHA256(key, []byte(toSign)))
	req.Header.Set("Authorization", "HMAC-SHA256 Credential="+accessKey+"/"+scope+", SignedHeaders=content-type;host;x-content-sha256;x-date, Signature="+sig)
}

func callbackHMAC(secret, sessionID string, expiry time.Time) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(sessionID + "|" + strconv.FormatInt(expiry.Unix(), 10)))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func callbackURL(raw, sessionID string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("voice callback URL must use HTTPS")
	}
	q := u.Query()
	q.Set("session_id", sessionID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func httpsURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func randomHex(size int) string {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return ""
	}
	return hex.EncodeToString(value)
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

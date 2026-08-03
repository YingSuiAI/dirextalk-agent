package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"math"
	"net/url"
	"strings"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/searchprofile"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	transientmodelsdk "github.com/YingSuiAI/dirextalk-agent/sdk/transientmodel"
	"github.com/google/uuid"
)

const (
	maximumTransientCredentialBytes = 4096
	maximumTransientContextWindow   = 100_000_000
	maximumTransientOutputTokens    = 10_000_000
	transientDeepSeekSearchURL      = "https://api.deepseek.com/anthropic/v1/messages"
)

type preparedTransientModel struct {
	profile       modelapi.Profile
	binding       transientmodelsdk.Profile
	targetID      string
	searchProfile *searchprofile.Profile
}

func prepareTransientModelMetadata(request ChatRequest) (*preparedTransientModel, error) {
	invocation := request.TransientModel
	if invocation == nil {
		if strings.TrimSpace(request.BootstrapClientID) != "" {
			return nil, ErrTransientModel
		}
		return nil, nil
	}
	profile := invocation.Profile
	profile.ProfileID = strings.TrimSpace(profile.ProfileID)
	profile.Provider = modelapi.Provider(strings.ToLower(strings.TrimSpace(string(profile.Provider))))
	profile.Model = strings.TrimSpace(profile.Model)
	profile.BaseURL = strings.TrimRight(strings.TrimSpace(profile.BaseURL), "/")
	profile.ReasoningEffort = strings.TrimSpace(profile.ReasoningEffort)
	if profile.SecretRef != "" || profile.AllowInsecureHTTP || !validTransientProfile(profile) ||
		strings.TrimSpace(request.BootstrapClientID) == "" ||
		invocation.CredentialSessionRevision != uint64(transientmodelsdk.ExpectedUploadedRevision) {
		return nil, ErrTransientModel
	}
	sessionID := strings.TrimSpace(invocation.CredentialSessionID)
	parsedSessionID, err := uuid.Parse(sessionID)
	if err != nil || parsedSessionID == uuid.Nil || parsedSessionID.String() != sessionID {
		return nil, ErrTransientModel
	}
	binding := transientmodelsdk.Profile{
		ProfileID: profile.ProfileID, Provider: string(profile.Provider), Model: profile.Model,
		BaseURL: profile.BaseURL, Temperature: cloneTransientFloat(profile.Temperature), TopP: cloneTransientFloat(profile.TopP),
		MaxOutputTokens: int32(profile.MaxOutputTokens), ContextWindow: int32(profile.ContextWindow),
		ReasoningEffort: profile.ReasoningEffort,
	}
	targetID, err := transientmodelsdk.TargetID(request.OwnerID, request.RequestID, binding, invocation.CredentialSHA256[:])
	if err != nil {
		return nil, ErrTransientModel
	}
	profile.SecretRef = "transient:" + sessionID
	prepared := &preparedTransientModel{profile: profile, binding: binding, targetID: targetID}
	if deepSeekSearchCompatible(profile) {
		prepared.searchProfile = &searchprofile.Profile{
			ProfileID: "transient-deepseek-native", Provider: searchprofile.ProviderDeepSeekNative,
			BaseURL: transientDeepSeekSearchURL, SecretRef: profile.SecretRef,
			MaxResults: 8, TimeoutSeconds: 45,
		}
	}
	return prepared, nil
}

func validTransientProfile(profile modelapi.Profile) bool {
	if profile.ProfileID == "" || len(profile.ProfileID) > 128 || strings.ContainsAny(profile.ProfileID, "\x00\r\n\t") ||
		profile.Model == "" || len(profile.Model) > 512 || strings.ContainsAny(profile.Model, "\x00\r\n\t") ||
		profile.ContextWindow < 1 || profile.ContextWindow > maximumTransientContextWindow ||
		profile.MaxOutputTokens < 1 || profile.MaxOutputTokens > profile.ContextWindow || profile.MaxOutputTokens > maximumTransientOutputTokens ||
		len(profile.ReasoningEffort) > 128 || strings.ContainsAny(profile.ReasoningEffort, "\x00\r\n\t") ||
		!validTransientFloat(profile.Temperature, 0, 2) || !validTransientFloat(profile.TopP, 0, 1) {
		return false
	}
	switch profile.Provider {
	case modelapi.ProviderOpenAICompatible, modelapi.ProviderDeepSeek, modelapi.ProviderAnthropic:
	default:
		return false
	}
	parsed, err := url.Parse(profile.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	for _, value := range []string{profile.ProfileID, string(profile.Provider), profile.Model, profile.BaseURL, profile.ReasoningEffort} {
		if security.ContainsLikelySecret(value) {
			return false
		}
	}
	return true
}

func (r *Runtime) consumeTransientCredential(ctx context.Context, request ChatRequest, prepared preparedTransientModel) ([]byte, error) {
	if r == nil || r.transientCredentials == nil {
		return nil, ErrTransientCredential
	}
	invocation := request.TransientModel
	if invocation == nil {
		return nil, ErrTransientCredential
	}
	session, err := r.transientCredentials.Get(ctx, request.BootstrapClientID, invocation.CredentialSessionID)
	if err != nil || session.OwnerID != request.OwnerID || session.Purpose != transientmodelsdk.CredentialPurpose ||
		session.TargetID != prepared.targetID || session.Status != secretbootstrap.StatusUploaded ||
		session.Revision != invocation.CredentialSessionRevision || r.now == nil || !r.now().UTC().Before(session.ExpiresAt) {
		return nil, ErrTransientCredential
	}
	var credential []byte
	consumed, err := r.transientCredentials.Consume(
		ctx, request.BootstrapClientID, invocation.CredentialSessionID, invocation.CredentialSessionRevision,
		func(plaintext []byte) error {
			if len(plaintext) == 0 || len(plaintext) > maximumTransientCredentialBytes || len(bytes.TrimSpace(plaintext)) == 0 {
				return ErrTransientCredential
			}
			digest := sha256.Sum256(plaintext)
			if subtle.ConstantTimeCompare(digest[:], invocation.CredentialSHA256[:]) != 1 {
				return ErrTransientCredential
			}
			if !validTransientProviderCredential(prepared.profile.Provider, plaintext) {
				return ErrTransientCredential
			}
			credential = append([]byte(nil), plaintext...)
			return nil
		},
	)
	if err != nil || consumed.SessionID != session.SessionID || consumed.Status != secretbootstrap.StatusConsumed || len(credential) == 0 {
		clear(credential)
		return nil, ErrTransientCredential
	}
	return credential, nil
}

type transientSecretResolver struct {
	ref        string
	credential []byte
}

func (resolver *transientSecretResolver) ResolveSecret(ctx context.Context, ref string) ([]byte, error) {
	if resolver == nil || ctx == nil || ctx.Err() != nil || strings.TrimSpace(ref) == "" || ref != resolver.ref || len(resolver.credential) == 0 {
		return nil, ErrTransientCredential
	}
	return append([]byte(nil), resolver.credential...), nil
}

func deepSeekSearchCompatible(profile modelapi.Profile) bool {
	if profile.Provider != modelapi.ProviderDeepSeek {
		return false
	}
	parsed, err := url.Parse(profile.BaseURL)
	if err != nil || !strings.EqualFold(parsed.Hostname(), "api.deepseek.com") {
		return false
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	return path == "" || path == "/v1"
}

func validTransientProviderCredential(provider modelapi.Provider, credential []byte) bool {
	if provider != modelapi.ProviderDeepSeek {
		return true
	}
	if len(credential) == 0 || !bytes.Equal(credential, bytes.TrimSpace(credential)) {
		return false
	}
	for _, character := range credential {
		if character >= '0' && character <= '9' ||
			character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' {
			continue
		}
		switch character {
		case '-', '.', '_', '~', '+', '/', '=':
			continue
		default:
			return false
		}
	}
	return true
}

func validTransientFloat(value *float64, minimum, maximum float64) bool {
	return value == nil || (!math.IsNaN(*value) && !math.IsInf(*value, 0) && *value >= minimum && *value <= maximum)
}

func cloneTransientFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

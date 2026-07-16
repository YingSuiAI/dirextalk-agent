package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const maximumProfileCatalogSize = 1 << 20

var (
	ErrInvalidProfileCatalog = errors.New("invalid model profile catalog")
	ErrUnknownProfile        = errors.New("unknown model profile")
	profileIDPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	mountedSecretRefPattern  = regexp.MustCompile(`^mounted:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// ProfileCatalog is immutable trusted configuration. It binds a public
// profile_id to exactly one provider endpoint and credential audience.
type ProfileCatalog struct {
	profiles map[string]Profile
}

type profileCatalogFile struct {
	SchemaVersion int                  `json:"schema_version"`
	Profiles      []profileCatalogItem `json:"profiles"`
}

type profileCatalogItem struct {
	ProfileID       string   `json:"profile_id"`
	Provider        Provider `json:"provider"`
	Model           string   `json:"model"`
	BaseURL         string   `json:"base_url"`
	SecretRef       string   `json:"secret_ref"`
	ContextWindow   int      `json:"context_window"`
	MaxOutputTokens int      `json:"max_output_tokens"`
	ReasoningEffort string   `json:"reasoning_effort,omitempty"`
}

// LoadProfileCatalog loads strict, non-secret profile metadata. Credential
// bytes remain in mounted secret files and are never accepted by this file.
func LoadProfileCatalog(path string) (*ProfileCatalog, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%w: path is required", ErrInvalidProfileCatalog)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open catalog", ErrInvalidProfileCatalog)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumProfileCatalogSize+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumProfileCatalogSize {
		return nil, fmt.Errorf("%w: unreadable or oversized catalog", ErrInvalidProfileCatalog)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document profileCatalogFile
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: decode catalog", ErrInvalidProfileCatalog)
	}
	if err := requireCatalogEOF(decoder); err != nil {
		return nil, err
	}
	if document.SchemaVersion != 1 {
		return nil, fmt.Errorf("%w: unsupported schema_version", ErrInvalidProfileCatalog)
	}
	profiles := make([]Profile, 0, len(document.Profiles))
	for _, item := range document.Profiles {
		profiles = append(profiles, Profile{
			ProfileID: item.ProfileID, Provider: item.Provider, Model: item.Model,
			BaseURL: item.BaseURL, SecretRef: item.SecretRef,
			ContextWindow: item.ContextWindow, MaxOutputTokens: item.MaxOutputTokens,
			ReasoningEffort: item.ReasoningEffort,
		})
	}
	return NewProfileCatalog(profiles)
}

func requireCatalogEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON value", ErrInvalidProfileCatalog)
	}
	return nil
}

// NewProfileCatalog is also the explicit test-construction seam. Production
// must use LoadProfileCatalog, which never permits insecure HTTP endpoints.
func NewProfileCatalog(profiles []Profile) (*ProfileCatalog, error) {
	if len(profiles) == 0 || len(profiles) > 128 {
		return nil, fmt.Errorf("%w: profiles are required", ErrInvalidProfileCatalog)
	}
	result := &ProfileCatalog{profiles: make(map[string]Profile, len(profiles))}
	for _, profile := range profiles {
		profile = normalizeCatalogProfile(profile)
		if err := validateCatalogProfile(profile); err != nil {
			return nil, err
		}
		if _, exists := result.profiles[profile.ProfileID]; exists {
			return nil, fmt.Errorf("%w: duplicate profile_id", ErrInvalidProfileCatalog)
		}
		result.profiles[profile.ProfileID] = profile
	}
	return result, nil
}

func (catalog *ProfileCatalog) IDs() []string {
	if catalog == nil {
		return nil
	}
	result := make([]string, 0, len(catalog.profiles))
	for id := range catalog.profiles {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func normalizeCatalogProfile(profile Profile) Profile {
	profile.ProfileID = strings.ToLower(strings.TrimSpace(profile.ProfileID))
	profile.Provider = Provider(strings.ToLower(strings.TrimSpace(string(profile.Provider))))
	profile.Model = strings.TrimSpace(profile.Model)
	profile.BaseURL = strings.TrimRight(strings.TrimSpace(profile.BaseURL), "/")
	profile.SecretRef = strings.TrimSpace(profile.SecretRef)
	profile.ReasoningEffort = strings.TrimSpace(profile.ReasoningEffort)
	return profile
}

func validateCatalogProfile(profile Profile) error {
	if !profileIDPattern.MatchString(profile.ProfileID) || profile.Model == "" || len(profile.Model) > 512 ||
		!mountedSecretRefPattern.MatchString(profile.SecretRef) || profile.ContextWindow < 1 || profile.ContextWindow > 100_000_000 ||
		profile.MaxOutputTokens < 1 || profile.MaxOutputTokens > profile.ContextWindow || profile.MaxOutputTokens > 10_000_000 ||
		len(profile.ReasoningEffort) > 128 || profile.Temperature != nil || profile.TopP != nil {
		return fmt.Errorf("%w: invalid profile fields", ErrInvalidProfileCatalog)
	}
	if profile.Provider != ProviderOpenAICompatible && profile.Provider != ProviderDeepSeek && profile.Provider != ProviderAnthropic {
		return fmt.Errorf("%w: unsupported provider", ErrInvalidProfileCatalog)
	}
	parsed, err := url.Parse(profile.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && profile.AllowInsecureHTTP)) {
		return fmt.Errorf("%w: invalid base_url", ErrInvalidProfileCatalog)
	}
	for _, value := range []string{profile.ProfileID, string(profile.Provider), profile.Model, profile.BaseURL, profile.SecretRef, profile.ReasoningEffort} {
		if security.ContainsLikelySecret(value) {
			return fmt.Errorf("%w: secret material is forbidden", ErrInvalidProfileCatalog)
		}
	}
	return nil
}

// ResolveSelection converts a caller selection into the canonical profile.
// Immutable fields may be omitted or repeated exactly for compatibility, but
// any mismatch is rejected rather than ignored.
func (catalog *ProfileCatalog) ResolveSelection(selection Profile) (Profile, error) {
	if catalog == nil {
		return Profile{}, ErrUnknownProfile
	}
	selection.ProfileID = strings.ToLower(strings.TrimSpace(selection.ProfileID))
	canonical, ok := catalog.profiles[selection.ProfileID]
	if !ok {
		return Profile{}, ErrUnknownProfile
	}
	if (selection.Provider != "" && Provider(strings.ToLower(strings.TrimSpace(string(selection.Provider)))) != canonical.Provider) ||
		(strings.TrimSpace(selection.Model) != "" && strings.TrimSpace(selection.Model) != canonical.Model) ||
		(strings.TrimSpace(selection.BaseURL) != "" && strings.TrimRight(strings.TrimSpace(selection.BaseURL), "/") != canonical.BaseURL) ||
		(strings.TrimSpace(selection.SecretRef) != "" && strings.TrimSpace(selection.SecretRef) != canonical.SecretRef) ||
		(selection.ContextWindow != 0 && selection.ContextWindow != canonical.ContextWindow) ||
		(strings.TrimSpace(selection.ReasoningEffort) != "" && strings.TrimSpace(selection.ReasoningEffort) != canonical.ReasoningEffort) ||
		selection.AllowInsecureHTTP != canonical.AllowInsecureHTTP {
		return Profile{}, fmt.Errorf("%w: immutable profile fields do not match profile_id", ErrInvalidProfile)
	}
	if selection.Temperature != nil && (math.IsNaN(*selection.Temperature) || math.IsInf(*selection.Temperature, 0) || *selection.Temperature < 0 || *selection.Temperature > 2) {
		return Profile{}, fmt.Errorf("%w: invalid temperature", ErrInvalidProfile)
	}
	if selection.TopP != nil && (math.IsNaN(*selection.TopP) || math.IsInf(*selection.TopP, 0) || *selection.TopP < 0 || *selection.TopP > 1) {
		return Profile{}, fmt.Errorf("%w: invalid top_p", ErrInvalidProfile)
	}
	if selection.MaxOutputTokens < 0 || selection.MaxOutputTokens > canonical.MaxOutputTokens {
		return Profile{}, fmt.Errorf("%w: max_output_tokens exceeds profile limit", ErrInvalidProfile)
	}
	canonical.Temperature = cloneFloat(selection.Temperature)
	canonical.TopP = cloneFloat(selection.TopP)
	if selection.MaxOutputTokens > 0 {
		canonical.MaxOutputTokens = selection.MaxOutputTokens
	}
	return canonical, nil
}

// ResolvePersisted requires every immutable field to match. This protects
// Chat from database corruption or writes that bypassed the public RPC.
func (catalog *ProfileCatalog) ResolvePersisted(profile Profile) (Profile, error) {
	resolved, err := catalog.ResolveSelection(profile)
	if err != nil {
		return Profile{}, err
	}
	if profile.Provider != resolved.Provider || strings.TrimSpace(profile.Model) != resolved.Model ||
		strings.TrimRight(strings.TrimSpace(profile.BaseURL), "/") != resolved.BaseURL || strings.TrimSpace(profile.SecretRef) != resolved.SecretRef ||
		profile.ContextWindow != resolved.ContextWindow || strings.TrimSpace(profile.ReasoningEffort) != resolved.ReasoningEffort ||
		profile.MaxOutputTokens != resolved.MaxOutputTokens {
		return Profile{}, fmt.Errorf("%w: stored profile differs from catalog", ErrInvalidProfile)
	}
	return resolved, nil
}

func cloneFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

// Package searchprofile owns immutable, server-controlled web-search
// configuration. Public callers select a profile ID and bounded limits;
// credential bytes remain in mounted secret files.
package searchprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const maximumCatalogSize = 1 << 20

type Provider string

const (
	ProviderTavily Provider = "tavily"
	ProviderBrave  Provider = "brave"
	ProviderExa    Provider = "exa"
	ProviderSerper Provider = "serper"
	// ProviderDeepSeekNative uses DeepSeek's Anthropic-compatible,
	// server-executed Web Search tool with the existing mounted model token.
	ProviderDeepSeekNative Provider = "deepseek_native"
)

var (
	ErrInvalidCatalog = errors.New("invalid search profile catalog")
	ErrInvalidProfile = errors.New("invalid search profile")
	ErrUnknownProfile = errors.New("unknown search profile")
	profileIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	secretRefPattern  = regexp.MustCompile(`^mounted:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type Profile struct {
	ProfileID      string
	Provider       Provider
	BaseURL        string
	SecretRef      string
	MaxResults     int
	TimeoutSeconds int
}

type Catalog struct {
	profiles               map[string]Profile
	autoProfileByModel     map[string]string
	allowedModelsByProfile map[string]map[string]struct{}
}

type catalogFile struct {
	SchemaVersion int           `json:"schema_version"`
	Profiles      []catalogItem `json:"profiles"`
}

type catalogItem struct {
	ProfileID           string   `json:"profile_id"`
	Provider            Provider `json:"provider"`
	BaseURL             string   `json:"base_url"`
	SecretRef           string   `json:"secret_ref"`
	MaxResults          int      `json:"max_results"`
	TimeoutSeconds      int      `json:"timeout_seconds"`
	AutoModelProfileIDs []string `json:"auto_model_profile_ids,omitempty"`
}

func LoadCatalog(path string) (*Catalog, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%w: path is required", ErrInvalidCatalog)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open catalog", ErrInvalidCatalog)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumCatalogSize+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumCatalogSize {
		return nil, fmt.Errorf("%w: unreadable or oversized catalog", ErrInvalidCatalog)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document catalogFile
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: decode catalog", ErrInvalidCatalog)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing JSON value", ErrInvalidCatalog)
	}
	if document.SchemaVersion != 1 {
		return nil, fmt.Errorf("%w: unsupported schema_version", ErrInvalidCatalog)
	}
	profiles := make([]Profile, 0, len(document.Profiles))
	autoBindings := make(map[string][]string, len(document.Profiles))
	for _, item := range document.Profiles {
		profiles = append(profiles, Profile{
			ProfileID: item.ProfileID, Provider: item.Provider,
			BaseURL: item.BaseURL, SecretRef: item.SecretRef,
			MaxResults: item.MaxResults, TimeoutSeconds: item.TimeoutSeconds,
		})
		if len(item.AutoModelProfileIDs) > 0 {
			autoBindings[item.ProfileID] = append([]string(nil), item.AutoModelProfileIDs...)
		}
	}
	return newCatalog(profiles, autoBindings)
}

func NewCatalog(profiles []Profile) (*Catalog, error) {
	return newCatalog(profiles, nil)
}

// NewCatalogWithAutoBindings is the explicit construction seam for trusted
// configuration that bundles one search profile with one or more model
// profiles. Production normally obtains the same mapping from LoadCatalog.
func NewCatalogWithAutoBindings(profiles []Profile, autoBindings map[string][]string) (*Catalog, error) {
	return newCatalog(profiles, autoBindings)
}

func newCatalog(profiles []Profile, autoBindings map[string][]string) (*Catalog, error) {
	if len(profiles) == 0 || len(profiles) > 128 {
		return nil, fmt.Errorf("%w: profiles are required", ErrInvalidCatalog)
	}
	result := &Catalog{
		profiles:               make(map[string]Profile, len(profiles)),
		autoProfileByModel:     make(map[string]string),
		allowedModelsByProfile: make(map[string]map[string]struct{}),
	}
	for _, profile := range profiles {
		profile = normalize(profile)
		if err := validate(profile); err != nil {
			return nil, err
		}
		if _, exists := result.profiles[profile.ProfileID]; exists {
			return nil, fmt.Errorf("%w: duplicate profile_id", ErrInvalidCatalog)
		}
		result.profiles[profile.ProfileID] = profile
	}
	boundProfiles := make(map[string]struct{}, len(autoBindings))
	for rawProfileID, rawModelIDs := range autoBindings {
		profileID := strings.ToLower(strings.TrimSpace(rawProfileID))
		if _, ok := result.profiles[profileID]; !ok || len(rawModelIDs) == 0 || len(rawModelIDs) > 128 {
			return nil, fmt.Errorf("%w: invalid auto model binding", ErrInvalidCatalog)
		}
		if _, duplicate := boundProfiles[profileID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate automatic search binding", ErrInvalidCatalog)
		}
		boundProfiles[profileID] = struct{}{}
		allowed := make(map[string]struct{}, len(rawModelIDs))
		for _, rawModelID := range rawModelIDs {
			modelID := strings.ToLower(strings.TrimSpace(rawModelID))
			if !profileIDPattern.MatchString(modelID) || security.ContainsLikelySecret(modelID) {
				return nil, fmt.Errorf("%w: invalid auto model profile_id", ErrInvalidCatalog)
			}
			if _, duplicate := allowed[modelID]; duplicate {
				return nil, fmt.Errorf("%w: duplicate auto model profile_id", ErrInvalidCatalog)
			}
			if _, duplicate := result.autoProfileByModel[modelID]; duplicate {
				return nil, fmt.Errorf("%w: model profile has multiple automatic search profiles", ErrInvalidCatalog)
			}
			allowed[modelID] = struct{}{}
			result.autoProfileByModel[modelID] = profileID
		}
		result.allowedModelsByProfile[profileID] = allowed
	}
	return result, nil
}

func (catalog *Catalog) IDs() []string {
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

// DefaultForModelProfile returns only an explicitly catalog-bound automatic
// search profile. No provider or profile-name guessing is used.
func (catalog *Catalog) DefaultForModelProfile(modelProfileID string) (Profile, bool) {
	if catalog == nil {
		return Profile{}, false
	}
	modelProfileID = strings.ToLower(strings.TrimSpace(modelProfileID))
	profileID, ok := catalog.autoProfileByModel[modelProfileID]
	if !ok {
		return Profile{}, false
	}
	profile, ok := catalog.profiles[profileID]
	return profile, ok
}

// AllowsModelProfile limits catalog-bound search profiles to their declared
// model profiles. Profiles without a binding remain valid advanced providers.
func (catalog *Catalog) AllowsModelProfile(searchProfileID, modelProfileID string) bool {
	if catalog == nil {
		return false
	}
	searchProfileID = strings.ToLower(strings.TrimSpace(searchProfileID))
	modelProfileID = strings.ToLower(strings.TrimSpace(modelProfileID))
	if _, exists := catalog.profiles[searchProfileID]; !exists {
		return false
	}
	allowed, restricted := catalog.allowedModelsByProfile[searchProfileID]
	if !restricted {
		return true
	}
	_, ok := allowed[modelProfileID]
	return ok
}

func (catalog *Catalog) ResolveSelection(selection Profile) (Profile, error) {
	if catalog == nil {
		return Profile{}, ErrUnknownProfile
	}
	selection = normalize(selection)
	canonical, ok := catalog.profiles[selection.ProfileID]
	if !ok {
		return Profile{}, ErrUnknownProfile
	}
	if (selection.Provider != "" && selection.Provider != canonical.Provider) ||
		(selection.BaseURL != "" && selection.BaseURL != canonical.BaseURL) ||
		(selection.SecretRef != "" && selection.SecretRef != canonical.SecretRef) ||
		selection.MaxResults < 0 || selection.MaxResults > canonical.MaxResults ||
		selection.TimeoutSeconds < 0 || selection.TimeoutSeconds > canonical.TimeoutSeconds {
		return Profile{}, fmt.Errorf("%w: selection exceeds profile", ErrInvalidProfile)
	}
	if selection.MaxResults > 0 {
		canonical.MaxResults = selection.MaxResults
	}
	if selection.TimeoutSeconds > 0 {
		canonical.TimeoutSeconds = selection.TimeoutSeconds
	}
	return canonical, nil
}

func (catalog *Catalog) ResolvePersisted(profile Profile) (Profile, error) {
	resolved, err := catalog.ResolveSelection(profile)
	if err != nil {
		return Profile{}, err
	}
	normalized := normalize(profile)
	if normalized.Provider != resolved.Provider || normalized.BaseURL != resolved.BaseURL ||
		normalized.SecretRef != resolved.SecretRef || normalized.MaxResults != resolved.MaxResults ||
		normalized.TimeoutSeconds != resolved.TimeoutSeconds {
		return Profile{}, fmt.Errorf("%w: stored profile differs from catalog", ErrInvalidProfile)
	}
	return resolved, nil
}

func normalize(profile Profile) Profile {
	profile.ProfileID = strings.ToLower(strings.TrimSpace(profile.ProfileID))
	profile.Provider = Provider(strings.ToLower(strings.TrimSpace(string(profile.Provider))))
	profile.BaseURL = strings.TrimRight(strings.TrimSpace(profile.BaseURL), "/")
	profile.SecretRef = strings.TrimSpace(profile.SecretRef)
	return profile
}

func validate(profile Profile) error {
	if !profileIDPattern.MatchString(profile.ProfileID) ||
		!secretRefPattern.MatchString(profile.SecretRef) ||
		profile.MaxResults < 1 || profile.MaxResults > 50 ||
		profile.TimeoutSeconds < 1 || profile.TimeoutSeconds > 60 {
		return fmt.Errorf("%w: invalid profile fields", ErrInvalidCatalog)
	}
	switch profile.Provider {
	case ProviderTavily, ProviderBrave, ProviderExa, ProviderSerper,
		ProviderDeepSeekNative:
	default:
		return fmt.Errorf("%w: unsupported provider", ErrInvalidCatalog)
	}
	parsed, err := url.Parse(profile.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.String() != officialEndpoint(profile.Provider) {
		return fmt.Errorf("%w: invalid base_url", ErrInvalidCatalog)
	}
	for _, value := range []string{
		profile.ProfileID, string(profile.Provider), profile.BaseURL,
		profile.SecretRef,
	} {
		if security.ContainsLikelySecret(value) {
			return fmt.Errorf("%w: secret material is forbidden", ErrInvalidCatalog)
		}
	}
	return nil
}

func officialEndpoint(provider Provider) string {
	switch provider {
	case ProviderTavily:
		return "https://api.tavily.com/search"
	case ProviderBrave:
		return "https://api.search.brave.com/res/v1/web/search"
	case ProviderExa:
		return "https://api.exa.ai/search"
	case ProviderSerper:
		return "https://google.serper.dev/search"
	case ProviderDeepSeekNative:
		return "https://api.deepseek.com/anthropic/v1/messages"
	default:
		return ""
	}
}

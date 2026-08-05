package coremodel

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidIdempotencyKey = errors.New("invalid idempotency key")
	ErrIdempotencyConflict   = errors.New("idempotency key was already used with a different request")
	ErrRevisionConflict      = errors.New("profile revision conflict")
	ErrProfileNotFound       = errors.New("model profile not found")
	ErrProfileInUse          = errors.New("model profile is still referenced")
	ErrInvalidCursor         = errors.New("invalid profile cursor")
	ErrInvalidPageSize       = errors.New("invalid profile page size")
	ErrConnectionTestFailed  = errors.New("model connection test failed")
	ErrProfileRepository     = errors.New("model profile repository unavailable")
	ErrSyncConflict          = errors.New("model profile sync conflict")
)

type CreateProfileCommand struct {
	IdempotencyKey string
	Spec           ProfileSpec
}
type UpdateProfileCommand struct {
	ID               string
	IdempotencyKey   string
	ExpectedRevision int64
	Spec             ProfileSpec
}
type DeleteProfileCommand struct {
	ID               string
	IdempotencyKey   string
	ExpectedRevision int64
}
type ListProfileCommand struct {
	Cursor string
	Limit  int
}

type ProfilePage struct {
	Profiles   []PublicProfile `json:"profiles"`
	NextCursor string          `json:"next_page_token"`
	Defaults   ProfileDefaults `json:"-"`
}

// ProfileDefaults are stable role bindings used by conversation, embedding,
// and speech runtimes. The default_client_profile_id field aliases the
// conversation role at the capability boundary.
type ProfileDefaults struct {
	ConversationClientProfileID string `json:"default_conversation_client_profile_id"`
	EmbeddingClientProfileID    string `json:"default_embedding_client_profile_id"`
	SpeechClientProfileID       string `json:"default_speech_client_profile_id"`
}

// ProfileDefaultsReader is optional so repositories can expose role bindings
// on profile-list responses when that boundary is available.
type ProfileDefaultsReader interface {
	GetProfileDefaults(context.Context) (ProfileDefaults, error)
}
type MutationSnapshot struct {
	Profile PublicProfile
	Deleted bool
	Replay  bool
}

type ProfileRepository interface {
	ReplayProfile(context.Context, string, string, string) (MutationSnapshot, bool, error)
	CreateProfile(context.Context, Profile, string, string) (MutationSnapshot, error)
	GetProfile(context.Context, string) (Profile, error)
	ListProfiles(context.Context, string, int) ([]Profile, string, error)
	UpdateProfile(context.Context, Profile, string, string, int64) (MutationSnapshot, error)
	DeleteProfile(context.Context, string, string, string, int64) (MutationSnapshot, error)
	ResolveProfile(context.Context, string) (Profile, error)
	RunConnectionTest(context.Context, string, string, string, func(Profile) ConnectionTestResult) (ConnectionTestResult, bool, error)
	SyncProfiles(context.Context, string, string, SyncProfileCommand) (SyncProfileResult, error)
}

type Service struct {
	repo   ProfileRepository
	tester ConnectionTester
	now    func() time.Time
}

func NewService(repo ProfileRepository, tester ConnectionTester) (*Service, error) {
	if repo == nil {
		return nil, errors.New("profile repository is required")
	}
	return &Service{repo: repo, tester: tester, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Service) Create(ctx context.Context, cmd CreateProfileCommand) (PublicProfile, error) {
	if err := validateIdempotencyKey(cmd.IdempotencyKey); err != nil {
		return PublicProfile{}, err
	}
	digest, err := profileSpecDigest("create", "", 0, cmd.Spec)
	if err != nil {
		return PublicProfile{}, err
	}
	if snap, ok, err := s.repo.ReplayProfile(ctx, "create", cmd.IdempotencyKey, digest); ok || err != nil {
		if err != nil {
			return PublicProfile{}, safeServiceError(err)
		}
		return snap.Profile, nil
	}
	if cmd.Spec.APIKeyClear {
		return PublicProfile{}, ErrInvalidProfile
	}
	if (cmd.Spec.APIKey == nil || *cmd.Spec.APIKey == "") && cmd.Spec.Provider != ProviderVolcVoice && cmd.Spec.ModelKind != ModelKindSpeech {
		return PublicProfile{}, ErrAPIKeyUnavailable
	}
	p := Profile{ID: cmd.Spec.ID, DisplayName: cmd.Spec.DisplayName, Provider: cmd.Spec.Provider, ModelKind: cmd.Spec.ModelKind, InputModalities: append([]string(nil), cmd.Spec.InputModalities...), ProviderConfig: cloneMap(cmd.Spec.ProviderConfig), ProviderSecrets: cloneStringMap(cmd.Spec.ProviderSecrets), BaseURL: cmd.Spec.BaseURL, Model: cmd.Spec.Model, SystemPrompt: cmd.Spec.SystemPrompt, Temperature: cmd.Spec.Temperature, TopP: cmd.Spec.TopP, MaxOutputTokens: cmd.Spec.MaxOutputTokens, ContextWindow: cmd.Spec.ContextWindow, ReasoningEffort: cmd.Spec.ReasoningEffort}
	if cmd.Spec.APIKey != nil {
		p.APIKey = *cmd.Spec.APIKey
	}
	if p.ID == "" {
		p.ID = deterministicProfileID(cmd.IdempotencyKey, digest)
	}
	p, err = validateStoredProfile(p)
	if err != nil {
		return PublicProfile{}, err
	}
	now := s.now().UTC()
	p.Revision = 1
	p.CredentialVersion = 1
	p.CreatedAt = now
	p.UpdatedAt = now
	snapshot, err := s.repo.CreateProfile(ctx, p, cmd.IdempotencyKey, digest)
	if err != nil {
		return PublicProfile{}, safeServiceError(err)
	}
	return snapshot.Profile, nil
}
func (s *Service) CreateProfile(ctx context.Context, cmd CreateProfileCommand) (PublicProfile, error) {
	return s.Create(ctx, cmd)
}

func (s *Service) Get(ctx context.Context, id string) (PublicProfile, error) {
	if err := validateUUID(id); err != nil {
		return PublicProfile{}, err
	}
	p, err := s.repo.GetProfile(ctx, id)
	if err != nil {
		return PublicProfile{}, safeServiceError(err)
	}
	return p.Public(), nil
}
func (s *Service) GetProfile(ctx context.Context, id string) (PublicProfile, error) {
	return s.Get(ctx, id)
}

func (s *Service) List(ctx context.Context, cmd ListProfileCommand) (ProfilePage, error) {
	if cmd.Limit == 0 {
		cmd.Limit = 50
	}
	if cmd.Limit < 1 || cmd.Limit > 100 {
		return ProfilePage{}, ErrInvalidPageSize
	}
	if cmd.Cursor != "" {
		if _, err := decodeCursor(cmd.Cursor); err != nil {
			return ProfilePage{}, err
		}
	}
	profiles, next, err := s.repo.ListProfiles(ctx, cmd.Cursor, cmd.Limit)
	if err != nil {
		return ProfilePage{}, safeServiceError(err)
	}
	page := ProfilePage{NextCursor: next, Profiles: make([]PublicProfile, 0, len(profiles))}
	for _, p := range profiles {
		page.Profiles = append(page.Profiles, p.Public())
	}
	if reader, ok := s.repo.(ProfileDefaultsReader); ok {
		defaults, err := reader.GetProfileDefaults(ctx)
		if err != nil {
			return ProfilePage{}, safeServiceError(err)
		}
		page.Defaults = defaults
	}
	return page, nil
}
func (s *Service) ListProfiles(ctx context.Context, cmd ListProfileCommand) (ProfilePage, error) {
	return s.List(ctx, cmd)
}

func (s *Service) Update(ctx context.Context, cmd UpdateProfileCommand) (PublicProfile, error) {
	if err := validateIdempotencyKey(cmd.IdempotencyKey); err != nil {
		return PublicProfile{}, err
	}
	if err := validateUUID(cmd.ID); err != nil {
		return PublicProfile{}, err
	}
	if cmd.ExpectedRevision < 1 {
		return PublicProfile{}, ErrRevisionConflict
	}
	digest, err := profileSpecDigest("update", cmd.ID, cmd.ExpectedRevision, cmd.Spec)
	if err != nil {
		return PublicProfile{}, err
	}
	if snap, ok, err := s.repo.ReplayProfile(ctx, "update", cmd.IdempotencyKey, digest); ok || err != nil {
		if err != nil {
			return PublicProfile{}, safeServiceError(err)
		}
		return snap.Profile, nil
	}
	// Updates may omit write-only credentials. Resolve the durable profile so
	// the repository can preserve its encrypted provider/API secret material
	// without ever serializing a redacted status placeholder.
	current, err := s.repo.ResolveProfile(ctx, cmd.ID)
	if err != nil {
		return PublicProfile{}, safeServiceError(err)
	}
	if current.Revision != cmd.ExpectedRevision {
		return PublicProfile{}, ErrRevisionConflict
	}
	updated, err := UpdateProfile(current, cmd.Spec)
	if err != nil {
		return PublicProfile{}, err
	}
	updated.ID = cmd.ID
	updated.Revision = current.Revision + 1
	updated.CredentialVersion = current.CredentialVersion
	if updated.CredentialVersion <= 0 {
		updated.CredentialVersion = 1
	}
	if credentialMaterialChanged(current, updated) {
		updated.CredentialVersion++
	}
	updated.UpdatedAt = s.now().UTC()
	updated.CreatedAt = current.CreatedAt
	if updated.CreatedAt.IsZero() {
		updated.CreatedAt = updated.UpdatedAt
	}
	updated, err = validateStoredProfile(updated)
	if err != nil {
		return PublicProfile{}, err
	}
	snapshot, err := s.repo.UpdateProfile(ctx, updated, cmd.IdempotencyKey, digest, cmd.ExpectedRevision)
	if err != nil {
		return PublicProfile{}, safeServiceError(err)
	}
	return snapshot.Profile, nil
}
func (s *Service) UpdateProfile(ctx context.Context, cmd UpdateProfileCommand) (PublicProfile, error) {
	return s.Update(ctx, cmd)
}

func (s *Service) Delete(ctx context.Context, cmd DeleteProfileCommand) (PublicProfile, error) {
	if err := validateIdempotencyKey(cmd.IdempotencyKey); err != nil {
		return PublicProfile{}, err
	}
	if err := validateUUID(cmd.ID); err != nil {
		return PublicProfile{}, err
	}
	if cmd.ExpectedRevision < 1 {
		return PublicProfile{}, ErrRevisionConflict
	}
	digest, err := profileDigest("delete", struct {
		ID       string
		Revision int64
	}{cmd.ID, cmd.ExpectedRevision})
	if err != nil {
		return PublicProfile{}, err
	}
	if snap, ok, err := s.repo.ReplayProfile(ctx, "delete", cmd.IdempotencyKey, digest); ok || err != nil {
		if err != nil {
			return PublicProfile{}, safeServiceError(err)
		}
		return snap.Profile, nil
	}
	snapshot, err := s.repo.DeleteProfile(ctx, cmd.ID, cmd.IdempotencyKey, digest, cmd.ExpectedRevision)
	if err != nil {
		return PublicProfile{}, safeServiceError(err)
	}
	return snapshot.Profile, nil
}
func (s *Service) DeleteProfile(ctx context.Context, cmd DeleteProfileCommand) (PublicProfile, error) {
	return s.Delete(ctx, cmd)
}

func (s *Service) Sync(ctx context.Context, cmd SyncProfileCommand) (SyncProfileResult, error) {
	if err := validateIdempotencyKey(cmd.IdempotencyKey); err != nil {
		return SyncProfileResult{}, err
	}
	if len(cmd.Entries) > 100 {
		return SyncProfileResult{}, ErrInvalidProfile
	}
	seen := make(map[string]struct{}, len(cmd.Entries))
	for i := range cmd.Entries {
		e := &cmd.Entries[i]
		e.ClientProfileID = strings.TrimSpace(e.ClientProfileID)
		if err := ValidateClientProfileID(e.ClientProfileID); err != nil {
			return SyncProfileResult{}, err
		}
		if _, ok := seen[e.ClientProfileID]; ok {
			return SyncProfileResult{}, ErrSyncConflict
		}
		seen[e.ClientProfileID] = struct{}{}
		if e.ExpectedRevision != nil && *e.ExpectedRevision < 1 {
			return SyncProfileResult{}, ErrRevisionConflict
		}
		if e.APIKey != nil && *e.APIKey == "" {
			return SyncProfileResult{}, ErrAPIKeyUnavailable
		}
		candidate := Profile{ID: SyncProfileID(e.ClientProfileID), ClientProfileID: e.ClientProfileID,
			DisplayName: e.DisplayName, Provider: e.Provider, ModelKind: e.ModelKind, InputModalities: e.InputModalities, ProviderConfig: e.ProviderConfig, ProviderSecrets: e.ProviderSecrets, BaseURL: e.BaseURL, Model: e.Model,
			APIKey: valueOrEmpty(e.APIKey), SystemPrompt: e.SystemPrompt, Temperature: e.Temperature,
			TopP: e.TopP, MaxOutputTokens: e.MaxOutputTokens, ContextWindow: e.ContextWindow, ReasoningEffort: e.ReasoningEffort}
		if _, err := validateStoredProfile(candidate); err != nil && (e.APIKey != nil || e.Provider != ProviderVolcVoice) {
			return SyncProfileResult{}, err
		}
	}
	cmd.DefaultClientProfileID = strings.TrimSpace(cmd.DefaultClientProfileID)
	cmd.DefaultConversationProfileID = strings.TrimSpace(cmd.DefaultConversationProfileID)
	cmd.DefaultEmbeddingProfileID = strings.TrimSpace(cmd.DefaultEmbeddingProfileID)
	cmd.DefaultSpeechProfileID = strings.TrimSpace(cmd.DefaultSpeechProfileID)
	if cmd.DefaultConversationProfileID == "" {
		cmd.DefaultConversationProfileID = cmd.DefaultClientProfileID
	}
	if cmd.DefaultClientProfileID == "" {
		cmd.DefaultClientProfileID = cmd.DefaultConversationProfileID
	}
	for _, defaultID := range []string{cmd.DefaultConversationProfileID, cmd.DefaultEmbeddingProfileID, cmd.DefaultSpeechProfileID} {
		if defaultID == "" {
			continue
		}
		if _, ok := seen[defaultID]; !ok {
			// The repository also accepts an already persisted profile as the default.
			if err := ValidateClientProfileID(defaultID); err != nil {
				return SyncProfileResult{}, err
			}
		}
	}
	if err := s.validateSyncDefaultKind(ctx, cmd.DefaultClientProfileID, ModelKindConversation, cmd.Entries); err != nil {
		return SyncProfileResult{}, err
	}
	if err := s.validateSyncDefaultKind(ctx, cmd.DefaultConversationProfileID, ModelKindConversation, cmd.Entries); err != nil {
		return SyncProfileResult{}, err
	}
	if err := s.validateSyncDefaultKind(ctx, cmd.DefaultEmbeddingProfileID, ModelKindEmbedding, cmd.Entries); err != nil {
		return SyncProfileResult{}, err
	}
	if err := s.validateSyncDefaultKind(ctx, cmd.DefaultSpeechProfileID, ModelKindSpeech, cmd.Entries); err != nil {
		return SyncProfileResult{}, err
	}
	digest, err := syncProfileDigest(cmd)
	if err != nil {
		return SyncProfileResult{}, err
	}
	result, err := s.repo.SyncProfiles(ctx, cmd.IdempotencyKey, digest, cmd)
	if err != nil {
		return SyncProfileResult{}, safeServiceError(err)
	}
	return result, nil
}

func (s *Service) validateSyncDefaultKind(ctx context.Context, clientOrProfileID, expectedKind string, entries []SyncProfileEntry) error {
	clientOrProfileID = strings.TrimSpace(clientOrProfileID)
	if clientOrProfileID == "" {
		return nil
	}
	for _, entry := range entries {
		if entry.ClientProfileID != clientOrProfileID {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(entry.ModelKind))
		if kind == "" {
			kind = ModelKindConversation
		}
		if entry.Provider == ProviderVolcVoice {
			kind = ModelKindSpeech
		}
		if kind != expectedKind {
			return ErrInvalidProfile
		}
		return nil
	}
	for cursor := ""; ; {
		profiles, next, err := s.repo.ListProfiles(ctx, cursor, 100)
		if err != nil {
			return safeServiceError(err)
		}
		for _, profile := range profiles {
			if profile.ClientProfileID != clientOrProfileID && profile.ID != clientOrProfileID {
				continue
			}
			kind := strings.ToLower(strings.TrimSpace(profile.ModelKind))
			if kind == "" {
				kind = ModelKindConversation
			}
			if profile.Provider == ProviderVolcVoice {
				kind = ModelKindSpeech
			}
			if kind != expectedKind {
				return ErrInvalidProfile
			}
			if expectedKind == ModelKindEmbedding && !profile.APIKeyConfigured && strings.TrimSpace(profile.APIKey) == "" {
				return ErrAPIKeyUnavailable
			}
			return nil
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return ErrProfileNotFound
}

func valueOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func credentialMaterialChanged(before, after Profile) bool {
	return before.APIKey != after.APIKey || !equalStringMap(before.ProviderSecrets, after.ProviderSecrets)
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

// SyncProfileID returns the stable Core UUID assigned to a new client profile.
func SyncProfileID(clientProfileID string) string {
	return deterministicProfileID("sync:"+clientProfileID, "")
}

// ResolveClientProfile resolves the durable profile selected by the public
// client_profile_id. SyncProfileID is the only server-owned mapping from that
// write-facing identifier to a Core profile UUID, so the lookup still flows
// through ResolveProfile and its secret-bearing repository boundary.
func (s *Service) ResolveClientProfile(ctx context.Context, clientProfileID string) (Profile, error) {
	if s == nil || s.repo == nil {
		return Profile{}, ErrProfileRepository
	}
	clientProfileID = strings.TrimSpace(clientProfileID)
	if err := ValidateClientProfileID(clientProfileID); err != nil {
		return Profile{}, err
	}
	return s.ResolveProfile(ctx, SyncProfileID(clientProfileID))
}

func (s *Service) ResolveProfile(ctx context.Context, id string) (Profile, error) {
	if err := validateUUID(id); err != nil {
		return Profile{}, err
	}
	p, err := s.repo.ResolveProfile(ctx, id)
	if err != nil {
		return Profile{}, safeServiceError(err)
	}
	if p.APIKey == "" && p.Provider != ProviderVolcVoice {
		return Profile{}, ErrAPIKeyUnavailable
	}
	return p, nil
}

// ResolveDefaultProfileID resolves the durable role binding to the Core UUID
// used by conversation/model runners.  Defaults are stored by the stable
// client_profile_id so that a client can replace its model configuration
// without knowing server-generated UUIDs.  The profile list is paged rather
// than assuming the first page contains the selected profile.
func (s *Service) ResolveDefaultProfileID(ctx context.Context, modelKind string) (string, error) {
	if s == nil || s.repo == nil {
		return "", ErrProfileRepository
	}
	switch modelKind {
	case "", ModelKindConversation, ModelKindEmbedding, ModelKindSpeech:
	default:
		return "", ErrInvalidProfile
	}
	reader, ok := s.repo.(ProfileDefaultsReader)
	if !ok {
		return "", ErrProfileNotFound
	}
	defaults, err := reader.GetProfileDefaults(ctx)
	if err != nil {
		return "", safeServiceError(err)
	}
	clientID := defaults.ConversationClientProfileID
	switch modelKind {
	case ModelKindEmbedding:
		clientID = defaults.EmbeddingClientProfileID
	case ModelKindSpeech:
		clientID = defaults.SpeechClientProfileID
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", ErrProfileNotFound
	}

	for cursor := ""; ; {
		profiles, next, listErr := s.repo.ListProfiles(ctx, cursor, 100)
		if listErr != nil {
			return "", safeServiceError(listErr)
		}
		for _, profile := range profiles {
			kind := strings.TrimSpace(profile.ModelKind)
			if kind == "" {
				kind = ModelKindConversation
			}
			if kind != modelKind && !(modelKind == "" && kind == ModelKindConversation) {
				continue
			}
			// Defaults normally contain the stable client ID. Accepting the
			// persisted Core UUID as well keeps the resolver tolerant of a
			// freshly provisioned database whose seed used server IDs.
			if profile.ClientProfileID == clientID || profile.ID == clientID {
				return profile.ID, nil
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return "", ErrProfileNotFound
}

type ConnectionTestResult struct {
	OK        bool
	ErrorCode string
}

func (s *Service) TestConnection(ctx context.Context, id string) (ConnectionTestResult, error) {
	if validateUUID(id) != nil {
		return ConnectionTestResult{ErrorCode: "invalid_profile"}, ErrInvalidProfile
	}
	if s.tester == nil {
		return ConnectionTestResult{ErrorCode: "unavailable"}, ErrConnectionTestFailed
	}
	p, err := s.repo.GetProfile(ctx, id)
	if err != nil {
		return ConnectionTestResult{ErrorCode: "not_found"}, err
	}
	return s.runConnectionTester(ctx, p), nil
}

func (s *Service) TestConnectionWithIdempotency(ctx context.Context, id, idempotencyKey string) (ConnectionTestResult, error) {
	if validateUUID(id) != nil {
		return ConnectionTestResult{ErrorCode: "invalid_profile"}, ErrInvalidProfile
	}
	if validateIdempotencyKey(idempotencyKey) != nil {
		return ConnectionTestResult{ErrorCode: "invalid_profile"}, ErrInvalidIdempotencyKey
	}
	digest, err := profileDigest("test_connection", struct{ ProfileID string }{id})
	if err != nil {
		return ConnectionTestResult{ErrorCode: "invalid_profile"}, err
	}
	result, _, err := s.repo.RunConnectionTest(ctx, idempotencyKey, digest, id, func(p Profile) ConnectionTestResult {
		return s.runConnectionTester(ctx, p)
	})
	if err != nil {
		return ConnectionTestResult{ErrorCode: "unavailable"}, safeServiceError(err)
	}
	return result, nil
}

func (s *Service) runConnectionTester(ctx context.Context, p Profile) ConnectionTestResult {
	if s.tester == nil {
		return ConnectionTestResult{ErrorCode: "unavailable"}
	}
	if p.APIKey == "" {
		return ConnectionTestResult{ErrorCode: "invalid_profile"}
	}
	if err := s.tester.TestConnection(ctx, p); err != nil {
		return ConnectionTestResult{ErrorCode: categorizeConnectionError(ctx, err)}
	}
	return ConnectionTestResult{OK: true}
}

func categorizeConnectionError(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "timeout"
	}
	if errors.Is(err, ErrInvalidProfile) || errors.Is(err, ErrAPIKeyUnavailable) {
		return "invalid_profile"
	}
	return "provider_unavailable"
}
func safeServiceError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidProfile), errors.Is(err, ErrInvalidIdempotencyKey), errors.Is(err, ErrAPIKeyUnavailable), errors.Is(err, ErrIdempotencyConflict), errors.Is(err, ErrRevisionConflict), errors.Is(err, ErrProfileNotFound), errors.Is(err, ErrProfileInUse), errors.Is(err, ErrInvalidCursor), errors.Is(err, ErrInvalidPageSize), errors.Is(err, ErrSyncConflict):
		return err
	default:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return ErrProfileRepository
	}
}

func validateUUID(id string) error {
	if !uuidPattern.MatchString(strings.ToLower(id)) || strings.Trim(id, "0-") == "" || strings.ToLower(id) != id {
		return ErrInvalidProfile
	}
	return nil
}
func validateIdempotencyKey(key string) error { return validateUUID(key) }
func profileDigest(op string, value any) (string, error) {
	b, err := json.Marshal(struct {
		Op    string `json:"op"`
		Value any    `json:"value"`
	}{op, redactDigestValue(value)})
	if err != nil {
		return "", ErrInvalidProfile
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func profileSpecDigest(op, id string, revision int64, spec ProfileSpec) (string, error) {
	keyOp, keyHash := "preserve", ""
	if spec.APIKeyClear {
		keyOp = "clear"
	} else if spec.APIKey != nil {
		keyOp = "set"
		sum := sha256.Sum256([]byte(*spec.APIKey))
		keyHash = hex.EncodeToString(sum[:])
	}
	canonical := struct {
		Op                 string         `json:"op"`
		ID                 string         `json:"id"`
		Revision           int64          `json:"revision"`
		DisplayName        string         `json:"display_name"`
		Provider           ModelProvider  `json:"provider"`
		ModelKind          string         `json:"model_kind,omitempty"`
		InputModalities    []string       `json:"input_modalities,omitempty"`
		ProviderConfig     map[string]any `json:"provider_config,omitempty"`
		ProviderSecrets    []secretDigest `json:"provider_secrets,omitempty"`
		BaseURL            string         `json:"base_url"`
		Model              string         `json:"model"`
		SystemPrompt       string         `json:"system_prompt"`
		APIKeyOp           string         `json:"api_key_op"`
		APIKeyClear        bool           `json:"api_key_clear"`
		APIKeyPresent      bool           `json:"api_key_present"`
		APIKeySHA256       string         `json:"api_key_sha256,omitempty"`
		Temperature        *float64       `json:"temperature,omitempty"`
		TemperatureSet     bool           `json:"temperature_set"`
		TemperatureClear   bool           `json:"temperature_clear"`
		TopP               *float64       `json:"top_p,omitempty"`
		TopPSet            bool           `json:"top_p_set"`
		TopPClear          bool           `json:"top_p_clear"`
		MaxOutputTokens    int            `json:"max_output_tokens"`
		ContextWindow      int            `json:"context_window"`
		ContextWindowSet   bool           `json:"context_window_set"`
		ReasoningEffort    string         `json:"reasoning_effort"`
		ReasoningEffortSet bool           `json:"reasoning_effort_set"`
		Patch              bool           `json:"patch"`
		DisplayNameSet     bool           `json:"display_name_set"`
		ProviderSet        bool           `json:"provider_set"`
		BaseURLSet         bool           `json:"base_url_set"`
		ModelSet           bool           `json:"model_set"`
		SystemPromptSet    bool           `json:"system_prompt_set"`
		MaxOutputTokensSet bool           `json:"max_output_tokens_set"`
	}{op, id, revision, spec.DisplayName, spec.Provider, spec.ModelKind, append([]string(nil), spec.InputModalities...), redactProviderConfig(spec.ProviderConfig), providerSecretDigests(spec.ProviderSecrets), spec.BaseURL, spec.Model, spec.SystemPrompt, keyOp, spec.APIKeyClear, spec.APIKey != nil, keyHash, spec.Temperature, spec.TemperatureSet, spec.TemperatureClear, spec.TopP, spec.TopPSet, spec.TopPClear, spec.MaxOutputTokens, spec.ContextWindow, spec.ContextWindowSet, spec.ReasoningEffort, spec.ReasoningEffortSet, spec.Patch, spec.DisplayNameSet, spec.ProviderSet, spec.BaseURLSet, spec.ModelSet, spec.SystemPromptSet, spec.MaxOutputTokensSet}
	b, err := json.Marshal(canonical)
	if err != nil {
		return "", ErrInvalidProfile
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func syncProfileDigest(cmd SyncProfileCommand) (string, error) {
	canonical := struct {
		Default             string `json:"default_client_profile_id"`
		ConversationDefault string `json:"default_conversation_client_profile_id"`
		EmbeddingDefault    string `json:"default_embedding_client_profile_id"`
		SpeechDefault       string `json:"default_speech_client_profile_id"`
		Entries             []any  `json:"entries"`
	}{Default: cmd.DefaultClientProfileID, ConversationDefault: cmd.DefaultConversationProfileID, EmbeddingDefault: cmd.DefaultEmbeddingProfileID, SpeechDefault: cmd.DefaultSpeechProfileID}
	for _, e := range cmd.Entries {
		keyHash := ""
		if e.APIKey != nil {
			sum := sha256.Sum256([]byte(*e.APIKey))
			keyHash = hex.EncodeToString(sum[:])
		}
		canonical.Entries = append(canonical.Entries, struct {
			ClientID     string         `json:"client_profile_id"`
			Expected     *int64         `json:"expected_revision,omitempty"`
			DisplayName  string         `json:"display_name"`
			Provider     ModelProvider  `json:"provider"`
			ModelKind    string         `json:"model_kind,omitempty"`
			Modalities   []string       `json:"input_modalities,omitempty"`
			Config       map[string]any `json:"provider_config,omitempty"`
			Secrets      []secretDigest `json:"provider_secrets,omitempty"`
			BaseURL      string         `json:"base_url"`
			Model        string         `json:"model"`
			SystemPrompt string         `json:"system_prompt"`
			APIKeySHA256 string         `json:"api_key_sha256,omitempty"`
			Temperature  *float64       `json:"temperature,omitempty"`
			TopP         *float64       `json:"top_p,omitempty"`
			Max          int            `json:"max_output_tokens"`
			Context      int            `json:"context_window"`
			Reasoning    string         `json:"reasoning_effort"`
		}{e.ClientProfileID, e.ExpectedRevision, e.DisplayName, e.Provider, e.ModelKind, append([]string(nil), e.InputModalities...), redactProviderConfig(e.ProviderConfig), providerSecretDigests(e.ProviderSecrets), e.BaseURL, e.Model, e.SystemPrompt, keyHash, e.Temperature, e.TopP, e.MaxOutputTokens, e.ContextWindow, e.ReasoningEffort})
	}
	return profileDigest("sync", canonical)
}

func providerSecretKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type secretDigest struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

// providerSecretDigests keeps secret bytes out of idempotency records while
// still making a credential rotation part of the canonical request identity.
// Sorting by key makes the digest stable across map iteration order.
func providerSecretDigests(values map[string]string) []secretDigest {
	keys := providerSecretKeys(values)
	result := make([]secretDigest, 0, len(keys))
	for _, key := range keys {
		sum := sha256.Sum256([]byte(values[key]))
		result = append(result, secretDigest{Key: key, SHA256: hex.EncodeToString(sum[:])})
	}
	return result
}
func redactDigestValue(value any) any {
	b, _ := json.Marshal(value)
	var v any
	_ = json.Unmarshal(b, &v)
	scrubDigest(v)
	return v
}
func scrubDigest(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if strings.EqualFold(k, "APIKey") || strings.EqualFold(k, "api_key") {
				raw, _ := val.(string)
				sum := sha256.Sum256([]byte(raw))
				x[k] = "sha256:" + hex.EncodeToString(sum[:])
			} else {
				scrubDigest(val)
			}
		}
	case []any:
		for _, val := range x {
			scrubDigest(val)
		}
	}
}
func deterministicProfileID(idem, digest string) string {
	sum := sha256.Sum256([]byte(idem + ":" + digest))
	b := hex.EncodeToString(sum[:])
	return b[:8] + "-" + b[8:12] + "-4" + b[13:16] + "-8" + b[17:20] + "-" + b[20:32]
}
func encodeCursor(id string) string { return base64.RawURLEncoding.EncodeToString([]byte(id)) }
func decodeCursor(cursor string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", ErrInvalidCursor
	}
	id := string(b)
	if validateUUID(id) != nil {
		return "", ErrInvalidCursor
	}
	return id, nil
}

// MemoryProfileRepository is a deterministic reference repository useful for
// tests and local adapters. Production repositories implement ProfileRepository.
type MemoryProfileRepository struct {
	mu          sync.Mutex
	profiles    map[string]Profile
	deleted     map[string]PublicProfile
	idempotency map[string]struct {
		Digest string
		Result MutationSnapshot
	}
	syncIdempotency map[string]struct {
		Digest string
		Result SyncProfileResult
	}
	connectionTests map[string]struct {
		Digest string
		Result ConnectionTestResult
	}
	refs     map[string]int
	defaults ProfileDefaults
}

func NewMemoryProfileRepository() *MemoryProfileRepository {
	return &MemoryProfileRepository{profiles: map[string]Profile{}, deleted: map[string]PublicProfile{}, idempotency: map[string]struct {
		Digest string
		Result MutationSnapshot
	}{}, syncIdempotency: map[string]struct {
		Digest string
		Result SyncProfileResult
	}{}, connectionTests: map[string]struct {
		Digest string
		Result ConnectionTestResult
	}{}, refs: map[string]int{}}
}
func (r *MemoryProfileRepository) replay(operation, key, digest string) (MutationSnapshot, bool, error) {
	replayKey := operation + ":" + key
	if rec, ok := r.idempotency[replayKey]; ok {
		if rec.Digest != digest {
			return MutationSnapshot{}, true, ErrIdempotencyConflict
		}
		rec.Result.Replay = true
		rec.Result.Profile = clonePublicProfile(rec.Result.Profile)
		return rec.Result, true, nil
	}
	return MutationSnapshot{}, false, nil
}
func (r *MemoryProfileRepository) ReplayProfile(_ context.Context, operation, key, digest string) (MutationSnapshot, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.replay(operation, key, digest)
}
func (r *MemoryProfileRepository) CreateProfile(_ context.Context, p Profile, key, digest string) (MutationSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok, e := r.replay("create", key, digest); ok {
		return v, e
	}
	if _, ok := r.profiles[p.ID]; ok {
		return MutationSnapshot{}, ErrIdempotencyConflict
	}
	snap := MutationSnapshot{Profile: p.Public()}
	r.profiles[p.ID] = cloneProfile(p)
	stored := snap
	stored.Profile = clonePublicProfile(snap.Profile)
	r.idempotency["create:"+key] = struct {
		Digest string
		Result MutationSnapshot
	}{digest, stored}
	return snap, nil
}
func (r *MemoryProfileRepository) GetProfile(_ context.Context, id string) (Profile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.profiles[id]
	if !ok {
		return Profile{}, ErrProfileNotFound
	}
	return cloneProfile(p), nil
}
func (r *MemoryProfileRepository) ResolveProfile(ctx context.Context, id string) (Profile, error) {
	return r.GetProfile(ctx, id)
}
func (r *MemoryProfileRepository) GetProfileDefaults(_ context.Context) (ProfileDefaults, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.defaults, nil
}
func (r *MemoryProfileRepository) RunConnectionTest(_ context.Context, key, digest, id string, test func(Profile) ConnectionTestResult) (ConnectionTestResult, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok, err := r.replayConnectionTest(key, digest); ok {
		return v, true, err
	}
	p, ok := r.profiles[id]
	if !ok {
		return ConnectionTestResult{ErrorCode: "not_found"}, false, ErrProfileNotFound
	}
	result := test(cloneProfile(p))
	r.connectionTests[key] = struct {
		Digest string
		Result ConnectionTestResult
	}{digest, result}
	return result, false, nil
}

func (r *MemoryProfileRepository) replayConnectionTest(key, digest string) (ConnectionTestResult, bool, error) {
	if rec, ok := r.connectionTests[key]; ok {
		if rec.Digest != digest {
			return ConnectionTestResult{}, true, ErrIdempotencyConflict
		}
		return rec.Result, true, nil
	}
	return ConnectionTestResult{}, false, nil
}
func (r *MemoryProfileRepository) ListProfiles(_ context.Context, cursor string, limit int) ([]Profile, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	start := ""
	if cursor != "" {
		var err error
		start, err = decodeCursor(cursor)
		if err != nil {
			return nil, "", err
		}
	}
	ids := make([]string, 0, len(r.profiles))
	for id := range r.profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Profile, 0, limit)
	for _, id := range ids {
		if start != "" && id <= start {
			continue
		}
		out = append(out, cloneProfile(r.profiles[id]))
		if len(out) == limit {
			break
		}
	}
	next := ""
	if len(out) == limit {
		next = encodeCursor(out[len(out)-1].ID)
	}
	return out, next, nil
}
func (r *MemoryProfileRepository) UpdateProfile(_ context.Context, p Profile, key, digest string, expected int64) (MutationSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok, e := r.replay("update", key, digest); ok {
		return v, e
	}
	cur, ok := r.profiles[p.ID]
	if !ok {
		return MutationSnapshot{}, ErrProfileNotFound
	}
	if cur.Revision != expected {
		return MutationSnapshot{}, ErrRevisionConflict
	}
	r.profiles[p.ID] = cloneProfile(p)
	snap := MutationSnapshot{Profile: p.Public()}
	stored := snap
	stored.Profile = clonePublicProfile(snap.Profile)
	r.idempotency["update:"+key] = struct {
		Digest string
		Result MutationSnapshot
	}{digest, stored}
	return snap, nil
}

func cloneProfile(p Profile) Profile {
	if p.Temperature != nil {
		v := *p.Temperature
		p.Temperature = &v
	}
	if p.TopP != nil {
		v := *p.TopP
		p.TopP = &v
	}
	p.InputModalities = append([]string(nil), p.InputModalities...)
	p.ProviderConfig = cloneMap(p.ProviderConfig)
	p.ProviderSecrets = cloneStringMap(p.ProviderSecrets)
	p.ProviderSecretStatus = cloneBoolMap(p.ProviderSecretStatus)
	return p
}
func clonePublicProfile(p PublicProfile) PublicProfile {
	if p.Temperature != nil {
		v := *p.Temperature
		p.Temperature = &v
	}
	if p.TopP != nil {
		v := *p.TopP
		p.TopP = &v
	}
	p.InputModalities = append([]string(nil), p.InputModalities...)
	p.ProviderConfig = cloneMap(p.ProviderConfig)
	p.ProviderSecretStatus = cloneBoolMap(p.ProviderSecretStatus)
	return p
}

func cloneMap(value map[string]any) map[string]any {
	if len(value) == 0 {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(encoded, &out) != nil {
		return nil
	}
	return out
}

func cloneStringMap(value map[string]string) map[string]string {
	if len(value) == 0 {
		return nil
	}
	out := make(map[string]string, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func cloneBoolMap(value map[string]bool) map[string]bool {
	if len(value) == 0 {
		return nil
	}
	out := make(map[string]bool, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}
func (r *MemoryProfileRepository) DeleteProfile(_ context.Context, id, key, digest string, expected int64) (MutationSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok, e := r.replay("delete", key, digest); ok {
		return v, e
	}
	p, ok := r.profiles[id]
	if !ok {
		return MutationSnapshot{}, ErrProfileNotFound
	}
	if p.Revision != expected {
		return MutationSnapshot{}, ErrRevisionConflict
	}
	if r.refs[id] > 0 {
		return MutationSnapshot{}, ErrProfileInUse
	}
	delete(r.profiles, id)
	snap := MutationSnapshot{Profile: p.Public(), Deleted: true}
	r.deleted[id] = clonePublicProfile(snap.Profile)
	stored := snap
	stored.Profile = clonePublicProfile(snap.Profile)
	r.idempotency["delete:"+key] = struct {
		Digest string
		Result MutationSnapshot
	}{digest, stored}
	return snap, nil
}
func (r *MemoryProfileRepository) SetActiveReferences(id string, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refs[id] = count
}

func (r *MemoryProfileRepository) SyncProfiles(_ context.Context, key, digest string, cmd SyncProfileCommand) (SyncProfileResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.syncIdempotency[key]; ok {
		if rec.Digest != digest {
			return SyncProfileResult{}, ErrIdempotencyConflict
		}
		out := rec.Result
		out.Replay = true
		out.Profiles = make([]PublicProfile, len(rec.Result.Profiles))
		for i, p := range rec.Result.Profiles {
			out.Profiles[i] = clonePublicProfile(p)
		}
		return out, nil
	}
	byClient := make(map[string]string, len(r.profiles))
	for id, p := range r.profiles {
		if p.ClientProfileID != "" {
			byClient[p.ClientProfileID] = id
		}
	}
	work := make(map[string]Profile, len(r.profiles))
	for id, p := range r.profiles {
		work[id] = cloneProfile(p)
	}
	out := SyncProfileResult{DefaultClientProfileID: cmd.DefaultClientProfileID, Profiles: make([]PublicProfile, 0, len(cmd.Entries))}
	for _, e := range cmd.Entries {
		id, exists := byClient[e.ClientProfileID]
		if exists {
			p := work[id]
			if e.ExpectedRevision == nil || p.Revision != *e.ExpectedRevision {
				return SyncProfileResult{}, ErrRevisionConflict
			}
			previousAPIKey := p.APIKey
			previousProviderSecrets := cloneStringMap(p.ProviderSecrets)
			p.DisplayName, p.Provider, p.ModelKind, p.InputModalities, p.ProviderConfig, p.BaseURL, p.Model, p.SystemPrompt = e.DisplayName, e.Provider, e.ModelKind, append([]string(nil), e.InputModalities...), e.ProviderConfig, e.BaseURL, e.Model, e.SystemPrompt
			if e.ProviderSecrets != nil {
				p.ProviderSecrets = cloneStringMap(e.ProviderSecrets)
			}
			p.Temperature, p.TopP = cloneFloat(e.Temperature), cloneFloat(e.TopP)
			p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort = e.MaxOutputTokens, e.ContextWindow, e.ReasoningEffort
			if e.APIKey != nil {
				p.APIKey = *e.APIKey
			}
			if p.CredentialVersion <= 0 {
				p.CredentialVersion = 1
			}
			if previousAPIKey != p.APIKey || !equalStringMap(previousProviderSecrets, p.ProviderSecrets) {
				p.CredentialVersion++
			}
			p.Revision++
			work[id] = p
		} else {
			if e.ExpectedRevision != nil {
				return SyncProfileResult{}, ErrRevisionConflict
			}
			p := Profile{ID: SyncProfileID(e.ClientProfileID), ClientProfileID: e.ClientProfileID, DisplayName: e.DisplayName, Provider: e.Provider, ModelKind: e.ModelKind, InputModalities: append([]string(nil), e.InputModalities...), ProviderConfig: e.ProviderConfig, ProviderSecrets: e.ProviderSecrets, BaseURL: e.BaseURL, Model: e.Model, APIKey: valueOrEmpty(e.APIKey), SystemPrompt: e.SystemPrompt, Temperature: cloneFloat(e.Temperature), TopP: cloneFloat(e.TopP), MaxOutputTokens: e.MaxOutputTokens, ContextWindow: e.ContextWindow, ReasoningEffort: e.ReasoningEffort, Revision: 1, CredentialVersion: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
			id = p.ID
			byClient[e.ClientProfileID] = id
			work[id] = p
			exists = true
		}
		p := work[id]
		if e.APIKey == nil && p.APIKey == "" && p.Provider != ProviderVolcVoice {
			return SyncProfileResult{}, ErrAPIKeyUnavailable
		}
		p, err := validateStoredProfile(p)
		if err != nil || (p.APIKey == "" && p.Provider != ProviderVolcVoice) {
			if err != nil {
				return SyncProfileResult{}, err
			}
			return SyncProfileResult{}, ErrAPIKeyUnavailable
		}
		p.UpdatedAt = time.Now().UTC()
		work[id] = p
		out.Profiles = append(out.Profiles, p.Public())
	}
	if cmd.DefaultConversationProfileID == "" {
		cmd.DefaultConversationProfileID = cmd.DefaultClientProfileID
	}
	if cmd.DefaultClientProfileID == "" {
		cmd.DefaultClientProfileID = cmd.DefaultConversationProfileID
	}
	for _, defaultID := range []string{cmd.DefaultConversationProfileID, cmd.DefaultEmbeddingProfileID, cmd.DefaultSpeechProfileID} {
		if defaultID == "" {
			continue
		}
		if _, ok := byClient[defaultID]; !ok {
			return SyncProfileResult{}, ErrProfileNotFound
		}
	}
	out.DefaultClientProfileID = cmd.DefaultClientProfileID
	out.DefaultConversationProfileID = cmd.DefaultConversationProfileID
	out.DefaultEmbeddingProfileID = cmd.DefaultEmbeddingProfileID
	out.DefaultSpeechProfileID = cmd.DefaultSpeechProfileID
	for id, p := range work {
		r.profiles[id] = p
	}
	r.defaults = ProfileDefaults{ConversationClientProfileID: out.DefaultConversationProfileID, EmbeddingClientProfileID: out.DefaultEmbeddingProfileID, SpeechClientProfileID: out.DefaultSpeechProfileID}
	r.syncIdempotency[key] = struct {
		Digest string
		Result SyncProfileResult
	}{digest, out}
	return out, nil
}

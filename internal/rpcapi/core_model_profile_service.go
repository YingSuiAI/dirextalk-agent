package rpcapi

import (
	"context"
	"errors"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ModelProfileService struct {
	agentv1.UnimplementedModelProfileServiceServer
	profiles *coremodel.Service
}

func NewModelProfileService(profiles *coremodel.Service) (*ModelProfileService, error) {
	if profiles == nil {
		return nil, errors.New("model profile service requires profiles")
	}
	return &ModelProfileService{profiles: profiles}, nil
}

func (s *ModelProfileService) Create(ctx context.Context, req *agentv1.ModelProfileServiceCreateRequest) (*agentv1.ModelProfileServiceCreateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	spec, err := createSpec(req)
	if err != nil {
		return nil, grpcProfileError(err)
	}
	p, err := s.profiles.Create(ctx, coremodel.CreateProfileCommand{IdempotencyKey: req.IdempotencyKey, Spec: spec})
	if err != nil {
		return nil, grpcProfileError(err)
	}
	return &agentv1.ModelProfileServiceCreateResponse{Profile: publicProfileProto(p)}, nil
}

func (s *ModelProfileService) Get(ctx context.Context, req *agentv1.ModelProfileServiceGetRequest) (*agentv1.ModelProfileServiceGetResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	p, err := s.profiles.Get(ctx, req.ProfileId)
	if err != nil {
		return nil, grpcProfileError(err)
	}
	return &agentv1.ModelProfileServiceGetResponse{Profile: publicProfileProto(p)}, nil
}

func (s *ModelProfileService) List(ctx context.Context, req *agentv1.ModelProfileServiceListRequest) (*agentv1.ModelProfileServiceListResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	page, err := s.profiles.List(ctx, coremodel.ListProfileCommand{Cursor: req.PageToken, Limit: int(req.PageSize)})
	if err != nil {
		return nil, grpcProfileError(err)
	}
	out := &agentv1.ModelProfileServiceListResponse{NextPageToken: page.NextCursor, Profiles: make([]*agentv1.CoreModelProfile, 0, len(page.Profiles))}
	for _, p := range page.Profiles {
		out.Profiles = append(out.Profiles, publicProfileProto(p))
	}
	return out, nil
}

func (s *ModelProfileService) Update(ctx context.Context, req *agentv1.ModelProfileServiceUpdateRequest) (*agentv1.ModelProfileServiceUpdateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	spec, err := updateSpec(req)
	if err != nil {
		return nil, grpcProfileError(err)
	}
	p, err := s.profiles.Update(ctx, coremodel.UpdateProfileCommand{ID: req.ProfileId, IdempotencyKey: req.IdempotencyKey, ExpectedRevision: req.ExpectedRevision, Spec: spec})
	if err != nil {
		return nil, grpcProfileError(err)
	}
	return &agentv1.ModelProfileServiceUpdateResponse{Profile: publicProfileProto(p)}, nil
}

func (s *ModelProfileService) Delete(ctx context.Context, req *agentv1.ModelProfileServiceDeleteRequest) (*agentv1.ModelProfileServiceDeleteResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	_, err := s.profiles.Delete(ctx, coremodel.DeleteProfileCommand{ID: req.ProfileId, IdempotencyKey: req.IdempotencyKey, ExpectedRevision: req.ExpectedRevision})
	if err != nil {
		return nil, grpcProfileError(err)
	}
	return &agentv1.ModelProfileServiceDeleteResponse{}, nil
}

func (s *ModelProfileService) TestConnection(ctx context.Context, req *agentv1.ModelProfileServiceTestConnectionRequest) (*agentv1.ModelProfileServiceTestConnectionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	result, err := s.profiles.TestConnectionWithIdempotency(ctx, req.ProfileId, req.IdempotencyKey)
	if err != nil {
		return nil, grpcProfileError(err)
	}
	return &agentv1.ModelProfileServiceTestConnectionResponse{Reachable: result.OK, ErrorCode: result.ErrorCode}, nil
}

func (s *ModelProfileService) Sync(ctx context.Context, req *agentv1.ModelProfileServiceSyncRequest) (*agentv1.ModelProfileServiceSyncResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	cmd := coremodel.SyncProfileCommand{IdempotencyKey: req.IdempotencyKey, DefaultClientProfileID: req.DefaultClientProfileId, Entries: make([]coremodel.SyncProfileEntry, 0, len(req.Entries))}
	for _, entry := range req.Entries {
		if entry == nil {
			return nil, grpcProfileError(coremodel.ErrInvalidProfile)
		}
		provider, err := fromProtoProvider(entry.Provider)
		if err != nil {
			return nil, grpcProfileError(err)
		}
		var key *string
		if entry.ApiKey != nil {
			value := *entry.ApiKey
			key = &value
		}
		e := coremodel.SyncProfileEntry{ClientProfileID: entry.ClientProfileId, ExpectedRevision: entry.ExpectedRevision, DisplayName: entry.DisplayName, Provider: provider, BaseURL: entry.BaseUrl, Model: entry.Model, SystemPrompt: entry.SystemPrompt, APIKey: key, Temperature: entry.Temperature, TopP: entry.TopP, MaxOutputTokens: int(entry.MaxOutputTokens), ContextWindow: int(entry.ContextWindow), ReasoningEffort: entry.ReasoningEffort}
		cmd.Entries = append(cmd.Entries, e)
	}
	result, err := s.profiles.Sync(ctx, cmd)
	if err != nil {
		return nil, grpcProfileError(err)
	}
	out := &agentv1.ModelProfileServiceSyncResponse{DefaultClientProfileId: result.DefaultClientProfileID, Profiles: make([]*agentv1.CoreModelProfile, 0, len(result.Profiles))}
	for _, p := range result.Profiles {
		out.Profiles = append(out.Profiles, publicProfileProto(p))
	}
	return out, nil
}

func createSpec(req *agentv1.ModelProfileServiceCreateRequest) (coremodel.ProfileSpec, error) {
	provider, err := fromProtoProvider(req.Provider)
	if err != nil {
		return coremodel.ProfileSpec{}, err
	}
	if strings.TrimSpace(req.ApiKey) == "" {
		return coremodel.ProfileSpec{}, coremodel.ErrAPIKeyUnavailable
	}
	key := req.ApiKey
	return coremodel.ProfileSpec{ID: "", DisplayName: req.DisplayName, Provider: provider, BaseURL: req.BaseUrl, Model: req.Model, APIKey: &key, SystemPrompt: req.SystemPrompt, Temperature: req.Temperature, TopP: req.TopP, MaxOutputTokens: int(req.MaxOutputTokens), ContextWindow: int(req.ContextWindow), ReasoningEffort: req.ReasoningEffort}, nil
}
func updateSpec(req *agentv1.ModelProfileServiceUpdateRequest) (coremodel.ProfileSpec, error) {
	spec := coremodel.ProfileSpec{ID: req.ProfileId, Patch: true}
	if req.DisplayName != nil {
		spec.DisplayName, spec.DisplayNameSet = *req.DisplayName, true
	}
	if req.Provider != nil {
		provider, err := fromProtoProvider(*req.Provider)
		if err != nil {
			return coremodel.ProfileSpec{}, err
		}
		spec.Provider, spec.ProviderSet = provider, true
	}
	if req.BaseUrl != nil {
		spec.BaseURL, spec.BaseURLSet = *req.BaseUrl, true
	}
	if req.Model != nil {
		spec.Model, spec.ModelSet = *req.Model, true
	}
	if req.SystemPrompt != nil {
		spec.SystemPrompt, spec.SystemPromptSet = *req.SystemPrompt, true
	}
	if req.ApiKeyUpdate != nil {
		switch v := req.ApiKeyUpdate.(type) {
		case *agentv1.ModelProfileServiceUpdateRequest_ReplacementApiKey:
			if v.ReplacementApiKey == "" {
				return coremodel.ProfileSpec{}, coremodel.ErrAPIKeyUnavailable
			}
			spec.APIKey = &v.ReplacementApiKey
		case *agentv1.ModelProfileServiceUpdateRequest_ClearApiKey:
			if !v.ClearApiKey {
				return coremodel.ProfileSpec{}, coremodel.ErrInvalidProfile
			}
			spec.APIKeyClear = true
		default:
			return coremodel.ProfileSpec{}, coremodel.ErrInvalidProfile
		}
	}
	if err := samplingSpec(req.Temperature, &spec.Temperature, &spec.TemperatureSet, &spec.TemperatureClear); err != nil {
		return coremodel.ProfileSpec{}, err
	}
	if err := samplingSpec(req.TopP, &spec.TopP, &spec.TopPSet, &spec.TopPClear); err != nil {
		return coremodel.ProfileSpec{}, err
	}
	if req.MaxOutputTokens != nil {
		spec.MaxOutputTokens = int(*req.MaxOutputTokens)
		spec.MaxOutputTokensSet = true
	}
	if req.ContextWindow != nil {
		spec.ContextWindow = int(*req.ContextWindow)
		spec.ContextWindowSet = true
	}
	if req.ReasoningEffort != nil {
		spec.ReasoningEffort = *req.ReasoningEffort
		spec.ReasoningEffortSet = true
	}
	return spec, nil
}
func samplingSpec(value *agentv1.CoreSamplingUpdate, out **float64, set, clear *bool) error {
	if value == nil {
		return nil
	}
	switch v := value.Value.(type) {
	case *agentv1.CoreSamplingUpdate_Preserve:
		if v.Preserve == nil {
			return coremodel.ErrInvalidProfile
		}
	case *agentv1.CoreSamplingUpdate_Set:
		x := v.Set
		*out = &x
		*set = true
	case *agentv1.CoreSamplingUpdate_Clear:
		if !v.Clear {
			return coremodel.ErrInvalidProfile
		}
		*clear = true
	default:
		return coremodel.ErrInvalidProfile
	}
	return nil
}
func fromProtoProvider(v agentv1.CoreModelProvider) (coremodel.ModelProvider, error) {
	switch v {
	case agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE:
		return coremodel.ProviderOpenAICompatible, nil
	case agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_ANTHROPIC:
		return coremodel.ProviderAnthropic, nil
	case agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_GEMINI:
		return coremodel.ProviderGemini, nil
	default:
		return "", coremodel.ErrUnsupportedProvider
	}
}
func publicProfileProto(p coremodel.PublicProfile) *agentv1.CoreModelProfile {
	out := &agentv1.CoreModelProfile{ProfileId: p.ID, ClientProfileId: p.ClientProfileID, DisplayName: p.DisplayName, Provider: toProtoProvider(p.Provider), BaseUrl: p.BaseURL, Model: p.Model, SystemPrompt: p.SystemPrompt, ApiKeyConfigured: p.APIKeyConfigured, MaxOutputTokens: int32(p.MaxOutputTokens), ContextWindow: int32(p.ContextWindow), ReasoningEffort: p.ReasoningEffort, Revision: p.Revision}
	if p.Temperature != nil {
		v := *p.Temperature
		out.Temperature = &v
	}
	if p.TopP != nil {
		v := *p.TopP
		out.TopP = &v
	}
	if !p.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(p.CreatedAt.UTC())
	}
	if !p.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(p.UpdatedAt.UTC())
	}
	return out
}
func toProtoProvider(v coremodel.ModelProvider) agentv1.CoreModelProvider {
	switch v {
	case coremodel.ProviderOpenAICompatible:
		return agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE
	case coremodel.ProviderAnthropic:
		return agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_ANTHROPIC
	case coremodel.ProviderGemini:
		return agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_GEMINI
	default:
		return agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_UNSPECIFIED
	}
}
func grpcProfileError(err error) error {
	switch {
	case errors.Is(err, coremodel.ErrInvalidProfile), errors.Is(err, coremodel.ErrInvalidBaseURL), errors.Is(err, coremodel.ErrUnsupportedProvider), errors.Is(err, coremodel.ErrInvalidIdempotencyKey), errors.Is(err, coremodel.ErrInvalidCursor), errors.Is(err, coremodel.ErrInvalidPageSize), errors.Is(err, coremodel.ErrAPIKeyUnavailable):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, coremodel.ErrProfileNotFound):
		return status.Error(codes.NotFound, "model profile not found")
	case errors.Is(err, coremodel.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "idempotency conflict")
	case errors.Is(err, coremodel.ErrRevisionConflict):
		return status.Error(codes.Aborted, "profile revision conflict")
	case errors.Is(err, coremodel.ErrProfileInUse):
		return status.Error(codes.FailedPrecondition, "model profile is in use")
	case errors.Is(err, coremodel.ErrSyncConflict):
		return status.Error(codes.AlreadyExists, "model profile sync conflict")
	case errors.Is(err, coremodel.ErrConnectionTestFailed):
		return status.Error(codes.Unavailable, "connection test unavailable")
	default:
		return status.Error(codes.Unavailable, "model profile unavailable")
	}
}

var _ agentv1.ModelProfileServiceServer = (*ModelProfileService)(nil)

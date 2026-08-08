package coretexttool

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	"github.com/google/uuid"
)

type memoryRepository struct {
	config   *Config
	mutation Mutation
}

func (r *memoryRepository) Get(_ context.Context, _ string, _ int64, now time.Time) (Config, error) {
	if r.config == nil {
		return DefaultConfig(now), nil
	}
	return cloneConfig(*r.config), nil
}

func (r *memoryRepository) Update(_ context.Context, mutation Mutation) (Config, error) {
	r.mutation = mutation
	if r.config != nil && r.config.Revision != mutation.ExpectedRevision || r.config == nil && mutation.ExpectedRevision != 0 {
		return Config{}, ErrRevisionConflict
	}
	next := Config{Enabled: mutation.Enabled, Revision: mutation.ExpectedRevision + 1, Tools: cloneTools(mutation.Tools), UpdatedAt: mutation.Now}
	r.config = &next
	return next, nil
}

type profileResolver struct {
	profile coremodel.Profile
	err     error
}

func (r profileResolver) ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error) {
	return r.profile, r.err
}

type recordingClient struct {
	request coremodel.CompletionRequest
	output  string
	err     error
}

func (c *recordingClient) Generate(_ context.Context, request coremodel.CompletionRequest) (coremodel.Completion, error) {
	c.request = request
	return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: c.output}}, c.err
}
func (*recordingClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, errors.New("not used")
}

type fakeSearch struct {
	max        int
	resolved   *corewebsearch.ResolvedConfig
	resolveErr error
}

func (f *fakeSearch) Resolve(context.Context, string, int64) (corewebsearch.ResolvedConfig, error) {
	if f.resolveErr != nil {
		return corewebsearch.ResolvedConfig{}, f.resolveErr
	}
	if f.resolved != nil {
		return *f.resolved, nil
	}
	return corewebsearch.ResolvedConfig{Config: corewebsearch.Config{Enabled: true, Provider: corewebsearch.ProviderTavily, APIKeyConfigured: true, Revision: 1}, APIKey: "tvly-server-secret", CredentialVersion: 1, OwnerID: "owner", AccountGeneration: 1}, nil
}
func (f *fakeSearch) SearchResolved(_ context.Context, _ string, _ int64, _ corewebsearch.ResolvedConfig, query string, max int) (corewebsearch.SearchResult, error) {
	f.max = max
	return corewebsearch.SearchResult{Results: []corewebsearch.SearchItem{{Title: "Title", URL: "https://example.test", Content: "Evidence"}}}, nil
}

func newTestService(t *testing.T, repository Repository, search WebSearch, client *recordingClient) *Service {
	t.Helper()
	service, err := NewService(repository, profileResolver{profile: coremodel.Profile{ID: uuid.NewString(), Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, APIKey: "secret", Revision: 1, CredentialVersion: 1}}, search, func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC) }
	return service
}

func TestVirtualDefaultsAndFirstFullReplacement(t *testing.T) {
	repository := &memoryRepository{}
	service := newTestService(t, repository, nil, &recordingClient{})
	config, err := service.Get(context.Background(), "owner", 1)
	if err != nil || config.Revision != 0 || config.Enabled || config.UpdatedAt.IsZero() || len(config.Tools) != 4 || config.Tools[3].ID != "search" || config.Tools[3].Enabled {
		t.Fatalf("virtual config=%+v err=%v", config, err)
	}
	tools := []Tool{{ID: "summary", Name: "S", SystemPrompt: "P", Order: 0, Enabled: true}, {ID: uuid.NewString(), Name: "Custom", SystemPrompt: "Custom prompt", Order: 1, Enabled: false}}
	updated, err := service.Update(context.Background(), UpdateCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), ExpectedRevision: 0, Enabled: true, Tools: tools})
	if err != nil || updated.Revision != 1 || len(updated.Tools) != 2 || updated.Tools[0].ID != "summary" {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
}

func TestValidationLimitsEnabledCountBytesAndOrder(t *testing.T) {
	now := time.Now().UTC()
	tools := make([]Tool, 7)
	for i := range tools {
		tools[i] = Tool{ID: uuid.NewString(), Name: "n", SystemPrompt: "p", Order: i, Enabled: true}
	}
	if !errors.Is(ValidateConfig(Config{Revision: 0, UpdatedAt: now, Tools: tools}), ErrInvalid) {
		t.Fatal("seven enabled tools accepted")
	}
	repository := &memoryRepository{config: &Config{Revision: 1, UpdatedAt: now, Tools: tools}}
	service := newTestService(t, repository, nil, &recordingClient{})
	if _, err := service.Get(context.Background(), "owner", 1); !errors.Is(err, ErrRepository) {
		t.Fatalf("invalid persisted enabled count read error=%v", err)
	}
	if _, err := service.Update(context.Background(), UpdateCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Tools: tools}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid enabled count update error=%v", err)
	}
	tools = tools[:6]
	tools[5].Order = 7
	if !errors.Is(ValidateConfig(Config{UpdatedAt: now, Tools: tools}), ErrInvalid) {
		t.Fatal("non-contiguous order accepted")
	}
	tools[5].Order = 5
	tools[0].Name = strings.Repeat("界", 22)
	if !errors.Is(ValidateConfig(Config{UpdatedAt: now, Tools: tools}), ErrInvalid) {
		t.Fatal("name over 64 UTF-8 bytes accepted")
	}
}

func TestUpdateRequiresEnabledTavilyCredentialOnlyWhenSearchWillBeUsable(t *testing.T) {
	searchTool := Tool{ID: "search", Name: "Search", SystemPrompt: "Search", Order: 0, Enabled: true}
	cases := []struct {
		name       string
		global     bool
		tool       Tool
		search     WebSearch
		wantErr    error
		wantUpdate bool
	}{
		{name: "globally disabled", global: false, tool: searchTool, wantUpdate: true},
		{name: "search disabled", global: true, tool: Tool{ID: "search", Name: "Search", SystemPrompt: "Search", Order: 0, Enabled: false}, wantUpdate: true},
		{name: "missing service", global: true, tool: searchTool, wantErr: corewebsearch.ErrNotConfigured},
		{name: "missing credential", global: true, tool: searchTool, search: &fakeSearch{resolveErr: corewebsearch.ErrNotConfigured}, wantErr: corewebsearch.ErrNotConfigured},
		{name: "provider disabled", global: true, tool: searchTool, search: &fakeSearch{resolved: &corewebsearch.ResolvedConfig{Config: corewebsearch.Config{Enabled: false, Provider: corewebsearch.ProviderTavily, APIKeyConfigured: true, Revision: 1}, APIKey: "tvly", CredentialVersion: 1, OwnerID: "owner", AccountGeneration: 1}}, wantErr: corewebsearch.ErrDisabled},
		{name: "valid credential", global: true, tool: searchTool, search: &fakeSearch{}, wantUpdate: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			repository := &memoryRepository{}
			service := newTestService(t, repository, test.search, &recordingClient{})
			_, err := service.Update(context.Background(), UpdateCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), ExpectedRevision: 0, Enabled: test.global, Tools: []Tool{test.tool}})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("update error=%v want=%v", err, test.wantErr)
			}
			if got := repository.config != nil; got != test.wantUpdate {
				t.Fatalf("repository updated=%v want=%v", got, test.wantUpdate)
			}
		})
	}
}

func TestExecuteCustomIsModelOnlyAndSearchUsesSeparateEvidence(t *testing.T) {
	customID := uuid.NewString()
	config := Config{Enabled: true, Revision: 1, UpdatedAt: time.Now().UTC(), Tools: []Tool{{ID: customID, Name: "Custom", SystemPrompt: "custom system", Order: 0, Enabled: true}, {ID: "search", Name: "Search", SystemPrompt: "search system", Order: 1, Enabled: true}}}
	repository := &memoryRepository{config: &config}
	client := &recordingClient{output: "answer"}
	search := &fakeSearch{}
	service := newTestService(t, repository, search, client)
	custom, err := service.Execute(context.Background(), ExecuteCommand{OwnerID: "owner", AccountGeneration: 1, ToolID: customID, SelectedText: "selected"})
	if err != nil || custom.Output != "answer" || search.max != 0 || len(client.request.Messages) != 2 || client.request.Messages[0].Role != coremodel.RoleSystem || client.request.Messages[1].Role != coremodel.RoleUser {
		t.Fatalf("custom=%+v request=%+v max=%d err=%v", custom, client.request, search.max, err)
	}
	result, err := service.Execute(context.Background(), ExecuteCommand{OwnerID: "owner", AccountGeneration: 1, ToolID: "search", SelectedText: "query"})
	if err != nil || search.max != 5 || len(result.Sources) != 1 || len(client.request.Messages) != 3 || client.request.Messages[1].Role != coremodel.RoleSystem || !strings.Contains(client.request.Messages[1].Content, "untrusted") || client.request.Messages[2].Content != "query" {
		t.Fatalf("search=%+v request=%+v max=%d err=%v", result, client.request, search.max, err)
	}
}

func TestExecuteRejectsDisabledAndOversizedOutput(t *testing.T) {
	repository := &memoryRepository{}
	service := newTestService(t, repository, nil, &recordingClient{output: "ok"})
	if _, err := service.Execute(context.Background(), ExecuteCommand{OwnerID: "owner", AccountGeneration: 1, ToolID: "summary", SelectedText: "x"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled error=%v", err)
	}
	config := DefaultConfig(time.Now().UTC())
	config.Enabled, config.Revision = true, 1
	repository.config = &config
	service = newTestService(t, repository, nil, &recordingClient{output: strings.Repeat("x", MaxOutputBytes+1)})
	if _, err := service.Execute(context.Background(), ExecuteCommand{OwnerID: "owner", AccountGeneration: 1, ToolID: "summary", SelectedText: "x"}); !errors.Is(err, ErrModel) {
		t.Fatalf("oversized output error=%v", err)
	}
}

func TestExecuteSearchFailsClosedBeforeModelResolutionWithoutSearchCredential(t *testing.T) {
	config := Config{Enabled: true, Revision: 1, UpdatedAt: time.Now().UTC(), Tools: []Tool{{ID: "search", Name: "Search", SystemPrompt: "Search", Order: 0, Enabled: true}}}
	service := newTestService(t, &memoryRepository{config: &config}, &fakeSearch{resolveErr: corewebsearch.ErrNotConfigured}, &recordingClient{output: "must not run"})
	service.models = profileResolver{}
	if _, err := service.Execute(context.Background(), ExecuteCommand{OwnerID: "owner", AccountGeneration: 1, ToolID: "search", SelectedText: "query"}); !errors.Is(err, corewebsearch.ErrNotConfigured) {
		t.Fatalf("execute error=%v", err)
	}
}

func TestExecuteDistinguishesMissingToolModelFromModelAndRepositoryFailures(t *testing.T) {
	config := DefaultConfig(time.Now().UTC())
	config.Enabled, config.Revision = true, 1
	service := newTestService(t, &memoryRepository{config: &config}, nil, &recordingClient{output: "ok"})
	command := ExecuteCommand{OwnerID: "owner", AccountGeneration: 1, ToolID: "summary", SelectedText: "selected"}

	service.models = profileResolver{err: coremodel.ErrProfileNotFound}
	if _, err := service.Execute(context.Background(), command); !errors.Is(err, ErrModelNotConfigured) || !errors.Is(err, coremodel.ErrProfileNotFound) || errors.Is(err, ErrModel) {
		t.Fatalf("missing profile error=%v", err)
	}

	service.models = profileResolver{err: coremodel.ErrProfileRepository}
	if _, err := service.Execute(context.Background(), command); !errors.Is(err, ErrModel) || !errors.Is(err, coremodel.ErrProfileRepository) || errors.Is(err, ErrModelNotConfigured) {
		t.Fatalf("repository error=%v", err)
	}

	service.models = profileResolver{profile: coremodel.Profile{ID: uuid.NewString(), Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, APIKey: "secret", Revision: 1, CredentialVersion: 1}}
	client := &recordingClient{err: coremodel.ErrProviderUnavailable}
	service.client = func(coremodel.Profile) (coremodel.Client, error) { return client, nil }
	if _, err := service.Execute(context.Background(), command); !errors.Is(err, ErrModel) || !errors.Is(err, coremodel.ErrProviderUnavailable) || errors.Is(err, ErrModelNotConfigured) {
		t.Fatalf("provider error=%v", err)
	}

	service.client = func(coremodel.Profile) (coremodel.Client, error) { return nil, coremodel.ErrInvalidProfile }
	if _, err := service.Execute(context.Background(), command); !errors.Is(err, ErrModel) || !errors.Is(err, coremodel.ErrInvalidProfile) || errors.Is(err, ErrModelNotConfigured) {
		t.Fatalf("client factory error=%v", err)
	}
}

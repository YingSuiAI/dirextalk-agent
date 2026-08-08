package coreimagetool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	"github.com/google/uuid"
)

type fakeRepository struct {
	source   ConsumedSource
	consume  ConsumeCommand
	consumed bool
}

func (*fakeRepository) Begin(context.Context, BeginCommand) (Upload, error)   { return Upload{}, nil }
func (*fakeRepository) Append(context.Context, AppendCommand) (Upload, error) { return Upload{}, nil }
func (*fakeRepository) Commit(context.Context, CommitCommand) (Source, error) { return Source{}, nil }
func (r *fakeRepository) Consume(_ context.Context, c ConsumeCommand) (ConsumedSource, error) {
	if r.consumed {
		return ConsumedSource{}, ErrConsumed
	}
	r.consumed = true
	r.consume = c
	return ConsumedSource{Source: r.source.Source, Content: append([]byte(nil), r.source.Content...)}, nil
}

type fakeConfig struct{ enabled bool }

func (f fakeConfig) Get(context.Context, string, int64) (coretexttool.Config, error) {
	return coretexttool.Config{Enabled: f.enabled, Revision: 1, UpdatedAt: time.Now()}, nil
}

type fakeResolver struct {
	profile coremodel.Profile
	err     error
}

func (f fakeResolver) ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error) {
	return f.profile, f.err
}

type fakeClient struct {
	request    coremodel.CompletionRequest
	output     string
	imageBytes int
	imageMIME  string
}

func (c *fakeClient) Generate(_ context.Context, r coremodel.CompletionRequest) (coremodel.Completion, error) {
	c.request = r
	if len(r.Messages) == 1 && len(r.Messages[0].InputParts) == 2 && r.Messages[0].InputParts[1].Image != nil {
		c.imageBytes = len(r.Messages[0].InputParts[1].Image.Bytes())
		c.imageMIME = r.Messages[0].InputParts[1].Image.MIMEType
	}
	return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: c.output}}, nil
}
func (*fakeClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, errors.New("unused")
}

func testService(t *testing.T, enabled bool, modalities []string, output string) (*Service, *fakeRepository, *fakeClient) {
	t.Helper()
	requestID := uuid.NewString()
	repo := &fakeRepository{source: ConsumedSource{Source: Source{SourceID: uuid.NewString(), Revision: 1, ImageRequestID: requestID, MIMEType: "image/png", SizeBytes: 3, Status: "committed"}, Content: []byte{1, 2, 3}}}
	client := &fakeClient{output: output}
	service, err := NewService(repo, fakeConfig{enabled}, fakeResolver{profile: coremodel.Profile{ID: uuid.NewString(), Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, InputModalities: modalities, APIKey: "secret", Revision: 1, CredentialVersion: 1}}, func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	return service, repo, client
}

func TestExecuteRequiresEnabledExplicitImageToolProfile(t *testing.T) {
	service, repo, _ := testService(t, false, []string{"image"}, "x")
	cmd := ExecuteCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: repo.source.Source.ImageRequestID, SourceID: repo.source.Source.SourceID, SourceRevision: 1}
	if _, err := service.ExtractText(context.Background(), cmd); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled error=%v", err)
	}
	if repo.consumed {
		t.Fatal("disabled request consumed source")
	}
	service, repo, _ = testService(t, true, []string{"text"}, "x")
	cmd.IdempotencyKey = repo.source.Source.ImageRequestID
	cmd.SourceID = repo.source.Source.SourceID
	if _, err := service.ExtractText(context.Background(), cmd); !errors.Is(err, ErrModelNotConfigured) {
		t.Fatalf("modality error=%v", err)
	}
	if repo.consumed {
		t.Fatal("ineligible model consumed source")
	}
	for _, mutate := range []func(*coremodel.Profile){
		func(p *coremodel.Profile) { p.ModelKind = "" },
		func(p *coremodel.Profile) { p.APIKey = "" },
	} {
		service, repo, _ = testService(t, true, []string{"image"}, "x")
		resolver := service.models.(fakeResolver)
		mutate(&resolver.profile)
		service.models = resolver
		cmd.IdempotencyKey, cmd.SourceID = repo.source.Source.ImageRequestID, repo.source.Source.SourceID
		if _, err := service.ExtractText(context.Background(), cmd); !errors.Is(err, ErrModelNotConfigured) {
			t.Fatalf("invalid explicit profile error=%v", err)
		}
		if repo.consumed {
			t.Fatal("invalid explicit profile consumed source")
		}
	}
	service, repo, _ = testService(t, true, []string{"image"}, "x")
	cmd.IdempotencyKey, cmd.SourceID, cmd.SourceRevision = repo.source.Source.ImageRequestID, repo.source.Source.SourceID, 2
	if _, err := service.ExtractText(context.Background(), cmd); !errors.Is(err, ErrInvalid) {
		t.Fatalf("source revision error=%v", err)
	}
}

func TestExtractConsumesOnceAndUsesTypedImageWithoutConversationState(t *testing.T) {
	service, repo, client := testService(t, true, []string{"text", "image"}, "")
	cmd := ExecuteCommand{OwnerID: "owner", AccountGeneration: 7, IdempotencyKey: repo.source.Source.ImageRequestID, SourceID: repo.source.Source.SourceID, SourceRevision: 1}
	result, err := service.ExtractText(context.Background(), cmd)
	if err != nil || result.Text != "" || result.SourceRevision != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(client.request.Messages) != 1 || len(client.request.Messages[0].InputParts) != 2 || client.request.Messages[0].Content != "" || client.request.Messages[0].InputParts[1].Type != coremodel.MessageInputPartImage || client.imageBytes != 3 || client.imageMIME != "image/png" {
		t.Fatalf("typed request=%+v", client.request)
	}
	if repo.consume.ImageRequestID != cmd.IdempotencyKey || repo.consume.AccountGeneration != 7 {
		t.Fatalf("consume=%+v", repo.consume)
	}
	if _, err = service.ExtractText(context.Background(), cmd); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume error=%v", err)
	}
}

func TestTranslateRequiresCanonicalBCP47AndEchoesLocale(t *testing.T) {
	service, repo, _ := testService(t, true, []string{"image"}, "译文")
	base := ExecuteCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: repo.source.Source.ImageRequestID, SourceID: repo.source.Source.SourceID, SourceRevision: 1}
	for _, bad := range []string{"zh_cn", "ZH-cn", " zh-CN", ""} {
		c := base
		c.TargetLocale = bad
		if _, err := service.TranslateText(context.Background(), c); !errors.Is(err, ErrInvalid) {
			t.Fatalf("locale %q error=%v", bad, err)
		}
	}
	base.TargetLocale = "zh-CN"
	result, err := service.TranslateText(context.Background(), base)
	if err != nil || result.TargetLocale != "zh-CN" || result.Text != "译文" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

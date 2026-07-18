package rpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestKnowledgeConfigMutationRequiresPrincipalAndBindsCallerScope(t *testing.T) {
	now := time.Now().UTC()
	fixture := knowledge.Config{
		OwnerID: "owner-knowledge", BindingID: uuid.NewString(),
		Spec: knowledge.ConfigSpec{DeploymentID: uuid.NewString(), ManagedServiceID: uuid.NewString(), RecipeDigest: knowledge.SHA256([]byte("recipe")),
			EmbeddingProfileID: knowledge.LocalMultilingualE5SmallProfileID, Enabled: true},
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	coordinator := &knowledgeCoordinatorStub{config: fixture}
	service := NewKnowledgeService(coordinator)
	request := &agentv1.PutKnowledgeConfigRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: fixture.OwnerID, BindingId: fixture.BindingID,
		Spec: &agentv1.KnowledgeConfigSpec{DeploymentId: fixture.Spec.DeploymentID, ManagedServiceId: fixture.Spec.ManagedServiceID,
			RecipeDigest: fixture.Spec.RecipeDigest, EmbeddingProfileId: fixture.Spec.EmbeddingProfileID, Enabled: false},
		ExpectedRevision: fixture.Revision,
	}
	if _, err := service.PutKnowledgeConfig(context.Background(), request); status.Code(err) != codes.Unauthenticated || coordinator.putCalls != 0 {
		t.Fatalf("unauthenticated mutation err=%v calls=%d", err, coordinator.putCalls)
	}
	principal := auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString(), Scopes: map[string]struct{}{"knowledge.write": {}}}
	response, err := service.PutKnowledgeConfig(auth.ContextWithPrincipal(context.Background(), principal), request)
	if err != nil || response.GetConfig().GetBindingId() != fixture.BindingID || coordinator.putCalls != 1 {
		t.Fatalf("response=%+v err=%v calls=%d", response, err, coordinator.putCalls)
	}
	if coordinator.scope.ClientID != principal.ClientID || coordinator.scope.CredentialID != principal.CredentialID || coordinator.put.OwnerID != fixture.OwnerID {
		t.Fatalf("mutation scope/command not bound: scope=%+v command=%+v", coordinator.scope, coordinator.put)
	}
}

func TestPublicKnowledgeConfigMutationIsUpdateOnlyAndOwnerBound(t *testing.T) {
	t.Parallel()
	fixture := knowledge.Config{
		OwnerID: "owner-knowledge", BindingID: uuid.NewString(), Revision: 1,
		Spec: knowledge.ConfigSpec{DeploymentID: uuid.NewString(), ManagedServiceID: uuid.NewString(),
			RecipeDigest: knowledge.SHA256([]byte("recipe")), EmbeddingProfileID: knowledge.LocalMultilingualE5SmallProfileID, Enabled: true},
	}
	principal := auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString(), Scopes: map[string]struct{}{"knowledge.write": {}}}
	ctx := auth.ContextWithPrincipal(context.Background(), principal)
	base := &agentv1.PutKnowledgeConfigRequest{IdempotencyKey: uuid.NewString(), OwnerId: fixture.OwnerID, BindingId: fixture.BindingID,
		ExpectedRevision: 1, Spec: &agentv1.KnowledgeConfigSpec{DeploymentId: fixture.Spec.DeploymentID,
			ManagedServiceId: fixture.Spec.ManagedServiceID, RecipeDigest: fixture.Spec.RecipeDigest,
			EmbeddingProfileId: fixture.Spec.EmbeddingProfileID, Enabled: false}}
	for name, mutate := range map[string]func(*agentv1.PutKnowledgeConfigRequest){
		"create":        func(value *agentv1.PutKnowledgeConfigRequest) { value.ExpectedRevision = 0 },
		"other owner":   func(value *agentv1.PutKnowledgeConfigRequest) { value.OwnerId = "owner-other" },
		"other binding": func(value *agentv1.PutKnowledgeConfigRequest) { value.BindingId = uuid.NewString() },
		"identity drift": func(value *agentv1.PutKnowledgeConfigRequest) {
			value.Spec.DeploymentId = uuid.NewString()
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := proto.Clone(base).(*agentv1.PutKnowledgeConfigRequest)
			mutate(request)
			coordinator := &knowledgeCoordinatorStub{config: fixture}
			if _, err := NewKnowledgeService(coordinator).PutKnowledgeConfig(ctx, request); status.Code(err) != codes.FailedPrecondition && status.Code(err) != codes.NotFound {
				t.Fatalf("public selector error=%v", err)
			}
			if coordinator.putCalls != 0 {
				t.Fatal("rejected public selector reached mutation")
			}
		})
	}
}

func TestKnowledgeErrorsNeverEchoQueryContentBackendOrSecretDiagnostics(t *testing.T) {
	const canary = "query-canary-sk-0123456789abcdefghijklmnopqrstuvwxyz"
	coordinator := &knowledgeCoordinatorStub{err: errors.New("backend https://private.example.test rejected " + canary)}
	service := NewKnowledgeService(coordinator)
	_, err := service.SearchKnowledge(context.Background(), &agentv1.SearchKnowledgeRequest{
		OwnerId: "owner-knowledge", BindingId: uuid.NewString(), ExpectedBindingRevision: 1, Query: canary, Limit: 5,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, err = %v", status.Code(err), err)
	}
	message := status.Convert(err).Message()
	for _, forbidden := range []string{canary, "sk-", "private.example.test", "https://"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("public error disclosed %q: %q", forbidden, message)
		}
	}
}

func TestKnowledgeConfigDefaultResolutionAndAmbiguityArePubliclyBounded(t *testing.T) {
	fixture := knowledge.Config{OwnerID: "owner-knowledge", BindingID: uuid.NewString(), Revision: 1}
	coordinator := &knowledgeCoordinatorStub{config: fixture}
	service := NewKnowledgeService(coordinator)
	response, err := service.GetKnowledgeConfig(context.Background(), &agentv1.GetKnowledgeConfigRequest{OwnerId: fixture.OwnerID})
	if err != nil || response.GetConfig().GetBindingId() != fixture.BindingID || coordinator.getBindingID != "" {
		t.Fatalf("response=%+v binding=%q err=%v", response, coordinator.getBindingID, err)
	}
	coordinator.err = knowledge.ErrAmbiguousConfig
	if _, err := service.GetKnowledgeConfig(context.Background(), &agentv1.GetKnowledgeConfigRequest{OwnerId: fixture.OwnerID}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ambiguous config code=%v err=%v", status.Code(err), err)
	}
}

type knowledgeCoordinatorStub struct {
	config       knowledge.Config
	err          error
	putCalls     int
	scope        knowledge.MutationScope
	put          knowledge.PutConfigCommand
	getBindingID string
	getOwnerID   string
}

func (stub *knowledgeCoordinatorStub) Capabilities(string) (knowledge.Capabilities, error) {
	return knowledge.Capabilities{}, stub.err
}

func (stub *knowledgeCoordinatorStub) GetConfig(_ context.Context, ownerID string, bindingID string) (knowledge.Config, error) {
	stub.getOwnerID, stub.getBindingID = ownerID, bindingID
	if stub.err == nil && (stub.config.OwnerID != ownerID || (bindingID != "" && stub.config.BindingID != bindingID)) {
		return knowledge.Config{}, knowledge.ErrNotFound
	}
	return stub.config, stub.err
}
func (stub *knowledgeCoordinatorStub) PutConfig(_ context.Context, scope knowledge.MutationScope, command knowledge.PutConfigCommand) (knowledge.Config, error) {
	stub.putCalls++
	stub.scope, stub.put = scope, command
	return stub.config, stub.err
}
func (stub *knowledgeCoordinatorStub) ListSources(context.Context, knowledge.ListSourcesQuery) (knowledge.SourcePage, error) {
	return knowledge.SourcePage{}, stub.err
}
func (stub *knowledgeCoordinatorStub) StartAttachmentUpload(context.Context, knowledge.MutationScope, knowledge.StartAttachmentUploadCommand) (knowledge.AttachmentUpload, error) {
	return knowledge.AttachmentUpload{}, stub.err
}
func (stub *knowledgeCoordinatorStub) AppendAttachmentChunk(context.Context, knowledge.MutationScope, knowledge.AppendAttachmentChunkCommand) (knowledge.AttachmentUpload, error) {
	return knowledge.AttachmentUpload{}, stub.err
}
func (stub *knowledgeCoordinatorStub) CommitAttachmentUpload(context.Context, knowledge.MutationScope, knowledge.CommitAttachmentUploadCommand) (knowledge.AttachmentUpload, knowledge.Source, error) {
	return knowledge.AttachmentUpload{}, knowledge.Source{}, stub.err
}
func (stub *knowledgeCoordinatorStub) CreateMemory(context.Context, knowledge.MutationScope, knowledge.CreateMemoryCommand) (knowledge.Source, error) {
	return knowledge.Source{}, stub.err
}
func (stub *knowledgeCoordinatorStub) DeleteSource(context.Context, knowledge.MutationScope, knowledge.DeleteSourceCommand) (knowledge.Source, error) {
	return knowledge.Source{}, stub.err
}
func (stub *knowledgeCoordinatorStub) Search(context.Context, knowledge.SearchQuery) (knowledge.SearchResult, error) {
	return knowledge.SearchResult{}, stub.err
}
func (stub *knowledgeCoordinatorStub) Status(context.Context, string, string) (knowledge.Status, error) {
	return knowledge.Status{}, stub.err
}

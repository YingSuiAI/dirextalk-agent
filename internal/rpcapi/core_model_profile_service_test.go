package rpcapi

import (
	"context"
	"strings"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestModelProfileRPCMapsAndRedacts(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	domain, _ := coremodel.NewService(repo, coremodel.ConnectionTesterFunc(func(context.Context, coremodel.Profile) error { return nil }))
	service, _ := NewModelProfileService(domain)
	response, err := service.Create(context.Background(), &agentv1.ModelProfileServiceCreateRequest{IdempotencyKey: "11111111-1111-4111-8111-111111111111", DisplayName: "Primary", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, Model: "test", ApiKey: "rpc-secret", ContextWindow: 32768, ReasoningEffort: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Profile.ApiKeyConfigured == false || strings.Contains(response.Profile.String(), "rpc-secret") {
		t.Fatalf("secret leaked: %#v", response.Profile)
	}
	if response.Profile.ContextWindow != 32768 || response.Profile.ReasoningEffort != "medium" {
		t.Fatalf("profile parameters not mapped: %#v", response.Profile)
	}
	got, err := service.Get(context.Background(), &agentv1.ModelProfileServiceGetRequest{ProfileId: response.Profile.ProfileId})
	if err != nil || got.Profile.ProfileId != response.Profile.ProfileId {
		t.Fatalf("get=%#v err=%v", got, err)
	}
	contextWindow := int32(65536)
	patched, err := service.Update(context.Background(), &agentv1.ModelProfileServiceUpdateRequest{
		IdempotencyKey: "33333333-3333-4333-8333-333333333333", ProfileId: response.Profile.ProfileId, ExpectedRevision: 1,
		ContextWindow: &contextWindow,
	})
	if err != nil || patched.Profile.ContextWindow != 65536 || patched.Profile.DisplayName != "Primary" || patched.Profile.Model != "test" {
		t.Fatalf("one-field patch=%#v err=%v", patched, err)
	}
}

func TestModelProfileRPCRejectsInvalidProviderAndSampling(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	domain, _ := coremodel.NewService(repo, nil)
	service, _ := NewModelProfileService(domain)
	_, err := service.Create(context.Background(), &agentv1.ModelProfileServiceCreateRequest{IdempotencyKey: "22222222-2222-4222-8222-222222222222", DisplayName: "bad", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_UNSPECIFIED, Model: "m", ApiKey: "k"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("provider code=%v err=%v", status.Code(err), err)
	}
	provider := agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE
	_, err = service.Update(context.Background(), &agentv1.ModelProfileServiceUpdateRequest{ProfileId: "bad", Provider: &provider, Temperature: &agentv1.CoreSamplingUpdate{Value: &agentv1.CoreSamplingUpdate_Set{Set: 1}}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("sampling code=%v err=%v", status.Code(err), err)
	}
}

func TestModelProfileRPCTestConnectionIdempotent(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	calls := 0
	domain, _ := coremodel.NewService(repo, coremodel.ConnectionTesterFunc(func(context.Context, coremodel.Profile) error {
		calls++
		return nil
	}))
	service, _ := NewModelProfileService(domain)
	created, err := service.Create(context.Background(), &agentv1.ModelProfileServiceCreateRequest{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", DisplayName: "one", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, Model: "m", ApiKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	key := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	first, err := service.TestConnection(context.Background(), &agentv1.ModelProfileServiceTestConnectionRequest{IdempotencyKey: key, ProfileId: created.Profile.ProfileId})
	if err != nil || !first.Reachable || calls != 1 {
		t.Fatalf("first test=%#v err=%v calls=%d", first, err, calls)
	}
	second, err := service.TestConnection(context.Background(), &agentv1.ModelProfileServiceTestConnectionRequest{IdempotencyKey: key, ProfileId: created.Profile.ProfileId})
	if err != nil || !second.Reachable || calls != 1 {
		t.Fatalf("replay test=%#v err=%v calls=%d", second, err, calls)
	}
	other, err := service.Create(context.Background(), &agentv1.ModelProfileServiceCreateRequest{IdempotencyKey: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", DisplayName: "two", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, Model: "m", ApiKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.TestConnection(context.Background(), &agentv1.ModelProfileServiceTestConnectionRequest{IdempotencyKey: key, ProfileId: other.Profile.ProfileId})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed profile idempotency code=%v err=%v", status.Code(err), err)
	}
}

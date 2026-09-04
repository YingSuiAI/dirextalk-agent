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
	response, err := service.Create(context.Background(), &agentv1.ModelProfileServiceCreateRequest{IdempotencyKey: "11111111-1111-4111-8111-111111111111", DisplayName: "Primary", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), Model: "test", ApiKey: "rpc-secret", ContextWindow: 32768, ReasoningEffort: "medium"})
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
		ContextWindow: &contextWindow, RequestDialect: stringPtrRPC(string(coremodel.DialectOpenAICompatibleChatV1)),
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
	created, err := service.Create(context.Background(), &agentv1.ModelProfileServiceCreateRequest{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", DisplayName: "one", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), Model: "m", ApiKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	key := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	first, err := service.TestConnection(context.Background(), &agentv1.ModelProfileServiceTestConnectionRequest{IdempotencyKey: key, ProfileId: created.Profile.ProfileId})
	if err != nil || !first.Reachable || first.ToolCompatibility.GetStatus() != coremodel.ToolCompatibilityNotRun || calls != 1 {
		t.Fatalf("first test=%#v err=%v calls=%d", first, err, calls)
	}
	second, err := service.TestConnection(context.Background(), &agentv1.ModelProfileServiceTestConnectionRequest{IdempotencyKey: key, ProfileId: created.Profile.ProfileId})
	if err != nil || !second.Reachable || calls != 1 {
		t.Fatalf("replay test=%#v err=%v calls=%d", second, err, calls)
	}
	other, err := service.Create(context.Background(), &agentv1.ModelProfileServiceCreateRequest{IdempotencyKey: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", DisplayName: "two", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), Model: "m", ApiKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.TestConnection(context.Background(), &agentv1.ModelProfileServiceTestConnectionRequest{IdempotencyKey: key, ProfileId: other.Profile.ProfileId})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed profile idempotency code=%v err=%v", status.Code(err), err)
	}
}

func TestToolCompatibilityProtoPreservesBoundedVerdict(t *testing.T) {
	result := toolCompatibilityProto(coremodel.ToolCompatibilityResult{
		Status: coremodel.ToolCompatibilityIncompatible,
		Probes: []coremodel.ToolCompatibilityProbeResult{{Name: "structured_tool_call", Status: "failed", ErrorCode: "structured_tool_call_count"}},
	})
	if result.Status != coremodel.ToolCompatibilityIncompatible || len(result.Probes) != 1 ||
		result.Probes[0].Name != "structured_tool_call" || result.Probes[0].Status != "failed" || result.Probes[0].ErrorCode != "structured_tool_call_count" {
		t.Fatalf("result=%#v", result)
	}
}

type rpcCompatibilityTester struct {
	probeCalls int
}

func (*rpcCompatibilityTester) TestConnection(context.Context, coremodel.Profile) error { return nil }

func (t *rpcCompatibilityTester) TestToolCompatibility(context.Context, coremodel.Profile) coremodel.ToolCompatibilityResult {
	t.probeCalls++
	return coremodel.ToolCompatibilityResult{Status: coremodel.ToolCompatibilityCompatible, Probes: []coremodel.ToolCompatibilityProbeResult{{Name: "structured_tool_call", Status: "passed"}}}
}

func TestModelProfileRPCToolCompatibilityIsExplicit(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	tester := &rpcCompatibilityTester{}
	domain, _ := coremodel.NewService(repo, tester)
	service, _ := NewModelProfileService(domain)
	created, err := service.Create(context.Background(), &agentv1.ModelProfileServiceCreateRequest{IdempotencyKey: "d0000000-0000-4000-8000-000000000001", DisplayName: "probe", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), Model: "m", ApiKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.TestConnection(context.Background(), &agentv1.ModelProfileServiceTestConnectionRequest{IdempotencyKey: "d0000000-0000-4000-8000-000000000002", ProfileId: created.Profile.ProfileId, ProbeToolCompatibility: true})
	if err != nil || result.ToolCompatibility.GetStatus() != coremodel.ToolCompatibilityCompatible || tester.probeCalls != 1 {
		t.Fatalf("result=%#v err=%v probe_calls=%d", result, err, tester.probeCalls)
	}
}

func TestModelProfileRPCSyncPresenceAndOrder(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	domain, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	service, _ := NewModelProfileService(domain)
	first, err := service.Sync(context.Background(), &agentv1.ModelProfileServiceSyncRequest{
		IdempotencyKey:                     "a0000000-0000-4000-8000-000000000040",
		DefaultConversationClientProfileId: "two",
		DefaultToolClientProfileId:         "one",
		Entries: []*agentv1.CoreModelProfileSyncEntry{
			{ClientProfileId: "one", DisplayName: "One", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), ModelKind: coremodel.ModelKindConversation, InputModalities: []string{"text", "image"}, Model: "model", ApiKey: stringPtrRPC("one-secret")},
			{ClientProfileId: "two", DisplayName: "Two", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), Model: "model", ApiKey: stringPtrRPC("two-secret")},
		},
	})
	if err != nil || len(first.Profiles) != 2 || first.Profiles[0].ClientProfileId != "one" || first.Profiles[0].ModelKind != coremodel.ModelKindConversation || len(first.Profiles[0].InputModalities) != 2 || first.DefaultConversationClientProfileId != "two" || first.DefaultToolClientProfileId != "one" {
		t.Fatalf("sync=%+v err=%v", first, err)
	}
	listed, err := service.List(context.Background(), &agentv1.ModelProfileServiceListRequest{PageSize: 10})
	if err != nil || listed.DefaultToolClientProfileId != "one" {
		t.Fatalf("list defaults=%+v err=%v", listed, err)
	}
	if strings.Contains(first.String(), "secret") {
		t.Fatal("sync response leaked API key")
	}
	second, err := service.Sync(context.Background(), &agentv1.ModelProfileServiceSyncRequest{
		IdempotencyKey: "a0000000-0000-4000-8000-000000000041", DefaultConversationClientProfileId: "two",
		Entries: []*agentv1.CoreModelProfileSyncEntry{{ClientProfileId: "two", ExpectedRevision: int64PtrRPC(1), DisplayName: "Two v2", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), Model: "model"}},
	})
	if err != nil || len(second.Profiles) != 1 || second.Profiles[0].Revision != 2 {
		t.Fatalf("preserve sync=%+v err=%v", second, err)
	}
	_, err = service.Sync(context.Background(), &agentv1.ModelProfileServiceSyncRequest{
		IdempotencyKey: "a0000000-0000-4000-8000-000000000042", DefaultConversationClientProfileId: "two",
		Entries: []*agentv1.CoreModelProfileSyncEntry{{ClientProfileId: "two", ExpectedRevision: int64PtrRPC(2), DisplayName: "Two v3", Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE, RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), Model: "model", ApiKey: stringPtrRPC("")}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty present key code=%v err=%v", status.Code(err), err)
	}
}

func TestModelProfileRPCSyncRequiresExplicitRequestDialect(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	domain, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	service, _ := NewModelProfileService(domain)
	_, err = service.Sync(context.Background(), &agentv1.ModelProfileServiceSyncRequest{
		IdempotencyKey: "a0000000-0000-4000-8000-000000000043",
		Entries: []*agentv1.CoreModelProfileSyncEntry{{
			ClientProfileId: "missing-dialect", DisplayName: "Missing dialect",
			Provider: agentv1.CoreModelProvider_CORE_MODEL_PROVIDER_OPENAI_COMPATIBLE,
			Model:    "model", ApiKey: stringPtrRPC("secret"),
		}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("blank request dialect code=%v err=%v", status.Code(err), err)
	}
}

func stringPtrRPC(v string) *string { return &v }
func int64PtrRPC(v int64) *int64    { return &v }

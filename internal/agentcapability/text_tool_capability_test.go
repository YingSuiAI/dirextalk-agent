package agentcapability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type textToolTestRepository struct{}

func (textToolTestRepository) Get(_ context.Context, _ string, _ int64, now time.Time) (coretexttool.Config, error) {
	return coretexttool.DefaultConfig(now), nil
}
func (textToolTestRepository) Update(context.Context, coretexttool.Mutation) (coretexttool.Config, error) {
	return coretexttool.Config{}, coretexttool.ErrRepository
}

type textToolTestModels struct{}

func (textToolTestModels) ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error) {
	return coremodel.Profile{}, coremodel.ErrProfileNotFound
}

func TestTextToolDescriptorCanonicalSchemasAndOwnerAudience(t *testing.T) {
	service, err := coretexttool.NewService(textToolTestRepository{}, textToolTestModels{}, nil, func(coremodel.Profile) (coremodel.Client, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	descriptor := NewCoreTextToolCapability(service).Descriptor()
	if descriptor.GetCapabilityId() != "agent.text_tools.v1" || len(descriptor.GetOperations()) != 3 {
		t.Fatalf("descriptor=%+v", descriptor)
	}
	want := map[string]struct {
		typeValue capv1.OperationType
		inputPin  string
		resultPin string
	}{
		"get_config":    {capv1.OperationType_OPERATION_TYPE_READ, "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa", "ce1c828fed02c65c9ba92123d5e88f8087acec7ca3007c6fb57e6a1aa34eef56"},
		"update_config": {capv1.OperationType_OPERATION_TYPE_MUTATION, "27e28f1ad68d20dc25e63264a830391adcd2fb9b24203fce8b9e311022f87e1e", "ce1c828fed02c65c9ba92123d5e88f8087acec7ca3007c6fb57e6a1aa34eef56"},
		"execute":       {capv1.OperationType_OPERATION_TYPE_MUTATION, "59b37979b65e9e0b1bdc57bae5950f0d53533b10060741be7fc6a36529beb9bf", "fa162b3374031e87711fa47067322839256115b2818d73506e8d99a288c9a316"},
	}
	for _, operation := range descriptor.GetOperations() {
		expected, ok := want[operation.GetOperationId()]
		if !ok || operation.GetOperationType() != expected.typeValue {
			t.Fatalf("unexpected operation %+v", operation)
		}
		inputDigest, resultDigest := sha256.Sum256([]byte(operation.GetInputSchemaJson())), sha256.Sum256([]byte(operation.GetResultSchemaJson()))
		if hex.EncodeToString(inputDigest[:]) != expected.inputPin || hex.EncodeToString(resultDigest[:]) != expected.resultPin || hex.EncodeToString(operation.GetInputSchemaDigest()) != expected.inputPin || hex.EncodeToString(operation.GetResultSchemaDigest()) != expected.resultPin {
			t.Fatalf("schema pin drift for %s", operation.GetOperationId())
		}
		if len(operation.GetAudience()) != 1 || operation.GetAudience()[0] != capv1.Audience_AUDIENCE_OWNER_CLIENT {
			t.Fatalf("unsafe audience for %s: %v", operation.GetOperationId(), operation.GetAudience())
		}
	}
}

func TestTextToolGetConfigUsesPermissionIdentityAndRejectsExtraInput(t *testing.T) {
	service, _ := coretexttool.NewService(textToolTestRepository{}, textToolTestModels{}, nil, func(coremodel.Profile) (coremodel.Client, error) { return nil, nil })
	capability := NewCoreTextToolCapability(service)
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{ChainId: "00000000-0000-4000-8000-000000000001", RootOperationId: "00000000-0000-4000-8000-000000000002"}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1})
	raw, err := capability.HandleOperation(ctx, "get_config", []byte(`{}`))
	if err != nil || len(raw) == 0 {
		t.Fatalf("get config raw=%s err=%v", raw, err)
	}
	if _, err = capability.HandleOperation(ctx, "get_config", []byte(`{"owner_id":"other"}`)); err == nil {
		t.Fatal("identity-bearing extra input accepted")
	}
}

func TestTextToolUpdateRequiresEveryCanonicalField(t *testing.T) {
	service, _ := coretexttool.NewService(textToolTestRepository{}, textToolTestModels{}, nil, func(coremodel.Profile) (coremodel.Client, error) { return nil, nil })
	capability := NewCoreTextToolCapability(service)
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{ChainId: "00000000-0000-4000-8000-000000000001", RootOperationId: "00000000-0000-4000-8000-000000000002"}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1})
	for _, raw := range []string{
		`{"idempotency_key":"00000000-0000-4000-8000-000000000003","enabled":false,"tools":[]}`,
		`{"idempotency_key":"00000000-0000-4000-8000-000000000003","expected_revision":0,"tools":[]}`,
		`{"idempotency_key":"00000000-0000-4000-8000-000000000003","expected_revision":0,"enabled":false}`,
	} {
		if _, err := capability.HandleOperation(ctx, "update_config", []byte(raw)); err == nil {
			t.Fatalf("missing required field accepted: %s", raw)
		}
	}
}

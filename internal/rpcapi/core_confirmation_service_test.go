package rpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

func TestConfirmationProtoPreservesNonCloudSecretGrantDescriptors(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	d := coreconfirmation.Digest(strings.Repeat("a", 64))
	c := coreconfirmation.Confirmation{ConfirmationID: id, Binding: coreconfirmation.Binding{OperationDomain: "aws", TargetID: id, TargetRevision: 1, SourceVersion: "v1", ContentDigest: d, ParameterDigest: d, NetworkDigest: d, SecretGrantDigest: d, SecretGrants: []coreconfirmation.SecretGrant{{ReferenceID: id, Purpose: coreconfirmation.SecretPurposeAWSCredential, BindingDigest: d}}}}
	out := confirmationProto(c)
	if len(out.GetBinding().GetSecretGrants()) != 1 || out.GetBinding().GetSecretGrants()[0].GetReferenceId() != id || out.GetBinding().GetSecretGrants()[0].GetPurpose() != agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_AWS_CREDENTIAL {
		t.Fatalf("secret grants not mapped: %+v", out.GetBinding().GetSecretGrants())
	}
}

func cloudWorkerRPCBinding(t *testing.T) coreconfirmation.Binding {
	t.Helper()
	d := coreconfirmation.Digest(strings.Repeat("a", 64))
	executionID := "11111111-1111-4111-8111-111111111111"
	binding := coreconfirmation.Binding{
		OwnerID: "@owner:example.test", AccountGeneration: 7, OperationDomain: "cloud_worker.execute",
		TargetID: executionID, TargetRevision: 1, TargetKind: "ephemeral_pi_worker",
		SourceVersion: "ephemeral-pi-task", SourceCommit: strings.Repeat("b", 64),
		ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, PermissionDigest: d,
		ParameterDigest: d, NetworkDigest: d, SecretGrantDigest: d, SelectedTool: "cloud_worker.propose",
		SelectedCommand: []string{}, NetworkGrants: []string{"controlled_https_egress"},
		SecretGrants: []coreconfirmation.SecretGrant{
			{ReferenceID: "22222222-2222-4222-8222-222222222222", Purpose: coreconfirmation.SecretPurposeModelAPIKey, BindingDigest: d},
			{ReferenceID: "33333333-3333-4333-8333-333333333333", Purpose: coreconfirmation.SecretPurposeModelAPIKey, BindingDigest: d},
		},
		ExecutionID: executionID, PlanID: "44444444-4444-4444-8444-444444444444", PlanRevision: 1,
		PlanDigest: d, RunID: executionID, RunRevision: 1, RunDigest: d, QuoteDigest: d,
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	binding.Digest = coreconfirmation.Digest(hex.EncodeToString(sum[:]))
	normalized, err := binding.Normalize()
	if err != nil {
		t.Fatalf("cloud binding: %v", err)
	}
	return normalized
}

type confirmationRPCRepository struct {
	*coreconfirmation.MemoryRepository
}

func (r *confirmationRPCRepository) Confirm(ctx context.Context, command coreconfirmation.ConfirmCommand) (coreconfirmation.Confirmation, error) {
	binding, err := r.ReadTargetBinding(ctx, command.ConfirmationID)
	if err != nil {
		return coreconfirmation.Confirmation{}, err
	}
	command.Binding = binding
	command.ResolveBinding = nil
	return r.MemoryRepository.Confirm(ctx, command)
}

func newCloudWorkerConfirmationRPC(t *testing.T) (*CoreConfirmationService, coreconfirmation.Confirmation) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	repository := &confirmationRPCRepository{MemoryRepository: coreconfirmation.NewMemoryRepository(func() time.Time { return now })}
	service, err := coreconfirmation.NewService(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := service.Request(context.Background(), coreconfirmation.RequestCommand{
		IdempotencyKey: "55555555-5555-4555-8555-555555555555", Binding: cloudWorkerRPCBinding(t),
		TaskID: "66666666-6666-4666-8666-666666666666", ExpiresAt: now.Add(time.Hour), At: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	rpc, err := NewCoreConfirmationService(service)
	if err != nil {
		t.Fatal(err)
	}
	return rpc, confirmation
}

func assertCloudWorkerConfirmationIsPurposeOnly(t *testing.T, value *agentv1.CoreConfirmation, expected coreconfirmation.Confirmation) {
	t.Helper()
	if value == nil || value.GetConfirmationId() != expected.ConfirmationID {
		t.Fatalf("confirmation identity=%v", value)
	}
	binding := value.GetBinding()
	if binding.GetDigest() != string(expected.Binding.Digest) || binding.GetSecretGrantDigest() != string(expected.Binding.SecretGrantDigest) {
		t.Fatalf("aggregate authorization digests were not preserved: %+v", binding)
	}
	grants := binding.GetSecretGrants()
	if len(grants) != 1 || grants[0].GetPurpose() != agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_MODEL_API_KEY || grants[0].GetReferenceId() != "" || grants[0].GetBindingDigest() != "" {
		t.Fatalf("Cloud Worker secret grants are not purpose-only: %+v", grants)
	}
}

func TestCloudWorkerConfirmationRPCsExposePurposeOnlySecretGrants(t *testing.T) {
	tests := []struct {
		name string
		call func(context.Context, *CoreConfirmationService, coreconfirmation.Confirmation) (*agentv1.CoreConfirmation, error)
	}{
		{name: "get", call: func(ctx context.Context, service *CoreConfirmationService, confirmation coreconfirmation.Confirmation) (*agentv1.CoreConfirmation, error) {
			response, err := service.Get(ctx, &agentv1.ConfirmationServiceGetRequest{ConfirmationId: confirmation.ConfirmationID})
			return response.GetConfirmation(), err
		}},
		{name: "list", call: func(ctx context.Context, service *CoreConfirmationService, _ coreconfirmation.Confirmation) (*agentv1.CoreConfirmation, error) {
			response, err := service.List(ctx, &agentv1.ConfirmationServiceListRequest{PageSize: 10, OperationDomain: "cloud_worker.execute"})
			if err != nil || len(response.GetConfirmations()) != 1 {
				return nil, err
			}
			return response.GetConfirmations()[0], nil
		}},
		{name: "confirm", call: func(ctx context.Context, service *CoreConfirmationService, confirmation coreconfirmation.Confirmation) (*agentv1.CoreConfirmation, error) {
			response, err := service.Confirm(ctx, &agentv1.ConfirmationServiceConfirmRequest{ConfirmationId: confirmation.ConfirmationID, IdempotencyKey: "77777777-7777-4777-8777-777777777777", ExpectedRevision: confirmation.Revision})
			return response.GetConfirmation(), err
		}},
		{name: "reject", call: func(ctx context.Context, service *CoreConfirmationService, confirmation coreconfirmation.Confirmation) (*agentv1.CoreConfirmation, error) {
			response, err := service.Reject(ctx, &agentv1.ConfirmationServiceRejectRequest{ConfirmationId: confirmation.ConfirmationID, IdempotencyKey: "88888888-8888-4888-8888-888888888888", ExpectedRevision: confirmation.Revision, Reason: "user_rejected"})
			return response.GetConfirmation(), err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, confirmation := newCloudWorkerConfirmationRPC(t)
			value, err := test.call(context.Background(), service, confirmation)
			if err != nil {
				t.Fatal(err)
			}
			assertCloudWorkerConfirmationIsPurposeOnly(t, value, confirmation)
		})
	}
}

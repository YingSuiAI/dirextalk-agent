package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/google/uuid"
)

func TestRootHelperApprovalBuildsAuthorityBindingAndExactApproveReplayBeatsFreshness(t *testing.T) {
	now := time.Date(2026, 7, 17, 17, 0, 0, 0, time.UTC)
	devicePublic, devicePrivate, _ := ed25519.GenerateKey(nil)
	deriver, _ := helperkey.NewDeterministicKeyDeriver(bytes.Repeat([]byte{0x71}, 32))
	approvalStore := helperkey.NewMemoryApprovalRepository()
	approvals, _ := helperkey.NewApprovalService(approvalStore,
		rootHelperDeviceVerifierFake{key: devicePublic}, deriver, func() time.Time { return now })
	publisher := &rootHelperPublisherFake{}
	deliveries, _ := helperkey.NewService(helperkey.NewMemoryRepository(), publisher, rootHelperRevokerFake{},
		func() time.Time { return now }, helperkey.WithApprovedKeyDelivery(approvals, deriver))
	facts := rootHelperBindingFacts{
		AgentInstanceID: uuid.NewString(), OwnerID: "owner-helper", DeploymentID: uuid.NewString(),
		DeploymentRevision: 7, InstanceID: "i-0123456789abcdef0",
		WorkerRoleARN:     "arn:aws:iam::123456789012:role/dtx-worker",
		WorkerPrincipalID: "AROAABCDEFGHIJKLMNOP:i-0123456789abcdef0",
		Partition:         "aws", AccountID: "123456789012", Region: "us-east-1",
		FoundationKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-4234-8234-123456789abc",
	}
	authority := &rootHelperAuthorityFake{facts: facts}
	coordinator, _ := newRootHelperApprovalCoordinator(authority, approvals, deliveries)
	scope := rpcapi.RootHelperKeyApprovalScope{
		Caller:  cloudapp.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
		OwnerID: facts.OwnerID, DeploymentID: facts.DeploymentID, ExpectedDeploymentRevision: facts.DeploymentRevision,
	}
	prepared, err := coordinator.Prepare(context.Background(), scope, helperkey.PrepareApprovalRequest{
		DeviceSignerKeyID: "device-1", IdempotencyKey: uuid.NewString(),
	})
	if err != nil || prepared.Binding.InstanceID != facts.InstanceID ||
		prepared.Binding.SecretPlan.KMSKeyARN != facts.FoundationKMSKeyARN || publisher.creates != 0 {
		t.Fatalf("prepared=%+v err=%v creates=%d", prepared, err, publisher.creates)
	}
	approveKey := uuid.NewString()
	request := helperkey.ApproveBindingRequest{
		DeliveryID: prepared.Binding.DeliveryID, IdempotencyKey: approveKey, ExpectedRevision: prepared.Revision,
		DeviceSignature: ed25519.Sign(devicePrivate, prepared.SigningPayloadCBOR),
	}
	approved, err := coordinator.Approve(context.Background(), scope, request)
	if err != nil || approved.Status != helperkey.ApprovalApproved || publisher.creates != 1 || publisher.grants != 1 {
		t.Fatalf("approved=%+v err=%v creates=%d grants=%d", approved, err, publisher.creates, publisher.grants)
	}
	authority.err = errors.New("deployment changed")
	replayed, err := coordinator.Approve(context.Background(), scope, request)
	if err != nil || replayed.Revision != approved.Revision || publisher.creates != 1 || publisher.grants != 1 {
		t.Fatalf("replayed=%+v err=%v creates=%d grants=%d", replayed, err, publisher.creates, publisher.grants)
	}
}

type rootHelperAuthorityFake struct {
	facts rootHelperBindingFacts
	err   error
}

func (fake *rootHelperAuthorityFake) ResolveRootHelperBinding(context.Context, string, string, int64) (rootHelperBindingFacts, error) {
	return fake.facts, fake.err
}

type rootHelperDeviceVerifierFake struct{ key ed25519.PublicKey }

func (fake rootHelperDeviceVerifierFake) VerifyRootHelperKeyApproval(_ context.Context, _ string, _ string,
	payload, signature []byte) error {
	if !ed25519.Verify(fake.key, payload, signature) {
		return helperkey.ErrInvalid
	}
	return nil
}

type rootHelperPublisherFake struct{ creates, grants int }

func (fake *rootHelperPublisherFake) CreateRootHelperKey(_ context.Context, binding helperkey.DeviceBinding,
	_ []byte) (helperkey.SecretCoordinate, error) {
	fake.creates++
	return helperkey.SecretCoordinate{
		ARN: "arn:" + binding.SecretPlan.Partition + ":secretsmanager:" + binding.SecretPlan.Region + ":" +
			binding.SecretPlan.AccountID + ":secret:" + binding.SecretPlan.Name + "-suffix",
		Name: binding.SecretPlan.Name, VersionID: binding.SecretPlan.VersionID, KMSKeyARN: binding.SecretPlan.KMSKeyARN,
	}, nil
}

func (fake *rootHelperPublisherFake) GrantRootHelperKey(context.Context, helperkey.DeviceBinding) error {
	fake.grants++
	return nil
}

type rootHelperRevokerFake struct{}

func (rootHelperRevokerFake) DenyRootHelperKey(context.Context, helperkey.DeviceBinding) error {
	return nil
}
func (rootHelperRevokerFake) ReadBackRootHelperKeyDenied(context.Context, helperkey.DeviceBinding) (bool, error) {
	return true, nil
}

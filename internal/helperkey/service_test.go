package helperkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeliveryRequiresPossessionExactRevokeAndSamePrincipalCanary(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	devicePublic, devicePrivate, _ := ed25519.GenerateKey(nil)
	publisher := &publisherFake{}
	revoker := &revokerFake{readbacksBeforeDenied: 1}
	binding := testBinding()
	deriver, _ := NewDeterministicKeyDeriver(bytes.Repeat([]byte{0x41}, 32))
	approvals, _ := NewApprovalService(NewMemoryApprovalRepository(), approvalDeviceVerifier{key: devicePublic}, deriver, func() time.Time { return now })
	prepared, _ := approvals.Prepare(context.Background(), PrepareApprovalRequest{Binding: binding, DeviceSignerKeyID: "device-1", IdempotencyKey: uuid.NewString()})
	approved, _ := approvals.Approve(context.Background(), ApproveBindingRequest{DeliveryID: binding.DeliveryID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: prepared.Revision, DeviceSignature: ed25519.Sign(devicePrivate, prepared.SigningPayloadCBOR)})
	if approved.Status != ApprovalApproved {
		t.Fatal("approval failed")
	}
	service, _ := NewService(NewMemoryRepository(), publisher, revoker, func() time.Time { return now },
		WithApprovedKeyDelivery(approvals, deriver))
	draft, err := service.Draft(context.Background(), DraftRequest{Binding: binding, IdempotencyKey: uuid.NewString()})
	if err != nil || draft.State != StateDraft || len(publisher.private) != ed25519.PrivateKeySize {
		t.Fatalf("draft=%+v err=%v", draft, err)
	}
	payload, _ := draft.Binding.SigningPayload()
	granted, err := service.Grant(context.Background(), GrantRequest{
		DeliveryID: draft.Binding.DeliveryID, IdempotencyKey: uuid.NewString(), DeviceSignature: ed25519.Sign(devicePrivate, payload),
	})
	if err != nil || granted.State != StateGrant || publisher.grants != 1 {
		t.Fatalf("grant=%+v err=%v", granted, err)
	}
	proofPayload, _ := PossessionPayload(granted.Binding, granted.Nonce)
	proof, err := service.SubmitProof(context.Background(), ProofRequest{
		DeliveryID: granted.Binding.DeliveryID, InstanceID: granted.Binding.InstanceID,
		PrincipalID: granted.Binding.WorkerPrincipalID, IdempotencyKey: uuid.NewString(),
		Signature: ed25519.Sign(ed25519.PrivateKey(publisher.private), proofPayload),
	}, granted.Nonce)
	if err != nil || proof.State != StateProof {
		t.Fatalf("proof=%+v err=%v", proof, err)
	}
	revokeKey := uuid.NewString()
	if _, err := service.ReconcileRevocation(context.Background(), proof.Binding.DeliveryID, revokeKey); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("propagation delay err=%v", err)
	}
	revoked, err := service.ReconcileRevocation(context.Background(), proof.Binding.DeliveryID, revokeKey)
	if err != nil || revoked.State != StateVerifiedRevoked || revoker.denyCalls != 2 {
		t.Fatalf("revoked=%+v err=%v calls=%d", revoked, err, revoker.denyCalls)
	}
	canaryPayload, _ := CanaryPayload(revoked.Binding, now)
	wrong := CanaryRequest{DeliveryID: revoked.Binding.DeliveryID, InstanceID: revoked.Binding.InstanceID,
		PrincipalID: "AROAOTHER:" + revoked.Binding.InstanceID, ErrorCode: "AccessDeniedException", ObservedAt: now,
		IdempotencyKey: uuid.NewString(), Signature: ed25519.Sign(ed25519.PrivateKey(publisher.private), canaryPayload)}
	if _, err := service.ConfirmCanary(context.Background(), wrong); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-principal canary err=%v", err)
	}
	wrong.PrincipalID, wrong.IdempotencyKey = revoked.Binding.WorkerPrincipalID, uuid.NewString()
	ready, err := service.ConfirmCanary(context.Background(), wrong)
	if err != nil || ready.State != StateReady {
		t.Fatalf("ready=%+v err=%v", ready, err)
	}
}

func TestRotationRejectsOldPrivateKeyAndReplayIsExact(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	devicePublic, devicePrivate, _ := ed25519.GenerateKey(nil)
	repository := NewMemoryRepository()
	publisher := &publisherFake{}
	deriver, _ := NewDeterministicKeyDeriver(bytes.Repeat([]byte{0x42}, 32))
	approvals, _ := NewApprovalService(NewMemoryApprovalRepository(), approvalDeviceVerifier{key: devicePublic}, deriver, func() time.Time { return now })
	service, _ := NewService(repository, publisher, &revokerFake{}, func() time.Time { return now },
		WithApprovedKeyDelivery(approvals, deriver))
	first := testBinding()
	firstPrepared, _ := approvals.Prepare(context.Background(), PrepareApprovalRequest{Binding: first, DeviceSignerKeyID: "device-1", IdempotencyKey: uuid.NewString()})
	_, _ = approvals.Approve(context.Background(), ApproveBindingRequest{DeliveryID: first.DeliveryID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: firstPrepared.Revision, DeviceSignature: ed25519.Sign(devicePrivate, firstPrepared.SigningPayloadCBOR)})
	firstDraftKey := uuid.NewString()
	firstDraft, _ := service.Draft(context.Background(), DraftRequest{Binding: first, IdempotencyKey: firstDraftKey})
	replayed, err := service.Draft(context.Background(), DraftRequest{Binding: first, IdempotencyKey: firstDraftKey})
	if err != nil || replayed.Binding.PublicKeyDigest != firstDraft.Binding.PublicKeyDigest || publisher.creates != 1 {
		t.Fatalf("draft replay=%+v err=%v creates=%d", replayed, err, publisher.creates)
	}
	oldPrivate := bytes.Clone(publisher.private)
	second := testBinding()
	second.DeliveryID, second.SignerKeyID = uuid.NewString(), "root-helper-2"
	second.SecretPlan.VersionID = second.DeliveryID
	secondPrepared, _ := approvals.Prepare(context.Background(), PrepareApprovalRequest{Binding: second, DeviceSignerKeyID: "device-1", IdempotencyKey: uuid.NewString()})
	_, _ = approvals.Approve(context.Background(), ApproveBindingRequest{DeliveryID: second.DeliveryID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: secondPrepared.Revision, DeviceSignature: ed25519.Sign(devicePrivate, secondPrepared.SigningPayloadCBOR)})
	secondDraft, _ := service.Draft(context.Background(), DraftRequest{Binding: second, IdempotencyKey: uuid.NewString()})
	payload, _ := secondDraft.Binding.SigningPayload()
	secondGranted, _ := service.Grant(context.Background(), GrantRequest{
		DeliveryID: secondDraft.Binding.DeliveryID, IdempotencyKey: uuid.NewString(), DeviceSignature: ed25519.Sign(devicePrivate, payload),
	})
	proofPayload, _ := PossessionPayload(secondGranted.Binding, secondGranted.Nonce)
	if _, err := service.SubmitProof(context.Background(), ProofRequest{
		DeliveryID: secondGranted.Binding.DeliveryID, InstanceID: secondGranted.Binding.InstanceID,
		PrincipalID: secondGranted.Binding.WorkerPrincipalID, IdempotencyKey: uuid.NewString(),
		Signature: ed25519.Sign(ed25519.PrivateKey(oldPrivate), proofPayload),
	}, secondGranted.Nonce); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rotated delivery accepted old key: %v", err)
	}
	clear(oldPrivate)
}

type deviceVerifier struct{ key ed25519.PublicKey }

func (v deviceVerifier) VerifyDeviceBinding(_ context.Context, binding DeviceBinding, signature []byte) error {
	payload, err := binding.SigningPayload()
	if err != nil || !ed25519.Verify(v.key, payload, signature) {
		return ErrInvalid
	}
	return nil
}

type approvalDeviceVerifier struct{ key ed25519.PublicKey }

func (v approvalDeviceVerifier) VerifyRootHelperKeyApproval(_ context.Context, _ string, _ string, payload, signature []byte) error {
	if !ed25519.Verify(v.key, payload, signature) {
		return ErrInvalid
	}
	return nil
}

type publisherFake struct {
	private         []byte
	creates, grants int
}

func (p *publisherFake) CreateRootHelperKey(_ context.Context, binding DeviceBinding, private []byte) (SecretCoordinate, error) {
	p.creates++
	p.private = bytes.Clone(private)
	name := "dtx/" + binding.AgentInstanceID + "/deployments/" + binding.DeploymentID + "/" + SecretSlot
	return SecretCoordinate{ARN: "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + name + "-Ab12Cd", Name: name, VersionID: binding.DeliveryID, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/key"}, nil
}
func (p *publisherFake) GrantRootHelperKey(context.Context, DeviceBinding) error {
	p.grants++
	return nil
}

type revokerFake struct{ readbacksBeforeDenied, reads, denyCalls int }

func (r *revokerFake) DenyRootHelperKey(context.Context, DeviceBinding) error {
	r.denyCalls++
	return nil
}
func (r *revokerFake) ReadBackRootHelperKeyDenied(context.Context, DeviceBinding) (bool, error) {
	r.reads++
	return r.reads > r.readbacksBeforeDenied, nil
}

func testBinding() DeviceBinding {
	instance := "i-0123456789abcdef0"
	agentID, deploymentID, deliveryID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	return DeviceBinding{SchemaVersion: SchemaV1, AgentInstanceID: agentID, OwnerID: "owner-helper",
		DeliveryID: deliveryID, DeploymentID: deploymentID, BindingRevision: 1,
		InstanceID: instance, WorkerRoleARN: "arn:aws:iam::123456789012:role/worker", WorkerPrincipalID: "AROATESTROLEIDENTIFIER:" + instance,
		HelperID: "root-helper", SignerKeyID: "root-helper-1",
		SecretPlan: SecretPlan{Partition: "aws", AccountID: "123456789012", Region: "us-west-2",
			Name: "dtx/" + agentID + "/deployments/" + deploymentID + "/" + SecretSlot, VersionID: deliveryID,
			KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/key", TargetPath: SecretTarget, FileMode: SecretMode}}
}

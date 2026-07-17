package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

func TestRootHelperBootstrapGatesActivationOnRealSamePrincipalAccessDenied(t *testing.T) {
	record, privateKey, service, revoker := helperDeliveryFixture(t)
	source := helperSource(record)
	secrets := &helperSecretAccessFake{privateKey: privateKey, revoker: revoker}
	files := &helperFileFake{}
	control := helperControlAdapter{service: service}
	bootstrap, _ := NewRootHelperKeyBootstrap(secrets, files, control, staticPrincipal(source.WorkerPrincipalID), func() time.Time {
		return time.Date(2026, 7, 17, 10, 0, 1, 0, time.UTC)
	})
	bootstrap.wait = func(context.Context, time.Duration) error { return nil }
	if err := bootstrap.Bootstrap(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	final, _ := service.Get(context.Background(), source.DeliveryID)
	if final.State != helperkey.StateReady || files.spec != (SecretFileSpec{
		Path: helperkey.SecretTarget, Mode: 0o400, UID: 0, GID: 0, VersionID: source.VersionID,
	}) ||
		secrets.canaries != 1 || revoker.reads < 2 {
		t.Fatalf("final=%+v file=%+v canaries=%d policy_reads=%d", final, files.spec, secrets.canaries, revoker.reads)
	}
}

func TestRootHelperBootstrapRejectsCrossPrincipalAndNonDeniedCanary(t *testing.T) {
	for name, configure := range map[string]func(*RootHelperKeyBootstrap, *helperSecretAccessFake){
		"cross principal": func(value *RootHelperKeyBootstrap, _ *helperSecretAccessFake) {
			value.identity = staticPrincipal("AROAOTHER:i-0123456789abcdef0")
		},
		"canary still readable": func(_ *RootHelperKeyBootstrap, secrets *helperSecretAccessFake) {
			secrets.forceReadable = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			record, privateKey, service, revoker := helperDeliveryFixture(t)
			source := helperSource(record)
			secrets := &helperSecretAccessFake{privateKey: privateKey, revoker: revoker}
			files := &helperFileFake{}
			bootstrap, _ := NewRootHelperKeyBootstrap(secrets, files, helperControlAdapter{service: service}, staticPrincipal(source.WorkerPrincipalID), func() time.Time {
				return time.Date(2026, 7, 17, 10, 0, 1, 0, time.UTC)
			})
			bootstrap.wait = func(context.Context, time.Duration) error { return nil }
			configure(bootstrap, secrets)
			if err := bootstrap.Bootstrap(context.Background(), source); !errors.Is(err, ErrMaterialize) {
				t.Fatalf("error=%v", err)
			}
			final, _ := service.Get(context.Background(), source.DeliveryID)
			if final.State == helperkey.StateReady {
				t.Fatal("unsafe bootstrap became ready")
			}
		})
	}
}

func helperDeliveryFixture(t *testing.T) (helperkey.Record, []byte, *helperkey.Service, *helperRevokerFake) {
	t.Helper()
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	devicePublic, devicePrivate, _ := ed25519.GenerateKey(nil)
	publisher := &helperPublisherFake{}
	revoker := &helperRevokerFake{delay: 1}
	instance := "i-0123456789abcdef0"
	agentID, deploymentID, deliveryID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	binding := helperkey.DeviceBinding{
		SchemaVersion: helperkey.SchemaV1, AgentInstanceID: agentID, OwnerID: "owner-helper",
		DeliveryID: deliveryID, DeploymentID: deploymentID, BindingRevision: 1,
		InstanceID: instance, WorkerRoleARN: "arn:aws:iam::123456789012:role/worker",
		WorkerPrincipalID: "AROATESTROLEIDENTIFIER:" + instance, HelperID: "root-helper", SignerKeyID: "root-helper-1",
		SecretPlan: helperkey.SecretPlan{Partition: "aws", AccountID: "123456789012", Region: "us-west-2",
			Name: "dtx/" + agentID + "/deployments/" + deploymentID + "/" + helperkey.SecretSlot, VersionID: deliveryID,
			KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/key", TargetPath: helperkey.SecretTarget, FileMode: helperkey.SecretMode},
	}
	deriver, _ := helperkey.NewDeterministicKeyDeriver(bytes.Repeat([]byte{0x51}, 32))
	approvalService, _ := helperkey.NewApprovalService(helperkey.NewMemoryApprovalRepository(), helperApprovalVerifier{devicePublic}, deriver, func() time.Time { return now })
	prepared, _ := approvalService.Prepare(context.Background(), helperkey.PrepareApprovalRequest{Binding: binding, DeviceSignerKeyID: "device-1", IdempotencyKey: uuid.NewString()})
	_, _ = approvalService.Approve(context.Background(), helperkey.ApproveBindingRequest{DeliveryID: deliveryID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: prepared.Revision, DeviceSignature: ed25519.Sign(devicePrivate, prepared.SigningPayloadCBOR)})
	service, _ := helperkey.NewService(helperkey.NewMemoryRepository(), publisher, revoker,
		func() time.Time { return now }, helperkey.WithApprovedKeyDelivery(approvalService, deriver))
	draft, err := service.Draft(context.Background(), helperkey.DraftRequest{Binding: binding, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := draft.Binding.SigningPayload()
	granted, err := service.Grant(context.Background(), helperkey.GrantRequest{DeliveryID: draft.Binding.DeliveryID,
		IdempotencyKey: uuid.NewString(), DeviceSignature: ed25519.Sign(devicePrivate, payload)})
	if err != nil {
		t.Fatal(err)
	}
	return granted, bytes.Clone(publisher.private), service, revoker
}

func helperSource(record helperkey.Record) RootHelperKeySourceV1 {
	b := record.Binding
	return RootHelperKeySourceV1{SchemaVersion: b.SchemaVersion, AgentInstanceID: b.AgentInstanceID, OwnerID: b.OwnerID,
		DeliveryID: b.DeliveryID, DeploymentID: b.DeploymentID, BindingRevision: b.BindingRevision,
		InstanceID: b.InstanceID, WorkerRoleARN: b.WorkerRoleARN, WorkerPrincipalID: b.WorkerPrincipalID, HelperID: b.HelperID, SignerKeyID: b.SignerKeyID,
		PublicKey: bytes.Clone(record.PublicKey), PublicKeyDigest: b.PublicKeyDigest, Nonce: bytes.Clone(record.Nonce), NonceDigest: b.NonceDigest,
		SecretPartition: b.SecretPlan.Partition, SecretAccountID: b.SecretPlan.AccountID, SecretRegion: b.SecretPlan.Region,
		SecretARN: b.Secret.ARN, SecretName: b.Secret.Name, VersionID: b.Secret.VersionID, KMSKeyARN: b.Secret.KMSKeyARN,
		TargetPath: b.SecretPlan.TargetPath, FileMode: b.SecretPlan.FileMode, OwnerUID: 0, OwnerGID: 0}
}

type helperControlAdapter struct{ service *helperkey.Service }

func (a helperControlAdapter) SubmitRootHelperProof(ctx context.Context, request helperkey.ProofRequest, nonce []byte) (helperkey.Record, error) {
	return a.service.SubmitProof(ctx, request, nonce)
}
func (a helperControlAdapter) ReconcileRootHelperRevocation(ctx context.Context, id, key string) (helperkey.Record, error) {
	return a.service.ReconcileRevocation(ctx, id, key)
}
func (a helperControlAdapter) ConfirmRootHelperCanary(ctx context.Context, request helperkey.CanaryRequest) (helperkey.Record, error) {
	return a.service.ConfirmCanary(ctx, request)
}

type staticPrincipal string

func (p staticPrincipal) CurrentPrincipal(context.Context) (string, error) { return string(p), nil }

type helperFileFake struct {
	spec  SecretFileSpec
	value []byte
}

func (f *helperFileFake) ReplaceSecret(_ context.Context, spec SecretFileSpec, value []byte) (bool, error) {
	f.spec = spec
	f.value = bytes.Clone(value)
	return true, nil
}

type helperSecretAccessFake struct {
	privateKey    []byte
	revoker       *helperRevokerFake
	forceReadable bool
	canaries      int
}

func (f *helperSecretAccessFake) ReadRootHelperKey(context.Context, RootHelperKeySourceV1) ([]byte, error) {
	return bytes.Clone(f.privateKey), nil
}
func (f *helperSecretAccessFake) CanaryRootHelperKey(context.Context, RootHelperKeySourceV1) error {
	f.canaries++
	if f.forceReadable {
		return nil
	}
	return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}
}

type helperPublisherFake struct{ private []byte }

func (p *helperPublisherFake) CreateRootHelperKey(_ context.Context, b helperkey.DeviceBinding, value []byte) (helperkey.SecretCoordinate, error) {
	p.private = bytes.Clone(value)
	name := "dtx/" + b.AgentInstanceID + "/deployments/" + b.DeploymentID + "/" + helperkey.SecretSlot
	return helperkey.SecretCoordinate{ARN: "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + name + "-Ab12Cd", Name: name, VersionID: b.DeliveryID, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/key"}, nil
}
func (*helperPublisherFake) GrantRootHelperKey(context.Context, helperkey.DeviceBinding) error {
	return nil
}

type helperDeviceVerifier struct{ key ed25519.PublicKey }

func (v helperDeviceVerifier) VerifyDeviceBinding(_ context.Context, b helperkey.DeviceBinding, sig []byte) error {
	payload, _ := b.SigningPayload()
	if !ed25519.Verify(v.key, payload, sig) {
		return helperkey.ErrInvalid
	}
	return nil
}

type helperApprovalVerifier struct{ key ed25519.PublicKey }

func (v helperApprovalVerifier) VerifyRootHelperKeyApproval(_ context.Context, _, _ string, payload, signature []byte) error {
	if !ed25519.Verify(v.key, payload, signature) {
		return helperkey.ErrInvalid
	}
	return nil
}

type helperRevokerFake struct{ delay, reads int }

func (*helperRevokerFake) DenyRootHelperKey(context.Context, helperkey.DeviceBinding) error {
	return nil
}
func (r *helperRevokerFake) ReadBackRootHelperKeyDenied(context.Context, helperkey.DeviceBinding) (bool, error) {
	r.reads++
	return r.reads > r.delay, nil
}

package helperkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestApprovalPrecedesEveryCloudSecretMutationAndReplayBeatsMutableDeviceState(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	devicePublic, devicePrivate, _ := ed25519.GenerateKey(nil)
	devices := &mutableApprovalVerifier{key: devicePublic}
	deriver, _ := NewDeterministicKeyDeriver(bytes.Repeat([]byte{0x61}, 32))
	approvals, _ := NewApprovalService(NewMemoryApprovalRepository(), devices, deriver, func() time.Time { return now })
	publisher := &publisherFake{}
	delivery, _ := NewService(NewMemoryRepository(), publisher, &revokerFake{},
		func() time.Time { return now }, WithApprovedKeyDelivery(approvals, deriver))
	binding := testBinding()
	prepareKey := uuid.NewString()
	prepared, err := approvals.Prepare(context.Background(), PrepareApprovalRequest{
		Binding: binding, DeviceSignerKeyID: "device-1", IdempotencyKey: prepareKey,
	})
	if err != nil || publisher.creates != 0 {
		t.Fatalf("Prepare mutated cloud: challenge=%+v err=%v creates=%d", prepared, err, publisher.creates)
	}
	if _, err := delivery.Draft(context.Background(), DraftRequest{Binding: binding, IdempotencyKey: uuid.NewString()}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("unapproved Draft error=%v", err)
	}
	signature := ed25519.Sign(devicePrivate, prepared.SigningPayloadCBOR)
	approveKey := uuid.NewString()
	approved, err := approvals.Approve(context.Background(), ApproveBindingRequest{
		DeliveryID: binding.DeliveryID, IdempotencyKey: approveKey,
		ExpectedRevision: prepared.Revision, DeviceSignature: signature,
	})
	if err != nil || approved.Status != ApprovalApproved || publisher.creates != 0 {
		t.Fatalf("Approve unexpectedly published: %+v err=%v creates=%d", approved, err, publisher.creates)
	}
	devices.revoked = true
	replayed, err := approvals.Approve(context.Background(), ApproveBindingRequest{
		DeliveryID: binding.DeliveryID, IdempotencyKey: approveKey,
		ExpectedRevision: prepared.Revision, DeviceSignature: signature,
	})
	if err != nil || replayed.Revision != approved.Revision || devices.calls != 1 {
		t.Fatalf("exact replay consulted mutable device: %+v err=%v calls=%d", replayed, err, devices.calls)
	}
	drafted, err := delivery.Draft(context.Background(), DraftRequest{Binding: binding, IdempotencyKey: uuid.NewString()})
	if err != nil || drafted.State != StateDraft || publisher.creates != 1 {
		t.Fatalf("approved Draft=%+v err=%v creates=%d", drafted, err, publisher.creates)
	}
}

func TestRootHelperDeviceBindingCBORGolden(t *testing.T) {
	deriver, _ := NewDeterministicKeyDeriver(bytes.Repeat([]byte{0x71}, 32))
	approvals, _ := NewApprovalService(NewMemoryApprovalRepository(), &mutableApprovalVerifier{},
		deriver, func() time.Time { return time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC) })
	binding := DeviceBinding{
		SchemaVersion: SchemaV1, AgentInstanceID: "11111111-1111-4111-8111-111111111111", OwnerID: "owner-golden",
		DeliveryID: "22222222-2222-4222-8222-222222222222", DeploymentID: "33333333-3333-4333-8333-333333333333",
		BindingRevision: 7, InstanceID: "i-0123456789abcdef0",
		WorkerRoleARN:     "arn:aws:iam::123456789012:role/worker",
		WorkerPrincipalID: "AROATESTROLEIDENTIFIER:i-0123456789abcdef0", HelperID: "root-helper", SignerKeyID: "helper-key-7",
		SecretPlan: SecretPlan{Partition: "aws", AccountID: "123456789012", Region: "us-west-2",
			Name:      "dtx/11111111-1111-4111-8111-111111111111/deployments/33333333-3333-4333-8333-333333333333/" + SecretSlot,
			VersionID: "22222222-2222-4222-8222-222222222222", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/abcd",
			TargetPath: SecretTarget, FileMode: SecretMode},
	}
	challenge, err := approvals.Prepare(context.Background(), PrepareApprovalRequest{
		Binding: binding, DeviceSignerKeyID: "device-golden", IdempotencyKey: "44444444-4444-4444-8444-444444444444",
	})
	if err != nil {
		t.Fatal(err)
	}
	const expectedHex = "b5686f776e65725f69646c6f776e65722d676f6c64656e6966696c655f6d6f64651901006968656c7065725f69646b726f6f742d68656c7065726b64656c69766572795f6964782432323232323232322d323232322d343232322d383232322d3232323232323232323232326b696e7374616e63655f696473692d30313233343536373839616263646566306b7365637265745f6e616d6578756474782f31313131313131312d313131312d343131312d383131312d3131313131313131313131312f6465706c6f796d656e74732f33333333333333332d333333332d343333332d383333332d3333333333333333333333332f5f5f646972657874616c6b5f726f6f745f68656c7065725f6b65796b7461726765745f7061746878262f6574632f646972657874616c6b2d726f6f742d68656c7065722f7369676e696e672e6b65796c6e6f6e63655f64696765737478477368613235363a313163646561316536343331646563316463633731316366656434643532316265363339363935303233613638386364663166613234636362303434336633306d6465706c6f796d656e745f6964782433333333333333332d333333332d343333332d383333332d3333333333333333333333336d7365637265745f726567696f6e6975732d776573742d326d7369676e65725f6b65795f69646c68656c7065722d6b65792d376e736368656d615f76657273696f6e7822646972657874616c6b2e6167656e742e726f6f742d68656c7065722d6b65792f76316f776f726b65725f726f6c655f61726e782561726e3a6177733a69616d3a3a3132333435363738393031323a726f6c652f776f726b65727062696e64696e675f7265766973696f6e07707365637265745f706172746974696f6e63617773716167656e745f696e7374616e63655f6964782431313131313131312d313131312d343131312d383131312d313131313131313131313131717075626c69635f6b65795f64696765737478477368613235363a32386166343865633937323035336434303661363361323830626534313535376539323137333236366565313333616337633436353037653135383739383266717365637265745f6163636f756e745f69646c313233343536373839303132717365637265745f76657273696f6e5f6964782432323232323232322d323232322d343232322d383232322d323232323232323232323232727365637265745f6b6d735f6b65795f61726e782b61726e3a6177733a6b6d733a75732d776573742d323a3132333435363738393031323a6b65792f6162636473776f726b65725f7072696e636970616c5f6964782a41524f4154455354524f4c454944454e5449464945523a692d3031323334353637383961626364656630"
	if actual := hex.EncodeToString(challenge.SigningPayloadCBOR); actual != expectedHex {
		t.Fatalf("CBOR golden changed:\n%s", actual)
	}
}

type mutableApprovalVerifier struct {
	key     ed25519.PublicKey
	revoked bool
	calls   int
}

func (verifier *mutableApprovalVerifier) VerifyRootHelperKeyApproval(_ context.Context, _, _ string, payload, signature []byte) error {
	verifier.calls++
	if verifier.revoked || len(verifier.key) != ed25519.PublicKeySize || !ed25519.Verify(verifier.key, payload, signature) {
		return ErrInvalid
	}
	return nil
}

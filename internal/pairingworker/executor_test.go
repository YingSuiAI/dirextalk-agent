package pairingworker

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
)

type dispatchFake struct {
	result Result
	calls  []Command
}

func (fake *dispatchFake) Dispatch(_ context.Context, command Command) (Result, error) {
	fake.calls = append(fake.calls, command)
	result := fake.result
	if result.Begin != nil {
		result.Begin.OperationID, result.Begin.DeploymentID, result.Begin.OwnerID = command.OperationID, command.DeploymentID, command.OwnerID
		result.Begin.CommandID, result.Begin.RecipientPublicKeyDigest = command.CommandID, command.RecipientPublicKeyDigest
		result.Begin.ExecutionEpoch, result.Begin.PairingExpiresAt, result.Begin.WorkerLeaseEpoch = command.ExecutionEpoch, pairingExpiryText(command.PairingExpiresAt), 1
	}
	if result.Resume != nil {
		result.Resume.OperationID, result.Resume.DeploymentID, result.Resume.OwnerID = command.OperationID, command.DeploymentID, command.OwnerID
		result.Resume.CommandID, result.Resume.RecipientPublicKeyDigest = command.CommandID, command.RecipientPublicKeyDigest
		result.Resume.ExecutionEpoch, result.Resume.PairingExpiresAt, result.Resume.WorkerLeaseEpoch = command.ExecutionEpoch, pairingExpiryText(command.PairingExpiresAt), 1
	}
	return result, nil
}

func TestExecutorCarriesOnlyEncryptedBeginResultAndReplaysStableOperation(t *testing.T) {
	fake := &dispatchFake{result: Result{Begin: &roothelper.PairingBeginReceiptV1{
		AssociatedData: []byte{0xa1, 0x01, 0x02}, Envelope: secretbootstrap.RecipientEnvelopeV1{
			SchemaVersion:   secretbootstrap.RecipientEnvelopeSchemaV1,
			ServerPublicKey: "server", Nonce: "nonce", Ciphertext: "ciphertext",
		}, Signature: make([]byte, ed25519.SignatureSize),
	}}}
	executor := Executor{Dispatch: fake}
	session := testSession(pairing.StatusWaitingPayload, 1, 0)
	recipient := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	first, err := executor.Begin(context.Background(), session, recipient, session.Revision)
	if err != nil || first.PayloadDigest == "" || string(first.AssociatedDataCBOR) != string(fake.result.Begin.AssociatedData) {
		t.Fatalf("begin failed: %#v %v", first, err)
	}
	_, _ = executor.Begin(context.Background(), session, recipient, session.Revision)
	if len(fake.calls) != 2 || fake.calls[0] != fake.calls[1] {
		t.Fatalf("response-loss retry changed durable command: %#v", fake.calls)
	}
}

func TestResumeUsesPayloadScopeRevisionAndNeverCarriesRecipient(t *testing.T) {
	fake := &dispatchFake{result: Result{Resume: &roothelper.PairingResumeReceiptV1{Signature: make([]byte, ed25519.SignatureSize)}}}
	session := testSession(pairing.StatusResuming, 3, 1)
	if err := (Executor{Dispatch: fake}).Resume(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 1 || fake.calls[0].PayloadScopeRevision != 1 || fake.calls[0].RecipientPublicKey != "" ||
		fake.calls[0].CommandID != session.ResumeCommand {
		t.Fatalf("unexpected resume command: %#v", fake.calls)
	}
}

func TestPayloadDigestCompatibilityVector(t *testing.T) {
	digest, err := canonical.Digest(struct {
		Envelope       secretbootstrap.RecipientEnvelopeV1 `json:"envelope"`
		AssociatedData []byte                              `json:"associated_data"`
	}{
		Envelope: secretbootstrap.RecipientEnvelopeV1{
			SchemaVersion:   secretbootstrap.RecipientEnvelopeSchemaV1,
			ServerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Nonce:           "AAAAAAAAAAAAAAAA",
			Ciphertext:      "AAAAAAAAAAAAAAAAAAAAAA",
		},
		AssociatedData: []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'b', 0x02},
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:eb22ebbba5651dede62e79aea395e1df3c4a05b8411f36ab003f37f8af99b7e4"
	if digest != want {
		t.Fatalf("payload digest = %s, want %s", digest, want)
	}
}

func testSession(status pairing.Status, revision, payloadRevision int64) pairing.SessionV1 {
	now := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	value := pairing.SessionV1{
		SchemaVersion: pairing.SchemaV1, SessionID: "11111111-1111-1111-1111-111111111111",
		OwnerID: "owner", DeploymentID: "22222222-2222-2222-2222-222222222222", DeploymentRevision: 7,
		PlanID: "33333333-3333-3333-3333-333333333333", ConnectionID: "44444444-4444-4444-4444-444444444444",
		TaskID: "55555555-5555-5555-5555-555555555555", StepID: "66666666-6666-6666-6666-666666666666",
		RecipeID: "recipe", RecipeDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RecipeRevision: 1, ExecutionManifestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BeginCommand: "pair.begin", ResumeCommand: "pair.resume", Status: status,
		ExpiresAt: now.Add(time.Hour), Revision: revision, CreatedAt: now, UpdatedAt: now,
	}
	if status != pairing.StatusWaitingPayload {
		started := now
		value.RecipientKeyDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		value.PayloadDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		value.PayloadScopeRevision = payloadRevision
		value.AssociatedDataCBOR = []byte{1}
		value.Envelope = &secretbootstrap.RecipientEnvelopeV1{
			SchemaVersion:   secretbootstrap.RecipientEnvelopeSchemaV1,
			ServerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Nonce:           "AAAAAAAAAAAAAAAA", Ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
		}
		if status == pairing.StatusResuming {
			value.ResumeStartedAt = &started
		}
	}
	return value
}

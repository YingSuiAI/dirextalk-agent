package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestCloudWorkerProjectExecutionBudgetEvidenceBindsCurrentTurn(t *testing.T) {
	snapshot := coremodel.ExecutionSnapshot{
		ProfileID: uuid.NewString(), Revision: 3, CredentialVersion: 4,
		Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://model.example.test/v1",
		Model: "model", APIKey: "secret", MaxOutputTokens: 2048,
	}
	turn := core.Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: "@owner:example.test",
		AccountGeneration: 7, ConversationID: uuid.NewString(), Revision: 5,
		Prompt: "deploy the repository and generate an HTML report", ProfileID: snapshot.ProfileID,
		ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest(),
	}
	turn.AttachmentSnapshotDigest = core.TurnAttachmentSnapshotDigest(nil)
	first, err := newCloudWorkerProjectExecutionBudgetEvidence(turn, turn.Prompt, turn.ProfileID, turn.ProfileSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newCloudWorkerProjectExecutionBudgetEvidence(turn, turn.Prompt, turn.ProfileID, turn.ProfileSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	if *first != *second || first.Revision != cloudWorkerLocalProjectExecutionPolicyRevision {
		t.Fatalf("evidence is not deterministic: first=%+v second=%+v", first, second)
	}
	stale := turn
	stale.Revision++
	drifted, err := newCloudWorkerProjectExecutionBudgetEvidence(stale, stale.Prompt, stale.ProfileID, stale.ProfileSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	if drifted.Digest == first.Digest {
		t.Fatal("turn revision drift reused capability evidence")
	}
	changedPrompt, err := newCloudWorkerProjectExecutionBudgetEvidence(turn, turn.Prompt+" changed", turn.ProfileID, turn.ProfileSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	if changedPrompt.Digest == first.Digest {
		t.Fatal("prompt drift reused capability evidence")
	}
}

func TestConversationAttachmentBecomesExactCloudWorkerSource(t *testing.T) {
	ctx, store, profileID, cleanup := corePG18Fixture(t)
	defer cleanup()
	conversation, err := NewCoreConversationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	owner, generation := "@attachment-owner:example.test", uint64(9)
	requestID := uuid.NewString()
	content := []byte("immutable-png-test-content")
	contentDigest := sha256.Sum256(content)
	contentSHA256 := hex.EncodeToString(contentDigest[:])

	upload, err := conversation.BeginTurnAttachmentUpload(ctx, core.BeginTurnAttachmentUploadCommand{
		OwnerID: owner, AccountGeneration: generation, IdempotencyKey: uuid.NewString(),
		TurnRequestID: requestID, Kind: core.TurnAttachmentKindImage, Name: "evidence.png", MediaType: "image/png",
		DeclaredSize: uint64(len(content)), ContentSHA256: contentSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	chunkDigest := sha256.Sum256(content)
	upload, err = conversation.AppendTurnAttachmentUpload(ctx, core.AppendTurnAttachmentUploadCommand{
		OwnerID: owner, AccountGeneration: generation, IdempotencyKey: uuid.NewString(),
		UploadID: upload.UploadID, ExpectedRevision: upload.Revision, Ordinal: 0, OffsetBytes: 0,
		Data: bytes.Clone(content), ChunkSHA256: hex.EncodeToString(chunkDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := conversation.CommitTurnAttachmentUpload(ctx, core.CommitTurnAttachmentUploadCommand{
		OwnerID: owner, AccountGeneration: generation, IdempotencyKey: uuid.NewString(),
		UploadID: upload.UploadID, ExpectedRevision: upload.Revision, ContentSHA256: contentSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := coremodel.ExecutionSnapshot{ProfileID: profileID, Revision: 1, CredentialVersion: 1,
		Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://example.invalid", Model: "test", APIKey: "test", ContextWindow: 32768}
	turn, err := conversation.StartTurn(ctx, core.TurnStartCommand{
		RequestID: requestID, OwnerID: owner, AccountGeneration: generation,
		ConversationID: uuid.NewString(), Prompt: "Run this exact attachment on AWS.", ProfileID: profileID,
		ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1, ProfileSnapshot: snapshot,
		AcceptedAttachmentIDs: []string{attachment.SourceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := conversation.ClaimTurn(ctx, turn.ID, time.Now().UTC(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ownerAuthority, err := conversation.ResolveCloudWorkerOwner(ctx, lease)
	if err != nil || ownerAuthority.OwnerID != owner || ownerAuthority.AccountGeneration != generation {
		t.Fatalf("owner authority=%+v err=%v", ownerAuthority, err)
	}
	manifest, err := conversation.ResolveCloudWorkerManifest(ctx, lease, cloudworker.WorkspaceWrite, []string{attachment.SourceID})
	if err != nil || len(manifest.Items) != 1 {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	item := manifest.Items[0]
	if item.SourceRef != attachment.SourceID || item.SourceRevision != 1 || item.SHA256 != contentSHA256 || item.SizeBytes != uint64(len(content)) {
		t.Fatalf("source descriptor drifted: %+v", item)
	}
	read, err := conversation.OpenSource(ctx, cloudworker.SourceRequest{OwnerID: owner, AccountGeneration: generation, Input: item})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(read.Body)
	if closeErr := read.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatalf("source bytes=%q err=%v", actual, err)
	}

	foreign := cloudworker.SourceRequest{OwnerID: "@foreign:example.test", AccountGeneration: generation, Input: item}
	if _, err = conversation.OpenSource(ctx, foreign); !errors.Is(err, cloudworker.ErrConflict) {
		t.Fatalf("foreign owner source read=%v", err)
	}
	stale := lease
	stale.Epoch++
	if _, err = conversation.ResolveCloudWorkerManifest(context.Background(), stale, cloudworker.WorkspaceReadOnly, []string{attachment.SourceID}); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("stale turn lease resolved manifest: %v", err)
	}
	if _, err = conversation.ResolveCloudWorkerManifest(ctx, lease, cloudworker.WorkspaceReadOnly, []string{uuid.NewString()}); !errors.Is(err, cloudworker.ErrInvalid) {
		t.Fatalf("unbound source resolved manifest: %v", err)
	}
}

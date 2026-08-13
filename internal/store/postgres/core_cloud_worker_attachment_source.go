package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/workspacearchive"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const cloudWorkerLocalProjectExecutionPolicyRevision uint64 = 1

// ResolveCloudWorkerOwner revalidates the live durable turn lease before
// returning owner authority. Model arguments are never an owner source.
func (s *CoreConversationStore) ResolveCloudWorkerOwner(ctx context.Context, lease core.TurnLease) (cloudworker.IntrinsicOwnerContext, error) {
	if err := s.validateCloudWorkerTurnLease(ctx, lease); err != nil {
		return cloudworker.IntrinsicOwnerContext{}, err
	}
	return cloudworker.IntrinsicOwnerContext{
		OwnerID:           strings.TrimSpace(lease.Turn.OwnerID),
		AccountGeneration: lease.Turn.AccountGeneration,
	}, nil
}

// ResolveCloudWorkerBudgetEvidence reports a versioned structural capability
// limit: the Native conversation runtime has no general project/shell executor.
// It never classifies prompt text or treats a model assertion, timeout, or
// failed local attempt as evidence.
func (s *CoreConversationStore) ResolveCloudWorkerBudgetEvidence(ctx context.Context, lease core.TurnLease) (*cloudworker.LocalBudgetEvidence, error) {
	if err := s.validateCloudWorkerTurnLease(ctx, lease); err != nil {
		return nil, err
	}
	accepted := attachmentSourceIDs(lease.Turn.AttachmentSources)
	if core.ValidateAcceptedTurnAttachments(lease.Turn.RequestID, accepted, lease.Turn.AttachmentSources) != nil ||
		lease.Turn.AttachmentSnapshotDigest != core.TurnAttachmentSnapshotDigest(lease.Turn.AttachmentSources) {
		return nil, cloudworker.ErrConflict
	}
	var prompt, profileID, profileDigest, attachmentDigest string
	var revision uint64
	if err := s.pool.QueryRow(ctx, `SELECT prompt,profile_id::text,profile_snapshot_digest,
		attachment_snapshot_digest,revision FROM core_conversation_turns
		WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3
		AND state='running' AND cancel_requested=false AND lease_expires_at>clock_timestamp()`,
		lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(
		&prompt, &profileID, &profileDigest, &attachmentDigest, &revision); err != nil {
		if err == pgx.ErrNoRows {
			return nil, cloudworker.ErrStaleAuthorization
		}
		return nil, err
	}
	if prompt != lease.Turn.Prompt || profileID != lease.Turn.ProfileID ||
		profileDigest != lease.Turn.ProfileSnapshotDigest || profileDigest != lease.Turn.ProfileSnapshot.Digest() ||
		attachmentDigest != lease.Turn.AttachmentSnapshotDigest || revision != lease.Turn.Revision {
		return nil, cloudworker.ErrStaleAuthorization
	}
	return newCloudWorkerProjectExecutionBudgetEvidence(lease.Turn, prompt, profileID, profileDigest)
}

func newCloudWorkerProjectExecutionBudgetEvidence(turn core.Turn, prompt, profileID, profileDigest string) (*cloudworker.LocalBudgetEvidence, error) {
	promptSHA := sha256.Sum256([]byte(prompt))
	binding := struct {
		Policy            string `json:"policy"`
		PolicyRevision    uint64 `json:"policy_revision"`
		OwnerID           string `json:"owner_id"`
		AccountGeneration uint64 `json:"account_generation"`
		TurnID            string `json:"turn_id"`
		TurnRevision      uint64 `json:"turn_revision"`
		RequestID         string `json:"request_id"`
		ConversationID    string `json:"conversation_id"`
		PromptSHA256      string `json:"prompt_sha256"`
		ProfileID         string `json:"profile_id"`
		ProfileDigest     string `json:"profile_digest"`
		AttachmentDigest  string `json:"attachment_digest"`
	}{"native_runtime_no_general_project_executor", cloudWorkerLocalProjectExecutionPolicyRevision,
		turn.OwnerID, turn.AccountGeneration, turn.ID, turn.Revision,
		turn.RequestID, turn.ConversationID, hex.EncodeToString(promptSHA[:]),
		profileID, profileDigest, turn.AttachmentSnapshotDigest}
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return &cloudworker.LocalBudgetEvidence{
		BudgetID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk/local-budget/native-runtime-no-general-project-executor/v1")).String(),
		Revision: cloudWorkerLocalProjectExecutionPolicyRevision, Digest: hex.EncodeToString(digest[:]),
	}, nil
}

// ResolveCloudWorkerManifest maps only sources frozen on this turn to private
// exact-revision descriptors. It does not read bytes or expose database/S3
// locations to the model.
func (s *CoreConversationStore) ResolveCloudWorkerManifest(ctx context.Context, lease core.TurnLease, mode cloudworker.WorkspaceMode, sourceIDs []string) (cloudworker.InputManifest, error) {
	if s == nil || s.pool == nil || ctx == nil || (mode != cloudworker.WorkspaceReadOnly && mode != cloudworker.WorkspaceWrite) ||
		len(sourceIDs) == 0 || len(sourceIDs) > core.MaxTurnAttachments {
		return cloudworker.InputManifest{}, cloudworker.ErrInvalid
	}
	if err := s.validateCloudWorkerTurnLease(ctx, lease); err != nil {
		return cloudworker.InputManifest{}, err
	}
	acceptedIDs := attachmentSourceIDs(lease.Turn.AttachmentSources)
	if core.ValidateAcceptedTurnAttachments(lease.Turn.RequestID, acceptedIDs, lease.Turn.AttachmentSources) != nil ||
		lease.Turn.AttachmentSnapshotDigest == "" ||
		lease.Turn.AttachmentSnapshotDigest != core.TurnAttachmentSnapshotDigest(lease.Turn.AttachmentSources) {
		return cloudworker.InputManifest{}, cloudworker.ErrConflict
	}
	allowed := make(map[string]core.TurnAttachment, len(lease.Turn.AttachmentSources))
	for _, attachment := range lease.Turn.AttachmentSources {
		allowed[attachment.SourceID] = attachment
	}
	seen := make(map[string]struct{}, len(sourceIDs))
	manifest := cloudworker.InputManifest{Schema: cloudworker.InputManifestSchema, Items: make([]cloudworker.InputManifestItem, 0, len(sourceIDs))}
	for _, sourceID := range sourceIDs {
		attachment, ok := allowed[sourceID]
		if !ok || !coretask.ValidUUID(sourceID) {
			return cloudworker.InputManifest{}, cloudworker.ErrInvalid
		}
		if _, duplicate := seen[sourceID]; duplicate {
			return cloudworker.InputManifest{}, cloudworker.ErrInvalid
		}
		seen[sourceID] = struct{}{}
		var ownerID, turnRequestID, consumedTurnID, status, kind, name, mediaType, contentSHA256 string
		var accountGeneration, declaredSize, receivedSize uint64
		var content []byte
		err := s.pool.QueryRow(ctx, `SELECT owner_id,account_generation,turn_request_id::text,
			COALESCE(consumed_turn_id::text,''),status,kind,name,media_type,declared_size,received_size,content_sha256,content_bytes
			FROM core_conversation_attachment_uploads WHERE source_id=$1`, sourceID).Scan(
			&ownerID, &accountGeneration, &turnRequestID, &consumedTurnID, &status, &kind, &name, &mediaType,
			&declaredSize, &receivedSize, &contentSHA256, &content)
		if err != nil {
			if err == pgx.ErrNoRows {
				return cloudworker.InputManifest{}, cloudworker.ErrNotFound
			}
			return cloudworker.InputManifest{}, err
		}
		if ownerID != lease.Turn.OwnerID || accountGeneration != lease.Turn.AccountGeneration ||
			turnRequestID != lease.Turn.RequestID || consumedTurnID != lease.Turn.ID ||
			status != string(core.TurnAttachmentConsumed) || kind != attachment.Kind || name != attachment.Name ||
			mediaType != attachment.MediaType || declaredSize != attachment.SizeBytes ||
			receivedSize != attachment.SizeBytes || contentSHA256 != attachment.SHA256 || attachment.Revision != 1 {
			clear(content)
			return cloudworker.InputManifest{}, cloudworker.ErrConflict
		}
		if kind == core.TurnAttachmentKindWorkspaceArchive && workspacearchive.Validate(bytes.NewReader(content)) != nil {
			clear(content)
			return cloudworker.InputManifest{}, cloudworker.ErrConflict
		}
		clear(content)
		manifestKind, mountPath := "file", "inputs/"+sourceID+"/"+attachment.Name
		if kind == core.TurnAttachmentKindWorkspaceArchive {
			manifestKind, mountPath = "archive", "workspace"
		}
		manifest.Items = append(manifest.Items, cloudworker.InputManifestItem{
			InputID: sourceID, Kind: manifestKind, Name: attachment.Name, MountPath: mountPath,
			MediaType: attachment.MediaType, SizeBytes: attachment.SizeBytes, SHA256: attachment.SHA256,
			SourceRef: sourceID, SourceRevision: attachment.Revision,
		})
	}
	if _, err := manifest.Seal(); err != nil {
		return cloudworker.InputManifest{}, err
	}
	return manifest, nil
}

// OpenSource is the post-confirmation staging read boundary. Every call
// revalidates immutable owner/generation and the exact source descriptor, then
// verifies the bytes before returning a clear-on-close reader.
func (s *CoreConversationStore) OpenSource(ctx context.Context, request cloudworker.SourceRequest) (cloudworker.SourceRead, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.OwnerID) == "" || request.AccountGeneration == 0 ||
		request.Input.SourceRef != request.Input.InputID || request.Input.SourceRevision != 1 {
		return cloudworker.SourceRead{}, cloudworker.ErrInvalid
	}
	canonical := cloudworker.InputManifest{Schema: cloudworker.InputManifestSchema, Items: []cloudworker.InputManifestItem{request.Input}}
	if _, err := canonical.Seal(); err != nil || len(canonical.Items) != 1 || canonical.Items[0] != request.Input {
		return cloudworker.SourceRead{}, cloudworker.ErrInvalid
	}
	var ownerID, consumedTurnID, status, kind, name, mediaType, contentSHA256 string
	var accountGeneration, declaredSize, receivedSize uint64
	var content []byte
	err := s.pool.QueryRow(ctx, `SELECT owner_id,account_generation,COALESCE(consumed_turn_id::text,''),status,
		kind,name,media_type,declared_size,received_size,content_sha256,content_bytes
		FROM core_conversation_attachment_uploads WHERE source_id=$1`, request.Input.SourceRef).Scan(
		&ownerID, &accountGeneration, &consumedTurnID, &status, &kind, &name, &mediaType,
		&declaredSize, &receivedSize, &contentSHA256, &content)
	if err != nil {
		if err == pgx.ErrNoRows {
			return cloudworker.SourceRead{}, cloudworker.ErrNotFound
		}
		return cloudworker.SourceRead{}, err
	}
	valid := false
	defer func() {
		if !valid {
			clear(content)
		}
	}()
	digest := sha256.Sum256(content)
	if ownerID != strings.TrimSpace(request.OwnerID) || accountGeneration != request.AccountGeneration ||
		!coretask.ValidUUID(consumedTurnID) || status != string(core.TurnAttachmentConsumed) ||
		name != request.Input.Name || mediaType != request.Input.MediaType || declaredSize != request.Input.SizeBytes ||
		receivedSize != request.Input.SizeBytes || uint64(len(content)) != request.Input.SizeBytes ||
		contentSHA256 != request.Input.SHA256 || hex.EncodeToString(digest[:]) != request.Input.SHA256 {
		return cloudworker.SourceRead{}, cloudworker.ErrConflict
	}
	if (kind == core.TurnAttachmentKindWorkspaceArchive) != (request.Input.Kind == "archive") ||
		(kind != core.TurnAttachmentKindWorkspaceArchive && request.Input.Kind != "file") ||
		(kind == core.TurnAttachmentKindWorkspaceArchive && workspacearchive.Validate(bytes.NewReader(content)) != nil) {
		return cloudworker.SourceRead{}, cloudworker.ErrConflict
	}
	valid = true
	body := newAttachmentSourceBody(content)
	return cloudworker.SourceRead{SourceRef: request.Input.SourceRef, SourceRevision: request.Input.SourceRevision,
		SizeBytes: request.Input.SizeBytes, MediaType: request.Input.MediaType, Body: body}, nil
}

func (s *CoreConversationStore) validateCloudWorkerTurnLease(ctx context.Context, lease core.TurnLease) error {
	if s == nil || s.pool == nil || ctx == nil || !coretask.ValidUUID(lease.Turn.ID) ||
		!coretask.ValidUUID(lease.Turn.RequestID) || !coretask.ValidUUID(lease.LeaseID) || lease.Epoch == 0 ||
		strings.TrimSpace(lease.Turn.OwnerID) == "" || lease.Turn.AccountGeneration == 0 || lease.Turn.Revision == 0 {
		return cloudworker.ErrInvalid
	}
	var ownerID, requestID, conversationID, snapshotDigest string
	var accountGeneration, revision uint64
	err := s.pool.QueryRow(ctx, `SELECT owner_id,account_generation,request_id::text,
		COALESCE(conversation_id::text,''),revision,attachment_snapshot_digest
		FROM core_conversation_turns
		WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running'
		  AND cancel_requested=false AND lease_expires_at>clock_timestamp()`,
		lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(
		&ownerID, &accountGeneration, &requestID, &conversationID, &revision, &snapshotDigest)
	if err != nil {
		if err == pgx.ErrNoRows {
			return cloudworker.ErrStaleAuthorization
		}
		return err
	}
	if ownerID != strings.TrimSpace(lease.Turn.OwnerID) || accountGeneration != lease.Turn.AccountGeneration ||
		requestID != lease.Turn.RequestID || conversationID != lease.Turn.ConversationID ||
		revision != lease.Turn.Revision || snapshotDigest != lease.Turn.AttachmentSnapshotDigest {
		return cloudworker.ErrStaleAuthorization
	}
	return nil
}

type attachmentSourceBody struct {
	data   []byte
	reader *bytes.Reader
}

func newAttachmentSourceBody(data []byte) *attachmentSourceBody {
	return &attachmentSourceBody{data: data, reader: bytes.NewReader(data)}
}

func (body *attachmentSourceBody) Read(value []byte) (int, error) {
	if body == nil || body.reader == nil {
		return 0, io.EOF
	}
	return body.reader.Read(value)
}

func (body *attachmentSourceBody) Seek(offset int64, whence int) (int64, error) {
	if body == nil || body.reader == nil {
		return 0, io.ErrClosedPipe
	}
	return body.reader.Seek(offset, whence)
}

func (body *attachmentSourceBody) Close() error {
	if body == nil {
		return nil
	}
	clear(body.data)
	body.data = nil
	body.reader = nil
	return nil
}

var _ cloudworker.IntrinsicOwnerResolver = (*CoreConversationStore)(nil)
var _ cloudworker.IntrinsicManifestResolver = (*CoreConversationStore)(nil)
var _ cloudworker.IntrinsicBudgetResolver = (*CoreConversationStore)(nil)
var _ cloudworker.StagingSourceReader = (*CoreConversationStore)(nil)

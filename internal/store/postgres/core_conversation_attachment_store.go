package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/workspacearchive"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type conversationAttachmentRecord struct {
	UploadID, SourceID, OwnerID, TurnRequestID string
	AccountGeneration                          uint64
	BeginKey, BeginDigest                      string
	Kind, Name, MediaType, ContentSHA256       string
	DeclaredSize, ReceivedSize                 uint64
	NextOrdinal                                uint32
	Status                                     core.TurnAttachmentStatus
	Revision                                   uint64
	ExpiresAt, CreatedAt, UpdatedAt            time.Time
	Content                                    []byte
}

func (s *CoreConversationStore) BeginTurnAttachmentUpload(ctx context.Context, command core.BeginTurnAttachmentUploadCommand) (core.TurnAttachmentUpload, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.Kind = strings.TrimSpace(command.Kind)
	command.Name = strings.TrimSpace(command.Name)
	command.MediaType = strings.ToLower(strings.TrimSpace(command.MediaType))
	command.ContentSHA256 = strings.TrimSpace(command.ContentSHA256)
	if s == nil || s.pool == nil || ctx == nil || command.OwnerID == "" || len(command.OwnerID) > 512 ||
		command.AccountGeneration == 0 || !coretask.ValidUUID(command.IdempotencyKey) ||
		!coretask.ValidUUID(command.TurnRequestID) || !core.ValidTurnAttachmentName(command.Name) ||
		!core.ValidTurnAttachmentKind(command.Kind) || !core.ValidTurnAttachmentMediaType(command.Kind, command.MediaType) || command.DeclaredSize == 0 ||
		command.DeclaredSize > core.MaxTurnAttachmentBytes || !lowerSHA256(command.ContentSHA256) {
		return core.TurnAttachmentUpload{}, core.ErrInvalid
	}
	requestDigest := attachmentDigest(struct {
		OwnerID           string
		AccountGeneration uint64
		TurnRequestID     string
		Kind              string
		Name              string
		MediaType         string
		DeclaredSize      uint64
		ContentSHA256     string
	}{command.OwnerID, command.AccountGeneration, command.TurnRequestID, command.Kind, command.Name, command.MediaType, command.DeclaredSize, command.ContentSHA256})
	uploadID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-attachment-upload:"+command.IdempotencyKey)).String()
	sourceID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-attachment-source:"+command.IdempotencyKey)).String()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.TurnAttachmentUpload{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "conversation-attachment:"+command.OwnerID+":"+command.TurnRequestID); err != nil {
		return core.TurnAttachmentUpload{}, err
	}
	var existing conversationAttachmentRecord
	if err = scanConversationAttachment(ctx, tx, "begin_idempotency_key=$1", []any{command.IdempotencyKey}, &existing); err == nil {
		if existing.BeginDigest != requestDigest || existing.OwnerID != command.OwnerID ||
			existing.AccountGeneration != command.AccountGeneration || existing.TurnRequestID != command.TurnRequestID {
			return core.TurnAttachmentUpload{}, core.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return core.TurnAttachmentUpload{}, err
		}
		return attachmentUploadProjection(existing), nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return core.TurnAttachmentUpload{}, err
	}
	var count, archiveCount uint64
	var total uint64
	if err = tx.QueryRow(ctx, `SELECT count(*),COALESCE(sum(declared_size),0),count(*) FILTER (WHERE kind='workspace_archive') FROM core_conversation_attachment_uploads
		WHERE owner_id=$1 AND account_generation=$2 AND turn_request_id=$3 AND status IN ('receiving','committed') AND expires_at>clock_timestamp()`,
		command.OwnerID, command.AccountGeneration, command.TurnRequestID).Scan(&count, &total, &archiveCount); err != nil {
		return core.TurnAttachmentUpload{}, err
	}
	if count >= core.MaxTurnAttachments || total+command.DeclaredSize > core.MaxTurnAttachmentsBytes ||
		(command.Kind == core.TurnAttachmentKindWorkspaceArchive && archiveCount != 0) {
		return core.TurnAttachmentUpload{}, core.ErrInvalid
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	expires := now.Add(core.TurnAttachmentUploadTTL)
	_, err = tx.Exec(ctx, `INSERT INTO core_conversation_attachment_uploads(
		upload_id,source_id,owner_id,account_generation,turn_request_id,begin_idempotency_key,begin_request_digest,
		kind,name,media_type,declared_size,content_sha256,status,revision,expires_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'receiving',1,$13,$14,$14)`,
		uploadID, sourceID, command.OwnerID, command.AccountGeneration, command.TurnRequestID,
		command.IdempotencyKey, requestDigest, command.Kind, command.Name, command.MediaType, command.DeclaredSize,
		command.ContentSHA256, expires, now)
	if err != nil {
		return core.TurnAttachmentUpload{}, err
	}
	record := conversationAttachmentRecord{UploadID: uploadID, SourceID: sourceID, OwnerID: command.OwnerID,
		AccountGeneration: command.AccountGeneration, TurnRequestID: command.TurnRequestID,
		BeginKey: command.IdempotencyKey, BeginDigest: requestDigest, Kind: command.Kind, Name: command.Name,
		MediaType: command.MediaType, ContentSHA256: command.ContentSHA256, DeclaredSize: command.DeclaredSize,
		Status: core.TurnAttachmentReceiving, Revision: 1, ExpiresAt: expires, CreatedAt: now, UpdatedAt: now}
	if err = tx.Commit(ctx); err != nil {
		return core.TurnAttachmentUpload{}, err
	}
	return attachmentUploadProjection(record), nil
}

func (s *CoreConversationStore) AppendTurnAttachmentUpload(ctx context.Context, command core.AppendTurnAttachmentUploadCommand) (core.TurnAttachmentUpload, error) {
	defer command.Destroy()
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.ChunkSHA256 = strings.TrimSpace(command.ChunkSHA256)
	if s == nil || s.pool == nil || ctx == nil || command.OwnerID == "" || command.AccountGeneration == 0 ||
		!coretask.ValidUUID(command.IdempotencyKey) || !coretask.ValidUUID(command.UploadID) ||
		command.ExpectedRevision == 0 || len(command.Data) == 0 || len(command.Data) > core.MaxTurnAttachmentChunkBytes ||
		!lowerSHA256(command.ChunkSHA256) {
		return core.TurnAttachmentUpload{}, core.ErrInvalid
	}
	chunkDigest := sha256.Sum256(command.Data)
	if hex.EncodeToString(chunkDigest[:]) != command.ChunkSHA256 {
		return core.TurnAttachmentUpload{}, core.ErrConflict
	}
	requestDigest := attachmentDigest(struct {
		OwnerID           string
		AccountGeneration uint64
		UploadID          string
		ExpectedRevision  uint64
		Ordinal           uint32
		OffsetBytes       uint64
		ChunkSHA256       string
		ChunkSize         int
	}{command.OwnerID, command.AccountGeneration, command.UploadID, command.ExpectedRevision,
		command.Ordinal, command.OffsetBytes, command.ChunkSHA256, len(command.Data)})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.TurnAttachmentUpload{}, err
	}
	defer tx.Rollback(ctx)
	if replay, found, replayErr := loadAttachmentUploadReplay(ctx, tx, "append", command.IdempotencyKey, requestDigest, command.OwnerID, command.AccountGeneration); replayErr != nil || found {
		return replay, replayErr
	}
	var record conversationAttachmentRecord
	if err = scanConversationAttachment(ctx, tx, "upload_id=$1 FOR UPDATE", []any{command.UploadID}, &record); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.TurnAttachmentUpload{}, core.ErrConflict
		}
		return core.TurnAttachmentUpload{}, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if record.OwnerID != command.OwnerID || record.AccountGeneration != command.AccountGeneration ||
		record.Status != core.TurnAttachmentReceiving || !now.Before(record.ExpiresAt) ||
		record.Revision != command.ExpectedRevision || record.NextOrdinal != command.Ordinal ||
		record.ReceivedSize != command.OffsetBytes || record.ReceivedSize+uint64(len(command.Data)) > record.DeclaredSize {
		return core.TurnAttachmentUpload{}, core.ErrConflict
	}
	nextContent := make([]byte, 0, len(record.Content)+len(command.Data))
	nextContent = append(nextContent, record.Content...)
	nextContent = append(nextContent, command.Data...)
	defer clear(nextContent)
	record.Content = nextContent
	record.ReceivedSize += uint64(len(command.Data))
	record.NextOrdinal++
	record.Revision++
	record.UpdatedAt = now
	result, err := tx.Exec(ctx, `UPDATE core_conversation_attachment_uploads SET content_bytes=$2,received_size=$3,
		next_ordinal=$4,revision=$5,updated_at=$6 WHERE upload_id=$1 AND revision=$7 AND status='receiving'`,
		record.UploadID, record.Content, record.ReceivedSize, record.NextOrdinal, record.Revision, now, command.ExpectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return core.TurnAttachmentUpload{}, core.ErrConflict
	}
	projection := attachmentUploadProjection(record)
	if err = storeAttachmentUploadReplay(ctx, tx, "append", command.IdempotencyKey, requestDigest, record.UploadID, projection); err != nil {
		return core.TurnAttachmentUpload{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.TurnAttachmentUpload{}, err
	}
	return projection, nil
}

func (s *CoreConversationStore) CommitTurnAttachmentUpload(ctx context.Context, command core.CommitTurnAttachmentUploadCommand) (core.TurnAttachment, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.ContentSHA256 = strings.TrimSpace(command.ContentSHA256)
	if s == nil || s.pool == nil || ctx == nil || command.OwnerID == "" || command.AccountGeneration == 0 ||
		!coretask.ValidUUID(command.IdempotencyKey) || !coretask.ValidUUID(command.UploadID) ||
		command.ExpectedRevision == 0 || !lowerSHA256(command.ContentSHA256) {
		return core.TurnAttachment{}, core.ErrInvalid
	}
	requestDigest := attachmentDigest(command)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.TurnAttachment{}, err
	}
	defer tx.Rollback(ctx)
	if replay, found, replayErr := loadAttachmentCommitReplay(ctx, tx, command.IdempotencyKey, requestDigest, command.OwnerID, command.AccountGeneration); replayErr != nil || found {
		return replay, replayErr
	}
	var record conversationAttachmentRecord
	if err = scanConversationAttachment(ctx, tx, "upload_id=$1 FOR UPDATE", []any{command.UploadID}, &record); err != nil {
		return core.TurnAttachment{}, core.ErrConflict
	}
	if record.Kind == core.TurnAttachmentKindWorkspaceArchive &&
		workspacearchive.Validate(bytes.NewReader(record.Content)) != nil {
		return core.TurnAttachment{}, core.ErrInvalid
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	contentDigest := sha256.Sum256(record.Content)
	if record.OwnerID != command.OwnerID || record.AccountGeneration != command.AccountGeneration ||
		record.Status != core.TurnAttachmentReceiving || !now.Before(record.ExpiresAt) ||
		record.Revision != command.ExpectedRevision || record.ReceivedSize != record.DeclaredSize ||
		command.ContentSHA256 != record.ContentSHA256 || hex.EncodeToString(contentDigest[:]) != record.ContentSHA256 {
		return core.TurnAttachment{}, core.ErrConflict
	}
	record.Status = core.TurnAttachmentCommitted
	record.Revision++
	record.UpdatedAt = now
	result, err := tx.Exec(ctx, `UPDATE core_conversation_attachment_uploads SET status='committed',revision=$2,updated_at=$3
		WHERE upload_id=$1 AND revision=$4 AND status='receiving'`, record.UploadID, record.Revision, now, command.ExpectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return core.TurnAttachment{}, core.ErrConflict
	}
	attachment := attachmentProjection(record)
	if err = storeAttachmentCommitReplay(ctx, tx, command.IdempotencyKey, requestDigest, record.UploadID, attachment); err != nil {
		return core.TurnAttachment{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.TurnAttachment{}, err
	}
	return attachment, nil
}

func resolveAcceptedTurnAttachments(ctx context.Context, tx pgx.Tx, command *core.TurnStartCommand, turnID string) error {
	if command == nil || !coretask.ValidUUID(turnID) || len(command.AcceptedAttachmentIDs) > core.MaxTurnAttachments {
		return core.ErrInvalid
	}
	command.AttachmentSources = nil
	if len(command.AcceptedAttachmentIDs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	var total uint64
	for _, sourceID := range command.AcceptedAttachmentIDs {
		var record conversationAttachmentRecord
		if err := scanConversationAttachment(ctx, tx, "source_id=$1 FOR UPDATE", []any{sourceID}, &record); err != nil {
			return core.ErrConflict
		}
		if record.OwnerID != strings.TrimSpace(command.OwnerID) || record.AccountGeneration != command.AccountGeneration ||
			record.TurnRequestID != command.RequestID || record.Status != core.TurnAttachmentCommitted ||
			!now.Before(record.ExpiresAt) || record.ReceivedSize != record.DeclaredSize {
			return core.ErrConflict
		}
		attachment := attachmentProjection(record)
		if attachment.Validate() != nil {
			return core.ErrConflict
		}
		total += attachment.SizeBytes
		if total > core.MaxTurnAttachmentsBytes {
			return core.ErrInvalid
		}
		command.AttachmentSources = append(command.AttachmentSources, attachment)
	}
	return core.ValidateAcceptedTurnAttachments(command.RequestID, command.AcceptedAttachmentIDs, command.AttachmentSources)
}

func resolveAcceptedAttachments(ctx context.Context, tx pgx.Tx, owner string, generation uint64, requestID string, acceptedIDs []string) ([]core.TurnAttachment, error) {
	command := core.TurnStartCommand{OwnerID: owner, AccountGeneration: generation, RequestID: requestID, AcceptedAttachmentIDs: acceptedIDs}
	if err := resolveAcceptedTurnAttachments(ctx, tx, &command, uuid.NewString()); err != nil {
		return nil, err
	}
	return command.AttachmentSources, nil
}

func consumeAcceptedAttachments(ctx context.Context, tx pgx.Tx, owner string, generation uint64, requestID string, acceptedIDs []string, attachments []core.TurnAttachment, turnID string) error {
	return consumeAcceptedTurnAttachments(ctx, tx, core.TurnStartCommand{OwnerID: owner, AccountGeneration: generation, RequestID: requestID, AcceptedAttachmentIDs: acceptedIDs, AttachmentSources: attachments}, turnID)
}

func (s *CoreConversationStore) ResolveTurnAttachment(ctx context.Context, turn core.Turn, attachment core.TurnAttachment) ([]byte, error) {
	var content []byte
	err := s.pool.QueryRow(ctx, `SELECT a.content_bytes FROM core_conversation_attachment_uploads a
		JOIN core_conversation_turns t ON t.turn_id=a.consumed_turn_id
		WHERE a.source_id=$1 AND a.consumed_turn_id=$2 AND a.owner_id=t.owner_id AND a.account_generation=t.account_generation
		AND a.status='consumed' AND a.kind=$3 AND a.name=$4 AND a.media_type=$5 AND a.declared_size=$6 AND a.content_sha256=$7`,
		attachment.SourceID, turn.ID, attachment.Kind, attachment.Name, attachment.MediaType, attachment.SizeBytes, attachment.SHA256).Scan(&content)
	if err != nil {
		return nil, core.ErrConflict
	}
	sum := sha256.Sum256(content)
	if uint64(len(content)) != attachment.SizeBytes || hex.EncodeToString(sum[:]) != attachment.SHA256 {
		clear(content)
		return nil, core.ErrConflict
	}
	return append([]byte(nil), content...), nil
}

// consumeAcceptedTurnAttachments performs the one-way source transition only
// after the turn row (and its immutable attachment snapshot) exists. It runs in
// the same transaction as StartTurn, so a failed event insert or commit cannot
// strand a source in consumed state.
func consumeAcceptedTurnAttachments(ctx context.Context, tx pgx.Tx, command core.TurnStartCommand, turnID string) error {
	if !coretask.ValidUUID(turnID) || core.ValidateAcceptedTurnAttachments(command.RequestID, command.AcceptedAttachmentIDs, command.AttachmentSources) != nil {
		return core.ErrInvalid
	}
	for _, attachment := range command.AttachmentSources {
		result, err := tx.Exec(ctx, `UPDATE core_conversation_attachment_uploads
			SET status='consumed',consumed_turn_id=$1,revision=revision+1,updated_at=clock_timestamp()
			WHERE source_id=$2 AND owner_id=$3 AND account_generation=$4 AND turn_request_id=$5
			  AND status='committed' AND consumed_turn_id IS NULL AND expires_at>clock_timestamp()
			  AND kind=$6 AND name=$7 AND media_type=$8 AND declared_size=$9
			  AND received_size=$9 AND content_sha256=$10`,
			turnID, attachment.SourceID, strings.TrimSpace(command.OwnerID), command.AccountGeneration,
			command.RequestID, attachment.Kind, attachment.Name, attachment.MediaType,
			attachment.SizeBytes, attachment.SHA256)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return core.ErrConflict
		}
	}
	return nil
}

func scanConversationAttachment(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, where string, args []any, out *conversationAttachmentRecord) error {
	statement := `SELECT upload_id::text,source_id::text,owner_id,account_generation,turn_request_id::text,
		begin_idempotency_key::text,begin_request_digest,kind,name,media_type,declared_size,content_sha256,
		content_bytes,received_size,next_ordinal,status,revision,expires_at,created_at,updated_at
		FROM core_conversation_attachment_uploads WHERE ` + where
	var status string
	err := query.QueryRow(ctx, statement, args...).Scan(&out.UploadID, &out.SourceID, &out.OwnerID,
		&out.AccountGeneration, &out.TurnRequestID, &out.BeginKey, &out.BeginDigest, &out.Kind, &out.Name, &out.MediaType,
		&out.DeclaredSize, &out.ContentSHA256, &out.Content, &out.ReceivedSize, &out.NextOrdinal,
		&status, &out.Revision, &out.ExpiresAt, &out.CreatedAt, &out.UpdatedAt)
	out.Status = core.TurnAttachmentStatus(status)
	out.ExpiresAt = out.ExpiresAt.UTC()
	return err
}

func attachmentUploadProjection(record conversationAttachmentRecord) core.TurnAttachmentUpload {
	return core.TurnAttachmentUpload{UploadID: record.UploadID, SourceID: record.SourceID,
		TurnRequestID: record.TurnRequestID, Status: record.Status, ReceivedSize: record.ReceivedSize,
		MaxChunkBytes: core.MaxTurnAttachmentChunkBytes, Revision: record.Revision, ExpiresAt: record.ExpiresAt.UTC()}
}

func attachmentProjection(record conversationAttachmentRecord) core.TurnAttachment {
	return core.TurnAttachment{SourceID: record.SourceID, Revision: 1, TurnRequestID: record.TurnRequestID,
		Kind: record.Kind, Name: record.Name, MediaType: record.MediaType, SizeBytes: record.DeclaredSize,
		SHA256: record.ContentSHA256, Status: core.TurnAttachmentCommitted, ExpiresAt: record.ExpiresAt.UTC()}
}

func loadAttachmentUploadReplay(ctx context.Context, tx pgx.Tx, operation, key, digest, owner string, generation uint64) (core.TurnAttachmentUpload, bool, error) {
	var storedDigest string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT replay.request_digest,replay.response_json FROM core_conversation_attachment_replays replay
		JOIN core_conversation_attachment_uploads upload ON upload.upload_id=replay.upload_id
		WHERE replay.operation=$1 AND replay.idempotency_key=$2 AND upload.owner_id=$3 AND upload.account_generation=$4`,
		operation, key, owner, generation).Scan(&storedDigest, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.TurnAttachmentUpload{}, false, nil
	}
	var value core.TurnAttachmentUpload
	if err != nil || storedDigest != digest || json.Unmarshal(raw, &value) != nil {
		return core.TurnAttachmentUpload{}, false, core.ErrConflict
	}
	return value, true, nil
}

func loadAttachmentCommitReplay(ctx context.Context, tx pgx.Tx, key, digest, owner string, generation uint64) (core.TurnAttachment, bool, error) {
	var storedDigest string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT replay.request_digest,replay.response_json FROM core_conversation_attachment_replays replay
		JOIN core_conversation_attachment_uploads upload ON upload.upload_id=replay.upload_id
		WHERE replay.operation='commit' AND replay.idempotency_key=$1 AND upload.owner_id=$2 AND upload.account_generation=$3`,
		key, owner, generation).Scan(&storedDigest, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.TurnAttachment{}, false, nil
	}
	var value core.TurnAttachment
	if err != nil || storedDigest != digest || json.Unmarshal(raw, &value) != nil {
		return core.TurnAttachment{}, false, core.ErrConflict
	}
	return value, true, nil
}

func storeAttachmentUploadReplay(ctx context.Context, tx pgx.Tx, operation, key, digest, uploadID string, value core.TurnAttachmentUpload) error {
	raw, _ := json.Marshal(value)
	_, err := tx.Exec(ctx, `INSERT INTO core_conversation_attachment_replays(operation,idempotency_key,request_digest,upload_id,response_json)
		VALUES($1,$2,$3,$4,$5)`, operation, key, digest, uploadID, raw)
	return err
}

func storeAttachmentCommitReplay(ctx context.Context, tx pgx.Tx, key, digest, uploadID string, value core.TurnAttachment) error {
	raw, _ := json.Marshal(value)
	_, err := tx.Exec(ctx, `INSERT INTO core_conversation_attachment_replays(operation,idempotency_key,request_digest,upload_id,response_json)
		VALUES('commit',$1,$2,$3,$4)`, key, digest, uploadID, raw)
	return err
}

func attachmentDigest(value any) string {
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func lowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

var _ core.TurnAttachmentUploadStore = (*CoreConversationStore)(nil)

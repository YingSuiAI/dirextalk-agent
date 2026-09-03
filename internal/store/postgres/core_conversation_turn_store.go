package postgres

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const durableTurnDispatchEnvelopeVersion = 1

const deferredTurnSteerStatus = "deferred_tool"

type durableTurnToolCallState string

const (
	durableTurnToolCallPending    durableTurnToolCallState = "pending"
	durableTurnToolCallDispatched durableTurnToolCallState = "dispatched"
	durableTurnToolCallTerminal   durableTurnToolCallState = "terminal"
)

// durableTurnDispatchEnvelope is the sole current durable model-result shape.
// Immediate tool dispatch authority is private to the turn row so it cannot
// consume or leak a public conversation event sequence.
type durableTurnDispatchEnvelope struct {
	Version int                   `json:"version"`
	Result  core.ModelRunResult   `json:"result"`
	Calls   []durableTurnToolCall `json:"calls,omitempty"`
}

type durableTurnToolCall struct {
	CallID       string                   `json:"call_id"`
	State        durableTurnToolCallState `json:"state"`
	ResultDigest string                   `json:"result_digest,omitempty"`
}

func durableTurnModelCalls(result core.ModelRunResult) []core.ToolCall {
	if len(result.ToolCalls) != 0 {
		return result.ToolCalls
	}
	return result.Message.ToolCalls
}

func durableTurnToolResultDigest(result core.ToolResult) string {
	raw, _ := json.Marshal(result)
	return sha256hexPG(raw)
}

func newDurableTurnDispatchEnvelope(result core.ModelRunResult) (durableTurnDispatchEnvelope, error) {
	result.TransientProviderReasoning = ""
	envelope := durableTurnDispatchEnvelope{Version: durableTurnDispatchEnvelopeVersion, Result: result}
	calls := durableTurnModelCalls(result)
	seen := make(map[string]struct{}, len(calls))
	for _, call := range calls {
		if call.Validate() != nil {
			return durableTurnDispatchEnvelope{}, core.ErrInvalid
		}
		if _, duplicate := seen[call.ID]; duplicate {
			return durableTurnDispatchEnvelope{}, core.ErrInvalid
		}
		seen[call.ID] = struct{}{}
		envelope.Calls = append(envelope.Calls, durableTurnToolCall{CallID: call.ID, State: durableTurnToolCallPending})
	}
	return envelope, nil
}

func loadDurableTurnDispatchEnvelope(raw []byte) (durableTurnDispatchEnvelope, error) {
	var envelope durableTurnDispatchEnvelope
	if len(raw) == 0 || json.Unmarshal(raw, &envelope) != nil || envelope.Version != durableTurnDispatchEnvelopeVersion {
		return durableTurnDispatchEnvelope{}, core.ErrConflict
	}
	expected, err := newDurableTurnDispatchEnvelope(envelope.Result)
	if err != nil || len(expected.Calls) != len(envelope.Calls) {
		return durableTurnDispatchEnvelope{}, core.ErrConflict
	}
	for index := range expected.Calls {
		entry := envelope.Calls[index]
		if entry.CallID != expected.Calls[index].CallID {
			return durableTurnDispatchEnvelope{}, core.ErrConflict
		}
		switch entry.State {
		case durableTurnToolCallPending, durableTurnToolCallDispatched:
			if entry.ResultDigest != "" {
				return durableTurnDispatchEnvelope{}, core.ErrConflict
			}
		case durableTurnToolCallTerminal:
			digestBytes, digestErr := hex.DecodeString(entry.ResultDigest)
			if digestErr != nil || len(digestBytes) != 32 || hex.EncodeToString(digestBytes) != entry.ResultDigest {
				return durableTurnDispatchEnvelope{}, core.ErrConflict
			}
		default:
			return durableTurnDispatchEnvelope{}, core.ErrConflict
		}
	}
	return envelope, nil
}

func durableTurnToolCallIndex(envelope durableTurnDispatchEnvelope, call core.ToolCall) (int, error) {
	calls := durableTurnModelCalls(envelope.Result)
	for index := range envelope.Calls {
		if envelope.Calls[index].CallID != call.ID {
			continue
		}
		if index >= len(calls) || !reflect.DeepEqual(calls[index], call) {
			return -1, core.ErrConflict
		}
		return index, nil
	}
	return -1, core.ErrConflict
}

// StartTurn stores the complete immutable request binding and its accepted
// event in one transaction. A request UUID is the idempotency identity.
func (s *CoreConversationStore) StartTurn(ctx context.Context, c core.TurnStartCommand) (core.Turn, error) {
	return s.startTurn(ctx, c, nil)
}

func (s *CoreConversationStore) PrepareTurnRuntimeAdmission(ctx context.Context, c core.TurnStartCommand) (core.Turn, error) {
	c.AcceptedAttachmentIDs = append([]string(nil), c.AcceptedAttachmentIDs...)
	c.AttachmentSources = nil
	if err := c.Validate(); err != nil {
		return core.Turn{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	turnID := c.TurnID
	if turnID == "" {
		turnID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn:"+c.RequestID)).String()
	}
	if err = resolveAcceptedTurnAttachments(ctx, tx, &c, turnID); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	now := time.Now().UTC()
	return core.Turn{
		ID: turnID, RequestID: c.RequestID, OwnerID: c.OwnerID, AccountGeneration: c.AccountGeneration,
		ConversationID: c.ConversationID, Prompt: c.Prompt, ProfileID: c.ProfileID,
		ExpectedRevision: cloneRevision(c.ExpectedRevision), State: core.TurnAccepted, Revision: 1,
		CreatedAt: now, UpdatedAt: now, ProfileSnapshot: c.ProfileSnapshot,
		ProfileSnapshotDigest: c.ProfileSnapshot.Digest(), ExtensionSnapshots: append([]core.ExtensionExecutionSnapshot(nil), c.ExtensionSnapshots...),
		ExtensionSnapshotDigest: c.ExtensionSnapshotDigest(), AttachmentSources: append([]core.TurnAttachment(nil), c.AttachmentSources...),
		AttachmentSnapshotDigest: core.TurnAttachmentSnapshotDigest(c.AttachmentSources),
	}, nil
}

func (s *CoreConversationStore) StartTurnWithRuntime(ctx context.Context, c core.TurnStartCommand, runtime core.TurnRuntimeSnapshot) (core.Turn, error) {
	if runtime.Validate() != nil {
		return core.Turn{}, core.ErrInvalid
	}
	return s.startTurn(ctx, c, &runtime)
}

func (s *CoreConversationStore) ValidateTurnRuntime(ctx context.Context, lease core.TurnLease, runtime core.TurnRuntimeSnapshot) error {
	if runtime.Validate() != nil {
		return core.ErrInvalid
	}
	var raw []byte
	var storedDigest *string
	if err := s.pool.QueryRow(ctx, `SELECT runtime_snapshot_json,runtime_snapshot_digest FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running'`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&raw, &storedDigest); err != nil {
		return core.ErrConflict
	}
	var stored core.TurnRuntimeSnapshot
	if storedDigest == nil || json.Unmarshal(raw, &stored) != nil || stored.Validate() != nil || stored.Digest() != *storedDigest || *storedDigest != runtime.Digest() {
		return core.ErrTurnRuntimeIncompatible
	}
	return nil
}

func (s *CoreConversationStore) startTurn(ctx context.Context, c core.TurnStartCommand, admittedRuntime *core.TurnRuntimeSnapshot) (core.Turn, error) {
	// The caller selects source UUIDs only. Immutable metadata is always
	// resolved from the attachment authority while this transaction holds the
	// source locks.
	c.AcceptedAttachmentIDs = append([]string(nil), c.AcceptedAttachmentIDs...)
	c.AttachmentSources = nil
	if err := c.Validate(); err != nil {
		return core.Turn{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	var existing core.Turn
	if err = s.scanTurn(ctx, tx, c.RequestID, &existing); err == nil {
		c.AttachmentSources = append([]core.TurnAttachment(nil), existing.AttachmentSources...)
		if err = c.Validate(); err != nil {
			return core.Turn{}, core.ErrConflict
		}
		fp := c.Fingerprint()
		if existing.ProfileSnapshotDigest != c.ProfileSnapshot.Digest() || existing.RequestFingerprint != fp {
			return core.Turn{}, core.ErrConflict
		}
		if admittedRuntime != nil && (existing.RuntimeSnapshot == nil || existing.RuntimeSnapshot.Digest() != admittedRuntime.Digest()) {
			return core.Turn{}, core.ErrTurnRuntimeIncompatible
		}
		if err = tx.Commit(ctx); err != nil {
			return core.Turn{}, err
		}
		return existing, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return core.Turn{}, err
	}
	var now time.Time
	if c.ExpectedRevision != nil {
		var revision uint64
		if err = tx.QueryRow(ctx, `SELECT revision FROM core_conversations WHERE conversation_id=$1 AND deleted_at IS NULL FOR UPDATE`, c.ConversationID).Scan(&revision); err != nil {
			return core.Turn{}, core.ErrConflict
		}
		if revision != *c.ExpectedRevision {
			return core.Turn{}, core.ErrConflict
		}
		now = time.Now().UTC()
		if _, err = tx.Exec(ctx, `UPDATE core_conversations SET title=$2,updated_at=GREATEST(updated_at,$3) WHERE conversation_id=$1 AND title='' AND NOT EXISTS (SELECT 1 FROM core_messages WHERE conversation_id=$1)`, c.ConversationID, core.ProvisionalConversationTitle(c.Prompt), now); err != nil {
			return core.Turn{}, err
		}
		if c.ContextCompaction != nil {
			if err = applyAutomaticTurnContextCompaction(ctx, tx, c.ConversationID, revision, *c.ContextCompaction); err != nil {
				return core.Turn{}, err
			}
		}
	}
	// A turn may open a new conversation. Materialize its empty revision
	// baseline before inserting the turn so the foreign key is valid; the
	// completion transaction advances this row with the fenced revision.
	if c.ExpectedRevision == nil {
		now = time.Now().UTC()
		if _, err = tx.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title,revision,created_at,updated_at) VALUES($1,$2,1,$3,$3) ON CONFLICT(conversation_id) DO NOTHING`, c.ConversationID, core.ProvisionalConversationTitle(c.Prompt), now); err != nil {
			return core.Turn{}, err
		}
		if _, err = tx.Exec(ctx, `UPDATE core_conversations SET title=$2,updated_at=GREATEST(updated_at,$3)
			WHERE conversation_id=$1 AND deleted_at IS NULL AND title=''
			AND NOT EXISTS (SELECT 1 FROM core_messages WHERE conversation_id=$1)`, c.ConversationID, core.ProvisionalConversationTitle(c.Prompt), now); err != nil {
			return core.Turn{}, err
		}
		var title string
		if err = tx.QueryRow(ctx, `SELECT title FROM core_conversations WHERE conversation_id=$1 AND deleted_at IS NULL`, c.ConversationID).Scan(&title); err != nil || strings.TrimSpace(title) == "" {
			return core.Turn{}, core.ErrConflict
		}
	}
	turnID := c.TurnID
	if turnID == "" {
		turnID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn:"+c.RequestID)).String()
	}
	if err = resolveAcceptedTurnAttachments(ctx, tx, &c, turnID); err != nil {
		return core.Turn{}, err
	}
	var runtimeSnapshot *core.TurnRuntimeSnapshot
	var runtimeRaw []byte
	var runtimeDigest any
	if admittedRuntime != nil {
		executionMode := c.ExecutionMode
		if executionMode == "" {
			executionMode = core.TurnExecutionInteractive
		}
		if admittedRuntime.Validate() != nil || admittedRuntime.ProfileSnapshotDigest != c.ProfileSnapshot.Digest() ||
			admittedRuntime.RequestDialect != string(c.ProfileSnapshot.RequestDialect) || admittedRuntime.ExtensionDigest != c.ExtensionSnapshotDigest() ||
			admittedRuntime.AttachmentDigest != core.TurnAttachmentSnapshotDigest(c.AttachmentSources) ||
			admittedRuntime.ExecutionPolicy.Mode != executionMode {
			return core.Turn{}, core.ErrInvalid
		}
		built := *admittedRuntime
		runtimeSnapshot = &built
		runtimeRaw, _ = json.Marshal(built)
		runtimeDigest = built.Digest()
	}
	fp := c.Fingerprint()
	metadataSnapshot := c.ProfileSnapshot
	metadataSnapshot.APIKey = ""
	raw, _ := json.Marshal(metadataSnapshot)
	plaintext := []byte(c.ProfileSnapshot.APIKey)
	envelope, err := s.sealDurableSecret("core_conversation_turns", turnID, c.ProfileSnapshot.Revision, "profile_snapshot_api_key", plaintext)
	clearBytes(plaintext)
	if err != nil {
		return core.Turn{}, err
	}
	textSnapshots := c.ExtensionSnapshots
	if textSnapshots == nil {
		textSnapshots = []core.ExtensionExecutionSnapshot{}
	}
	extRaw, _ := json.Marshal(textSnapshots)
	attachmentSnapshots := c.AttachmentSources
	if attachmentSnapshots == nil {
		attachmentSnapshots = []core.TurnAttachment{}
	}
	attachmentRaw, _ := json.Marshal(attachmentSnapshots)
	attachmentDigest := core.TurnAttachmentSnapshotDigest(c.AttachmentSources)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turns(turn_id,request_id,conversation_id,request_fingerprint,owner_id,account_generation,prompt,profile_id,expected_revision,profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,extension_snapshot_json,extension_snapshot_digest,attachment_snapshot_json,attachment_snapshot_digest,runtime_snapshot_json,runtime_snapshot_digest,state,revision,last_sequence,lease_epoch,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,'accepted',1,1,1,$21,$21)`, turnID, c.RequestID, nullableUUIDPG(c.ConversationID), fp, c.OwnerID, c.AccountGeneration, c.Prompt, c.ProfileID, nullableUint64(c.ExpectedRevision), raw, c.ProfileSnapshot.Digest(), envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext, extRaw, c.ExtensionSnapshotDigest(), attachmentRaw, attachmentDigest, nullableJSONPG(runtimeRaw), runtimeDigest, now); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			_ = tx.Rollback(ctx)
			replay, replayErr := s.GetTurnByRequestID(ctx, c.RequestID)
			if replayErr == nil {
				if replay.RequestFingerprint == fp {
					return replay, nil
				}
				return core.Turn{}, core.ErrConflict
			}
		}
		return core.Turn{}, err
	}
	if err = consumeAcceptedTurnAttachments(ctx, tx, c, turnID); err != nil {
		return core.Turn{}, err
	}
	payload, _ := json.Marshal(core.TurnEvent{TurnID: turnID, Sequence: 1, Revision: 1, Kind: core.TurnEventAccepted, CreatedAt: now})
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,1,$2,$3,$4)`, turnID, string(core.TurnEventAccepted), payload, now); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return core.Turn{ID: turnID, RequestID: c.RequestID, RequestFingerprint: fp, OwnerID: c.OwnerID, AccountGeneration: c.AccountGeneration, ConversationID: c.ConversationID, Prompt: c.Prompt, ProfileID: c.ProfileID, ExpectedRevision: cloneRevision(c.ExpectedRevision), Revision: 1, State: core.TurnAccepted, LastSequence: 1, CreatedAt: now, UpdatedAt: now, ProfileSnapshot: c.ProfileSnapshot, ProfileSnapshotDigest: c.ProfileSnapshot.Digest(), ExtensionSnapshots: append([]core.ExtensionExecutionSnapshot(nil), c.ExtensionSnapshots...), ExtensionSnapshotDigest: c.ExtensionSnapshotDigest(), AttachmentSources: append([]core.TurnAttachment(nil), c.AttachmentSources...), AttachmentSnapshotDigest: attachmentDigest, RuntimeSnapshot: runtimeSnapshot}, nil
}

func applyAutomaticTurnContextCompaction(ctx context.Context, tx pgx.Tx, conversationID string, revision uint64, plan core.TurnContextCompaction) error {
	if !coreUUID(conversationID) || plan.Validate() != nil || revision != plan.ExpectedRevision {
		return core.ErrInvalid
	}
	var existingOffset int64
	var existingWorkingRaw []byte
	var existingProtectedDigest *string
	contextErr := tx.QueryRow(ctx, `SELECT message_offset,working_context_json,protected_digest FROM core_conversation_contexts WHERE conversation_id=$1 FOR UPDATE`, conversationID).Scan(&existingOffset, &existingWorkingRaw, &existingProtectedDigest)
	if contextErr != nil && !errors.Is(contextErr, pgx.ErrNoRows) {
		return contextErr
	}
	existing := core.Conversation{}
	if err := decodeWorkingContextPG(existingWorkingRaw, existingProtectedDigest, &existing); err != nil {
		return err
	}
	if existingOffset < 0 || uint64(existingOffset) != plan.ExpectedPreviousOffset ||
		existing.WorkingContextProtectedDigest != plan.ExpectedPreviousProtectedDigest {
		return core.ErrConflict
	}
	var messageCount int64
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM core_messages WHERE conversation_id=$1`, conversationID).Scan(&messageCount); err != nil {
		return err
	}
	if messageCount < 0 || uint64(messageCount) != plan.ExpectedTranscriptCount {
		return core.ErrConflict
	}
	var firstID, throughID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT message_id FROM core_messages WHERE conversation_id=$1 ORDER BY sequence LIMIT 1 FOR SHARE`, conversationID).Scan(&firstID); err != nil {
		return core.ErrConflict
	}
	if err := tx.QueryRow(ctx, `SELECT message_id FROM core_messages WHERE conversation_id=$1 ORDER BY sequence OFFSET $2 LIMIT 1 FOR SHARE`, conversationID, int64(plan.Offset-1)).Scan(&throughID); err != nil {
		return core.ErrConflict
	}
	if firstID.String() != plan.FirstMessageID || throughID.String() != plan.ThroughMessageID {
		return core.ErrConflict
	}
	if plan.Offset < plan.ExpectedTranscriptCount {
		var retainedID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT message_id FROM core_messages WHERE conversation_id=$1 ORDER BY sequence OFFSET $2 LIMIT 1 FOR SHARE`, conversationID, int64(plan.Offset)).Scan(&retainedID); err != nil || retainedID.String() != plan.RetainedFirstMessageID {
			return core.ErrConflict
		}
	}
	workingRaw, err := json.Marshal(plan.WorkingContext)
	if err != nil {
		return core.ErrInvalid
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_contexts(conversation_id,summary,message_offset,working_context_version,working_context_json,protected_digest,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(conversation_id) DO UPDATE SET summary=$2,message_offset=$3,working_context_version=$4,working_context_json=$5,protected_digest=$6,updated_at=$7`, conversationID, plan.Summary, int64(plan.Offset), core.WorkingContextVersion, workingRaw, plan.WorkingContext.ProtectedDigest(), time.Now().UTC()); err != nil {
		return err
	}
	return nil
}

func nullableJSONPG(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

func nullableUint64(v *uint64) any {
	if v == nil {
		return nil
	}
	return *v
}
func cloneRevision(v *uint64) *uint64 {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}

type turnRow interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *CoreConversationStore) scanTurn(ctx context.Context, q turnRow, key string, out *core.Turn) error {
	var conv, profile *uuid.UUID
	var expected *int64
	var snapshot, runtimeRaw []byte
	var responseRaw []byte
	var digest, extensionDigest, attachmentDigest, state, code, summary string
	var runtimeDigest *string
	var cancel bool
	var cancelRequestID *uuid.UUID
	var cancelRequestFingerprint *string
	var dispatchResult []byte
	var dispatchState string
	var dispatchEpoch uint64
	var modelDispatchCount uint32
	var modelActiveMilliseconds int64
	var modelDispatchStartedAt *time.Time
	var last int64
	var extensionRaw, attachmentRaw []byte
	var snapshotKeyVersion uint32
	var snapshotNonce, snapshotCiphertext []byte
	err := q.QueryRow(ctx, `SELECT turn_id,request_id,request_fingerprint,owner_id,account_generation,conversation_id,prompt,profile_id,expected_revision,profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,extension_snapshot_json,extension_snapshot_digest,attachment_snapshot_json,attachment_snapshot_digest,runtime_snapshot_json,runtime_snapshot_digest,state,cancel_requested,cancel_request_id,cancel_request_fingerprint,revision,last_sequence,terminal_code,terminal_summary,response_json,dispatch_state,dispatch_epoch,dispatch_result_json,model_dispatch_count,model_active_milliseconds,model_dispatch_started_at,created_at,updated_at FROM core_conversation_turns WHERE request_id=$1 OR turn_id=$1`, key).Scan(&out.ID, &out.RequestID, &out.RequestFingerprint, &out.OwnerID, &out.AccountGeneration, &conv, &out.Prompt, &profile, &expected, &snapshot, &digest, &snapshotKeyVersion, &snapshotNonce, &snapshotCiphertext, &extensionRaw, &extensionDigest, &attachmentRaw, &attachmentDigest, &runtimeRaw, &runtimeDigest, &state, &cancel, &cancelRequestID, &cancelRequestFingerprint, &out.Revision, &last, &code, &summary, &responseRaw, &dispatchState, &dispatchEpoch, &dispatchResult, &modelDispatchCount, &modelActiveMilliseconds, &modelDispatchStartedAt, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return err
	}
	if conv != nil {
		out.ConversationID = conv.String()
	}
	if profile != nil {
		out.ProfileID = profile.String()
	}
	if expected != nil {
		x := uint64(*expected)
		out.ExpectedRevision = &x
	}
	if len(snapshot) > 0 {
		if json.Unmarshal(snapshot, &out.ProfileSnapshot) != nil {
			return core.ErrConflict
		}
		plaintext, openErr := s.openDurableSecret("core_conversation_turns", out.ID, out.ProfileSnapshot.Revision, "profile_snapshot_api_key", snapshotKeyVersion, snapshotNonce, snapshotCiphertext)
		if openErr != nil {
			return core.ErrConflict
		}
		out.ProfileSnapshot.APIKey = string(plaintext)
		clearBytes(plaintext)
		if out.ProfileSnapshot.Validate() != nil || out.ProfileSnapshot.Digest() != digest {
			return core.ErrConflict
		}
	}
	out.ProfileSnapshotDigest, out.State, out.CancelRequested, out.LastSequence = digest, core.TurnState(state), cancel, last
	out.ExtensionSnapshotDigest = extensionDigest
	if len(extensionRaw) > 0 {
		if json.Unmarshal(extensionRaw, &out.ExtensionSnapshots) != nil {
			return core.ErrConflict
		}
	}
	out.AttachmentSnapshotDigest = attachmentDigest
	if len(attachmentRaw) > 0 {
		if json.Unmarshal(attachmentRaw, &out.AttachmentSources) != nil ||
			core.ValidateAcceptedTurnAttachments(out.RequestID, attachmentSourceIDs(out.AttachmentSources), out.AttachmentSources) != nil ||
			core.TurnAttachmentSnapshotDigest(out.AttachmentSources) != attachmentDigest {
			return core.ErrConflict
		}
	} else if attachmentDigest != "" {
		return core.ErrConflict
	}
	if len(runtimeRaw) != 0 {
		var runtime core.TurnRuntimeSnapshot
		if runtimeDigest == nil || json.Unmarshal(runtimeRaw, &runtime) != nil || runtime.Validate() != nil || runtime.Digest() != *runtimeDigest {
			return core.ErrConflict
		}
		out.RuntimeSnapshot = &runtime
	} else if runtimeDigest != nil {
		return core.ErrConflict
	}
	if cancelRequestID != nil {
		out.CancelRequestID = cancelRequestID.String()
	}
	if cancelRequestFingerprint != nil {
		out.CancelRequestFingerprint = *cancelRequestFingerprint
	}
	out.TerminalCode, out.TerminalSummary = code, summary
	out.DispatchState, out.DispatchEpoch = dispatchState, dispatchEpoch
	out.ModelDispatchCount = modelDispatchCount
	out.ModelActiveDuration = time.Duration(modelActiveMilliseconds) * time.Millisecond
	if modelDispatchStartedAt != nil {
		out.ModelDispatchStartedAt = modelDispatchStartedAt.UTC()
	}
	if len(dispatchResult) > 0 && (out.State == core.TurnAccepted || out.State == core.TurnRunning || out.State == core.TurnWaitingConfirmation) {
		envelope, envelopeErr := loadDurableTurnDispatchEnvelope(dispatchResult)
		if envelopeErr != nil {
			return core.ErrConflict
		}
		out.DispatchResult = &envelope.Result
	}
	if len(responseRaw) > 0 {
		var response core.ChatResponse
		if json.Unmarshal(responseRaw, &response) == nil {
			out.Response = &response
		}
	}
	return nil
}

func attachmentSourceIDs(values []core.TurnAttachment) []string {
	ids := make([]string, 0, len(values))
	for _, value := range values {
		ids = append(ids, value.SourceID)
	}
	return ids
}

func (s *CoreConversationStore) GetTurn(ctx context.Context, id string) (core.Turn, error) {
	var out core.Turn
	err := s.scanTurn(ctx, s.pool, id, &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, core.ErrConflict
	}
	return out, err
}

func (s *CoreConversationStore) GetTurnByRequestID(ctx context.Context, id string) (core.Turn, error) {
	var out core.Turn
	err := s.scanTurn(ctx, s.pool, id, &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, core.ErrConflict
	}
	return out, err
}

func (s *CoreConversationStore) ListRecoverableTurns(ctx context.Context) ([]core.Turn, error) {
	rows, err := s.pool.Query(ctx, `SELECT request_id FROM core_conversation_turns WHERE state IN ('accepted','running','waiting_confirmation')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Turn
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		turn, e := s.GetTurn(ctx, id)
		if e != nil {
			return nil, e
		}
		out = append(out, turn)
	}
	return out, rows.Err()
}

func (s *CoreConversationStore) ListTurns(ctx context.Context, conversationID, token string, limit int) ([]core.Turn, string, error) {
	if _, err := uuid.Parse(conversationID); err != nil || limit <= 0 || limit > 1000 {
		return nil, "", core.ErrInvalid
	}
	type cursor struct {
		CreatedAt time.Time `json:"created_at"`
		TurnID    string    `json:"turn_id"`
	}
	var after cursor
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || json.Unmarshal(raw, &after) != nil || after.CreatedAt.IsZero() || uuid.Validate(after.TurnID) != nil {
			return nil, "", core.ErrInvalid
		}
	}
	rows, err := s.pool.Query(ctx, `SELECT turn_id,created_at FROM core_conversation_turns WHERE conversation_id=$1 AND ($2::timestamptz IS NULL OR (created_at,turn_id)>($2,$3::uuid)) ORDER BY created_at,turn_id LIMIT $4`, conversationID, nullableTime(after.CreatedAt), nullableUUID(after.TurnID), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	ids := make([]cursor, 0, limit+1)
	for rows.Next() {
		var item cursor
		if err := rows.Scan(&item.TurnID, &item.CreatedAt); err != nil {
			return nil, "", err
		}
		item.CreatedAt = item.CreatedAt.UTC()
		ids = append(ids, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(ids) > limit {
		last := ids[limit-1]
		ids = ids[:limit]
		raw, _ := json.Marshal(last)
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	out := make([]core.Turn, 0, len(ids))
	for _, item := range ids {
		turn, err := s.GetTurn(ctx, item.TurnID)
		if err != nil {
			return nil, "", err
		}
		out = append(out, turn)
	}
	return out, next, nil
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return uuid.MustParse(value)
}

func (s *CoreConversationStore) ClaimTurn(ctx context.Context, id string, now time.Time, ttl time.Duration) (core.TurnLease, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.TurnLease{}, err
	}
	defer tx.Rollback(ctx)
	var turn core.Turn
	if err = s.scanTurn(ctx, tx, id, &turn); err != nil {
		return core.TurnLease{}, core.ErrConflict
	}
	if turn.State == core.TurnCompleted || turn.State == core.TurnCanceled || turn.State == core.TurnFailed || turn.State == core.TurnWaitingConfirmation {
		_ = tx.Commit(ctx)
		return core.TurnLease{Turn: turn}, nil
	}
	var leaseID *uuid.UUID
	var epoch uint64
	var exp *time.Time
	var currentState string
	var cancelRequested bool
	if err = tx.QueryRow(ctx, `SELECT state,cancel_requested,lease_id,lease_epoch,lease_expires_at FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, id).Scan(&currentState, &cancelRequested, &leaseID, &epoch, &exp); err != nil {
		return core.TurnLease{}, core.ErrConflict
	}
	turn.State, turn.CancelRequested = core.TurnState(currentState), cancelRequested
	if currentState == string(core.TurnCompleted) || currentState == string(core.TurnCanceled) || currentState == string(core.TurnFailed) || currentState == string(core.TurnWaitingConfirmation) {
		_ = tx.Commit(ctx)
		return core.TurnLease{Turn: turn}, nil
	}
	if cancelRequested {
		_ = tx.Commit(ctx)
		return core.TurnLease{Turn: turn}, nil
	}
	if exp != nil && exp.After(now) && leaseID != nil {
		return core.TurnLease{}, core.ErrInFlight
	}
	newID := uuid.New()
	expire := now.Add(ttl)
	epoch++
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET state='running',lease_id=$2,lease_epoch=$3,lease_expires_at=$4,updated_at=$5 WHERE turn_id=$1`, id, newID, epoch, expire, now); err != nil {
		return core.TurnLease{}, err
	}
	turn.State, turn.UpdatedAt = core.TurnRunning, now
	if err = tx.Commit(ctx); err != nil {
		return core.TurnLease{}, err
	}
	return core.TurnLease{Turn: turn, LeaseID: newID.String(), Epoch: epoch, ExpiresAt: expire}, nil
}

func (s *CoreConversationStore) RenewTurn(ctx context.Context, id, lease string, epoch uint64, now time.Time, ttl time.Duration) (core.TurnLease, error) {
	newExp := now.Add(ttl)
	var next uint64
	if err := s.pool.QueryRow(ctx, `UPDATE core_conversation_turns SET lease_epoch=lease_epoch+1,lease_expires_at=$4,updated_at=$5 WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running' RETURNING lease_epoch`, id, lease, epoch, newExp, now).Scan(&next); err != nil {
		return core.TurnLease{}, core.ErrConflict
	}
	turn, err := s.GetTurn(ctx, id)
	if err != nil {
		return core.TurnLease{}, err
	}
	return core.TurnLease{Turn: turn, LeaseID: lease, Epoch: next, ExpiresAt: newExp}, nil
}

func (s *CoreConversationStore) PrepareTurnModel(ctx context.Context, lease core.TurnLease, directive core.TurnDispatchDirective) (core.Turn, error) {
	if uuid.Validate(lease.Turn.ID) != nil || uuid.Validate(lease.LeaseID) != nil || lease.Epoch == 0 || lease.Turn.Revision == 0 {
		return core.Turn{}, core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	var current core.Turn
	if err = s.scanTurn(ctx, tx, lease.Turn.ID, &current); errors.Is(err, pgx.ErrNoRows) {
		return core.Turn{}, core.ErrConflict
	} else if err != nil {
		return core.Turn{}, err
	}
	if current.RuntimeSnapshot == nil || lease.Turn.RuntimeSnapshot == nil ||
		current.RequestID != lease.Turn.RequestID || current.OwnerID != lease.Turn.OwnerID || current.AccountGeneration != lease.Turn.AccountGeneration ||
		current.ConversationID != lease.Turn.ConversationID || current.ProfileID != lease.Turn.ProfileID || current.Revision != lease.Turn.Revision ||
		current.RuntimeSnapshot.Digest() != lease.Turn.RuntimeSnapshot.Digest() {
		return core.Turn{}, core.ErrConflict
	}
	if directive.ValidateFor(*current.RuntimeSnapshot, current.ExtensionSnapshots) != nil {
		return core.Turn{}, core.ErrInvalid
	}
	directiveRaw, err := json.Marshal(directive)
	if err != nil {
		return core.Turn{}, core.ErrInvalid
	}
	var out core.Turn
	var attempt uint32
	var dispatchEpoch uint64
	var started time.Time
	finalizing := directive.FinalizationReason != ""
	policy := current.RuntimeSnapshot.ExecutionPolicy
	maxDispatches := policy.MaxModelDispatches
	if finalizing {
		maxDispatches += core.MaxTurnFinalizationDispatches
	}
	err = tx.QueryRow(ctx, `UPDATE core_conversation_turns SET dispatch_state='dispatched',dispatch_epoch=dispatch_epoch+1,
		model_dispatch_count=model_dispatch_count+1,model_dispatch_started_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running' AND dispatch_state=''
		AND model_dispatch_count < $4 AND ($7 OR model_active_milliseconds < $5) AND revision=$6
		AND (NOT $7 OR EXISTS (SELECT 1 FROM core_conversation_turn_finalizations f
			WHERE f.turn_id=core_conversation_turns.turn_id AND f.turn_revision=core_conversation_turns.revision
			AND f.owner_id=core_conversation_turns.owner_id AND f.account_generation=core_conversation_turns.account_generation
			AND f.reason=$8))
		AND (NOT $7 OR NOT EXISTS (SELECT 1 FROM core_conversation_model_dispatch_directives d
			WHERE d.turn_id=core_conversation_turns.turn_id AND d.directive_json ? 'finalization_reason'))
		RETURNING turn_id,model_dispatch_count,dispatch_epoch,model_dispatch_started_at`,
		lease.Turn.ID, lease.LeaseID, lease.Epoch, maxDispatches, policy.MaxModelActiveMilliseconds,
		lease.Turn.Revision, finalizing, string(directive.FinalizationReason)).Scan(&out.ID, &attempt, &dispatchEpoch, &started)
	if err != nil {
		current, getErr := s.GetTurn(ctx, lease.Turn.ID)
		if getErr == nil && current.RuntimeSnapshot != nil && ((!finalizing && (current.ModelDispatchCount >= policy.MaxModelDispatches || current.ModelActiveDuration >= policy.MaxModelActiveDuration())) ||
			(finalizing && current.ModelDispatchCount >= policy.MaxModelDispatches+core.MaxTurnFinalizationDispatches)) {
			return core.Turn{}, core.ErrModelBudgetExhausted
		}
		return core.Turn{}, core.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_model_attempts(turn_id,attempt_sequence,dispatch_epoch,lease_id,lease_epoch,state,started_at) VALUES($1,$2,$3,$4,$5,'dispatched',$6)`, lease.Turn.ID, attempt, dispatchEpoch, lease.LeaseID, lease.Epoch, started); err != nil {
		return core.Turn{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_model_dispatch_directives(turn_id,attempt_sequence,owner_id,account_generation,turn_revision,dispatch_epoch,lease_id,lease_epoch,runtime_snapshot_digest,directive_json,directive_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, lease.Turn.ID, attempt, current.OwnerID, current.AccountGeneration, current.Revision, dispatchEpoch, lease.LeaseID, lease.Epoch, current.RuntimeSnapshot.Digest(), directiveRaw, directive.Digest(), started); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, out.ID)
}

func (s *CoreConversationStore) LoadTurnModelDirective(ctx context.Context, lease core.TurnLease) (core.TurnDispatchDirective, error) {
	if uuid.Validate(lease.Turn.ID) != nil || uuid.Validate(lease.LeaseID) != nil || lease.Epoch == 0 || lease.Turn.Revision == 0 {
		return core.TurnDispatchDirective{}, core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.TurnDispatchDirective{}, err
	}
	defer tx.Rollback(ctx)
	var current core.Turn
	if err = s.scanTurn(ctx, tx, lease.Turn.ID, &current); errors.Is(err, pgx.ErrNoRows) {
		return core.TurnDispatchDirective{}, core.ErrConflict
	} else if err != nil {
		return core.TurnDispatchDirective{}, err
	}
	if current.RuntimeSnapshot == nil || lease.Turn.RuntimeSnapshot == nil ||
		current.RequestID != lease.Turn.RequestID || current.OwnerID != lease.Turn.OwnerID || current.AccountGeneration != lease.Turn.AccountGeneration ||
		current.ConversationID != lease.Turn.ConversationID || current.ProfileID != lease.Turn.ProfileID || current.Revision != lease.Turn.Revision ||
		current.RuntimeSnapshot.Digest() != lease.Turn.RuntimeSnapshot.Digest() {
		return core.TurnDispatchDirective{}, core.ErrConflict
	}
	var raw []byte
	var directiveDigest, runtimeDigest string
	err = tx.QueryRow(ctx, `SELECT d.directive_json,d.directive_digest,d.runtime_snapshot_digest
		FROM core_conversation_model_dispatch_directives d
		JOIN core_conversation_model_attempts a ON a.turn_id=d.turn_id AND a.attempt_sequence=d.attempt_sequence
		JOIN core_conversation_turns t ON t.turn_id=d.turn_id
		WHERE d.turn_id=$1 AND t.lease_id=$2 AND t.lease_epoch=$3 AND t.revision=$4
		AND d.owner_id=t.owner_id AND d.account_generation=t.account_generation
		AND t.state='running' AND t.dispatch_state='dispatched' AND t.dispatch_epoch=d.dispatch_epoch
		AND t.runtime_snapshot_digest=d.runtime_snapshot_digest
		AND a.state='dispatched' AND a.dispatch_epoch=d.dispatch_epoch
		AND a.lease_id=d.lease_id AND a.lease_epoch=d.lease_epoch
		AND d.turn_revision=t.revision`, lease.Turn.ID, lease.LeaseID, lease.Epoch, lease.Turn.Revision).Scan(&raw, &directiveDigest, &runtimeDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.TurnDispatchDirective{}, core.ErrConflict
	} else if err != nil {
		return core.TurnDispatchDirective{}, err
	}
	var directive core.TurnDispatchDirective
	if json.Unmarshal(raw, &directive) != nil || directive.ValidateFor(*current.RuntimeSnapshot, current.ExtensionSnapshots) != nil || directive.Digest() != directiveDigest || current.RuntimeSnapshot.Digest() != runtimeDigest {
		return core.TurnDispatchDirective{}, core.ErrTurnRuntimeIncompatible
	}
	if err = tx.Commit(ctx); err != nil {
		return core.TurnDispatchDirective{}, err
	}
	return directive, nil
}

func (s *CoreConversationStore) PrepareTurnFinalization(ctx context.Context, lease core.TurnLease, intent core.TurnFinalizationIntent, failure *core.ModelAttemptFailure) error {
	if uuid.Validate(lease.Turn.ID) != nil || uuid.Validate(lease.LeaseID) != nil || lease.Epoch == 0 ||
		lease.Turn.Revision == 0 || intent.Validate() != nil || failure != nil && failure.Validate() != nil {
		return core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var ownerID, state, dispatchState, leaseID, terminalCode, terminalSummary string
	var accountGeneration, revision, leaseEpoch, dispatchEpoch uint64
	var modelDispatchCount uint32
	var modelDispatchStartedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT owner_id,account_generation,revision,state,COALESCE(lease_id::text,''),lease_epoch,
		dispatch_state,dispatch_epoch,model_dispatch_count,model_dispatch_started_at,terminal_code,terminal_summary
		FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, lease.Turn.ID).
		Scan(&ownerID, &accountGeneration, &revision, &state, &leaseID, &leaseEpoch, &dispatchState, &dispatchEpoch,
			&modelDispatchCount, &modelDispatchStartedAt, &terminalCode, &terminalSummary)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ErrConflict
	}
	if err != nil {
		return err
	}
	if state != string(core.TurnRunning) || leaseID != lease.LeaseID || leaseEpoch != lease.Epoch ||
		revision != lease.Turn.Revision || ownerID != lease.Turn.OwnerID || accountGeneration != lease.Turn.AccountGeneration {
		return core.ErrConflict
	}
	inserted, err := tx.Exec(ctx, `INSERT INTO core_conversation_turn_finalizations(
		turn_id,owner_id,account_generation,turn_revision,intent_version,reason,created_at)
		VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()) ON CONFLICT (turn_id,turn_revision) DO NOTHING`,
		lease.Turn.ID, ownerID, accountGeneration, revision, intent.Version, string(intent.Reason))
	if err != nil {
		return err
	}
	newIntent := inserted.RowsAffected() == 1
	if !newIntent {
		var storedVersion int
		var storedReason string
		if err = tx.QueryRow(ctx, `SELECT intent_version,reason FROM core_conversation_turn_finalizations
			WHERE turn_id=$1 AND turn_revision=$2 AND owner_id=$3 AND account_generation=$4`,
			lease.Turn.ID, revision, ownerID, accountGeneration).Scan(&storedVersion, &storedReason); err != nil ||
			storedVersion != intent.Version || storedReason != string(intent.Reason) {
			return core.ErrConflict
		}
	}
	if failure != nil {
		switch dispatchState {
		case "dispatched":
			if modelDispatchStartedAt == nil || modelDispatchCount == 0 || dispatchEpoch == 0 {
				return core.ErrConflict
			}
			attempt, updateErr := tx.Exec(ctx, `UPDATE core_conversation_model_attempts a SET state='uncertain',failure_code=$4,
				rate_limited=$5,retry_after_ms=$6,finished_at=clock_timestamp()
				WHERE a.turn_id=$1 AND a.attempt_sequence=$2 AND a.dispatch_epoch=$3 AND a.state='dispatched'
				AND (($7 AND NOT EXISTS (SELECT 1 FROM core_conversation_model_dispatch_directives d
					WHERE d.turn_id=a.turn_id AND d.attempt_sequence=a.attempt_sequence AND d.dispatch_epoch=a.dispatch_epoch
					AND d.directive_json ? 'finalization_reason'))
				OR (NOT $7 AND EXISTS (SELECT 1 FROM core_conversation_model_dispatch_directives d
					WHERE d.turn_id=a.turn_id AND d.attempt_sequence=a.attempt_sequence AND d.dispatch_epoch=a.dispatch_epoch
					AND d.directive_json->>'finalization_reason'=$8)))`,
				lease.Turn.ID, modelDispatchCount, dispatchEpoch, failure.Code, failure.RateLimited, failure.RetryAfterMS,
				newIntent, string(intent.Reason))
			if updateErr != nil {
				return updateErr
			}
			if attempt.RowsAffected() != 1 {
				return core.ErrConflict
			}
			nextState, nextDispatchState := string(core.TurnRunning), "uncertain"
			var nextLeaseID any = lease.LeaseID
			var nextLeaseExpiry any = lease.ExpiresAt
			if newIntent {
				nextState, nextDispatchState = string(core.TurnAccepted), ""
				nextLeaseID, nextLeaseExpiry = nil, nil
			}
			turnUpdate, updateErr := tx.Exec(ctx, `UPDATE core_conversation_turns SET state=$6,dispatch_state=$7,
				terminal_code=$2,terminal_summary=$3,
				model_active_milliseconds=model_active_milliseconds+CASE WHEN $10 THEN GREATEST(0,FLOOR(EXTRACT(EPOCH FROM (clock_timestamp()-model_dispatch_started_at))*1000))::bigint ELSE 0 END,
				model_dispatch_started_at=NULL,lease_id=$8,lease_expires_at=$9,updated_at=clock_timestamp()
				WHERE turn_id=$1 AND lease_id=$4 AND lease_epoch=$5 AND state='running' AND dispatch_state='dispatched'`,
				lease.Turn.ID, failure.Code, failure.Summary, lease.LeaseID, lease.Epoch,
				nextState, nextDispatchState, nextLeaseID, nextLeaseExpiry, newIntent)
			if updateErr != nil {
				return updateErr
			}
			if turnUpdate.RowsAffected() != 1 {
				return core.ErrConflict
			}
		case "uncertain":
			if newIntent || terminalCode != failure.Code || terminalSummary != failure.Summary {
				return core.ErrConflict
			}
		default:
			return core.ErrConflict
		}
	} else if newIntent {
		if dispatchState != "" && dispatchState != "completed" && !(dispatchState == "dispatched" && modelDispatchStartedAt == nil) {
			return core.ErrConflict
		}
		turnUpdate, updateErr := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',dispatch_state='',
			dispatch_result_json=NULL,lease_id=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
			WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running'`, lease.Turn.ID, lease.LeaseID, lease.Epoch)
		if updateErr != nil {
			return updateErr
		}
		if turnUpdate.RowsAffected() != 1 {
			return core.ErrConflict
		}
	}
	return tx.Commit(ctx)
}

func (s *CoreConversationStore) LoadTurnFinalization(ctx context.Context, id string) (core.TurnFinalizationIntent, bool, error) {
	if uuid.Validate(id) != nil {
		return core.TurnFinalizationIntent{}, false, core.ErrInvalid
	}
	var intent core.TurnFinalizationIntent
	err := s.pool.QueryRow(ctx, `SELECT f.intent_version,f.reason
		FROM core_conversation_turn_finalizations f
		JOIN core_conversation_turns t ON t.turn_id=f.turn_id AND t.revision=f.turn_revision
		WHERE f.turn_id=$1 AND f.owner_id=t.owner_id AND f.account_generation=t.account_generation`, id).
		Scan(&intent.Version, &intent.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.TurnFinalizationIntent{}, false, nil
	}
	if err != nil {
		return core.TurnFinalizationIntent{}, false, err
	}
	if intent.Validate() != nil {
		return core.TurnFinalizationIntent{}, false, core.ErrConflict
	}
	return intent, true, nil
}

func (s *CoreConversationStore) MarkTurnModelRetryable(ctx context.Context, lease core.TurnLease, failure core.ModelAttemptFailure) error {
	if failure.Validate() != nil {
		return core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `UPDATE core_conversation_model_attempts a SET state='retryable',failure_code=$2,rate_limited=$3,retry_after_ms=$4,finished_at=clock_timestamp()
		WHERE a.turn_id=$1 AND a.state='dispatched' AND a.lease_id=$5 AND a.lease_epoch <= $6 AND a.runtime_snapshot_json IS NOT NULL
		AND (NOT EXISTS (SELECT 1 FROM core_conversation_model_dispatch_directives d
			WHERE d.turn_id=a.turn_id AND d.attempt_sequence=a.attempt_sequence AND d.dispatch_epoch=a.dispatch_epoch
			AND d.directive_json ? 'finalization_reason')
			OR ($7 AND EXISTS (SELECT 1 FROM core_conversation_model_dispatch_directives d
				WHERE d.turn_id=a.turn_id AND d.attempt_sequence=a.attempt_sequence AND d.dispatch_epoch=a.dispatch_epoch
				AND d.directive_json ? 'finalization_reason')))`, lease.Turn.ID, failure.Code, failure.RateLimited, failure.RetryAfterMS, lease.LeaseID, lease.Epoch, failure.Code == core.ModelToolCallFormatInvalidCode)
	if err != nil || result.RowsAffected() != 1 {
		return core.ErrConflict
	}
	result, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET model_active_milliseconds=model_active_milliseconds+CASE WHEN EXISTS (
		SELECT 1 FROM core_conversation_model_dispatch_directives d
		WHERE d.turn_id=core_conversation_turns.turn_id AND d.attempt_sequence=core_conversation_turns.model_dispatch_count
		AND d.dispatch_epoch=core_conversation_turns.dispatch_epoch AND d.directive_json ? 'finalization_reason'
	) THEN 0 ELSE GREATEST(0,FLOOR(EXTRACT(EPOCH FROM (clock_timestamp()-model_dispatch_started_at))*1000))::bigint END,
		model_dispatch_started_at=NULL,updated_at=clock_timestamp()
		WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running' AND dispatch_state='dispatched' AND model_dispatch_started_at IS NOT NULL`, lease.Turn.ID, lease.LeaseID, lease.Epoch)
	if err != nil || result.RowsAffected() != 1 {
		return core.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s *CoreConversationStore) BindTurnModelRuntime(ctx context.Context, lease core.TurnLease, snapshot core.TurnRuntimeSnapshot) error {
	if snapshot.Validate() != nil {
		return core.ErrInvalid
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return core.ErrInvalid
	}
	digest := snapshot.Digest()
	result, err := s.pool.Exec(ctx, `UPDATE core_conversation_model_attempts a SET runtime_snapshot_json=$2,runtime_snapshot_digest=$3 WHERE a.turn_id=$1 AND a.state='dispatched' AND a.lease_id=$4 AND a.lease_epoch <= $5 AND a.runtime_snapshot_json IS NULL AND EXISTS (SELECT 1 FROM core_conversation_model_dispatch_directives d WHERE d.turn_id=a.turn_id AND d.attempt_sequence=a.attempt_sequence AND d.dispatch_epoch=a.dispatch_epoch AND d.lease_id=a.lease_id AND d.lease_epoch=a.lease_epoch AND d.runtime_snapshot_digest=$3)`, lease.Turn.ID, raw, digest, lease.LeaseID, lease.Epoch)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	var storedRaw []byte
	var storedDigest string
	if err = s.pool.QueryRow(ctx, `SELECT runtime_snapshot_json,runtime_snapshot_digest FROM core_conversation_model_attempts WHERE turn_id=$1 AND state='dispatched' AND lease_id=$2 AND lease_epoch <= $3`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&storedRaw, &storedDigest); err != nil {
		return core.ErrConflict
	}
	var stored core.TurnRuntimeSnapshot
	if json.Unmarshal(storedRaw, &stored) != nil || stored.Validate() != nil || stored.Digest() != storedDigest || storedDigest != digest {
		return core.ErrTurnRuntimeIncompatible
	}
	return nil
}

func (s *CoreConversationStore) PrepareTurnModelRetry(ctx context.Context, lease core.TurnLease) (core.Turn, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	var current core.Turn
	if err = s.scanTurn(ctx, tx, lease.Turn.ID, &current); err != nil {
		return core.Turn{}, core.ErrConflict
	}
	if current.RuntimeSnapshot == nil || lease.Turn.RuntimeSnapshot == nil ||
		current.RequestID != lease.Turn.RequestID || current.OwnerID != lease.Turn.OwnerID || current.AccountGeneration != lease.Turn.AccountGeneration ||
		current.ConversationID != lease.Turn.ConversationID || current.ProfileID != lease.Turn.ProfileID || current.Revision != lease.Turn.Revision ||
		current.RuntimeSnapshot.Digest() != lease.Turn.RuntimeSnapshot.Digest() {
		return core.Turn{}, core.ErrConflict
	}
	policy := current.RuntimeSnapshot.ExecutionPolicy
	var finalizationFormatRetry bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM core_conversation_model_attempts a
		JOIN core_conversation_model_dispatch_directives d ON d.turn_id=a.turn_id
			AND d.attempt_sequence=a.attempt_sequence AND d.dispatch_epoch=a.dispatch_epoch
		WHERE a.turn_id=$1 AND a.attempt_sequence=$2 AND a.state='retryable'
			AND a.failure_code=$3 AND d.directive_json ? 'finalization_reason')`,
		lease.Turn.ID, current.ModelDispatchCount, core.ModelToolCallFormatInvalidCode).Scan(&finalizationFormatRetry); err != nil {
		return core.Turn{}, err
	}
	maxDispatches := policy.MaxModelDispatches
	if finalizationFormatRetry {
		maxDispatches += core.MaxTurnFinalizationDispatches + core.MaxTurnFinalizationFormatRetries
	}
	var attempt uint32
	var dispatchEpoch uint64
	var started time.Time
	err = tx.QueryRow(ctx, `UPDATE core_conversation_turns SET model_dispatch_count=model_dispatch_count+1,model_dispatch_started_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running' AND dispatch_state='dispatched'
		AND model_dispatch_started_at IS NULL AND model_dispatch_count < $4 AND ($6 OR model_active_milliseconds < $5)
		AND EXISTS (SELECT 1 FROM core_conversation_model_attempts a
			WHERE a.turn_id=$1 AND a.attempt_sequence=core_conversation_turns.model_dispatch_count AND a.state='retryable'
			AND (($6 AND a.failure_code=$7 AND EXISTS (SELECT 1 FROM core_conversation_model_dispatch_directives d
				WHERE d.turn_id=a.turn_id AND d.attempt_sequence=a.attempt_sequence AND d.dispatch_epoch=a.dispatch_epoch
				AND d.directive_json ? 'finalization_reason'))
				OR (NOT $6 AND NOT EXISTS (SELECT 1 FROM core_conversation_model_dispatch_directives d
					WHERE d.turn_id=a.turn_id AND d.attempt_sequence=a.attempt_sequence AND d.dispatch_epoch=a.dispatch_epoch
					AND d.directive_json ? 'finalization_reason'))))
		RETURNING model_dispatch_count,dispatch_epoch,model_dispatch_started_at`, lease.Turn.ID, lease.LeaseID, lease.Epoch, maxDispatches, policy.MaxModelActiveMilliseconds, finalizationFormatRetry, core.ModelToolCallFormatInvalidCode).Scan(&attempt, &dispatchEpoch, &started)
	if err != nil {
		latest, getErr := s.GetTurn(ctx, lease.Turn.ID)
		if getErr == nil && (latest.ModelDispatchCount >= maxDispatches || (!finalizationFormatRetry && latest.ModelActiveDuration >= policy.MaxModelActiveDuration())) {
			return core.Turn{}, core.ErrModelBudgetExhausted
		}
		return core.Turn{}, core.ErrConflict
	}
	inserted, insertErr := tx.Exec(ctx, `INSERT INTO core_conversation_model_attempts(turn_id,attempt_sequence,dispatch_epoch,lease_id,lease_epoch,state,runtime_snapshot_json,runtime_snapshot_digest,started_at) SELECT $1,$2,$3,$4,$5,'dispatched',runtime_snapshot_json,runtime_snapshot_digest,$6 FROM core_conversation_model_attempts WHERE turn_id=$1 AND attempt_sequence=$2-1 AND state='retryable' AND runtime_snapshot_json IS NOT NULL`, lease.Turn.ID, attempt, dispatchEpoch, lease.LeaseID, lease.Epoch, started)
	if insertErr != nil {
		return core.Turn{}, insertErr
	}
	if inserted.RowsAffected() != 1 {
		return core.Turn{}, core.ErrConflict
	}
	directiveInserted, insertErr := tx.Exec(ctx, `INSERT INTO core_conversation_model_dispatch_directives(turn_id,attempt_sequence,owner_id,account_generation,turn_revision,dispatch_epoch,lease_id,lease_epoch,runtime_snapshot_digest,directive_json,directive_digest,created_at) SELECT $1,$2,owner_id,account_generation,turn_revision,$3,$4,$5,runtime_snapshot_digest,directive_json,directive_digest,$6 FROM core_conversation_model_dispatch_directives WHERE turn_id=$1 AND attempt_sequence=$2-1 AND dispatch_epoch=$3 AND turn_revision=(SELECT revision FROM core_conversation_turns WHERE turn_id=$1)`, lease.Turn.ID, attempt, dispatchEpoch, lease.LeaseID, lease.Epoch, started)
	if insertErr != nil {
		return core.Turn{}, insertErr
	}
	if directiveInserted.RowsAffected() != 1 {
		return core.Turn{}, core.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, lease.Turn.ID)
}

func (s *CoreConversationStore) LoadTurnModelResult(ctx context.Context, id string) (core.ModelRunResult, bool, error) {
	var raw []byte
	var state string
	err := s.pool.QueryRow(ctx, `SELECT dispatch_state,dispatch_result_json FROM core_conversation_turns WHERE turn_id=$1`, id).Scan(&state, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ModelRunResult{}, false, core.ErrConflict
	}
	if err != nil {
		return core.ModelRunResult{}, false, err
	}
	if state != "completed" || len(raw) == 0 {
		return core.ModelRunResult{}, false, nil
	}
	envelope, err := loadDurableTurnDispatchEnvelope(raw)
	if err != nil {
		return core.ModelRunResult{}, false, err
	}
	return envelope.Result, true, nil
}

func (s *CoreConversationStore) RecordTurnModelResult(ctx context.Context, lease core.TurnLease, result core.ModelRunResult) error {
	envelope, err := newDurableTurnDispatchEnvelope(result)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(envelope)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx, `UPDATE core_conversation_model_attempts SET state='completed',finished_at=clock_timestamp() WHERE turn_id=$1 AND state='dispatched' AND lease_id=$2 AND lease_epoch <= $3 AND runtime_snapshot_json IS NOT NULL`, lease.Turn.ID, lease.LeaseID, lease.Epoch)
	if err != nil || command.RowsAffected() != 1 {
		return core.ErrConflict
	}
	command, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET dispatch_state='completed',dispatch_result_json=$2,
		model_active_milliseconds=model_active_milliseconds+CASE WHEN EXISTS (
			SELECT 1 FROM core_conversation_model_dispatch_directives d
			WHERE d.turn_id=core_conversation_turns.turn_id AND d.attempt_sequence=core_conversation_turns.model_dispatch_count
			AND d.dispatch_epoch=core_conversation_turns.dispatch_epoch AND d.directive_json ? 'finalization_reason'
		) THEN 0 ELSE GREATEST(0,FLOOR(EXTRACT(EPOCH FROM (clock_timestamp()-model_dispatch_started_at))*1000))::bigint END,
		model_dispatch_started_at=NULL,updated_at=clock_timestamp()
		WHERE turn_id=$1 AND lease_id=$3 AND lease_epoch=$4 AND state='running' AND dispatch_state='dispatched' AND model_dispatch_started_at IS NOT NULL`, lease.Turn.ID, raw, lease.LeaseID, lease.Epoch)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return core.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s *CoreConversationStore) RecordConversationToolCall(ctx context.Context, lease core.TurnLease, call core.ToolCall) error {
	if call.Validate() != nil {
		return core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var state, dispatchState string
	var lastSequence int64
	var dispatchRaw []byte
	if err = tx.QueryRow(ctx, `SELECT state,dispatch_state,last_sequence,dispatch_result_json FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 FOR UPDATE`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&state, &dispatchState, &lastSequence, &dispatchRaw); err != nil || state != string(core.TurnRunning) || dispatchState != "completed" {
		return core.ErrConflict
	}
	envelope, err := loadDurableTurnDispatchEnvelope(dispatchRaw)
	if err != nil {
		return err
	}
	if _, err = durableTurnToolCallIndex(envelope, call); err != nil {
		return err
	}
	authority, err := conversationToolEventAuthorityTx(ctx, tx, lease.Turn.ID, call.ID)
	if err != nil {
		return err
	}
	if authority.state != conversationToolCallAbsent {
		if !reflect.DeepEqual(authority.call, call) {
			return core.ErrConflict
		}
		return tx.Commit(ctx)
	}
	now := time.Now().UTC()
	if err = insertTurnEventTx(ctx, tx, lease.Turn.ID, lastSequence+1, core.TurnEvent{Kind: core.TurnEventToolCall, ToolCall: &call}, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET last_sequence=$2,updated_at=$3 WHERE turn_id=$1`, lease.Turn.ID, lastSequence+1, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *CoreConversationStore) BeginConversationToolDispatch(ctx context.Context, lease core.TurnLease, call core.ToolCall) (bool, error) {
	if call.Validate() != nil {
		return false, core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var state, dispatchState string
	var dispatchRaw []byte
	if err = tx.QueryRow(ctx, `SELECT state,dispatch_state,dispatch_result_json FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 FOR UPDATE`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&state, &dispatchState, &dispatchRaw); err != nil || state != string(core.TurnRunning) || dispatchState != "completed" {
		return false, core.ErrConflict
	}
	envelope, err := loadDurableTurnDispatchEnvelope(dispatchRaw)
	if err != nil {
		return false, err
	}
	index, err := durableTurnToolCallIndex(envelope, call)
	if err != nil {
		return false, err
	}
	switch envelope.Calls[index].State {
	case durableTurnToolCallPending:
		envelope.Calls[index].State = durableTurnToolCallDispatched
		raw, _ := json.Marshal(envelope)
		if _, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET dispatch_result_json=$2,updated_at=clock_timestamp() WHERE turn_id=$1`, lease.Turn.ID, raw); err != nil {
			return false, err
		}
		if err = tx.Commit(ctx); err != nil {
			return false, err
		}
		return true, nil
	case durableTurnToolCallDispatched:
		if err = tx.Commit(ctx); err != nil {
			return false, err
		}
		return false, nil
	default:
		return false, core.ErrConflict
	}
}

func (s *CoreConversationStore) RecordConversationToolResult(ctx context.Context, lease core.TurnLease, result core.ToolResult) error {
	if result.ValidateObservation() != nil {
		return core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var state, dispatchState string
	var lastSequence int64
	var dispatchRaw []byte
	if err = tx.QueryRow(ctx, `SELECT state,dispatch_state,last_sequence,dispatch_result_json FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 FOR UPDATE`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&state, &dispatchState, &lastSequence, &dispatchRaw); err != nil || state != string(core.TurnRunning) || dispatchState != "completed" {
		return core.ErrConflict
	}
	envelope, err := loadDurableTurnDispatchEnvelope(dispatchRaw)
	if err != nil {
		return err
	}
	index := -1
	for candidate := range envelope.Calls {
		if envelope.Calls[candidate].CallID == result.CallID {
			index = candidate
			break
		}
	}
	calls := durableTurnModelCalls(envelope.Result)
	if index < 0 || index >= len(calls) || result.ToolName != calls[index].Name {
		return core.ErrConflict
	}
	if envelope.Calls[index].State == durableTurnToolCallTerminal {
		if envelope.Calls[index].ResultDigest != durableTurnToolResultDigest(result) {
			return core.ErrConflict
		}
		return tx.Commit(ctx)
	}
	if envelope.Calls[index].State != durableTurnToolCallDispatched {
		return core.ErrConflict
	}
	envelope.Calls[index].State = durableTurnToolCallTerminal
	envelope.Calls[index].ResultDigest = durableTurnToolResultDigest(result)
	now := time.Now().UTC()
	if err = insertTurnEventTx(ctx, tx, lease.Turn.ID, lastSequence+1, core.TurnEvent{Kind: core.TurnEventToolResult, ToolResult: &result}, now); err != nil {
		return err
	}
	raw, _ := json.Marshal(envelope)
	stalled, err := recordConversationProgressTx(ctx, tx, lease.Turn.ID, result.CallID, result, lastSequence+1, now)
	if err != nil {
		return err
	}
	if stalled {
		var turn core.Turn
		if err = s.scanTurn(ctx, tx, lease.Turn.ID, &turn); err != nil {
			return err
		}
		if err = prepareTurnNoProgressFinalizationTx(ctx, tx, turn, lastSequence+1, now); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET dispatch_result_json=$2,updated_at=$3 WHERE turn_id=$1`, lease.Turn.ID, raw, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *CoreConversationStore) FailConversationToolDispatch(ctx context.Context, lease core.TurnLease, call core.ToolCall, code, summary string) (core.Turn, error) {
	if call.Validate() != nil || strings.TrimSpace(code) != code || code == "" || len(code) > 128 || strings.TrimSpace(summary) != summary || summary == "" || len(summary) > 4096 {
		return core.Turn{}, core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	var state, dispatchState string
	var lastSequence int64
	var dispatchRaw []byte
	if err = tx.QueryRow(ctx, `SELECT state,dispatch_state,last_sequence,dispatch_result_json FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 FOR UPDATE`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&state, &dispatchState, &lastSequence, &dispatchRaw); err != nil || state != string(core.TurnRunning) || dispatchState != "completed" {
		return core.Turn{}, core.ErrConflict
	}
	envelope, err := loadDurableTurnDispatchEnvelope(dispatchRaw)
	if err != nil {
		return core.Turn{}, err
	}
	index, err := durableTurnToolCallIndex(envelope, call)
	if err != nil || envelope.Calls[index].State != durableTurnToolCallDispatched {
		return core.Turn{}, core.ErrConflict
	}
	result := core.ToolResult{CallID: call.ID, ToolName: call.Name, Content: summary}.
		WithObservation(core.ToolOutcomeFatal, summary, core.ToolMutationNone)
	if result.ValidateObservation() != nil {
		return core.Turn{}, core.ErrInvalid
	}
	envelope.Calls[index].State, envelope.Calls[index].ResultDigest = durableTurnToolCallTerminal, durableTurnToolResultDigest(result)
	raw, _ := json.Marshal(envelope)
	now := time.Now().UTC()
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET state='failed',revision=revision+1,terminal_code=$2,terminal_summary=$3,dispatch_result_json=$4,lease_id=NULL,lease_expires_at=NULL,updated_at=$5 WHERE turn_id=$1`, lease.Turn.ID, code, summary, raw, now); err != nil {
		return core.Turn{}, err
	}
	if err = insertTurnEventTx(ctx, tx, lease.Turn.ID, lastSequence+1, core.TurnEvent{Kind: core.TurnEventToolResult, ToolResult: &result}, now); err != nil {
		return core.Turn{}, err
	}
	if err = insertTurnEventTx(ctx, tx, lease.Turn.ID, lastSequence+2, core.TurnEvent{Kind: core.TurnEventError, ErrorCode: code, ErrorSummary: summary}, now); err != nil {
		return core.Turn{}, err
	}
	if err = failedTurnTranscriptTx(ctx, tx, lease.Turn, code, summary, now); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, lease.Turn.ID)
}

func (s *CoreConversationStore) CompleteConversationToolRound(ctx context.Context, lease core.TurnLease) (core.Turn, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT dispatch_result_json FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running' AND dispatch_state='completed' FOR UPDATE`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&raw); err != nil {
		return core.Turn{}, core.ErrConflict
	}
	envelope, err := loadDurableTurnDispatchEnvelope(raw)
	if err != nil {
		return core.Turn{}, core.ErrConflict
	}
	calls := durableTurnModelCalls(envelope.Result)
	for index, entry := range envelope.Calls {
		if index >= len(calls) {
			return core.Turn{}, core.ErrConflict
		}
		call := calls[index]
		if coremodel.IsIntrinsicToolName(call.Name) {
			continue
		}
		if entry.State != durableTurnToolCallTerminal || entry.ResultDigest == "" {
			return core.Turn{}, core.ErrConflict
		}
		authority, authorityErr := conversationToolEventAuthorityTx(ctx, tx, lease.Turn.ID, call.ID)
		if authorityErr != nil || authority.state != conversationToolCallTerminal || !reflect.DeepEqual(authority.call, call) || authority.result == nil || durableTurnToolResultDigest(*authority.result) != entry.ResultDigest {
			return core.Turn{}, core.ErrConflict
		}
	}
	command, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',dispatch_state='',dispatch_epoch=0,dispatch_result_json=NULL,lease_id=NULL,lease_expires_at=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE turn_id=$1`, lease.Turn.ID)
	if err != nil || command.RowsAffected() != 1 {
		if err != nil {
			return core.Turn{}, err
		}
		return core.Turn{}, core.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, lease.Turn.ID)
}

type conversationToolCallState uint8

const (
	conversationToolCallAbsent conversationToolCallState = iota
	conversationToolCallPending
	conversationToolCallTerminal
)

type conversationToolEventAuthority struct {
	state          conversationToolCallState
	call           core.ToolCall
	result         *core.ToolResult
	resultSequence int64
}

func conversationToolEventAuthorityTx(ctx context.Context, tx pgx.Tx, turnID, callID string) (conversationToolEventAuthority, error) {
	rows, err := tx.Query(ctx, `SELECT sequence,payload_json FROM core_conversation_turn_events WHERE turn_id=$1 AND kind IN ($2,$3) ORDER BY sequence`, turnID, string(core.TurnEventToolCall), string(core.TurnEventToolResult))
	if err != nil {
		return conversationToolEventAuthority{}, err
	}
	defer rows.Close()
	var authority conversationToolEventAuthority
	for rows.Next() {
		var raw []byte
		var sequence int64
		if err = rows.Scan(&sequence, &raw); err != nil {
			return conversationToolEventAuthority{}, err
		}
		var event core.TurnEvent
		if json.Unmarshal(raw, &event) != nil {
			return conversationToolEventAuthority{}, core.ErrConflict
		}
		switch event.Kind {
		case core.TurnEventToolCall:
			if event.ToolCall == nil || event.ToolCall.ID != callID {
				continue
			}
			if authority.state != conversationToolCallAbsent || event.ToolCall.Validate() != nil {
				return conversationToolEventAuthority{}, core.ErrConflict
			}
			authority.call, authority.state = *event.ToolCall, conversationToolCallPending
		case core.TurnEventToolResult:
			if event.ToolResult == nil || event.ToolResult.CallID != callID {
				continue
			}
			if authority.state != conversationToolCallPending || event.ToolResult.ValidateObservation() != nil || event.ToolResult.ToolName != authority.call.Name {
				return conversationToolEventAuthority{}, core.ErrConflict
			}
			result := *event.ToolResult
			authority.result, authority.resultSequence, authority.state = &result, sequence, conversationToolCallTerminal
		}
	}
	return authority, rows.Err()
}

func (s *CoreConversationStore) MarkTurnModelUncertain(ctx context.Context, lease core.TurnLease, code, summary string) error {
	return s.MarkTurnModelAttemptUncertain(ctx, lease, core.ModelAttemptFailure{Code: code, Summary: summary})
}

func (s *CoreConversationStore) MarkTurnModelAttemptUncertain(ctx context.Context, lease core.TurnLease, failure core.ModelAttemptFailure) error {
	if failure.Validate() != nil {
		return core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx, `UPDATE core_conversation_model_attempts SET state='uncertain',failure_code=$2,rate_limited=$3,retry_after_ms=$4,finished_at=clock_timestamp() WHERE turn_id=$1 AND state='dispatched' AND lease_id=$5 AND lease_epoch <= $6`, lease.Turn.ID, failure.Code, failure.RateLimited, failure.RetryAfterMS, lease.LeaseID, lease.Epoch)
	if err != nil || command.RowsAffected() != 1 {
		return core.ErrConflict
	}
	command, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET dispatch_state='uncertain',terminal_code=$2,terminal_summary=$3,model_active_milliseconds=model_active_milliseconds+GREATEST(0,FLOOR(EXTRACT(EPOCH FROM (clock_timestamp()-model_dispatch_started_at))*1000))::bigint,model_dispatch_started_at=NULL,updated_at=clock_timestamp() WHERE turn_id=$1 AND lease_id=$4 AND lease_epoch=$5 AND state='running' AND dispatch_state='dispatched' AND model_dispatch_started_at IS NOT NULL`, lease.Turn.ID, failure.Code, failure.Summary, lease.LeaseID, lease.Epoch)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return core.ErrConflict
	}
	return tx.Commit(ctx)
}

func validateDurableTurnEventAuthority(event core.TurnEvent) error {
	switch event.Kind {
	case core.TurnEventWaitingConfirmation:
		return event.ValidateWaitingConfirmationAuthority()
	case core.TurnEventWorkerStatus:
		return event.ValidateWorkerStatusAuthority()
	case core.TurnEventWarning:
		return event.ValidateWarningAuthority()
	default:
		return nil
	}
}

func (s *CoreConversationStore) AppendTurnEvent(ctx context.Context, id string, event core.TurnEvent) (core.TurnEvent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.TurnEvent{}, err
	}
	defer tx.Rollback(ctx)
	var lastSequence int64
	var revision uint64
	var state string
	if err = tx.QueryRow(ctx, `SELECT state,last_sequence,revision FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, id).Scan(&state, &lastSequence, &revision); err != nil {
		return core.TurnEvent{}, err
	}
	if state == string(core.TurnCompleted) || state == string(core.TurnCanceled) || state == string(core.TurnFailed) {
		return core.TurnEvent{}, core.ErrConflict
	}
	sequence := lastSequence + 1
	event.TurnID, event.Sequence, event.Revision = id, sequence, revision
	event.CreatedAt = time.Now().UTC()
	if validateDurableTurnEventAuthority(event) != nil {
		return core.TurnEvent{}, core.ErrInvalid
	}
	payload, _ := json.Marshal(event)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,$2,$3,$4,$5)`, id, sequence, string(event.Kind), payload, event.CreatedAt); err != nil {
		return core.TurnEvent{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET last_sequence=$2,updated_at=$3 WHERE turn_id=$1`, id, sequence, event.CreatedAt); err != nil {
		return core.TurnEvent{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.TurnEvent{}, err
	}
	return event, nil
}

func insertTurnEventTx(ctx context.Context, tx pgx.Tx, id string, sequence int64, event core.TurnEvent, now time.Time) error {
	var revision uint64
	if err := tx.QueryRow(ctx, `SELECT revision FROM core_conversation_turns WHERE turn_id=$1`, id).Scan(&revision); err != nil {
		return err
	}
	if event.Revision != 0 && event.Revision != revision {
		return core.ErrConflict
	}
	event.TurnID, event.Sequence, event.Revision, event.CreatedAt = id, sequence, revision, now
	if validateDurableTurnEventAuthority(event) != nil {
		return core.ErrInvalid
	}
	payload, _ := json.Marshal(event)
	if _, err := tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,$2,$3,$4,$5)`, id, sequence, string(event.Kind), payload, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET last_sequence=$2,updated_at=$3 WHERE turn_id=$1`, id, sequence, now)
	return err
}

func (s *CoreConversationStore) LoadTurnEvents(ctx context.Context, id string, after int64, limit int) ([]core.TurnEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT sequence,kind,payload_json,created_at FROM core_conversation_turn_events WHERE turn_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3`, id, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.TurnEvent
	for rows.Next() {
		var e core.TurnEvent
		var sequence int64
		var kind string
		var raw []byte
		var createdAt time.Time
		if err = rows.Scan(&sequence, &kind, &raw, &createdAt); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &e) != nil || e.TurnID != id || e.Sequence != sequence ||
			e.Kind != core.TurnEventKind(kind) || e.Revision == 0 || validateDurableTurnEventAuthority(e) != nil {
			return nil, core.ErrConflict
		}
		e.CreatedAt = createdAt
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *CoreConversationStore) TurnEventBounds(ctx context.Context, id string) (int64, int64, error) {
	var first, last *int64
	err := s.pool.QueryRow(ctx, `SELECT MIN(sequence),MAX(sequence) FROM core_conversation_turn_events WHERE turn_id=$1`, id).Scan(&first, &last)
	if err != nil {
		return 0, 0, err
	}
	if first == nil || last == nil {
		return 0, 0, nil
	}
	return *first, *last, nil
}

func (s *CoreConversationStore) CommitTurn(ctx context.Context, lease core.TurnLease, response core.ChatResponse) (core.Turn, error) {
	response.Message.CreatedAt = response.Message.CreatedAt.UTC().Truncate(time.Microsecond)
	if response.Message.CreatedAt.IsZero() || bindTurnResponseIdentity(&response, lease.Turn.ID) != nil {
		return core.Turn{}, core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	if err = s.commitTurnTx(ctx, tx, lease, response); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, lease.Turn.ID)
}

func (s *CoreConversationStore) commitTurnTx(ctx context.Context, tx pgx.Tx, lease core.TurnLease, response core.ChatResponse) error {
	var turn core.Turn
	if err := s.scanTurn(ctx, tx, lease.Turn.ID, &turn); err != nil {
		return core.ErrConflict
	}
	if turn.State != core.TurnRunning || turn.RequestID != lease.Turn.RequestID || turn.OwnerID != lease.Turn.OwnerID ||
		turn.AccountGeneration != lease.Turn.AccountGeneration || turn.ConversationID != lease.Turn.ConversationID || turn.ProfileID != lease.Turn.ProfileID {
		return core.ErrConflict
	}
	raw, _ := json.Marshal(response)
	now := time.Now().UTC()
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='completed',revision=revision+1,response_json=$2,lease_id=NULL,lease_expires_at=NULL,updated_at=$3 WHERE turn_id=$1 AND lease_id=$4 AND lease_epoch=$5 AND state='running'`, lease.Turn.ID, raw, now, lease.LeaseID, lease.Epoch)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return core.ErrConflict
	}
	convResult, err := tx.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$4) ON CONFLICT(conversation_id) DO UPDATE SET title=CASE WHEN core_conversations.title='' OR core_conversations.title=$6 OR core_conversations.title=$7 THEN EXCLUDED.title ELSE core_conversations.title END,revision=$3,updated_at=$4 WHERE core_conversations.revision=$5`, response.ConversationID, response.ConversationTitle, response.Revision, now, response.Revision-1, core.ProvisionalConversationTitle(turn.Prompt), core.ProvisionalConversationTitle(response.ConversationTitleSource))
	if err != nil {
		return err
	}
	if convResult.RowsAffected() != 1 {
		return core.ErrConflict
	}
	var nextSequence int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_messages WHERE conversation_id=$1`, response.ConversationID).Scan(&nextSequence); err != nil {
		return err
	}
	steers, err := listTurnSteersTx(ctx, tx, lease.Turn.ID)
	if err != nil {
		return err
	}
	userMessageID := core.TurnUserMessageID(lease.Turn.RequestID)
	userAlreadyCommitted, err := turnUserMessageExistsTx(ctx, tx, userMessageID, lease.Turn)
	if err != nil {
		return err
	}
	transcript := make([]core.Message, 0, len(steers)+2)
	firstUserAt := response.Message.CreatedAt.Add(-time.Duration(len(steers)+1) * time.Microsecond)
	if !userAlreadyCommitted {
		transcript = append(transcript, core.Message{ID: userMessageID, TurnID: turn.ID, Role: core.RoleUser, Content: lease.Turn.Prompt, ModelProfileID: lease.Turn.ProfileID, CreatedAt: firstUserAt, Attachments: core.PresentTurnAttachments(turn.AttachmentSources)})
	}
	for index, steer := range steers {
		transcript = append(transcript, core.Message{
			ID:             uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn-steer-user:"+steer.RequestID)).String(),
			TurnID:         turn.ID,
			Role:           core.RoleUser,
			Content:        steer.Instruction,
			ModelProfileID: lease.Turn.ProfileID,
			CreatedAt:      firstUserAt.Add(time.Duration(index+1) * time.Microsecond),
			Attachments:    core.PresentTurnAttachments(steer.AttachmentSources),
		})
	}
	transcript = append(transcript, response.Message)
	for i, m := range transcript {
		payload, _ := json.Marshal(m)
		tasks, _ := stringArrayJSONPG(m.RelatedTaskIDs)
		plans, _ := stringArrayJSONPG(m.RelatedPlanIDs)
		references, _ := referenceArrayJSONPG(m.References)
		sums, _ := stringArrayJSONPG(m.ToolSummaries)
		insertResult, insertErr := tx.Exec(ctx, `INSERT INTO core_messages(message_id,conversation_id,sequence,role,content,model_profile_id,payload_json,related_task_ids,related_plan_ids,references_json,tool_summaries,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(message_id) DO NOTHING`, m.ID, response.ConversationID, nextSequence+int64(i), m.Role, m.Content, nullableUUIDPG(m.ModelProfileID), payload, tasks, plans, references, sums, m.CreatedAt)
		if insertErr != nil {
			return insertErr
		}
		if insertResult.RowsAffected() == 0 {
			var existingPayload []byte
			var existingConversation string
			var existingSequence int64
			var existingRole, existingContent string
			var existingProfile *uuid.UUID
			var expectedValue, existingValue any
			_ = json.Unmarshal(payload, &expectedValue)
			if err = tx.QueryRow(ctx, `SELECT conversation_id,sequence,role,content,model_profile_id,payload_json FROM core_messages WHERE message_id=$1`, m.ID).Scan(&existingConversation, &existingSequence, &existingRole, &existingContent, &existingProfile, &existingPayload); err != nil {
				return core.ErrConflict
			}
			_ = json.Unmarshal(existingPayload, &existingValue)
			profileMatches := (existingProfile == nil && m.ModelProfileID == "") || (existingProfile != nil && existingProfile.String() == m.ModelProfileID)
			if existingConversation != response.ConversationID || existingSequence != nextSequence+int64(i) || existingRole != string(m.Role) || existingContent != m.Content || !profileMatches || !reflect.DeepEqual(expectedValue, existingValue) {
				return core.ErrConflict
			}
		}
		if m.ModelProfileID != "" {
			if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('conversation',$1,$2) ON CONFLICT DO NOTHING`, response.ConversationID, m.ModelProfileID); err != nil {
				return err
			}
		}
	}
	userParts := make([]string, 0, len(steers)+1)
	userParts = append(userParts, lease.Turn.Prompt)
	for _, steer := range steers {
		userParts = append(userParts, steer.Instruction)
	}
	if err = s.enqueueMemoryObservationTx(ctx, tx, lease.Turn.RequestID, response.ConversationID, lease.Turn.ProfileID, strings.Join(userParts, "\n"), response.Message.Content, now); err != nil {
		return err
	}
	if err = insertTurnEventTx(ctx, tx, lease.Turn.ID, turn.LastSequence+1, core.TurnEvent{Kind: core.TurnEventDone, Message: &response.Message, Response: &response}, now); err != nil {
		return err
	}
	return nil
}

func bindTurnResponseIdentity(response *core.ChatResponse, turnID string) error {
	if response == nil || uuid.Validate(turnID) != nil ||
		(response.Message.TurnID != "" && response.Message.TurnID != turnID) {
		return core.ErrInvalid
	}
	response.Message.TurnID = turnID
	return nil
}

func turnUserMessageExistsTx(ctx context.Context, tx pgx.Tx, messageID string, turn core.Turn) (bool, error) {
	var conversationID, role, content string
	var profileID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT conversation_id::text,role,content,model_profile_id FROM core_messages WHERE message_id=$1`, messageID).
		Scan(&conversationID, &role, &content, &profileID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if profileID == nil || conversationID != turn.ConversationID || role != string(core.RoleUser) ||
		content != turn.Prompt || profileID.String() != turn.ProfileID {
		return false, core.ErrConflict
	}
	return true, nil
}

func failedTurnTranscriptTx(ctx context.Context, tx pgx.Tx, turn core.Turn, code, summary string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT payload_json FROM core_conversation_turn_events WHERE turn_id=$1 AND kind=$2 ORDER BY sequence`, turn.ID, string(core.TurnEventDelta))
	if err != nil {
		return err
	}
	var partial strings.Builder
	for rows.Next() {
		var raw []byte
		var event core.TurnEvent
		if err = rows.Scan(&raw); err != nil || json.Unmarshal(raw, &event) != nil || event.Kind != core.TurnEventDelta {
			rows.Close()
			return core.ErrConflict
		}
		partial.WriteString(event.Text)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	var conversationRevision uint64
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_conversations WHERE conversation_id=$1 AND deleted_at IS NULL FOR UPDATE`, turn.ConversationID).Scan(&conversationRevision); err != nil {
		return core.ErrConflict
	}
	var nextSequence int64
	var latestCreatedAt *time.Time
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1,MAX(created_at) FROM core_messages WHERE conversation_id=$1`, turn.ConversationID).Scan(&nextSequence, &latestCreatedAt); err != nil {
		return err
	}
	createdAt := now.UTC().Truncate(time.Microsecond)
	if latestCreatedAt != nil && !createdAt.After(latestCreatedAt.UTC()) {
		createdAt = latestCreatedAt.UTC().Add(time.Microsecond)
	}

	userMessageID := core.TurnUserMessageID(turn.RequestID)
	userAlreadyCommitted, err := turnUserMessageExistsTx(ctx, tx, userMessageID, turn)
	if err != nil {
		return err
	}
	if !userAlreadyCommitted {
		user := core.Message{ID: userMessageID, TurnID: turn.ID, Role: core.RoleUser, Content: turn.Prompt, ModelProfileID: turn.ProfileID, CreatedAt: createdAt, Attachments: core.PresentTurnAttachments(turn.AttachmentSources)}
		if user.Validate() != nil {
			return core.ErrInvalid
		}
		if err = insertCloudWorkerMessageTx(ctx, tx, turn.ConversationID, nextSequence, user); err != nil {
			return err
		}
		nextSequence++
		createdAt = createdAt.Add(time.Microsecond)
	}
	assistant := core.Message{
		ID:             uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn-failed-assistant:"+turn.RequestID)).String(),
		TurnID:         turn.ID,
		Role:           core.RoleAssistant,
		Content:        failedTurnAssistantContent(partial.String(), code, summary),
		ModelProfileID: turn.ProfileID,
		CreatedAt:      createdAt,
		Status:         "failed",
	}
	if assistant.Validate() != nil {
		return core.ErrInvalid
	}
	if err = insertCloudWorkerMessageTx(ctx, tx, turn.ConversationID, nextSequence, assistant); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('conversation',$1,$2) ON CONFLICT DO NOTHING`, turn.ConversationID, turn.ProfileID); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `UPDATE core_conversations SET revision=revision+1,updated_at=$2 WHERE conversation_id=$1 AND revision=$3`, turn.ConversationID, assistant.CreatedAt, conversationRevision)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return core.ErrConflict
	}
	return nil
}

func failedTurnAssistantContent(partial, code, summary string) string {
	code = boundedTurnFailureText(strings.TrimSpace(code), 128)
	summary = boundedTurnFailureText(strings.TrimSpace(summary), core.MaxSummaryBytes)
	terminal := "Error"
	if code != "" {
		terminal += " (" + code + ")"
	}
	if summary != "" {
		terminal += ": " + summary
	}
	if strings.TrimSpace(partial) == "" {
		return terminal
	}
	suffix := "\n\n" + terminal
	return boundedTurnFailureText(partial, core.MaxContentBytes-len(suffix)) + suffix
}

func boundedTurnFailureText(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	var bounded strings.Builder
	bounded.Grow(limit)
	for _, current := range value {
		if bounded.Len()+len(string(current)) > limit {
			break
		}
		bounded.WriteRune(current)
	}
	return bounded.String()
}

func listTurnSteersTx(ctx context.Context, tx pgx.Tx, turnID string) ([]core.TurnSteer, error) {
	rows, err := tx.Query(ctx, `SELECT sequence,payload_json,created_at FROM core_conversation_turn_events WHERE turn_id=$1 AND kind=$2 ORDER BY sequence`, turnID, string(core.TurnEventSteered))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]core.TurnSteer, 0)
	for rows.Next() {
		var sequence int64
		var raw []byte
		var createdAt time.Time
		if err = rows.Scan(&sequence, &raw, &createdAt); err != nil {
			return nil, err
		}
		var event core.TurnEvent
		if json.Unmarshal(raw, &event) != nil || uuid.Validate(event.MutationID) != nil || event.ExpectedRevision == 0 || strings.TrimSpace(event.Text) == "" {
			return nil, core.ErrConflict
		}
		if event.Status != "" && event.Status != deferredTurnSteerStatus {
			return nil, core.ErrConflict
		}
		result = append(result, core.TurnSteer{RequestID: event.MutationID, Instruction: event.Text, ExpectedRevision: event.ExpectedRevision, Sequence: sequence, CreatedAt: createdAt.UTC(), Deferred: event.Status == deferredTurnSteerStatus, AttachmentSources: event.AttachmentSources})
	}
	return result, rows.Err()
}

func (s *CoreConversationStore) RequestTurnCancel(ctx context.Context, c core.TurnCancelCommand) (core.Turn, error) {
	if uuid.Validate(c.RequestID) != nil || uuid.Validate(c.TurnID) != nil {
		return core.Turn{}, core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	var exactTurnID string
	if err = tx.QueryRow(ctx, `SELECT turn_id::text FROM core_conversation_turns WHERE turn_id=$1`, c.TurnID).Scan(&exactTurnID); err != nil || exactTurnID != c.TurnID {
		return core.Turn{}, core.ErrConflict
	}
	var turn core.Turn
	if err = s.scanTurn(ctx, tx, c.TurnID, &turn); err != nil {
		return core.Turn{}, core.ErrConflict
	}
	cancelFingerprint := sha256hexPG([]byte(c.TurnID))
	if turn.CancelRequestID == c.RequestID {
		if turn.CancelRequestFingerprint != cancelFingerprint {
			return core.Turn{}, core.ErrConflict
		}
		_ = tx.Commit(ctx)
		return turn, nil
	}
	if turn.State == core.TurnCompleted || turn.State == core.TurnCanceled || turn.State == core.TurnFailed {
		_ = tx.Commit(ctx)
		return turn, nil
	}
	if turn.CancelRequested {
		_ = tx.Commit(ctx)
		return turn, nil
	}
	now := time.Now().UTC()
	// A parked turn is owned either by a confirmation-gated conversation tool or
	// by its Cloud Worker execution. Cancel the owning task before exposing the
	// terminal turn so no queued or remote work survives the stop mutation.
	if turn.State == core.TurnWaitingConfirmation {
		var cloudTaskID, cloudConfirmationID string
		cloudErr := tx.QueryRow(ctx, `SELECT e.task_id::text,e.confirmation_id::text
			FROM core_cloud_worker_executions e JOIN core_tasks t ON t.task_id=e.task_id
			WHERE e.turn_id=$1 AND e.state NOT IN ('succeeded','failed','canceled','rejected','expired')
			ORDER BY e.created_at DESC,e.execution_id DESC LIMIT 1 FOR UPDATE OF t`, c.TurnID).Scan(&cloudTaskID, &cloudConfirmationID)
		if cloudErr == nil {
			task, taskErr := NewCoreTaskStore(s.Store).taskTxLocked(ctx, tx, cloudTaskID, false)
			if taskErr != nil {
				return core.Turn{}, core.ErrConflict
			}
			plan, execution, loadErr := cloudWorkerPlanAndExecutionTx(ctx, tx, task.Spec.Payload.CloudWorker, true)
			if loadErr != nil {
				return core.Turn{}, core.ErrConflict
			}
			confirmation, confirmationErr := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, cloudConfirmationID))
			if confirmationErr != nil || plan.TurnID != c.TurnID || plan.TaskID != cloudTaskID || plan.ConfirmationID != cloudConfirmationID ||
				cloudworker.ValidateFrozenBinding(plan, execution, confirmation.Binding) != nil {
				return core.Turn{}, core.ErrConflict
			}
			if _, cancelErr := cancelCloudWorkerExecutionTx(ctx, tx, task, confirmation, plan, execution, c.RequestID, now, false); cancelErr != nil {
				return core.Turn{}, core.ErrConflict
			}
			result, updateErr := tx.Exec(ctx, `UPDATE core_conversation_turns SET cancel_requested=true,
				cancel_request_id=$2,cancel_request_fingerprint=$3
				WHERE turn_id=$1 AND state='canceled' AND cancel_requested=false`, c.TurnID, c.RequestID, cancelFingerprint)
			if updateErr != nil || result.RowsAffected() != 1 {
				return core.Turn{}, core.ErrConflict
			}
			if err = tx.Commit(ctx); err != nil {
				return core.Turn{}, err
			}
			return s.GetTurn(ctx, c.TurnID)
		}
		if !errors.Is(cloudErr, pgx.ErrNoRows) {
			return core.Turn{}, cloudErr
		}
		var taskID, lockedTaskID string
		if err = tx.QueryRow(ctx, `SELECT task_id::text FROM core_conversation_tool_attempts WHERE turn_id=$1 AND state='waiting_confirmation'`, c.TurnID).Scan(&taskID); err != nil {
			return core.Turn{}, core.ErrConflict
		}
		if err = tx.QueryRow(ctx, `SELECT task_id::text FROM core_tasks WHERE task_id=$1 FOR UPDATE`, taskID).Scan(&lockedTaskID); err != nil || lockedTaskID != taskID {
			return core.Turn{}, core.ErrConflict
		}
		if err = tx.QueryRow(ctx, `SELECT task_id::text FROM core_conversation_tool_attempts WHERE turn_id=$1 AND task_id=$2 AND state='waiting_confirmation' FOR UPDATE`, c.TurnID, taskID).Scan(&lockedTaskID); err != nil || lockedTaskID != taskID {
			return core.Turn{}, core.ErrConflict
		}
		taskUpdate, taskErr := tx.Exec(ctx, `UPDATE core_tasks SET status='canceled',failure_code='user_canceled',failure_summary='turn canceled before tool dispatch',revision=revision+1,updated_at=$2 WHERE task_id=$1 AND status='waiting_user'`, taskID, now)
		if taskErr != nil || taskUpdate.RowsAffected() != 1 {
			if taskErr != nil {
				return core.Turn{}, taskErr
			}
			return core.Turn{}, core.ErrConflict
		}
		if err = terminalizeConfirmationForTaskModeTx(ctx, tx, taskID, "turn_canceled", now, false); err != nil {
			return core.Turn{}, err
		}
	}
	if turn.State == core.TurnRunning {
		var dispatchedTask, lockedTaskID, callID, toolName string
		if scanErr := tx.QueryRow(ctx, `SELECT a.task_id::text,t.payload_json#>>'{conversation_tool,call_id}',a.tool_name
				FROM core_conversation_tool_attempts a JOIN core_tasks t ON t.task_id=a.task_id
				WHERE a.turn_id=$1 AND a.state='dispatched'`, c.TurnID).Scan(&dispatchedTask, &callID, &toolName); scanErr == nil {
			if scanErr = tx.QueryRow(ctx, `SELECT task_id::text FROM core_tasks WHERE task_id=$1 FOR UPDATE`, dispatchedTask).Scan(&lockedTaskID); scanErr != nil || lockedTaskID != dispatchedTask {
				return core.Turn{}, core.ErrConflict
			}
			if scanErr = tx.QueryRow(ctx, `SELECT task_id::text FROM core_conversation_tool_attempts WHERE turn_id=$1 AND task_id=$2 AND state='dispatched' FOR UPDATE`, c.TurnID, dispatchedTask).Scan(&lockedTaskID); scanErr != nil || lockedTaskID != dispatchedTask {
				return core.Turn{}, core.ErrConflict
			}
			observation := core.ToolResult{CallID: callID, ToolName: toolName, Content: "turn canceled after tool dispatch; reconciliation required", RelatedTaskIDs: []string{dispatchedTask}}.
				WithObservation(core.ToolOutcomeUnknownMutation, "Conversation tool completion is unknown", core.ToolMutationUnknown)
			if observation.ValidateObservation() != nil {
				return core.Turn{}, core.ErrConflict
			}
			observationRaw, _ := json.Marshal(observation)
			if _, scanErr = tx.Exec(ctx, `UPDATE core_conversation_tool_attempts SET state='uncertain',result_json=$2,updated_at=$3 WHERE task_id=$1 AND state='dispatched'`, dispatchedTask, observationRaw, now); scanErr != nil {
				return core.Turn{}, scanErr
			}
			if _, scanErr = tx.Exec(ctx, `UPDATE core_tasks SET status='failed',failure_code='tool_uncertain',failure_summary='turn canceled after tool dispatch; reconciliation required',lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$2 WHERE task_id=$1 AND status='running'`, dispatchedTask, now); scanErr != nil {
				return core.Turn{}, scanErr
			}
		}
	}
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state=CASE WHEN state='waiting_confirmation' THEN 'canceled' ELSE state END,cancel_requested=true,cancel_request_id=$4,cancel_request_fingerprint=$5,lease_id=NULL,lease_expires_at=NULL,lease_epoch=lease_epoch+1,revision=revision+1,updated_at=$2 WHERE turn_id=$1 AND state=$3 AND cancel_requested=false`, c.TurnID, now, turn.State, c.RequestID, cancelFingerprint)
	if err != nil {
		return core.Turn{}, err
	}
	if result.RowsAffected() != 1 {
		_ = tx.Rollback(ctx)
		replay, replayErr := s.GetTurn(ctx, c.TurnID)
		if replayErr == nil && replay.CancelRequestID == c.RequestID && replay.CancelRequestFingerprint == cancelFingerprint {
			return replay, nil
		}
		return core.Turn{}, core.ErrConflict
	}
	if turn.State == core.TurnWaitingConfirmation {
		if err = insertTurnEventTx(ctx, tx, c.TurnID, turn.LastSequence+1, core.TurnEvent{Kind: core.TurnEventCanceled}, now); err != nil {
			return core.Turn{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, c.TurnID)
}

func (s *CoreConversationStore) RequestTurnSteer(ctx context.Context, c core.TurnSteerCommand) (core.Turn, bool, error) {
	if uuid.Validate(c.RequestID) != nil || uuid.Validate(c.TurnID) != nil || c.ExpectedRevision == 0 || strings.TrimSpace(c.Instruction) == "" {
		return core.Turn{}, false, core.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, false, err
	}
	defer tx.Rollback(ctx)
	var state string
	var revision uint64
	var lastSequence int64
	var cancelRequested bool
	var dispatchState string
	var dispatchRaw []byte
	var owner string
	var generation uint64
	if err = tx.QueryRow(ctx, `SELECT state,revision,last_sequence,cancel_requested,dispatch_state,dispatch_result_json,owner_id,account_generation FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, c.TurnID).Scan(&state, &revision, &lastSequence, &cancelRequested, &dispatchState, &dispatchRaw, &owner, &generation); err != nil {
		return core.Turn{}, false, core.ErrConflict
	}
	rows, err := tx.Query(ctx, `SELECT payload_json FROM core_conversation_turn_events WHERE turn_id=$1 AND kind=$2 ORDER BY sequence`, c.TurnID, string(core.TurnEventSteered))
	if err != nil {
		return core.Turn{}, false, err
	}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return core.Turn{}, false, err
		}
		var event core.TurnEvent
		if json.Unmarshal(raw, &event) != nil {
			rows.Close()
			return core.Turn{}, false, core.ErrConflict
		}
		if event.MutationID == c.RequestID {
			rows.Close()
			if event.ExpectedRevision != c.ExpectedRevision || event.Text != strings.TrimSpace(c.Instruction) || strings.Join(attachmentSourceIDs(event.AttachmentSources), ",") != strings.Join(c.AcceptedAttachmentIDs, ",") {
				return core.Turn{}, false, core.ErrConflict
			}
			if err = tx.Commit(ctx); err != nil {
				return core.Turn{}, false, err
			}
			turn, getErr := s.GetTurn(ctx, c.TurnID)
			return turn, false, getErr
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return core.Turn{}, false, err
	}
	rows.Close()
	if cancelRequested || revision != c.ExpectedRevision ||
		(state != string(core.TurnAccepted) && state != string(core.TurnRunning) && state != string(core.TurnWaitingConfirmation)) {
		return core.Turn{}, false, core.ErrConflict
	}
	deferred := false
	if state == string(core.TurnWaitingConfirmation) {
		if dispatchState != "completed" {
			return core.Turn{}, false, core.ErrConflict
		}
		var cloudWorkerSteerable bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM core_cloud_worker_plans p JOIN core_tasks t ON t.task_id=p.task_id
			WHERE p.turn_id=$1 AND p.status='waiting_user' AND t.status IN ('waiting_user','queued','running'))`, c.TurnID).Scan(&cloudWorkerSteerable); err != nil {
			return core.Turn{}, false, err
		}
		if !cloudWorkerSteerable {
			return core.Turn{}, false, core.ErrConflict
		}
		deferred = true
	}
	if dispatchState == "completed" {
		envelope, envelopeErr := loadDurableTurnDispatchEnvelope(dispatchRaw)
		if envelopeErr != nil {
			return core.Turn{}, false, core.ErrConflict
		}
		calls := durableTurnModelCalls(envelope.Result)
		for index, entry := range envelope.Calls {
			if index >= len(calls) {
				return core.Turn{}, false, core.ErrConflict
			}
			call := calls[index]
			authority, authorityErr := conversationToolEventAuthorityTx(ctx, tx, c.TurnID, call.ID)
			if authorityErr != nil {
				return core.Turn{}, false, authorityErr
			}
			switch entry.State {
			case durableTurnToolCallDispatched:
				if authority.state != conversationToolCallPending {
					return core.Turn{}, false, core.ErrConflict
				}
				deferred = true
			case durableTurnToolCallPending:
				// A model-authored pending entry is safe to discard until its
				// public tool_call has been appended. Once public, preserve the
				// exact batch and apply the steer after its result arrives.
				if authority.state == conversationToolCallPending {
					deferred = true
				} else if authority.state != conversationToolCallAbsent {
					return core.Turn{}, false, core.ErrConflict
				}
			case durableTurnToolCallTerminal:
				if authority.state != conversationToolCallTerminal || authority.result == nil || durableTurnToolResultDigest(*authority.result) != entry.ResultDigest {
					return core.Turn{}, false, core.ErrConflict
				}
			}
		}
	}
	now := time.Now().UTC()
	c.AttachmentSources, err = resolveAcceptedAttachments(ctx, tx, owner, generation, c.RequestID, c.AcceptedAttachmentIDs)
	if err != nil {
		return core.Turn{}, false, err
	}
	if err = validateSteerModelAttachments(ctx, tx, c.AttachmentSources); err != nil {
		return core.Turn{}, false, err
	}
	event := core.TurnEvent{
		Kind:              core.TurnEventSteered,
		Text:              strings.TrimSpace(c.Instruction),
		MutationID:        c.RequestID,
		ExpectedRevision:  c.ExpectedRevision,
		AttachmentSources: c.AttachmentSources,
	}
	if deferred {
		event.Status = deferredTurnSteerStatus
	}
	if err = insertTurnEventTx(ctx, tx, c.TurnID, lastSequence+1, event, now); err != nil {
		return core.Turn{}, false, err
	}
	if err = consumeAcceptedAttachments(ctx, tx, owner, generation, c.RequestID, c.AcceptedAttachmentIDs, c.AttachmentSources, c.TurnID); err != nil {
		return core.Turn{}, false, err
	}
	if deferred {
		result, updateErr := tx.Exec(ctx, `UPDATE core_conversation_turns SET revision=revision+1,updated_at=$2
			WHERE turn_id=$1 AND revision=$3 AND state=$4 AND cancel_requested=false`, c.TurnID, now, c.ExpectedRevision, state)
		if updateErr != nil {
			return core.Turn{}, false, updateErr
		}
		if result.RowsAffected() != 1 {
			return core.Turn{}, false, core.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return core.Turn{}, false, err
		}
		turn, getErr := s.GetTurn(ctx, c.TurnID)
		return turn, false, getErr
	}
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_model_attempts
		SET state='superseded',failure_code='',rate_limited=false,retry_after_ms=0,finished_at=$2
		WHERE turn_id=$1 AND state='dispatched'`, c.TurnID, now); err != nil {
		return core.Turn{}, false, err
	}
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',dispatch_state='',dispatch_epoch=0,dispatch_result_json=NULL,
		model_active_milliseconds=model_active_milliseconds+CASE WHEN model_dispatch_started_at IS NULL THEN 0 ELSE GREATEST(0,FLOOR(EXTRACT(EPOCH FROM ($2-model_dispatch_started_at))*1000))::bigint END,
		model_dispatch_started_at=NULL,lease_id=NULL,lease_expires_at=NULL,lease_epoch=lease_epoch+1,revision=revision+1,updated_at=$2
		WHERE turn_id=$1 AND revision=$3 AND state IN ('accepted','running') AND cancel_requested=false`, c.TurnID, now, c.ExpectedRevision)
	if err != nil {
		return core.Turn{}, false, err
	}
	if result.RowsAffected() != 1 {
		return core.Turn{}, false, core.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, false, err
	}
	turn, getErr := s.GetTurn(ctx, c.TurnID)
	return turn, true, getErr
}

func (s *CoreConversationStore) ListTurnSteers(ctx context.Context, turnID string) ([]core.TurnSteer, error) {
	if uuid.Validate(turnID) != nil {
		return nil, core.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `SELECT sequence,payload_json,created_at FROM core_conversation_turn_events WHERE turn_id=$1 AND kind=$2 ORDER BY sequence`, turnID, string(core.TurnEventSteered))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]core.TurnSteer, 0)
	for rows.Next() {
		var sequence int64
		var raw []byte
		var createdAt time.Time
		if err = rows.Scan(&sequence, &raw, &createdAt); err != nil {
			return nil, err
		}
		var event core.TurnEvent
		if json.Unmarshal(raw, &event) != nil || uuid.Validate(event.MutationID) != nil || event.ExpectedRevision == 0 || strings.TrimSpace(event.Text) == "" {
			return nil, core.ErrConflict
		}
		if event.Status != "" && event.Status != deferredTurnSteerStatus {
			return nil, core.ErrConflict
		}
		result = append(result, core.TurnSteer{RequestID: event.MutationID, Instruction: event.Text, ExpectedRevision: event.ExpectedRevision, Sequence: sequence, CreatedAt: createdAt.UTC(), Deferred: event.Status == deferredTurnSteerStatus, AttachmentSources: event.AttachmentSources})
	}
	return result, rows.Err()
}

func (s *CoreConversationStore) MarkTurnCanceled(ctx context.Context, lease core.TurnLease) (core.Turn, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	var lastSequence int64
	if err = tx.QueryRow(ctx, `SELECT last_sequence FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running' FOR UPDATE`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&lastSequence); err != nil {
		return core.Turn{}, core.ErrConflict
	}
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='canceled',revision=revision+1,lease_id=NULL,lease_expires_at=NULL,updated_at=$2 WHERE turn_id=$1 AND lease_id=$3 AND lease_epoch=$4 AND state='running'`, lease.Turn.ID, now, lease.LeaseID, lease.Epoch)
	if err != nil {
		return core.Turn{}, err
	}
	if result.RowsAffected() != 1 {
		return core.Turn{}, core.ErrConflict
	}
	if err = insertTurnEventTx(ctx, tx, lease.Turn.ID, lastSequence+1, core.TurnEvent{Kind: core.TurnEventCanceled}, now); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, lease.Turn.ID)
}

func (s *CoreConversationStore) MarkTurnCanceledRequested(ctx context.Context, id string) (core.Turn, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='canceled',revision=revision+1,updated_at=$2 WHERE turn_id=$1 AND state IN ('accepted','running') AND cancel_requested=true AND lease_id IS NULL`, id, now)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return core.Turn{}, err
		}
		return core.Turn{}, core.ErrConflict
	}
	var turn core.Turn
	if err = s.scanTurn(ctx, tx, id, &turn); err != nil {
		return core.Turn{}, err
	}
	if err = insertTurnEventTx(ctx, tx, id, turn.LastSequence+1, core.TurnEvent{Kind: core.TurnEventCanceled}, now); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, id)
}

func (s *CoreConversationStore) FailTurnUncertain(ctx context.Context, id, code, summary string) (core.Turn, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	var turn core.Turn
	if err = s.scanTurn(ctx, tx, id, &turn); err != nil {
		return core.Turn{}, core.ErrConflict
	}
	now := time.Now().UTC()
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='failed',revision=revision+1,terminal_code=$2,terminal_summary=$3,lease_id=NULL,lease_expires_at=NULL,updated_at=$4 WHERE turn_id=$1 AND state IN ('accepted','running') AND cancel_requested=false AND dispatch_state='uncertain'`, id, code, summary, now)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return core.Turn{}, err
		}
		return core.Turn{}, core.ErrConflict
	}
	if err = insertTurnEventTx(ctx, tx, id, turn.LastSequence+1, core.TurnEvent{Kind: core.TurnEventError, ErrorCode: code, ErrorSummary: summary}, now); err != nil {
		return core.Turn{}, err
	}
	if err = failedTurnTranscriptTx(ctx, tx, turn, code, summary, now); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, id)
}

func (s *CoreConversationStore) FailTurn(ctx context.Context, lease core.TurnLease, code, summary string) (core.Turn, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Turn{}, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	var lastSequence int64
	if err = tx.QueryRow(ctx, `SELECT last_sequence FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='running' FOR UPDATE`, lease.Turn.ID, lease.LeaseID, lease.Epoch).Scan(&lastSequence); err != nil {
		return core.Turn{}, core.ErrConflict
	}
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='failed',revision=revision+1,terminal_code=$2,terminal_summary=$3,lease_id=NULL,lease_expires_at=NULL,updated_at=$4 WHERE turn_id=$1 AND lease_id=$5 AND lease_epoch=$6 AND state='running'`, lease.Turn.ID, code, summary, now, lease.LeaseID, lease.Epoch)
	if err != nil {
		return core.Turn{}, err
	}
	if result.RowsAffected() != 1 {
		return core.Turn{}, core.ErrConflict
	}
	if err = failedTurnTranscriptTx(ctx, tx, lease.Turn, code, summary, now); err != nil {
		return core.Turn{}, err
	}
	if err = insertTurnEventTx(ctx, tx, lease.Turn.ID, lastSequence+1, core.TurnEvent{Kind: core.TurnEventError, ErrorCode: code, ErrorSummary: summary}, now); err != nil {
		return core.Turn{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Turn{}, err
	}
	return s.GetTurn(ctx, lease.Turn.ID)
}

var _ core.TurnStore = (*CoreConversationStore)(nil)

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	coremodel "github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type chatRequestIdentity struct {
	ownerID           string
	accountGeneration int64
	storageRequestID  string
}

func chatRequestIdentityForContext(ctx context.Context, requestID string) (chatRequestIdentity, error) {
	ownerID, generation, err := ownerScopeOrInternal(ctx, "chat_request", requestID)
	if err != nil {
		return chatRequestIdentity{}, err
	}
	storageRequestID := requestID
	if publicOwnerID, _ := publicOwnerScopeValues(ctx); publicOwnerID != "" {
		storageRequestID = ownerScopedStableUUID(ctx, "chat_request", requestID)
	}
	return chatRequestIdentity{ownerID: ownerID, accountGeneration: generation, storageRequestID: storageRequestID}, nil
}

func (s *CoreConversationStore) resolveChatRequestIdentity(ctx context.Context, requestID string) (chatRequestIdentity, error) {
	identity, err := chatRequestIdentityForContext(ctx, requestID)
	if err != nil {
		return chatRequestIdentity{}, core.ErrInvalid
	}
	err = s.pool.QueryRow(ctx, `SELECT request_id FROM core_chat_request_leases WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, identity.ownerID, identity.accountGeneration, requestID).Scan(&identity.storageRequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return chatRequestIdentity{}, core.ErrConflict
	}
	if err != nil {
		return chatRequestIdentity{}, err
	}
	return identity, nil
}

func (s *CoreConversationStore) ClaimChat(ctx context.Context, id, conv, fp, profile string, exts []core.ExtensionSelection, now time.Time, ttl time.Duration) (core.ChatLease, error) {
	_ = now // PostgreSQL is the lease clock authority for persisted chat claims.
	identity, e := chatRequestIdentityForContext(ctx, id)
	if e != nil {
		return core.ChatLease{}, core.ErrInvalid
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return core.ChatLease{}, e
	}
	defer tx.Rollback(ctx)
	var state, storedFP, failureCode, failureSummary string
	var epoch uint64
	var leaseActive bool
	var lease *uuid.UUID
	var exp *time.Time
	var storedConv, storedProfile *uuid.UUID
	var storedExt, responseRaw, snapshotRaw, snapshotNonce, snapshotCiphertext []byte
	var snapshotKeyVersion *int32
	var snapshotDigest *string
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, fmt.Sprintf("core_chat_request:%s:%d:%s", identity.ownerID, identity.accountGeneration, id)); e != nil {
		return core.ChatLease{}, e
	}
	e = tx.QueryRow(ctx, `SELECT request_id,state,request_fingerprint,conversation_id,profile_id,extensions_json,profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,lease_epoch,lease_id,lease_expires_at,COALESCE(lease_expires_at > clock_timestamp(),false),response_json,error_code,error_summary FROM core_chat_request_leases WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, identity.ownerID, identity.accountGeneration, id).Scan(&identity.storageRequestID, &state, &storedFP, &storedConv, &storedProfile, &storedExt, &snapshotRaw, &snapshotDigest, &snapshotKeyVersion, &snapshotNonce, &snapshotCiphertext, &epoch, &lease, &exp, &leaseActive, &responseRaw, &failureCode, &failureSummary)
	if errors.Is(e, pgx.ErrNoRows) {
		leaseID := uuid.New()
		lease = &leaseID
		epoch = 1
		raw, _ := extensionJSONPG(exts)
		var expTime time.Time
		e = tx.QueryRow(ctx, `INSERT INTO core_chat_request_leases(request_id,conversation_id,idempotency_key,request_fingerprint,profile_id,extensions_json,state,lease_id,lease_epoch,lease_expires_at,owner_id,account_generation) VALUES($1,$2,$3,$4,$5,$6,'in_flight',$7,$8,clock_timestamp()+$9::bigint*interval '1 microsecond',$10,$11) RETURNING lease_expires_at`, identity.storageRequestID, nullableUUIDPG(conv), id, fp, profile, raw, lease, epoch, ttl.Microseconds(), identity.ownerID, identity.accountGeneration).Scan(&expTime)
		if e != nil {
			return core.ChatLease{}, e
		}
		expTime = expTime.UTC()
		exp = &expTime
		if e = tx.Commit(ctx); e != nil {
			return core.ChatLease{}, e
		}
		return core.ChatLease{RequestID: id, ConversationID: conv, Fingerprint: fp, LeaseID: lease.String(), Epoch: epoch, ExpiresAt: *exp, Status: core.ClaimNew, ProfileID: profile, Extensions: exts}, nil
	}
	if e != nil {
		return core.ChatLease{}, e
	}
	wantExt, _ := extensionJSONPG(exts)
	if storedFP != fp || (storedProfile != nil && storedProfile.String() != profile) || sha256hexPG(storedExt) != sha256hexPG(wantExt) || (storedConv != nil && (conv == "" || storedConv.String() != conv)) {
		return core.ChatLease{}, core.ErrConflict
	}
	var storedExts []core.ExtensionSelection
	_ = json.Unmarshal(storedExt, &storedExts)
	base := core.ChatLease{RequestID: id, ConversationID: conv, Fingerprint: fp, ProfileID: profile, Extensions: storedExts, Epoch: epoch}
	if snapshotDigest != nil {
		if snapshotKeyVersion == nil || len(snapshotRaw) == 0 || s.decodeChatSnapshot(ctx, identity.storageRequestID, snapshotRaw, *snapshotDigest, uint32(*snapshotKeyVersion), snapshotNonce, snapshotCiphertext, &base.ProfileSnapshot) != nil {
			return core.ChatLease{}, core.ErrConflict
		}
		base.ProfileSnapshotDigest = *snapshotDigest
	}
	if state == "completed" {
		_ = json.Unmarshal(responseRaw, &base.Response)
		base.Status = core.ClaimCompleted
		return base, tx.Commit(ctx)
	}
	if state == "failed" {
		base.Status, base.FailureCode, base.FailureSummary = core.ClaimFailed, failureCode, failureSummary
		return base, tx.Commit(ctx)
	}
	if leaseActive && exp != nil && lease != nil {
		base.Status, base.LeaseID, base.ExpiresAt = core.ClaimInFlight, lease.String(), *exp
		return base, tx.Commit(ctx)
	}
	leaseID := uuid.New()
	lease = &leaseID
	epoch++
	var expTime time.Time
	e = tx.QueryRow(ctx, `UPDATE core_chat_request_leases SET lease_id=$2,lease_epoch=$3,lease_expires_at=clock_timestamp()+$4::bigint*interval '1 microsecond',updated_at=clock_timestamp() WHERE request_id=$1 RETURNING lease_expires_at`, identity.storageRequestID, lease, epoch, ttl.Microseconds()).Scan(&expTime)
	if e != nil {
		return core.ChatLease{}, e
	}
	expTime = expTime.UTC()
	exp = &expTime
	// Model-step rows are durable provider results for this idempotency
	// request.  Rebind them to the newly claimed epoch while holding the same
	// transaction so a retry can replay a completed provider call after a
	// worker crash, while the old lease/epoch remains fenced for every read and
	// write path.
	if _, e = tx.Exec(ctx, `UPDATE core_model_steps SET epoch=$2 WHERE request_id=$1 AND state='completed'`, identity.storageRequestID, epoch); e != nil {
		return core.ChatLease{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return core.ChatLease{}, e
	}
	base.Status, base.LeaseID, base.Epoch, base.ExpiresAt = core.ClaimReclaimed, lease.String(), epoch, *exp
	return base, nil
}

func (s *CoreConversationStore) BindChatProfileSnapshot(ctx context.Context, id, lease string, epoch uint64, fp string, snapshot coremodel.ExecutionSnapshot) (core.ChatLease, error) {
	if err := snapshot.Validate(); err != nil {
		return core.ChatLease{}, core.ErrInvalid
	}
	identity, err := s.resolveChatRequestIdentity(ctx, id)
	if err != nil {
		return core.ChatLease{}, err
	}
	metadataSnapshot := snapshot
	metadataSnapshot.APIKey = ""
	raw, err := json.Marshal(metadataSnapshot)
	if err != nil {
		return core.ChatLease{}, err
	}
	digest := snapshot.Digest()
	plaintext := []byte(snapshot.APIKey)
	envelope, err := s.sealDurableSecret("core_chat_request_leases", identity.storageRequestID, snapshot.Revision, "profile_snapshot_api_key", plaintext)
	clearBytes(plaintext)
	if err != nil {
		return core.ChatLease{}, err
	}
	var out core.ChatLease
	var conv, profile *uuid.UUID
	var leaseUUID *uuid.UUID
	var expires *time.Time
	var exts, snapshotRaw, snapshotNonce, snapshotCiphertext []byte
	var snapshotKeyVersion int32
	var storedDigest *string
	err = s.pool.QueryRow(ctx, `UPDATE core_chat_request_leases SET profile_snapshot_json=$5,profile_snapshot_digest=$6,profile_snapshot_key_version=$8,profile_snapshot_api_key_nonce=$9,profile_snapshot_api_key_ciphertext=$10,updated_at=clock_timestamp() WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND request_fingerprint=$4 AND profile_id=$7 AND state='in_flight' AND profile_snapshot_json IS NULL AND profile_snapshot_digest IS NULL RETURNING conversation_id,request_fingerprint,profile_id,extensions_json,profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,lease_epoch,lease_id,lease_expires_at`, identity.storageRequestID, lease, epoch, fp, raw, digest, snapshot.ProfileID, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext).Scan(&conv, &out.Fingerprint, &profile, &exts, &snapshotRaw, &storedDigest, &snapshotKeyVersion, &snapshotNonce, &snapshotCiphertext, &out.Epoch, &leaseUUID, &expires)
	if err != nil {
		return core.ChatLease{}, core.ErrConflict
	}
	out.RequestID, out.Status = id, core.ClaimInFlight
	if leaseUUID != nil {
		out.LeaseID = leaseUUID.String()
	}
	if expires != nil {
		out.ExpiresAt = *expires
	}
	if conv != nil {
		out.ConversationID = conv.String()
	}
	if profile != nil {
		out.ProfileID = profile.String()
	}
	_ = json.Unmarshal(exts, &out.Extensions)
	if storedDigest == nil || *storedDigest != digest || s.decodeChatSnapshot(ctx, identity.storageRequestID, snapshotRaw, *storedDigest, uint32(snapshotKeyVersion), snapshotNonce, snapshotCiphertext, &out.ProfileSnapshot) != nil {
		return core.ChatLease{}, core.ErrConflict
	}
	out.ProfileSnapshotDigest = *storedDigest
	return out, nil
}

func (s *CoreConversationStore) RenewChat(ctx context.Context, id, lease string, epoch uint64, now time.Time, ttl time.Duration) (core.ChatLease, error) {
	_ = now // PostgreSQL is the lease clock authority for persisted chat claims.
	identity, e := s.resolveChatRequestIdentity(ctx, id)
	if e != nil {
		return core.ChatLease{}, e
	}
	var out core.ChatLease
	var ep uint64
	var conv, profile *uuid.UUID
	var fp string
	var exts, snapshotRaw, snapshotNonce, snapshotCiphertext []byte
	var snapshotKeyVersion *int32
	var snapshotDigest *string
	e = s.pool.QueryRow(ctx, `UPDATE core_chat_request_leases SET lease_epoch=lease_epoch+1,lease_expires_at=clock_timestamp()+$4::bigint*interval '1 microsecond',updated_at=clock_timestamp() WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='in_flight' RETURNING conversation_id,request_fingerprint,profile_id,extensions_json,profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,lease_epoch,lease_expires_at`, identity.storageRequestID, lease, epoch, ttl.Microseconds()).Scan(&conv, &fp, &profile, &exts, &snapshotRaw, &snapshotDigest, &snapshotKeyVersion, &snapshotNonce, &snapshotCiphertext, &ep, &out.ExpiresAt)
	if e != nil {
		return out, core.ErrConflict
	}
	out.RequestID, out.Fingerprint, out.LeaseID = id, fp, lease
	if conv != nil {
		out.ConversationID = conv.String()
	}
	if profile != nil {
		out.ProfileID = profile.String()
	}
	_ = json.Unmarshal(exts, &out.Extensions)
	if snapshotDigest != nil {
		if snapshotKeyVersion == nil || s.decodeChatSnapshot(ctx, identity.storageRequestID, snapshotRaw, *snapshotDigest, uint32(*snapshotKeyVersion), snapshotNonce, snapshotCiphertext, &out.ProfileSnapshot) != nil {
			return core.ChatLease{}, core.ErrConflict
		}
		out.ProfileSnapshotDigest = *snapshotDigest
	}
	out.Epoch = ep
	out.ExpiresAt = out.ExpiresAt.UTC()
	out.Status = core.ClaimInFlight
	return out, nil
}

func (s *CoreConversationStore) decodeChatSnapshot(ctx context.Context, requestID string, raw []byte, digest string, version uint32, nonce, ciphertext []byte, out *coremodel.ExecutionSnapshot) error {
	if out == nil || json.Unmarshal(raw, out) != nil || out.APIKey != "" {
		return core.ErrConflict
	}
	plaintext, err := s.openDurableSecret("core_chat_request_leases", requestID, out.Revision, "profile_snapshot_api_key", version, nonce, ciphertext)
	if err != nil {
		return core.ErrConflict
	}
	out.APIKey = string(plaintext)
	clearBytes(plaintext)
	if err := out.Validate(); err != nil || out.Digest() != digest {
		return core.ErrConflict
	}
	_ = ctx
	return nil
}
func (s *CoreConversationStore) ReleaseChat(ctx context.Context, id, lease string, epoch uint64) error {
	// A released request remains reclaimable so a completed model step can be
	// replayed after a failure between provider completion and conversation
	// commit. Keep the lease identity required by the in_flight row constraint,
	// but expire it immediately so the next ClaimChat advances the epoch.
	identity, e := s.resolveChatRequestIdentity(ctx, id)
	if e != nil {
		return e
	}
	res, e := s.pool.Exec(ctx, `UPDATE core_chat_request_leases SET lease_expires_at=clock_timestamp(),updated_at=clock_timestamp() WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='in_flight'`, identity.storageRequestID, lease, epoch)
	if e != nil {
		return e
	}
	if res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	return nil
}
func (s *CoreConversationStore) FailChat(ctx context.Context, id, lease string, epoch uint64, code, summary string) error {
	identity, e := s.resolveChatRequestIdentity(ctx, id)
	if e != nil {
		return e
	}
	res, e := s.pool.Exec(ctx, `UPDATE core_chat_request_leases SET state='failed',lease_id=NULL,lease_expires_at=NULL,error_code=$4,error_summary=$5 WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='in_flight'`, identity.storageRequestID, lease, epoch, code, summary)
	if e == nil && res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	return e
}
func (s *CoreConversationStore) ClaimToolExecution(ctx context.Context, req, call, args, ext string, now time.Time, ttl time.Duration) (core.ToolLease, error) {
	identity, e := s.resolveChatRequestIdentity(ctx, req)
	if e != nil {
		return core.ToolLease{}, e
	}
	var state string
	var eid uuid.UUID
	var lease *uuid.UUID
	var ep uint64
	var exp *time.Time
	var resultRaw []byte
	e = s.pool.QueryRow(ctx, `SELECT state,execution_id,lease_id,epoch,lease_expires_at,result_json FROM core_tool_executions WHERE request_id=$1 AND tool_call_id=$2 AND args_digest=$3 AND extension_digest=$4`, identity.storageRequestID, call, args, ext).Scan(&state, &eid, &lease, &ep, &exp, &resultRaw)
	if errors.Is(e, pgx.ErrNoRows) {
		eid = uuid.New()
		leaseID := uuid.New()
		lease = &leaseID
		ep = 1
		expTime := now.Add(ttl)
		exp = &expTime
		tx, txErr := s.pool.Begin(ctx)
		if txErr != nil {
			return core.ToolLease{}, txErr
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, `INSERT INTO core_execution_ledger(execution_id,request_id,execution_kind) VALUES($1,$2,'tool')`, eid, identity.storageRequestID); e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO core_tool_executions(request_id,tool_call_id,execution_id,args_digest,extension_digest,lease_id,lease_epoch,lease_expires_at,state,epoch) VALUES($2,$3,$1,$4,$5,$6,$7,$8,'claimed',$7)`, eid, identity.storageRequestID, call, args, ext, lease, ep, exp)
		}
		if e != nil {
			return core.ToolLease{}, e
		}
		if e = tx.Commit(ctx); e != nil {
			return core.ToolLease{}, e
		}
		return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: lease.String(), Epoch: ep, ExecutionID: eid.String(), ExpiresAt: *exp, Status: core.ToolClaimNew}, nil
	}
	if e != nil {
		return core.ToolLease{}, e
	}
	if state == "uncertain" {
		return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: nullableLeaseID(lease), Epoch: ep, ExecutionID: eid.String(), Status: core.ToolClaimUncertain}, nil
	}
	if state == "completed" {
		var result core.ToolResult
		if e := json.Unmarshal(resultRaw, &result); e != nil {
			return core.ToolLease{}, e
		}
		return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: nullableLeaseID(lease), Epoch: ep, ExecutionID: eid.String(), Status: core.ToolClaimCompleted, Result: &result, ArgsDigest: args, ExtensionDigest: ext}, nil
	}
	if state == "dispatched" {
		return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: nullableLeaseID(lease), Epoch: ep, ExecutionID: eid.String(), Status: core.ToolClaimDispatched, ArgsDigest: args, ExtensionDigest: ext}, nil
	}
	if exp != nil && exp.After(now) && lease != nil {
		return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: lease.String(), Epoch: ep, ExecutionID: eid.String(), ExpiresAt: *exp, Status: core.ToolClaimInFlight}, nil
	}
	leaseID := uuid.New()
	lease = &leaseID
	ep++
	expTime := now.Add(ttl)
	exp = &expTime
	_, e = s.pool.Exec(ctx, `UPDATE core_tool_executions SET lease_id=$3,lease_epoch=$4,lease_expires_at=$5,state='claimed',epoch=$4 WHERE request_id=$1 AND tool_call_id=$2`, identity.storageRequestID, call, lease, ep, exp)
	return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: lease.String(), Epoch: ep, ExecutionID: eid.String(), ExpiresAt: *exp, Status: core.ToolClaimReclaimed}, e
}

func nullableLeaseID(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
func (s *CoreConversationStore) MarkToolDispatched(ctx context.Context, req, call, lease string, epoch uint64) error {
	identity, e := s.resolveChatRequestIdentity(ctx, req)
	if e != nil {
		return e
	}
	res, e := s.pool.Exec(ctx, `UPDATE core_tool_executions SET state='dispatched',updated_at=clock_timestamp() WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND state IN ('claimed')`, identity.storageRequestID, call, lease, epoch)
	if e == nil && res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	return e
}
func (s *CoreConversationStore) CompleteToolExecution(ctx context.Context, c core.ToolCompletion) (core.ToolResult, error) {
	identity, err := s.resolveChatRequestIdentity(ctx, c.RequestID)
	if err != nil {
		return core.ToolResult{}, err
	}
	raw, _ := json.Marshal(c.Result)
	var out core.ToolResult
	e := s.pool.QueryRow(ctx, `UPDATE core_tool_executions SET state='completed',result_json=$6,lease_id=NULL,lease_expires_at=NULL WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND args_digest=$5 AND extension_digest=$7 AND state='dispatched' RETURNING result_json`, identity.storageRequestID, c.ToolCallID, c.LeaseID, c.Epoch, c.ArgsDigest, raw, c.ExtensionDigest).Scan(&raw)
	if e != nil {
		return out, core.ErrConflict
	}
	_ = json.Unmarshal(raw, &out)
	return out, nil
}
func (s *CoreConversationStore) TerminalizeToolUncertain(ctx context.Context, req, call, tlease string, tepoch uint64, please string, pepoch uint64, code, summary string) error {
	identity, e := s.resolveChatRequestIdentity(ctx, req)
	if e != nil {
		return e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	res, e := tx.Exec(ctx, `UPDATE core_tool_executions SET state='uncertain',error_code=$5,error_summary=$6,lease_id=NULL,lease_expires_at=NULL WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND state IN ('dispatched','uncertain')`, identity.storageRequestID, call, tlease, tepoch, code, summary)
	if e != nil {
		return e
	}
	if res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	res, e = tx.Exec(ctx, `UPDATE core_chat_request_leases SET state='failed',error_code=$4,error_summary=$5,lease_id=NULL,lease_expires_at=NULL WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='in_flight'`, identity.storageRequestID, please, pepoch, code, summary)
	if e == nil && res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *CoreConversationStore) RenewToolExecution(ctx context.Context, req, call, lease string, epoch uint64, now time.Time, ttl time.Duration) (core.ToolLease, error) {
	identity, e := s.resolveChatRequestIdentity(ctx, req)
	if e != nil {
		return core.ToolLease{}, e
	}
	x := now.Add(ttl)
	var state string
	var ep uint64
	var eid uuid.UUID
	e = s.pool.QueryRow(ctx, `UPDATE core_tool_executions SET lease_epoch=lease_epoch+1,epoch=epoch+1,lease_expires_at=$5,updated_at=clock_timestamp() WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND state IN ('claimed','dispatched') RETURNING lease_epoch,execution_id,state`, identity.storageRequestID, call, lease, epoch, x).Scan(&ep, &eid, &state)
	if e != nil {
		return core.ToolLease{}, core.ErrConflict
	}
	status := core.ToolClaimNew
	if state == "dispatched" {
		status = core.ToolClaimDispatched
	}
	return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: lease, Epoch: ep, ExecutionID: eid.String(), ExpiresAt: x, Status: status}, nil
}
func (s *CoreConversationStore) ReleaseToolExecution(ctx context.Context, req, call, lease string, epoch uint64) error {
	identity, e := s.resolveChatRequestIdentity(ctx, req)
	if e != nil {
		return e
	}
	_, e = s.pool.Exec(ctx, `DELETE FROM core_tool_executions WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND state='claimed'`, identity.storageRequestID, call, lease, epoch)
	return e
}

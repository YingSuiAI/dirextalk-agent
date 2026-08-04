package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	coremodel "github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *CoreConversationStore) ClaimChat(ctx context.Context, id, conv, fp, profile string, exts []core.ExtensionSelection, now time.Time, ttl time.Duration) (core.ChatLease, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return core.ChatLease{}, e
	}
	defer tx.Rollback(ctx)
	var state, storedFP, failureCode, failureSummary string
	var epoch uint64
	var lease *uuid.UUID
	var exp *time.Time
	var storedConv, storedProfile *uuid.UUID
	var storedExt, responseRaw, snapshotRaw, snapshotNonce, snapshotCiphertext []byte
	var snapshotKeyVersion *int32
	var snapshotDigest *string
	e = tx.QueryRow(ctx, `SELECT state,request_fingerprint,conversation_id,profile_id,extensions_json,profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,lease_epoch,lease_id,lease_expires_at,response_json,error_code,error_summary FROM core_chat_request_leases WHERE request_id=$1`, id).Scan(&state, &storedFP, &storedConv, &storedProfile, &storedExt, &snapshotRaw, &snapshotDigest, &snapshotKeyVersion, &snapshotNonce, &snapshotCiphertext, &epoch, &lease, &exp, &responseRaw, &failureCode, &failureSummary)
	if errors.Is(e, pgx.ErrNoRows) {
		leaseID := uuid.New()
		lease = &leaseID
		epoch = 1
		expTime := now.Add(ttl)
		exp = &expTime
		raw, _ := extensionJSONPG(exts)
		_, e = tx.Exec(ctx, `INSERT INTO core_chat_request_leases(request_id,conversation_id,idempotency_key,request_fingerprint,profile_id,extensions_json,state,lease_id,lease_epoch,lease_expires_at) VALUES($1,$2,$1,$3,$4,$5,'in_flight',$6,$7,$8)`, id, nullableUUIDPG(conv), fp, profile, raw, lease, epoch, exp)
		if e != nil {
			return core.ChatLease{}, e
		}
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
		if snapshotKeyVersion == nil || len(snapshotRaw) == 0 || s.decodeChatSnapshot(ctx, id, snapshotRaw, *snapshotDigest, uint32(*snapshotKeyVersion), snapshotNonce, snapshotCiphertext, &base.ProfileSnapshot) != nil {
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
	if exp != nil && exp.After(now) && lease != nil {
		base.Status, base.LeaseID, base.ExpiresAt = core.ClaimInFlight, lease.String(), *exp
		return base, tx.Commit(ctx)
	}
	leaseID := uuid.New()
	lease = &leaseID
	epoch++
	expTime := now.Add(ttl)
	exp = &expTime
	_, e = tx.Exec(ctx, `UPDATE core_chat_request_leases SET lease_id=$2,lease_epoch=$3,lease_expires_at=$4 WHERE request_id=$1`, id, lease, epoch, exp)
	if e != nil {
		return core.ChatLease{}, e
	}
	// Model-step rows are durable provider results for this idempotency
	// request.  Rebind them to the newly claimed epoch while holding the same
	// transaction so a retry can replay a completed provider call after a
	// worker crash, while the old lease/epoch remains fenced for every read and
	// write path.
	if _, e = tx.Exec(ctx, `UPDATE core_model_steps SET epoch=$2 WHERE request_id=$1 AND state='completed'`, id, epoch); e != nil {
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
	metadataSnapshot := snapshot
	metadataSnapshot.APIKey = ""
	raw, err := json.Marshal(metadataSnapshot)
	if err != nil {
		return core.ChatLease{}, err
	}
	digest := snapshot.Digest()
	plaintext := []byte(snapshot.APIKey)
	envelope, err := s.sealDurableSecret("core_chat_request_leases", id, snapshot.Revision, "profile_snapshot_api_key", plaintext)
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
	err = s.pool.QueryRow(ctx, `UPDATE core_chat_request_leases SET profile_snapshot_json=$5,profile_snapshot_digest=$6,profile_snapshot_key_version=$8,profile_snapshot_api_key_nonce=$9,profile_snapshot_api_key_ciphertext=$10,updated_at=clock_timestamp() WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND request_fingerprint=$4 AND profile_id=$7 AND state='in_flight' AND profile_snapshot_json IS NULL AND profile_snapshot_digest IS NULL RETURNING conversation_id,request_fingerprint,profile_id,extensions_json,profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,lease_epoch,lease_id,lease_expires_at`, id, lease, epoch, fp, raw, digest, snapshot.ProfileID, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext).Scan(&conv, &out.Fingerprint, &profile, &exts, &snapshotRaw, &storedDigest, &snapshotKeyVersion, &snapshotNonce, &snapshotCiphertext, &out.Epoch, &leaseUUID, &expires)
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
	if storedDigest == nil || *storedDigest != digest || s.decodeChatSnapshot(ctx, id, snapshotRaw, *storedDigest, uint32(snapshotKeyVersion), snapshotNonce, snapshotCiphertext, &out.ProfileSnapshot) != nil {
		return core.ChatLease{}, core.ErrConflict
	}
	out.ProfileSnapshotDigest = *storedDigest
	return out, nil
}

func (s *CoreConversationStore) RenewChat(ctx context.Context, id, lease string, epoch uint64, now time.Time, ttl time.Duration) (core.ChatLease, error) {
	x := now.Add(ttl)
	var e error
	var out core.ChatLease
	var ep uint64
	var conv, profile *uuid.UUID
	var fp string
	var exts, snapshotRaw, snapshotNonce, snapshotCiphertext []byte
	var snapshotKeyVersion *int32
	var snapshotDigest *string
	e = s.pool.QueryRow(ctx, `UPDATE core_chat_request_leases SET lease_epoch=lease_epoch+1,lease_expires_at=$4,updated_at=clock_timestamp() WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='in_flight' RETURNING conversation_id,request_fingerprint,profile_id,extensions_json,profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,lease_epoch`, id, lease, epoch, x).Scan(&conv, &fp, &profile, &exts, &snapshotRaw, &snapshotDigest, &snapshotKeyVersion, &snapshotNonce, &snapshotCiphertext, &ep)
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
		if snapshotKeyVersion == nil || s.decodeChatSnapshot(ctx, id, snapshotRaw, *snapshotDigest, uint32(*snapshotKeyVersion), snapshotNonce, snapshotCiphertext, &out.ProfileSnapshot) != nil {
			return core.ChatLease{}, core.ErrConflict
		}
		out.ProfileSnapshotDigest = *snapshotDigest
	}
	out.Epoch = ep
	out.ExpiresAt = x
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
	res, e := s.pool.Exec(ctx, `UPDATE core_chat_request_leases SET lease_id=NULL,lease_expires_at=NULL WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='in_flight'`, id, lease, epoch)
	if e != nil {
		return e
	}
	if res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	return nil
}
func (s *CoreConversationStore) FailChat(ctx context.Context, id, lease string, epoch uint64, code, summary string) error {
	res, e := s.pool.Exec(ctx, `UPDATE core_chat_request_leases SET state='failed',lease_id=NULL,lease_expires_at=NULL,error_code=$4,error_summary=$5 WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='in_flight'`, id, lease, epoch, code, summary)
	if e == nil && res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	return e
}
func (s *CoreConversationStore) ClaimToolExecution(ctx context.Context, req, call, args, ext string, now time.Time, ttl time.Duration) (core.ToolLease, error) {
	var state string
	var eid uuid.UUID
	var lease *uuid.UUID
	var ep uint64
	var exp *time.Time
	var resultRaw []byte
	e := s.pool.QueryRow(ctx, `SELECT state,execution_id,lease_id,epoch,lease_expires_at,result_json FROM core_tool_executions WHERE request_id=$1 AND tool_call_id=$2 AND args_digest=$3 AND extension_digest=$4`, req, call, args, ext).Scan(&state, &eid, &lease, &ep, &exp, &resultRaw)
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
		if _, e = tx.Exec(ctx, `INSERT INTO core_execution_ledger(execution_id,request_id,execution_kind) VALUES($1,$2,'tool')`, eid, req); e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO core_tool_executions(request_id,tool_call_id,execution_id,args_digest,extension_digest,lease_id,lease_epoch,lease_expires_at,state,epoch) VALUES($2,$3,$1,$4,$5,$6,$7,$8,'claimed',$7)`, eid, req, call, args, ext, lease, ep, exp)
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
	_, e = s.pool.Exec(ctx, `UPDATE core_tool_executions SET lease_id=$3,lease_epoch=$4,lease_expires_at=$5,state='claimed',epoch=$4 WHERE request_id=$1 AND tool_call_id=$2`, req, call, lease, ep, exp)
	return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: lease.String(), Epoch: ep, ExecutionID: eid.String(), ExpiresAt: *exp, Status: core.ToolClaimReclaimed}, e
}

func nullableLeaseID(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
func (s *CoreConversationStore) MarkToolDispatched(ctx context.Context, req, call, lease string, epoch uint64) error {
	res, e := s.pool.Exec(ctx, `UPDATE core_tool_executions SET state='dispatched',updated_at=clock_timestamp() WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND state IN ('claimed')`, req, call, lease, epoch)
	if e == nil && res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	return e
}
func (s *CoreConversationStore) CompleteToolExecution(ctx context.Context, c core.ToolCompletion) (core.ToolResult, error) {
	raw, _ := json.Marshal(c.Result)
	var out core.ToolResult
	e := s.pool.QueryRow(ctx, `UPDATE core_tool_executions SET state='completed',result_json=$6,lease_id=NULL,lease_expires_at=NULL WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND args_digest=$5 AND extension_digest=$7 AND state='dispatched' RETURNING result_json`, c.RequestID, c.ToolCallID, c.LeaseID, c.Epoch, c.ArgsDigest, raw, c.ExtensionDigest).Scan(&raw)
	if e != nil {
		return out, core.ErrConflict
	}
	_ = json.Unmarshal(raw, &out)
	return out, nil
}
func (s *CoreConversationStore) TerminalizeToolUncertain(ctx context.Context, req, call, tlease string, tepoch uint64, please string, pepoch uint64, code, summary string) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	res, e := tx.Exec(ctx, `UPDATE core_tool_executions SET state='uncertain',error_code=$5,error_summary=$6,lease_id=NULL,lease_expires_at=NULL WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND state IN ('dispatched','uncertain')`, req, call, tlease, tepoch, code, summary)
	if e != nil {
		return e
	}
	if res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	res, e = tx.Exec(ctx, `UPDATE core_chat_request_leases SET state='failed',error_code=$4,error_summary=$5,lease_id=NULL,lease_expires_at=NULL WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND state='in_flight'`, req, please, pepoch, code, summary)
	if e == nil && res.RowsAffected() == 0 {
		return core.ErrConflict
	}
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *CoreConversationStore) RenewToolExecution(ctx context.Context, req, call, lease string, epoch uint64, now time.Time, ttl time.Duration) (core.ToolLease, error) {
	x := now.Add(ttl)
	var ep uint64
	var eid uuid.UUID
	e := s.pool.QueryRow(ctx, `UPDATE core_tool_executions SET lease_epoch=lease_epoch+1,epoch=epoch+1,lease_expires_at=$5 WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND state IN ('claimed','dispatched') RETURNING lease_epoch,execution_id`, req, call, lease, epoch, x).Scan(&ep, &eid)
	if e != nil {
		return core.ToolLease{}, core.ErrConflict
	}
	return core.ToolLease{RequestID: req, ToolCallID: call, LeaseID: lease, Epoch: ep, ExecutionID: eid.String(), ExpiresAt: x, Status: core.ToolClaimInFlight}, nil
}
func (s *CoreConversationStore) ReleaseToolExecution(ctx context.Context, req, call, lease string, epoch uint64) error {
	_, e := s.pool.Exec(ctx, `DELETE FROM core_tool_executions WHERE request_id=$1 AND tool_call_id=$2 AND lease_id=$3 AND epoch=$4 AND state='claimed'`, req, call, lease, epoch)
	return e
}

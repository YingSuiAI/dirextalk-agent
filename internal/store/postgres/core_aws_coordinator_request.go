package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreAWSChangeCoordinator struct {
	store *Store
	now   func() time.Time
}

func bindingEmpty(b coreconfirmation.Binding) bool {
	return b.TargetID == "" && b.OperationDomain == ""
}

func NewCoreAWSChangeCoordinator(s *Store, now func() time.Time) *CoreAWSChangeCoordinator {
	if now == nil {
		now = time.Now
	}
	return &CoreAWSChangeCoordinator{store: s, now: now}
}
func awsBinding(p coreaws.Plan, cred coreaws.Credentials) coreconfirmation.Binding {
	return coreaws.BindingForPlan(p, cred)
}
func (c *CoreAWSChangeCoordinator) RequestChange(ctx context.Context, in coreaws.RequestChangeInput) (coreaws.ChangeRequestResult, error) {
	if _, e := uuid.Parse(in.PlanID); e != nil || in.Scope.Validate() != nil {
		return coreaws.ChangeRequestResult{}, coreaws.ErrInvalid
	}
	p, e := NewCoreAWSStore(c.store).GetPlanScoped(ctx, in.Scope, in.PlanID)
	if e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	cred, e := NewCoreAWSStore(c.store).GetCredentialScoped(ctx, in.Scope, p.CredentialID)
	if e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	if cred.VerifiedRevision != cred.Revision || cred.AccountID == "" || cred.UserARN == "" || cred.Region != p.Region {
		return coreaws.ChangeRequestResult{}, coreaws.ErrConflict
	}
	b, e := awsBinding(p, cred).Normalize()
	if e != nil {
		return coreaws.ChangeRequestResult{}, coreaws.ErrInvalid
	}
	now := c.now().UTC()
	tx, e := c.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, fmt.Sprintf("core_aws:request_change:%d:%s:%s", in.Scope.AccountGeneration, in.Scope.OwnerID, in.IdempotencyKey)); e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	reqHash := sha256.Sum256([]byte(in.Scope.OwnerID + ":" + fmt.Sprint(in.Scope.AccountGeneration) + ":" + in.PlanID + ":" + in.IdempotencyKey + ":" + b.TargetID + ":" + fmt.Sprint(b.TargetRevision)))
	reqHashHex := hex.EncodeToString(reqHash[:])
	var replayRaw []byte
	var storedHash string
	var hashVersion int
	if e = tx.QueryRow(ctx, `SELECT request_hash,hash_version,response_json FROM core_aws_change_request_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 FOR UPDATE`, in.Scope.OwnerID, in.Scope.AccountGeneration, in.IdempotencyKey).Scan(&storedHash, &hashVersion, &replayRaw); e == nil {
		var out coreaws.ChangeRequestResult
		if json.Unmarshal(replayRaw, &out) != nil {
			return coreaws.ChangeRequestResult{}, coreaws.ErrIdempotencyConflict
		}
		switch hashVersion {
		case 2:
			if storedHash != reqHashHex {
				return coreaws.ChangeRequestResult{}, coreaws.ErrIdempotencyConflict
			}
		case 1:
			legacyHash := sha256.Sum256([]byte(in.PlanID + ":" + in.IdempotencyKey + ":" + b.TargetID + ":" + fmt.Sprint(b.TargetRevision)))
			if storedHash != hex.EncodeToString(legacyHash[:]) {
				return coreaws.ChangeRequestResult{}, coreaws.ErrIdempotencyConflict
			}
			matches, matchErr := legacyAWSRequestReplayMatchesTx(ctx, tx, in, b, out)
			if matchErr != nil {
				return coreaws.ChangeRequestResult{}, matchErr
			}
			if !matches {
				return coreaws.ChangeRequestResult{}, coreaws.ErrIdempotencyConflict
			}
			tag, updateErr := tx.Exec(ctx, `UPDATE core_aws_change_request_replays SET request_hash=$4,hash_version=2 WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 AND request_hash=$5 AND hash_version=1`, in.Scope.OwnerID, in.Scope.AccountGeneration, in.IdempotencyKey, reqHashHex, storedHash)
			if updateErr != nil {
				return coreaws.ChangeRequestResult{}, updateErr
			}
			if tag.RowsAffected() != 1 {
				return coreaws.ChangeRequestResult{}, coreaws.ErrIdempotencyConflict
			}
			if e = tx.Commit(ctx); e != nil {
				return coreaws.ChangeRequestResult{}, e
			}
		default:
			return coreaws.ChangeRequestResult{}, coreaws.ErrIdempotencyConflict
		}
		return out, nil
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return coreaws.ChangeRequestResult{}, e
	}
	tid, cid, chid := uuid.New(), uuid.New(), uuid.New()
	raw, _ := json.Marshal(b)
	payload, _ := json.Marshal(map[string]any{"aws_change": map[string]string{"change_id": chid.String()}})
	_, e = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,$2,NULL,$3,'aws_change',$4,'waiting_user',1,$5,$5,$5)`, tid, "AWS change", in.IdempotencyKey, payload, now)
	if e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	if e = setTaskOwnerScopeTx(ctx, tx, tid.String(), coretask.OwnerScope{OwnerID: in.Scope.OwnerID, AccountGeneration: in.Scope.AccountGeneration}); e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',1,$7,$7,$8)`, cid, b.OperationDomain, b.TargetID, b.TargetRevision, raw, tid, now, now.Add(24*time.Hour))
	if e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json) VALUES($1,$2)`, cid, raw); e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(operation_domain,target_id) DO UPDATE SET target_revision=EXCLUDED.target_revision,binding_json=EXCLUDED.binding_json,updated_at=EXCLUDED.updated_at`, b.OperationDomain, b.TargetID, b.TargetRevision, raw, now)
	if e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	ch := coreaws.Change{ID: chid.String(), PlanID: p.ID, CredentialID: cred.ID, TaskID: tid.String(), ConfirmationID: cid.String(), Operation: p.Operation, Status: coreaws.ChangeWaitingUser, Stage: coreaws.StageRequested, Revision: 1, ProviderToken: cid.String(), CreatedAt: now, UpdatedAt: now}
	ch.ProviderRequestDigest = coreaws.ProviderRequestDigest(p, cid.String())
	_, e = tx.Exec(ctx, `INSERT INTO core_aws_changes(change_id,plan_id,credential_id,task_id,confirmation_id,operation,status,stage,provider_token,provider_request_digest,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, chid, p.ID, cred.ID, tid, cid, p.Operation, ch.Status, ch.Stage, cid.String(), ch.ProviderRequestDigest, 1, now)
	if e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	if e = appendAWSAndTaskEvent(ctx, tx, chid.String(), tid.String(), "requested", 1, 0, "waiting_user", now); e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	out := coreaws.ChangeRequestResult{Change: ch, Task: coreaws.Task{ID: tid.String(), Status: "waiting_user", Revision: 1, PlanID: p.ID, ConfirmationID: cid.String()}, Confirmation: coreconfirmation.Confirmation{ConfirmationID: cid.String(), Binding: b, TaskID: tid.String(), State: coreconfirmation.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}}
	snap, _ := json.Marshal(out)
	_, e = tx.Exec(ctx, `INSERT INTO core_aws_change_request_replays(owner_id,account_generation,idempotency_key,request_hash,hash_version,response_json) VALUES($1,$2,$3,$4,2,$5)`, in.Scope.OwnerID, in.Scope.AccountGeneration, in.IdempotencyKey, reqHashHex, snap)
	if e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.ChangeRequestResult{}, e
	}
	return out, nil
}

func legacyAWSRequestReplayMatchesTx(ctx context.Context, tx pgx.Tx, in coreaws.RequestChangeInput, binding coreconfirmation.Binding, out coreaws.ChangeRequestResult) (bool, error) {
	if out.Change.ID == "" || out.Change.PlanID != in.PlanID || out.Change.TaskID != out.Task.ID || out.Change.ConfirmationID != out.Confirmation.ConfirmationID ||
		out.Change.CredentialID == "" || out.Task.PlanID != in.PlanID || out.Task.ConfirmationID != out.Confirmation.ConfirmationID || out.Confirmation.TaskID != out.Task.ID {
		return false, nil
	}
	replayBinding, err := out.Confirmation.Binding.Normalize()
	if err != nil || replayBinding.OperationDomain != "aws" || replayBinding.TargetID != binding.TargetID || replayBinding.TargetRevision != binding.TargetRevision {
		return false, nil
	}
	var marker int
	var confirmationBindingRaw, targetBindingRaw []byte
	err = tx.QueryRow(ctx, `
		SELECT 1,confirmation.binding_json,target_binding.binding_json
		FROM core_aws_changes change
		JOIN core_aws_plans plan ON plan.plan_id=change.plan_id AND plan.credential_id=change.credential_id
		JOIN core_aws_credentials credential ON credential.credential_id=change.credential_id AND credential.owner_id=plan.owner_id AND credential.account_generation=plan.account_generation
		JOIN core_tasks task ON task.task_id=change.task_id
		JOIN core_task_scopes scope ON scope.task_id=task.task_id AND scope.owner_id=plan.owner_id AND scope.account_generation=plan.account_generation
		JOIN core_confirmations confirmation ON confirmation.confirmation_id=change.confirmation_id AND confirmation.task_id=task.task_id
		JOIN core_confirmation_target_bindings target_binding ON target_binding.confirmation_id=confirmation.confirmation_id
		WHERE change.change_id=$1 AND change.plan_id=$2 AND change.credential_id=$3
		  AND change.task_id=$4 AND change.confirmation_id=$5
		  AND plan.owner_id=$6 AND plan.account_generation=$7
		  AND confirmation.operation_domain=$8 AND confirmation.target_id=$9 AND confirmation.target_revision=$10
		FOR UPDATE OF change,plan,credential,task,scope,confirmation,target_binding`,
		out.Change.ID, in.PlanID, out.Change.CredentialID, out.Task.ID, out.Confirmation.ConfirmationID,
		in.Scope.OwnerID, in.Scope.AccountGeneration, replayBinding.OperationDomain, replayBinding.TargetID, replayBinding.TargetRevision).Scan(&marker, &confirmationBindingRaw, &targetBindingRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil || marker != 1 {
		return false, err
	}
	var storedConfirmationBinding, storedTargetBinding coreconfirmation.Binding
	if json.Unmarshal(confirmationBindingRaw, &storedConfirmationBinding) != nil || json.Unmarshal(targetBindingRaw, &storedTargetBinding) != nil ||
		!storedConfirmationBinding.Equal(replayBinding) || !storedTargetBinding.Equal(replayBinding) {
		return false, nil
	}
	return true, nil
}
func (c *CoreAWSChangeCoordinator) ConsumeChange(ctx context.Context, cmd coreaws.ConsumeChangeCommand) (coreaws.Reservation, error) {
	tx, e := c.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.Reservation{}, e
	}
	defer tx.Rollback(ctx)
	reqHash := sha256.Sum256([]byte(fmt.Sprintf("%+v", cmd)))
	var replayRaw []byte
	if e = tx.QueryRow(ctx, `SELECT response_json FROM core_aws_replays WHERE operation='consume_change' AND idempotency_key=$1 AND request_hash=$2`, cmd.IdempotencyKey, hex.EncodeToString(reqHash[:])).Scan(&replayRaw); e == nil {
		var out coreaws.Reservation
		if json.Unmarshal(replayRaw, &out) == nil {
			if !out.Active || out.TaskID != cmd.TaskID || out.Attempt != cmd.Attempt || out.LeaseEpoch != cmd.LeaseEpoch || out.TaskRevision != cmd.ExpectedTaskRevision {
				return coreaws.Reservation{}, coreaws.ErrRevisionConflict
			}
			return out, nil
		}
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return coreaws.Reservation{}, e
	}
	if errors.Is(e, pgx.ErrNoRows) {
		var old string
		if qe := tx.QueryRow(ctx, `SELECT request_hash FROM core_aws_replays WHERE operation='consume_change' AND idempotency_key=$1`, cmd.IdempotencyKey).Scan(&old); qe == nil && old != hex.EncodeToString(reqHash[:]) {
			return coreaws.Reservation{}, coreaws.ErrIdempotencyConflict
		}
	}
	var st string
	var rev int64
	var taskID, confID string
	if e = tx.QueryRow(ctx, `SELECT status,revision,task_id::text,confirmation_id::text FROM core_aws_changes WHERE change_id=$1 FOR UPDATE`, cmd.ChangeID).Scan(&st, &rev, &taskID, &confID); e != nil {
		return coreaws.Reservation{}, coreaws.ErrNotFound
	}
	if rev != cmd.ExpectedChangeRevision || taskID != cmd.TaskID || confID != cmd.ConfirmationID {
		return coreaws.Reservation{}, coreaws.ErrRevisionConflict
	}
	var ts string
	var att uint32
	var lease uint64
	var tr int64
	var taskLeaseExpires *time.Time
	if e = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,revision,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cmd.TaskID).Scan(&ts, &att, &lease, &tr, &taskLeaseExpires); e != nil {
		return coreaws.Reservation{}, coreaws.ErrConflict
	}
	claimed := ts == "running"
	if claimed {
		if att != cmd.Attempt || lease != cmd.LeaseEpoch || tr != cmd.ExpectedTaskRevision || taskLeaseExpires == nil || !taskLeaseExpires.After(c.now().UTC()) {
			return coreaws.Reservation{}, coreaws.ErrRevisionConflict
		}
	} else if (ts != "waiting_user" && ts != "queued") || tr != cmd.ExpectedTaskRevision {
		return coreaws.Reservation{}, coreaws.ErrConflict
	}
	var planID, ownerID, credentialID, region, stack, account, user, templateSHA, operation string
	var accountGeneration int64
	now := c.now().UTC()
	var template, parametersRaw, tagsRaw, capabilitiesRaw []byte
	var planRev, verified, credRevision int64
	if e = tx.QueryRow(ctx, `SELECT p.plan_id::text,p.owner_id,p.account_generation,p.credential_id::text,p.region,p.stack_name,p.operation,p.template,p.template_sha256,p.parameters_json,p.tags_json,p.capabilities_json,p.revision,c.account_id,c.user_arn,c.revision,c.verified_revision FROM core_aws_changes x JOIN core_aws_plans p ON p.plan_id=x.plan_id JOIN core_aws_credentials c ON c.credential_id=x.credential_id AND c.owner_id=p.owner_id AND c.account_generation=p.account_generation WHERE x.change_id=$1 FOR UPDATE`, cmd.ChangeID).Scan(&planID, &ownerID, &accountGeneration, &credentialID, &region, &stack, &operation, &template, &templateSHA, &parametersRaw, &tagsRaw, &capabilitiesRaw, &planRev, &account, &user, &credRevision, &verified); e != nil {
		return coreaws.Reservation{}, e
	}
	cred, e := NewCoreAWSStore(c.store).scanCredentialRow(tx.QueryRow(ctx, `SELECT credential_id::text,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at FROM core_aws_credentials WHERE credential_id=$1 AND owner_id=$2 AND account_generation=$3 FOR UPDATE`, credentialID, ownerID, accountGeneration))
	if e != nil {
		return coreaws.Reservation{}, e
	}
	var parameters, tags map[string]string
	var capabilities []string
	_ = json.Unmarshal(parametersRaw, &parameters)
	_ = json.Unmarshal(tagsRaw, &tags)
	_ = json.Unmarshal(capabilitiesRaw, &capabilities)
	plan := coreaws.Plan{ID: planID, OwnerID: ownerID, AccountGeneration: accountGeneration, CredentialID: credentialID, Region: region, StackName: stack, Operation: coreaws.Operation(operation), Template: template, TemplateSHA256: templateSHA, Parameters: parameters, Tags: tags, Capabilities: capabilities, Revision: planRev}
	wantBinding, _ := coreaws.BindingForPlan(plan, cred).Normalize()
	storedBinding, _ := cmd.Binding.Normalize()
	if verified != credRevision || account == "" || user == "" || !storedBinding.Equal(wantBinding) {
		now := c.now().UTC()
		_, _ = tx.Exec(ctx, `UPDATE core_confirmations SET state='expired',revision=revision+1,terminal_code='confirmation_stale',terminal_reason='confirmation_stale',updated_at=$2 WHERE confirmation_id=$1 AND revision=$3`, cmd.ConfirmationID, now, cmd.ExpectedConfirmationRevision)
		_, _ = tx.Exec(ctx, `UPDATE core_tasks SET status='failed',failure_code='confirmation_stale',failure_summary='AWS confirmation binding is stale',lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$2 WHERE task_id=$1 AND revision=$3 AND status IN ('running','queued','waiting_user')`, cmd.TaskID, now, cmd.ExpectedTaskRevision)
		_, _ = tx.Exec(ctx, `UPDATE core_aws_changes SET status='failed',stage='failed',error_code='confirmation_stale',error_summary='AWS confirmation binding is stale',revision=revision+1,updated_at=$2 WHERE change_id=$1 AND revision=$3`, cmd.ChangeID, now, cmd.ExpectedChangeRevision)
		if e = tx.Commit(ctx); e != nil {
			return coreaws.Reservation{}, e
		}
		return coreaws.Reservation{}, coreaws.ErrConflict
	}
	var cs string
	var cr int64
	var expires time.Time
	if e = tx.QueryRow(ctx, `SELECT state,revision,expires_at FROM core_confirmations WHERE confirmation_id=$1 FOR UPDATE`, cmd.ConfirmationID).Scan(&cs, &cr, &expires); e != nil || cr != cmd.ExpectedConfirmationRevision {
		return coreaws.Reservation{}, coreaws.ErrUnconfirmed
	}
	if cs == "consumed" {
		var active bool
		var rat uint32
		var rep uint64
		var rrev int64
		var oldLeaseExpires time.Time
		rerr := tx.QueryRow(ctx, `SELECT active,acquired_attempt,acquired_lease_epoch,task_revision,acquired_lease_expires_at FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, cmd.ConfirmationID).Scan(&active, &rat, &rep, &rrev, &oldLeaseExpires)
		if rerr == nil && active && rat == cmd.Attempt && rep == cmd.LeaseEpoch && rrev == cmd.ExpectedTaskRevision {
			out := coreaws.Reservation{ConfirmationID: cmd.ConfirmationID, TaskID: cmd.TaskID, Attempt: rat, LeaseEpoch: rep, TaskRevision: rrev, Active: true}
			return out, nil
		}
		// A reclaimed generic task may continue an already-consumed request only
		// after the former reservation's recorded lease expired.  This keeps the
		// provider token/digest intact and prevents a live worker from being
		// fenced out or a known mutation from being issued a second time.
		if rerr == nil && active && !oldLeaseExpires.After(now) && ts == "running" && taskLeaseExpires != nil && taskLeaseExpires.After(now) && att == cmd.Attempt && lease == cmd.LeaseEpoch && tr == cmd.ExpectedTaskRevision && (rat != cmd.Attempt || rep != cmd.LeaseEpoch || rrev != cmd.ExpectedTaskRevision) {
			tag, pe := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET acquired_attempt=$2,acquired_lease_epoch=$3,task_revision=$4,acquired_lease_expires_at=$5 WHERE confirmation_id=$1 AND active=true AND acquired_attempt=$6 AND acquired_lease_epoch=$7 AND task_revision=$8 AND acquired_lease_expires_at=$9`, cmd.ConfirmationID, cmd.Attempt, cmd.LeaseEpoch, cmd.ExpectedTaskRevision, *taskLeaseExpires, rat, rep, rrev, oldLeaseExpires)
			if pe != nil {
				return coreaws.Reservation{}, pe
			}
			if tag.RowsAffected() != 1 {
				return coreaws.Reservation{}, coreaws.ErrRevisionConflict
			}
			out := coreaws.Reservation{ConfirmationID: cmd.ConfirmationID, TaskID: cmd.TaskID, Attempt: cmd.Attempt, LeaseEpoch: cmd.LeaseEpoch, TaskRevision: cmd.ExpectedTaskRevision, Active: true}
			snap, _ := json.Marshal(out)
			if _, pe = tx.Exec(ctx, `INSERT INTO core_aws_replays(operation,idempotency_key,request_hash,response_json) VALUES('consume_change',$1,$2,$3)`, cmd.IdempotencyKey, hex.EncodeToString(reqHash[:]), snap); pe != nil {
				return coreaws.Reservation{}, pe
			}
			if pe = tx.Commit(ctx); pe != nil {
				return coreaws.Reservation{}, pe
			}
			return out, nil
		}
		return coreaws.Reservation{}, coreaws.ErrRevisionConflict
	}
	if cs != "confirmed" || !expires.After(now) {
		_, _ = tx.Exec(ctx, `UPDATE core_confirmations SET state='expired',revision=revision+1,terminal_code='confirmation_expired',terminal_reason='confirmation_expired',updated_at=$2 WHERE confirmation_id=$1`, cmd.ConfirmationID, now)
		code, summary := "confirmation_expired", "AWS confirmation expired"
		if cs != "confirmed" {
			code, summary = "confirmation_unconfirmed", "AWS confirmation is not confirmed"
		}
		_, _ = tx.Exec(ctx, `UPDATE core_tasks SET status='failed',attempt=GREATEST(attempt,1),failure_code=$2,failure_summary=$3,lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$4 WHERE task_id=$1 AND status='running' AND attempt=$5 AND lease_epoch=$6 AND revision=$7`, cmd.TaskID, code, summary, now, cmd.Attempt, cmd.LeaseEpoch, cmd.ExpectedTaskRevision)
		_, _ = tx.Exec(ctx, `UPDATE core_aws_changes SET status='failed',stage='failed',error_code=$2,error_summary=$3,revision=revision+1,updated_at=$4 WHERE change_id=$1 AND revision=$5`, cmd.ChangeID, code, summary, now, cmd.ExpectedChangeRevision)
		_, _ = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1`, cmd.ConfirmationID)
		if e = tx.Commit(ctx); e != nil {
			return coreaws.Reservation{}, e
		}
		return coreaws.Reservation{}, coreaws.ErrConflict
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmations SET state='consumed',revision=revision+1,updated_at=$2 WHERE confirmation_id=$1`, cmd.ConfirmationID, now); e != nil {
		return coreaws.Reservation{}, e
	}
	if !claimed {
		newExpiry := now.Add(time.Hour)
		if _, e = tx.Exec(ctx, `UPDATE core_tasks SET status='running',attempt=$2,lease_epoch=$3,lease_holder='coreaws',lease_expires_at=$4,revision=revision+1,updated_at=$5 WHERE task_id=$1 AND revision=$6 AND status IN ('waiting_user','queued')`, cmd.TaskID, cmd.Attempt, cmd.LeaseEpoch, newExpiry, now, cmd.ExpectedTaskRevision); e != nil {
			return coreaws.Reservation{}, e
		}
		taskLeaseExpires = &newExpiry
		tr++
	}
	if taskLeaseExpires == nil {
		return coreaws.Reservation{}, coreaws.ErrRevisionConflict
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_confirmation_reservations(confirmation_id,task_id,acquired_attempt,acquired_lease_epoch,task_revision,acquired_lease_expires_at,active) VALUES($1,$2,$3,$4,$5,$6,true) ON CONFLICT(confirmation_id) DO UPDATE SET active=true,acquired_attempt=EXCLUDED.acquired_attempt,acquired_lease_epoch=EXCLUDED.acquired_lease_epoch,task_revision=EXCLUDED.task_revision,acquired_lease_expires_at=EXCLUDED.acquired_lease_expires_at`, cmd.ConfirmationID, cmd.TaskID, cmd.Attempt, cmd.LeaseEpoch, tr, *taskLeaseExpires); e != nil {
		return coreaws.Reservation{}, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_aws_changes SET status='running',stage='change_set_creating',revision=revision+1,updated_at=$2 WHERE change_id=$1`, cmd.ChangeID, now); e != nil {
		return coreaws.Reservation{}, e
	}
	if e = appendAWSAndTaskEvent(ctx, tx, cmd.ChangeID, cmd.TaskID, "consumed", rev+1, cmd.Attempt, "running", now); e != nil {
		return coreaws.Reservation{}, e
	}
	out := coreaws.Reservation{ConfirmationID: cmd.ConfirmationID, TaskID: cmd.TaskID, Attempt: cmd.Attempt, LeaseEpoch: cmd.LeaseEpoch, TaskRevision: tr, Active: true}
	snap, _ := json.Marshal(out)
	if _, e = tx.Exec(ctx, `INSERT INTO core_aws_replays(operation,idempotency_key,request_hash,response_json) VALUES('consume_change',$1,$2,$3)`, cmd.IdempotencyKey, hex.EncodeToString(reqHash[:]), snap); e != nil {
		return coreaws.Reservation{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.Reservation{}, e
	}
	return out, nil
}

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *CoreExtensionStore) CreateMutation(ctx context.Context, m coreextension.Mutation) (coreextension.MutationResult, error) {
	if m.Candidate.Validate() != nil || m.Inspection.Validate() != nil || m.Candidate.ID != m.Inspection.Candidate.ID || uuid.Validate(m.IdempotencyKey) != nil {
		return coreextension.MutationResult{}, coreextension.ErrInvalid
	}
	if err := validateSecretInputsPG(m); err != nil {
		return coreextension.MutationResult{}, err
	}
	now := time.Now().UTC()
	vid := uuid.New()
	iid := uuid.New()
	v := versionFromInspectionPG(m.Inspection, vid, now, m)
	i := coreextension.Installation{ID: iid.String(), Candidate: m.Candidate, Kind: m.Candidate.Kind, Source: m.Candidate.Source, CandidateID: m.Candidate.ID, Name: m.Candidate.Name, Description: m.Candidate.Description, Transport: m.Candidate.Transport, Revision: 1, State: coreextension.StateInstalling, ProposedVersionID: vid.String(), Versions: []coreextension.VersionRecord{v}, CreatedAt: now, UpdatedAt: now, SecretGrants: configuredGrants(m.Inspection.SecretGrants), NetworkGrants: m.Inspection.NetworkGrants}
	out, err := s.request(ctx, m.IdempotencyKey, coreextension.OperationInstall, i, m)
	if err != nil {
		return out, fmt.Errorf("create extension request: %w", err)
	}
	return out, nil
}
func (s *CoreExtensionStore) UpdateMutation(ctx context.Context, m coreextension.Mutation, state coreextension.State) (coreextension.MutationResult, error) {
	if uuid.Validate(m.InstallationID) != nil || m.ExpectedRevision < 1 {
		return coreextension.MutationResult{}, coreextension.ErrInvalid
	}
	cur, e := s.Get(ctx, m.InstallationID)
	if e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("insert extension installation: %w", e)
	}
	if cur.Revision != m.ExpectedRevision {
		return coreextension.MutationResult{}, coreextension.ErrRevisionConflict
	}
	if state == coreextension.StateUpdating {
		if err := validateSecretInputsPG(m); err != nil {
			return coreextension.MutationResult{}, err
		}
		v := versionFromInspectionPG(m.Inspection, uuid.New(), time.Now().UTC(), m)
		cur.Versions = append(cur.Versions, v)
		cur.ProposedVersionID = v.VersionID
		cur.Candidate = m.Candidate
		cur.NetworkGrants = m.Inspection.NetworkGrants
		cur.SecretGrants = configuredGrants(m.Inspection.SecretGrants)
	}
	cur.Revision++
	cur.State = state
	cur.UpdatedAt = time.Now().UTC()
	return s.request(ctx, m.IdempotencyKey, opForPG(state), cur, m)
}
func (s *CoreExtensionStore) RemoveMutation(ctx context.Context, m coreextension.Mutation) (coreextension.MutationResult, error) {
	if uuid.Validate(m.InstallationID) != nil {
		return coreextension.MutationResult{}, coreextension.ErrInvalid
	}
	current, err := s.Get(ctx, m.InstallationID)
	if err != nil {
		return coreextension.MutationResult{}, err
	}
	if current.ActiveVersionID != "" {
		for _, v := range current.Versions {
			if v.VersionID == current.ActiveVersionID && s.hasPinnedVersion(ctx, current.ID, v.VersionID, v.ArtifactDigest) {
				return coreextension.MutationResult{}, coreextension.ErrConflict
			}
		}
	}
	return s.UpdateMutation(ctx, m, coreextension.StateUninstalling)
}

func (s *CoreExtensionStore) hasPinnedVersion(ctx context.Context, installationID, versionID, artifactDigest string) bool {
	rows, err := s.store.pool.Query(ctx, `SELECT s.snapshot_json FROM core_task_execution_snapshots s JOIN core_tasks t ON t.task_id=s.task_id WHERE t.deleted_at IS NULL`)
	if err != nil {
		return true
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			return true
		}
		var snapshot coretask.ExecutionSnapshot
		if json.Unmarshal(raw, &snapshot) != nil {
			return true
		}
		for _, ext := range snapshot.Extensions {
			if ext.InstallationID == installationID && ext.VersionID == versionID && (artifactDigest == "" || ext.ArtifactDigest == artifactDigest) {
				return true
			}
		}
	}
	return rows.Err() != nil
}

func (s *CoreExtensionStore) request(ctx context.Context, key, op string, i coreextension.Installation, m coreextension.Mutation) (coreextension.MutationResult, error) {
	d := digestPG(m, op)
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("insert extension installation: %w", e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `core_extension:`+key); e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("extension advisory lock: %w", e)
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `core_extension_installation:`+i.ID); e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("extension installation advisory lock: %w", e)
	}
	var hash string
	var raw []byte
	e = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_extension_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, op, key).Scan(&hash, &raw)
	if e == nil {
		if hash != d {
			return coreextension.MutationResult{}, coreextension.ErrIdempotencyConflict
		}
		var out coreextension.MutationResult
		_ = json.Unmarshal(raw, &out)
		_ = tx.Commit(ctx)
		return out, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) && !strings.Contains(strings.ToLower(e.Error()), "no rows") {
		return coreextension.MutationResult{}, fmt.Errorf("extension replay lookup: %w", e)
	}
	e = nil
	var activeLifecycle bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_extension_lifecycles WHERE installation_id=$1 AND state NOT IN ('succeeded','failed','canceled','expired'))`, i.ID).Scan(&activeLifecycle); e != nil {
		return coreextension.MutationResult{}, e
	}
	if activeLifecycle {
		return coreextension.MutationResult{}, coreextension.ErrConflict
	}
	var activeUncertainReservation bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1
		FROM core_confirmations c
		JOIN core_confirmation_reservations r ON r.confirmation_id = c.confirmation_id
		WHERE c.target_id=$1 AND c.operation_domain='extension.execute'
		  AND c.state='consumed' AND c.consumed_released=false AND r.active=true
	)`, i.ID).Scan(&activeUncertainReservation); e != nil {
		return coreextension.MutationResult{}, e
	}
	if activeUncertainReservation {
		return coreextension.MutationResult{}, coreextension.ErrConflict
	}
	var previousCandidate, previousNetwork, previousSecrets []byte
	var previousKind, previousSource, previousCandidateID, previousName, previousDescription, previousTransport string
	_ = tx.QueryRow(ctx, `SELECT candidate_json,kind,source,candidate_id,name,description,transport,network_grants_json,secret_grants_json FROM core_extension_installations WHERE installation_id=$1 FOR UPDATE`, i.ID).Scan(&previousCandidate, &previousKind, &previousSource, &previousCandidateID, &previousName, &previousDescription, &previousTransport, &previousNetwork, &previousSecrets)
	if op == coreextension.OperationInstall {
		previousCandidate = nil
		previousKind, previousSource, previousCandidateID, previousName, previousDescription, previousTransport = "", "", "", "", "", ""
		previousNetwork, previousSecrets = []byte(`[]`), []byte(`[]`)
	}
	b := coreextension.LifecycleRequest{}
	taskID := uuid.New()
	binding := bindingPG(i, m)
	expires := time.Now().UTC().Add(time.Hour)
	cmd := coreconfirmation.RequestCommand{IdempotencyKey: key, TaskID: taskID.String(), Binding: binding, ExpiresAt: expires}
	cmd.RequestDigest = coreconfirmation.Digest(digestPG(cmd, "request"))
	b.Installation = i
	b.Task = coreextension.TaskRequest{IdempotencyKey: key, TaskID: taskID.String(), Goal: "extension " + op, TargetID: i.ID, ExpectedRevision: i.Revision}
	b.Confirmation = cmd
	b.Operation = op
	candRaw, _ := json.Marshal(i.Candidate)
	ngRaw, _ := json.Marshal(i.NetworkGrants)
	sgRaw, _ := json.Marshal(i.SecretGrants)
	var inserted bool
	if tag, ee := tx.Exec(ctx, `INSERT INTO core_extension_installations(installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,active_version_id,proposed_version_id,network_grants_json,secret_grants_json,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,'')::uuid,NULLIF($13,'')::uuid,$14,$15,$16,$16) ON CONFLICT (installation_id) DO NOTHING`, i.ID, candRaw, string(i.Kind), string(i.Source), i.CandidateID, i.Name, i.Description, string(i.Transport), i.Revision, string(i.State), i.Enabled, i.ActiveVersionID, i.ProposedVersionID, ngRaw, sgRaw, i.CreatedAt); ee != nil {
		e = ee
	} else {
		inserted = tag.RowsAffected() == 1
	}
	if e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("extension installation insert: %w", e)
	}
	if !inserted {
		var currentRev int64
		if e = tx.QueryRow(ctx, `SELECT revision FROM core_extension_installations WHERE installation_id=$1 FOR UPDATE`, i.ID).Scan(&currentRev); e != nil {
			return coreextension.MutationResult{}, fmt.Errorf("extension installation lock: %w", e)
		}
		if currentRev+1 != i.Revision {
			return coreextension.MutationResult{}, coreextension.ErrRevisionConflict
		}
		if _, e = tx.Exec(ctx, `UPDATE core_extension_installations SET candidate_json=$2,kind=$3,source=$4,candidate_id=$5,name=$6,description=$7,transport=$8,state=$9,revision=$10,proposed_version_id=NULLIF($11,'')::uuid,network_grants_json=$12,secret_grants_json=$13,updated_at=$14 WHERE installation_id=$1 AND revision=$15`, i.ID, candRaw, string(i.Kind), string(i.Source), i.CandidateID, i.Name, i.Description, string(i.Transport), string(i.State), i.Revision, i.ProposedVersionID, ngRaw, sgRaw, i.UpdatedAt, currentRev); e != nil {
			return coreextension.MutationResult{}, e
		}
	}
	for _, v := range i.Versions {
		vr, _ := json.Marshal(v)
		if _, e = tx.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(version_id) DO NOTHING`, v.VersionID, i.ID, vr, v.CreatedAt); e != nil {
			return coreextension.MutationResult{}, fmt.Errorf("insert extension version: %w", e)
		}
	}
	// Secret material is staged with the lifecycle proposal. It becomes
	// usable only when CompleteLifecycle commits the successful promotion.
	for _, secret := range m.SecretInputs {
		if _, e = tx.Exec(ctx, `INSERT INTO core_extension_secret_receipts(reference_id,purpose,fingerprint) VALUES($1,$2,$3) ON CONFLICT(reference_id,purpose) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,updated_at=clock_timestamp()`, secret.ReferenceID, string(secret.Purpose), secret.Fingerprint()); e != nil {
			return coreextension.MutationResult{}, fmt.Errorf("stage extension secret receipt: %w", e)
		}
		plaintext := []byte(secret.Value)
		envelope, sealErr := s.store.sealDurableSecret("core_extension_secret_revisions", i.ID+"/"+i.ProposedVersionID+"/"+secret.ReferenceID+"/"+string(secret.Purpose), int64(i.Revision), "secret_value", plaintext)
		for index := range plaintext {
			plaintext[index] = 0
		}
		if sealErr != nil {
			return coreextension.MutationResult{}, sealErr
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_extension_secret_revisions(revision_id,installation_id,version_id,reference_id,purpose,binding_revision,secret_key_version,secret_value_nonce,secret_value_ciphertext,fingerprint,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'staged')`, uuid.New(), i.ID, i.ProposedVersionID, secret.ReferenceID, string(secret.Purpose), i.Revision, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext, secret.Fingerprint()); e != nil {
			return coreextension.MutationResult{}, fmt.Errorf("stage extension secret: %w", e)
		}
	}
	braw, _ := json.Marshal(binding)
	cid := uuid.New()
	versionID, digest := i.ProposedVersionID, m.Inspection.ContentDigest
	if op == coreextension.OperationUninstall {
		versionID = i.ActiveVersionID
		for _, v := range i.Versions {
			if v.VersionID == versionID {
				digest = v.ContentDigest
			}
		}
	}
	payloadObj := coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{Operation: coretask.ExtensionOperation(op), InstallationID: i.ID, ExpectedRevision: uint64(i.Revision), Version: versionID, Digest: digest, ConfirmationID: cid.String()}}
	payload, _ := json.Marshal(payloadObj)
	if _, e = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,available_at,revision,created_at,updated_at) VALUES($1,$2,NULL,$3,'extension',$4,'waiting_user',$5,1,$5,$5)`, taskID, b.Task.Goal, key, payload, time.Now().UTC()); e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("insert extension task: %w", e)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,'extension',$2,$3,$4,$5,'pending',1,$6,$6,$7)`, cid, i.ID, i.Revision, braw, taskID, time.Now().UTC(), expires); e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("insert extension confirmation: %w", e)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json) VALUES($1,$2)`, cid, braw); e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("insert extension target binding: %w", e)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES('extension',$1,$2,$3,$4) ON CONFLICT(operation_domain,target_id) DO UPDATE SET target_revision=EXCLUDED.target_revision,binding_json=EXCLUDED.binding_json,updated_at=EXCLUDED.updated_at`, i.ID, i.Revision, braw, time.Now().UTC()); e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("upsert extension current binding: %w", e)
	}
	lifecycleID := uuid.New()
	if _, e = tx.Exec(ctx, `INSERT INTO core_extension_lifecycles(lifecycle_id,installation_id,operation,confirmation_id,task_id,binding_json,request_hash,expected_revision,previous_candidate_json,previous_kind,previous_source,previous_candidate_id,previous_name,previous_description,previous_transport,previous_network_grants_json,previous_secret_grants_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, lifecycleID, i.ID, op, cid, taskID, braw, d, i.Revision, previousCandidate, previousKind, previousSource, previousCandidateID, previousName, previousDescription, previousTransport, previousNetwork, previousSecrets); e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("insert extension lifecycle: %w", e)
	}
	out := coreextension.MutationResult{Installation: i, ConfirmationID: cid.String(), TaskID: taskID.String()}
	enc, _ := json.Marshal(out)
	if _, e = tx.Exec(ctx, `INSERT INTO core_extension_replays(operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4)`, op, key, d, enc); e != nil {
		return coreextension.MutationResult{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreextension.MutationResult{}, fmt.Errorf("commit extension request: %w", e)
	}
	return out, nil
}

func (s *CoreExtensionStore) RequestLifecycle(context.Context, coreextension.LifecycleRequest) (coreextension.MutationResult, error) {
	return coreextension.MutationResult{}, coreextension.ErrInvalid
}
func (s *CoreExtensionStore) ConfirmLifecycle(ctx context.Context, c coreconfirmation.ConfirmCommand) (coreconfirmation.Confirmation, error) {
	return NewCoreConfirmationStore(s.store).Confirm(ctx, c)
}
func (s *CoreExtensionStore) ConsumeLifecycle(ctx context.Context, c coreconfirmation.ConsumeCommand) (coreconfirmation.Confirmation, error) {
	return NewCoreConfirmationStore(s.store).Consume(ctx, c)
}

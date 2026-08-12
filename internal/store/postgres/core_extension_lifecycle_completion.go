package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *CoreExtensionStore) CompleteLifecycle(ctx context.Context, c coreextension.Completion) (coreextension.Installation, error) {
	return s.completeLifecycle(ctx, c, false)
}

// completeLifecycle records whether the proposed managed Node artifact was
// already promoted by the runner. A failed terminal transition persists the
// exact active-reference cleanup in the same transaction; the external remove
// is never allowed to precede that durable decision.
func (s *CoreExtensionStore) completeLifecycle(ctx context.Context, c coreextension.Completion, artifactPromoted bool) (coreextension.Installation, error) {
	if uuid.Validate(c.InstallationID) != nil || uuid.Validate(c.ConfirmationID) != nil || uuid.Validate(c.TaskID) != nil || c.ExpectedRevision < 1 || c.Attempt == 0 || c.LeaseEpoch == 0 || c.AcquiredTaskRevision < 1 || c.TerminalAttempt == 0 || c.TerminalLeaseEpoch == 0 || c.TerminalTaskRevision < 1 {
		return coreextension.Installation{}, coreextension.ErrInvalid
	}
	if artifactPromoted && c.Success {
		return coreextension.Installation{}, coreextension.ErrInvalid
	}
	if c.Success {
		if c.FailureCode != "" || c.FailureSummary != "" {
			return coreextension.Installation{}, coreextension.ErrInvalid
		}
	} else if c.FailureCode == "" && c.FailureSummary == "" {
		c.FailureCode, c.FailureSummary = coreextension.LifecycleFailureDetails(nil)
	} else if !coreextension.ValidLifecycleFailureDetails(c.FailureCode, c.FailureSummary) {
		return coreextension.Installation{}, coreextension.ErrInvalid
	}
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coreextension.Installation{}, e
	}
	defer tx.Rollback(ctx)
	var hash string
	_ = tx.QueryRow(ctx, `SELECT completion_hash FROM core_extension_lifecycles WHERE installation_id=$1 AND confirmation_id=$2 FOR UPDATE`, c.InstallationID, c.ConfirmationID).Scan(&hash)
	cd := digestPG(c, "completion")
	if hash != "" {
		if hash != cd {
			return coreextension.Installation{}, coreextension.ErrConflict
		}
		return s.getTx(ctx, tx.QueryRow(ctx, `SELECT installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,COALESCE(active_version_id::text,''),COALESCE(proposed_version_id::text,''),network_grants_json,secret_grants_json,created_at,updated_at FROM core_extension_installations WHERE installation_id=$1`, c.InstallationID))
	}
	var op, confirm, task, state string
	var expected int64
	var bind []byte
	if e = tx.QueryRow(ctx, `SELECT operation,confirmation_id::text,task_id::text,binding_json,expected_revision,state FROM core_extension_lifecycles WHERE installation_id=$1 AND confirmation_id=$2 FOR UPDATE`, c.InstallationID, c.ConfirmationID).Scan(&op, &confirm, &task, &bind, &expected, &state); e != nil {
		return coreextension.Installation{}, coreextension.ErrNotFound
	}
	if op != c.Operation || confirm != c.ConfirmationID || task != c.TaskID || expected != c.ExpectedRevision {
		return coreextension.Installation{}, coreextension.ErrConflict
	}
	var rev int64
	var proposed, active string
	if e = tx.QueryRow(ctx, `SELECT revision,COALESCE(proposed_version_id::text,''),COALESCE(active_version_id::text,'') FROM core_extension_installations WHERE installation_id=$1 FOR UPDATE`, c.InstallationID).Scan(&rev, &proposed, &active); e != nil {
		return coreextension.Installation{}, coreextension.ErrNotFound
	}
	if rev != c.ExpectedRevision {
		return coreextension.Installation{}, coreextension.ErrRevisionConflict
	}
	var st string
	var attempt int
	var lease int64
	var taskrev int64
	if e = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,revision FROM core_tasks WHERE task_id=$1 FOR UPDATE`, c.TaskID).Scan(&st, &attempt, &lease, &taskrev); e != nil {
		return coreextension.Installation{}, coreextension.ErrConflict
	}
	if st != "running" || uint32(attempt) != c.Attempt || uint64(lease) != c.LeaseEpoch || taskrev != c.AcquiredTaskRevision {
		return coreextension.Installation{}, coreextension.ErrConflict
	}
	if c.TerminalAttempt != c.Attempt || c.TerminalLeaseEpoch != c.LeaseEpoch || c.TerminalTaskRevision != taskrev+1 {
		return coreextension.Installation{}, coreextension.ErrConflict
	}
	var cstate string
	var rtask string
	var rattempt int
	var rlease int64
	var activeRes bool
	if e = tx.QueryRow(ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, c.ConfirmationID, c.TaskID).Scan(&cstate); e != nil || cstate != "consumed" {
		return coreextension.Installation{}, coreextension.ErrConflict
	}
	if e = tx.QueryRow(ctx, `SELECT task_id::text,acquired_attempt,acquired_lease_epoch,active FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, c.ConfirmationID).Scan(&rtask, &rattempt, &rlease, &activeRes); e != nil || !activeRes || rtask != c.TaskID || rattempt != int(c.Attempt) || rlease != int64(c.LeaseEpoch) {
		return coreextension.Installation{}, coreextension.ErrConflict
	}
	if c.Success {
		if op != coreextension.OperationUninstall {
			if e = validateExtensionPromotionQuotaTx(ctx, tx, c.InstallationID, proposed); e != nil {
				return coreextension.Installation{}, e
			}
		}
		keepVersionID := proposed
		if op == coreextension.OperationUninstall {
			keepVersionID = ""
		}
		if e = retirePublishedNodeVersionsTx(ctx, tx, c.InstallationID, keepVersionID, rev+1); e != nil {
			return coreextension.Installation{}, e
		}
	}
	newState := coreextension.StateFailed
	newActive := active
	newProposed := proposed
	if !c.Success && proposed != "" {
		var proposedRaw []byte
		if e = tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2 FOR UPDATE`, c.InstallationID, proposed).Scan(&proposedRaw); e != nil {
			return coreextension.Installation{}, coreextension.ErrConflict
		}
		var failedProposal coreextension.VersionRecord
		if json.Unmarshal(proposedRaw, &failedProposal) != nil {
			return coreextension.Installation{}, coreextension.ErrConflict
		}
		if artifactPromoted {
			if e = enqueuePromotedNodeCleanupTx(ctx, tx, c.InstallationID, failedProposal, rev+1); e != nil {
				return coreextension.Installation{}, e
			}
		} else {
			if e = enqueueArtifactCleanupTx(ctx, tx, c.InstallationID, failedProposal, "failure"); e != nil {
				return coreextension.Installation{}, e
			}
		}
	}
	if c.Success {
		newState = coreextension.StateInstalled
		if op == coreextension.OperationUninstall {
			newState = coreextension.StateRemoved
			newActive = ""
			newProposed = ""
		} else {
			newActive = proposed
			newProposed = ""
		}
		// Promotion and canonical secret replacement are part of the same
		// transaction as the lifecycle/task terminal transition.
		if op != coreextension.OperationUninstall {
			if _, e = tx.Exec(ctx, `UPDATE core_extension_secret_revisions r SET state='rolled_back',updated_at=clock_timestamp() WHERE r.installation_id=$1 AND r.version_id<>$2 AND r.state='staged'`, c.InstallationID, proposed); e != nil {
				return coreextension.Installation{}, e
			}
			if _, e = tx.Exec(ctx, `UPDATE core_extension_secrets s SET binding_revision=r.binding_revision,secret_key_version=r.secret_key_version,secret_value_nonce=r.secret_value_nonce,secret_value_ciphertext=r.secret_value_ciphertext,fingerprint=r.fingerprint,revision=s.revision+1,updated_at=clock_timestamp() FROM core_extension_secret_revisions r WHERE r.installation_id=$1 AND r.version_id=$2 AND r.state='staged' AND s.reference_id=r.reference_id AND s.purpose=r.purpose`, c.InstallationID, proposed); e != nil {
				return coreextension.Installation{}, e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO core_extension_secrets(reference_id,purpose,binding_revision,secret_key_version,secret_value_nonce,secret_value_ciphertext,fingerprint) SELECT reference_id,purpose,binding_revision,secret_key_version,secret_value_nonce,secret_value_ciphertext,fingerprint FROM core_extension_secret_revisions WHERE installation_id=$1 AND version_id=$2 AND state='staged' ON CONFLICT(reference_id,purpose) DO UPDATE SET binding_revision=EXCLUDED.binding_revision,secret_key_version=EXCLUDED.secret_key_version,secret_value_nonce=EXCLUDED.secret_value_nonce,secret_value_ciphertext=EXCLUDED.secret_value_ciphertext,fingerprint=EXCLUDED.fingerprint,revision=core_extension_secrets.revision+1,updated_at=clock_timestamp()`, c.InstallationID, proposed); e != nil {
				return coreextension.Installation{}, e
			}
			if _, e = tx.Exec(ctx, `UPDATE core_extension_secret_revisions SET state='promoted',updated_at=clock_timestamp() WHERE installation_id=$1 AND version_id=$2 AND state='staged'`, c.InstallationID, proposed); e != nil {
				return coreextension.Installation{}, e
			}
		}
	} else {
		// Rejected, expired, or failed proposals must not leak staged material
		// or the proposed projection into the active installation.
		if _, e = tx.Exec(ctx, `UPDATE core_extension_secret_revisions SET state='rolled_back',updated_at=clock_timestamp() WHERE installation_id=$1 AND state='staged'`, c.InstallationID); e != nil {
			return coreextension.Installation{}, e
		}
		newProposed = ""
		if active != "" && op != coreextension.OperationInstall {
			newState = coreextension.StateInstalled
		}
		var prevCandidate, prevNetwork, prevSecrets []byte
		var prevKind, prevSource, prevID, prevName, prevDescription, prevTransport string
		if e = tx.QueryRow(ctx, `SELECT previous_candidate_json,previous_kind,previous_source,previous_candidate_id,previous_name,previous_description,previous_transport,previous_network_grants_json,previous_secret_grants_json FROM core_extension_lifecycles WHERE installation_id=$1 AND confirmation_id=$2`, c.InstallationID, c.ConfirmationID).Scan(&prevCandidate, &prevKind, &prevSource, &prevID, &prevName, &prevDescription, &prevTransport, &prevNetwork, &prevSecrets); e == nil && prevCandidate != nil {
			if _, e = tx.Exec(ctx, `UPDATE core_extension_installations SET candidate_json=$2,kind=$3,source=$4,candidate_id=$5,name=$6,description=$7,transport=$8,network_grants_json=$9,secret_grants_json=$10 WHERE installation_id=$1`, c.InstallationID, prevCandidate, prevKind, prevSource, prevID, prevName, prevDescription, prevTransport, prevNetwork, prevSecrets); e != nil {
				return coreextension.Installation{}, e
			}
		}
		if active == "" {
			newActive = ""
			if _, e = tx.Exec(ctx, `UPDATE core_extension_installations SET active_version_id=NULL,network_grants_json='[]'::jsonb,secret_grants_json='[]'::jsonb WHERE installation_id=$1`, c.InstallationID); e != nil {
				return coreextension.Installation{}, e
			}
		} else {
			var prior []byte
			if e = tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE version_id=$1 AND installation_id=$2`, active, c.InstallationID).Scan(&prior); e != nil {
				return coreextension.Installation{}, coreextension.ErrConflict
			}
			var pv coreextension.VersionRecord
			if json.Unmarshal(prior, &pv) != nil {
				return coreextension.Installation{}, coreextension.ErrConflict
			}
			ng, _ := json.Marshal(pv.NetworkGrants)
			sg, _ := json.Marshal(pv.SecretGrants)
			if _, e = tx.Exec(ctx, `UPDATE core_extension_installations SET active_version_id=$2,network_grants_json=$3,secret_grants_json=$4 WHERE installation_id=$1`, c.InstallationID, active, ng, sg); e != nil {
				return coreextension.Installation{}, e
			}
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE core_extension_installations SET state=$2,enabled=CASE WHEN $5='install' THEN true WHEN $5='uninstall' THEN false ELSE enabled END,active_version_id=NULLIF($3,'')::uuid,proposed_version_id=NULLIF($4,'')::uuid,revision=revision+1,updated_at=clock_timestamp() WHERE installation_id=$1`, c.InstallationID, string(newState), newActive, newProposed, op); e != nil {
		return coreextension.Installation{}, e
	}
	statusTask := "failed"
	if c.Success {
		statusTask = "succeeded"
	}
	if statusTask == "succeeded" {
		if _, e = tx.Exec(ctx, `UPDATE core_tasks SET status='succeeded',attempt=GREATEST(attempt,1),lease_holder='',lease_expires_at=NULL,result_json=$2,progress_sequence=progress_sequence+1,revision=$3,updated_at=clock_timestamp() WHERE task_id=$1`, c.TaskID, []byte(`{"outcome_digest":"`+c.OutcomeDigest+`"}`), c.TerminalTaskRevision); e != nil {
			return coreextension.Installation{}, e
		}
	} else if _, e = tx.Exec(ctx, `UPDATE core_tasks SET status='failed',attempt=GREATEST(attempt,1),lease_holder='',lease_expires_at=NULL,failure_code=$3,failure_summary=$4,progress_sequence=progress_sequence+1,revision=$2,updated_at=clock_timestamp() WHERE task_id=$1`, c.TaskID, c.TerminalTaskRevision, c.FailureCode, c.FailureSummary); e != nil {
		return coreextension.Installation{}, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,result_json,error_code,error_summary,occurred_at) SELECT task_id,progress_sequence,$2,attempt,$3,'extension_lifecycle',$4,result_json,failure_code,failure_summary,clock_timestamp() FROM core_tasks WHERE task_id=$1`, c.TaskID, uuid.New(), statusTask, statusTask); e != nil {
		return coreextension.Installation{}, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1`, c.ConfirmationID); e != nil {
		return coreextension.Installation{}, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,updated_at=clock_timestamp(),revision=revision+1 WHERE confirmation_id=$1 AND state='consumed'`, c.ConfirmationID); e != nil {
		return coreextension.Installation{}, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_extension_lifecycles SET completion_hash=$2,state=$3,acquired_attempt=$4,acquired_lease_epoch=$5,acquired_task_revision=$6,terminal_attempt=$7,terminal_lease_epoch=$8,terminal_task_revision=$9,updated_at=clock_timestamp() WHERE installation_id=$1 AND confirmation_id=$10`, c.InstallationID, cd, statusTask, c.Attempt, c.LeaseEpoch, c.AcquiredTaskRevision, c.TerminalAttempt, c.TerminalLeaseEpoch, c.TerminalTaskRevision, c.ConfirmationID); e != nil {
		return coreextension.Installation{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreextension.Installation{}, e
	}
	return s.Get(ctx, c.InstallationID)
}

func validateExtensionPromotionQuotaTx(ctx context.Context, tx pgx.Tx, installationID, proposedVersionID string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `core_extension_install_quota`); err != nil {
		return fmt.Errorf("extension promotion quota lock: %w", err)
	}
	var installationCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_installations WHERE state NOT IN ('removed','failed')`).Scan(&installationCount); err != nil {
		return fmt.Errorf("extension promotion installation quota: %w", err)
	}
	if installationCount > coreextension.MaxInstallations {
		return coreextension.ErrInstallationLimit
	}
	var transport string
	var candidateRaw []byte
	if err := tx.QueryRow(ctx, `SELECT transport,candidate_json FROM core_extension_installations WHERE installation_id=$1`, installationID).Scan(&transport, &candidateRaw); err != nil {
		return coreextension.ErrNotFound
	}
	if transport != string(coreextension.TransportStdioNode) {
		return nil
	}
	var candidate coreextension.Candidate
	if json.Unmarshal(candidateRaw, &candidate) != nil {
		return coreextension.ErrConflict
	}
	var versionRaw []byte
	if err := tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2 FOR UPDATE`, installationID, proposedVersionID).Scan(&versionRaw); err != nil {
		return coreextension.ErrConflict
	}
	var version coreextension.VersionRecord
	if json.Unmarshal(versionRaw, &version) != nil || version.NodeArtifact == nil || version.NodeArtifact.Validate(candidate, version.Execution, version.ArtifactDigest) != nil || version.NodeArtifact.InputDigest != version.ContentDigest {
		return coreextension.ErrConflict
	}
	artifactBytes := version.NodeArtifact.ArtifactBytes
	var publishedBytes int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(v.artifact_bytes),0)
		FROM core_extension_versions v
		JOIN core_extension_installations i ON i.installation_id=v.installation_id
		WHERE i.transport=$1 AND v.published_at IS NOT NULL`, string(coreextension.TransportStdioNode)).Scan(&publishedBytes); err != nil {
		return fmt.Errorf("extension Node storage quota: %w", err)
	}
	if publishedBytes < 0 || uint64(publishedBytes)+artifactBytes > coreextension.MaxNodeStorageBytes {
		return coreextension.ErrNodeStorageQuota
	}
	publishedAt := time.Now().UTC()
	version.PublishedAt = publishedAt
	updatedVersion, err := json.Marshal(version)
	if err != nil {
		return coreextension.ErrConflict
	}
	if _, err := tx.Exec(ctx, `UPDATE core_extension_versions
		SET version_json=$3,artifact_bytes=$4,file_count=$5,lifecycle_scripts_disabled=true,native_addons_absent=true,published_at=COALESCE(published_at,$6)
		WHERE installation_id=$1 AND version_id=$2`, installationID, proposedVersionID, updatedVersion, artifactBytes, version.NodeArtifact.FileCount, publishedAt); err != nil {
		return fmt.Errorf("publish extension Node artifact receipt: %w", err)
	}
	return nil
}

func retirePublishedNodeVersionsTx(ctx context.Context, tx pgx.Tx, installationID, keepVersionID string, installationRevision int64) error {
	if installationRevision < 1 {
		return coreextension.ErrInvalid
	}
	var transport string
	if err := tx.QueryRow(ctx, `SELECT transport FROM core_extension_installations WHERE installation_id=$1`, installationID).Scan(&transport); err != nil {
		return coreextension.ErrNotFound
	}
	if transport != string(coreextension.TransportStdioNode) {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT version_id::text,version_json FROM core_extension_versions WHERE installation_id=$1 AND published_at IS NOT NULL AND version_id IS DISTINCT FROM NULLIF($2,'')::uuid FOR UPDATE`, installationID, keepVersionID)
	if err != nil {
		return err
	}
	type retainedVersion struct {
		id  string
		raw []byte
	}
	var retiring []retainedVersion
	for rows.Next() {
		var version retainedVersion
		if err = rows.Scan(&version.id, &version.raw); err != nil {
			rows.Close()
			return err
		}
		retiring = append(retiring, version)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, retired := range retiring {
		var version coreextension.VersionRecord
		if json.Unmarshal(retired.raw, &version) != nil || version.NodeArtifact == nil || uuid.Validate(version.ArtifactCleanupToken) != nil || version.ArtifactDigest != version.NodeArtifact.ArtifactDigest {
			return coreextension.ErrConflict
		}
		cleanupID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk-agent/core-extension-node-cleanup/v1\x00"+installationID+"\x00"+version.VersionID+"\x00"+version.ArtifactDigest+"\x00"+version.ArtifactCleanupToken))
		if _, err = tx.Exec(ctx, `INSERT INTO core_extension_node_artifact_cleanup(cleanup_id,installation_id,version_id,artifact_digest,cleanup_token,installation_revision,version_json) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (cleanup_id) DO NOTHING`, cleanupID, installationID, version.VersionID, version.ArtifactDigest, version.ArtifactCleanupToken, installationRevision, retired.raw); err != nil {
			return err
		}
	}
	return nil
}

func enqueuePromotedNodeCleanupTx(ctx context.Context, tx pgx.Tx, installationID string, version coreextension.VersionRecord, installationRevision int64) error {
	if uuid.Validate(installationID) != nil || uuid.Validate(version.VersionID) != nil || uuid.Validate(version.ArtifactCleanupToken) != nil || installationRevision < 1 || version.NodeArtifact == nil || version.ArtifactDigest != version.NodeArtifact.ArtifactDigest || !version.PublishedAt.IsZero() {
		return coreextension.ErrInvalid
	}
	publishedAt := time.Now().UTC()
	version.PublishedAt = publishedAt
	versionRaw, err := json.Marshal(version)
	if err != nil {
		return coreextension.ErrInvalid
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `core_extension_install_quota`); err != nil {
		return fmt.Errorf("promoted Node cleanup quota lock: %w", err)
	}
	publishedTag, err := tx.Exec(ctx, `UPDATE core_extension_versions
		SET version_json=$3,artifact_bytes=$4,file_count=$5,lifecycle_scripts_disabled=true,native_addons_absent=true,published_at=$6
		WHERE installation_id=$1 AND version_id=$2 AND published_at IS NULL`, installationID, version.VersionID, versionRaw, version.NodeArtifact.ArtifactBytes, version.NodeArtifact.FileCount, publishedAt)
	if err != nil {
		return fmt.Errorf("persist promoted Node artifact receipt: %w", err)
	}
	if publishedTag.RowsAffected() != 1 {
		return coreextension.ErrConflict
	}
	cleanupID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk-agent/core-extension-node-cleanup/v1\x00"+installationID+"\x00"+version.VersionID+"\x00"+version.ArtifactDigest+"\x00"+version.ArtifactCleanupToken))
	_, err = tx.Exec(ctx, `INSERT INTO core_extension_node_artifact_cleanup(cleanup_id,installation_id,version_id,artifact_digest,cleanup_token,installation_revision,version_json) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (cleanup_id) DO NOTHING`, cleanupID, installationID, version.VersionID, version.ArtifactDigest, version.ArtifactCleanupToken, installationRevision, versionRaw)
	return err
}

// rollbackExtensionLifecycleTx is called by confirmation expiry/staleness
// while the confirmation, task, projection, and staged secrets share one
// transaction. It is deliberately a no-op for non-extension confirmations.
func rollbackExtensionLifecycleTx(ctx context.Context, tx pgx.Tx, confirmationID string) error {
	var installationID string
	var operation string
	var previousCandidate, previousNetwork, previousSecrets []byte
	var previousKind, previousSource, previousCandidateID, previousName, previousDescription, previousTransport string
	if err := tx.QueryRow(ctx, `SELECT installation_id::text,operation,previous_candidate_json,previous_kind,previous_source,previous_candidate_id,previous_name,previous_description,previous_transport,previous_network_grants_json,previous_secret_grants_json FROM core_extension_lifecycles WHERE confirmation_id=$1 FOR UPDATE`, confirmationID).Scan(&installationID, &operation, &previousCandidate, &previousKind, &previousSource, &previousCandidateID, &previousName, &previousDescription, &previousTransport, &previousNetwork, &previousSecrets); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	var active, proposed string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(active_version_id::text,''),COALESCE(proposed_version_id::text,'') FROM core_extension_installations WHERE installation_id=$1 FOR UPDATE`, installationID).Scan(&active, &proposed); err != nil {
		return err
	}
	if proposed != "" {
		var proposedRaw []byte
		if err := tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2 FOR UPDATE`, installationID, proposed).Scan(&proposedRaw); err != nil {
			return err
		}
		var failedProposal coreextension.VersionRecord
		if json.Unmarshal(proposedRaw, &failedProposal) != nil {
			return coreextension.ErrConflict
		}
		if err := enqueueArtifactCleanupTx(ctx, tx, installationID, failedProposal, "failure"); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE core_extension_secret_revisions SET state='rolled_back',updated_at=clock_timestamp() WHERE installation_id=$1 AND state='staged'`, installationID); err != nil {
		return err
	}
	if previousCandidate != nil {
		state := "failed"
		if active != "" && operation != coreextension.OperationInstall {
			state = "installed"
		}
		if _, err := tx.Exec(ctx, `UPDATE core_extension_installations SET candidate_json=$2,kind=$3,source=$4,candidate_id=$5,name=$6,description=$7,transport=$8,state=$9,proposed_version_id=NULL,network_grants_json=$10,secret_grants_json=$11,revision=revision+1,updated_at=clock_timestamp() WHERE installation_id=$1`, installationID, previousCandidate, previousKind, previousSource, previousCandidateID, previousName, previousDescription, previousTransport, state, previousNetwork, previousSecrets); err != nil {
			return err
		}
	} else if active == "" {
		if _, err := tx.Exec(ctx, `UPDATE core_extension_installations SET state='failed',proposed_version_id=NULL,active_version_id=NULL,network_grants_json='[]'::jsonb,secret_grants_json='[]'::jsonb,revision=revision+1,updated_at=clock_timestamp() WHERE installation_id=$1`, installationID); err != nil {
			return err
		}
	} else {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2`, installationID, active).Scan(&raw); err != nil {
			return err
		}
		var v coreextension.VersionRecord
		if json.Unmarshal(raw, &v) != nil {
			return coreextension.ErrConflict
		}
		ng, _ := json.Marshal(v.NetworkGrants)
		sg, _ := json.Marshal(v.SecretGrants)
		state := "failed"
		if operation != coreextension.OperationInstall {
			state = "installed"
		}
		if _, err := tx.Exec(ctx, `UPDATE core_extension_installations SET state=$2,proposed_version_id=NULL,network_grants_json=$3,secret_grants_json=$4,revision=revision+1,updated_at=clock_timestamp() WHERE installation_id=$1`, installationID, state, ng, sg); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE core_extension_lifecycles SET state='failed',updated_at=clock_timestamp() WHERE confirmation_id=$1`, confirmationID)
	return err
}

func enqueueArtifactCleanupTx(ctx context.Context, tx pgx.Tx, installationID string, version coreextension.VersionRecord, reason string) error {
	if uuid.Validate(installationID) != nil || uuid.Validate(version.VersionID) != nil || len(version.ArtifactDigest) != 64 || filepath.Base(version.ArtifactPath) != version.ArtifactDigest || !validCleanupReason(reason) {
		return coreextension.ErrInvalid
	}
	cleanupID := extensionArtifactCleanupID(installationID, version.VersionID, version.ArtifactDigest)
	var cleanupToken any
	var versionJSON any
	nodeArtifact := version.NodeArtifact != nil
	if nodeArtifact {
		if uuid.Validate(version.ArtifactCleanupToken) != nil || version.NodeArtifact.ArtifactDigest != version.ArtifactDigest {
			return coreextension.ErrInvalid
		}
		raw, err := json.Marshal(version)
		if err != nil {
			return coreextension.ErrInvalid
		}
		cleanupToken = version.ArtifactCleanupToken
		versionJSON = raw
	}
	_, err := tx.Exec(ctx, `INSERT INTO core_extension_artifact_cleanup(cleanup_id,installation_id,version_id,artifact_digest,staging_relative_path,reason,cleanup_token,node_artifact,version_json) VALUES($1,$2,$3,$4,$4,$5,$6,$7,$8) ON CONFLICT (cleanup_id) DO NOTHING`, cleanupID, installationID, version.VersionID, version.ArtifactDigest, reason, cleanupToken, nodeArtifact, versionJSON)
	return err
}

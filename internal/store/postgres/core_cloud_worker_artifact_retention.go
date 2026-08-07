package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/jackc/pgx/v5"
)

const cloudWorkerArtifactRetentionSelect = `SELECT
artifact_id::text,execution_id::text,kind,name,media_type,size_bytes,sha256,status,
s3_bucket,s3_key,s3_version_id,retention_owner_id,retention_account_id,
retention_account_generation,retention_region,retention_credential_id::text,
retention_credential_revision,retention_provider_id,retention_plan_id::text,
retention_plan_digest,retention_key_prefix,retention_kms_key_arn,
retention_expires_at,retention_state,retention_revision,
retention_deletion_claim_id::text,retention_deletion_lease_until,
retention_delete_attempts,retention_next_attempt_at,retention_updated_at,
retention_verified_deleted_at,artifact_json,created_at
FROM core_cloud_worker_artifacts`

type artifactRetentionRowScanner interface{ Scan(...any) error }

func scanCloudWorkerArtifactRetention(row artifactRetentionRowScanner) (cloudworker.ArtifactRetentionRecord, cloudworker.Artifact, error) {
	var record cloudworker.ArtifactRetentionRecord
	var artifact cloudworker.Artifact
	var claim cloudresult.ObjectClaim
	var artifactID, executionID, kind, status, ownerID, accountID, region string
	var credentialID, providerID, planID, planDigest, keyPrefix, kmsKeyARN string
	var retentionState string
	var deletionClaimID *string
	var deletionLeaseUntil, verifiedDeletedAt *time.Time
	var accountGeneration, credentialRevision, sizeBytes, retentionRevision int64
	var deleteAttempts int32
	var artifactRaw []byte
	err := row.Scan(
		&artifactID, &executionID, &kind, &claim.Name, &claim.MediaType, &sizeBytes, &claim.SHA256, &status,
		&claim.Bucket, &claim.Key, &claim.VersionID, &ownerID, &accountID,
		&accountGeneration, &region, &credentialID, &credentialRevision, &providerID, &planID,
		&planDigest, &keyPrefix, &kmsKeyARN, &record.Identity.ExpiresAt, &retentionState,
		&retentionRevision, &deletionClaimID, &deletionLeaseUntil, &deleteAttempts,
		&record.NextAttemptAt, &record.UpdatedAt, &verifiedDeletedAt, &artifactRaw, &record.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return record, artifact, cloudworker.ErrNotFound
		}
		return record, artifact, err
	}
	if accountGeneration < 1 || credentialRevision < 1 || sizeBytes < 1 || retentionRevision < 1 || deleteAttempts < 0 ||
		json.Unmarshal(artifactRaw, &artifact) != nil {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.Artifact{}, cloudworker.ErrConflict
	}
	claim.SizeBytes = sizeBytes
	record.Identity = cloudworker.ArtifactRetentionIdentity{
		ArtifactID: artifactID, OwnerID: ownerID, AccountID: accountID,
		AccountGeneration: uint64(accountGeneration), Region: region,
		CredentialID: credentialID, CredentialRevision: uint64(credentialRevision),
		ProviderID: providerID, ExecutionID: executionID, PlanID: planID,
		PlanDigest: planDigest, KeyPrefix: keyPrefix, KMSKeyARN: kmsKeyARN,
		Claim: claim, ExpiresAt: record.Identity.ExpiresAt.UTC(),
	}
	record.State, record.Revision, record.DeleteAttempts = cloudworker.ArtifactRetentionState(retentionState), uint64(retentionRevision), uint32(deleteAttempts)
	if deletionClaimID != nil {
		record.DeletionClaimID = *deletionClaimID
	}
	if deletionLeaseUntil != nil {
		record.DeletionLeaseUntil = deletionLeaseUntil.UTC()
	}
	if verifiedDeletedAt != nil {
		record.VerifiedDeletedAt = verifiedDeletedAt.UTC()
	}
	record.NextAttemptAt, record.CreatedAt, record.UpdatedAt = record.NextAttemptAt.UTC(), record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if status != string(cloudworker.ArtifactVerified) || artifact.ArtifactID != artifactID ||
		artifact.ExecutionID != executionID || artifact.Kind != kind || artifact.Name != claim.Name ||
		artifact.MediaType != claim.MediaType || artifact.SizeBytes != uint64(sizeBytes) ||
		artifact.SHA256 != claim.SHA256 || artifact.Status != cloudworker.ArtifactVerified ||
		artifact.Retention != nil || record.Validate() != nil {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.Artifact{}, cloudworker.ErrConflict
	}
	return record, artifact, nil
}

func (s *CloudWorkerStore) ArtifactRetentionReady(ctx context.Context) error {
	if s == nil || s.store == nil || ctx == nil {
		return cloudworker.ErrInvalid
	}
	var table string
	err := s.store.pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('core_cloud_worker_artifacts')::text,'')`).Scan(&table)
	if err != nil || table != "core_cloud_worker_artifacts" {
		return errors.Join(cloudworker.ErrNotFound, err)
	}
	_, err = s.store.pool.Exec(ctx, `SELECT retention_state,retention_revision,retention_next_attempt_at
		FROM core_cloud_worker_artifacts WHERE false`)
	return err
}

func (s *CloudWorkerStore) ClaimArtifactDeletion(ctx context.Context, claim cloudworker.ArtifactRetentionClaim) (cloudworker.ArtifactRetentionRecord, bool, error) {
	if s == nil || s.store == nil || ctx == nil || claim.Validate() != nil {
		return cloudworker.ArtifactRetentionRecord{}, false, cloudworker.ErrInvalid
	}
	// READ COMMITTED plus FOR UPDATE SKIP LOCKED is the durable worker-claim
	// primitive. SERIALIZABLE would turn an ordinary concurrent loser into a
	// transaction failure instead of the expected "no due claim" outcome.
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudworker.ArtifactRetentionRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	var artifactID string
	err = tx.QueryRow(ctx, `SELECT artifact_id::text FROM core_cloud_worker_artifacts
		WHERE ((retention_state IN ('retained','delete_uncertain') AND retention_next_attempt_at <= $1)
			OR (retention_state='delete_started' AND retention_deletion_lease_until <= $1))
		ORDER BY retention_next_attempt_at,artifact_id FOR UPDATE SKIP LOCKED LIMIT 1`, claim.At).Scan(&artifactID)
	if errors.Is(err, pgx.ErrNoRows) {
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.ArtifactRetentionRecord{}, false, err
		}
		return cloudworker.ArtifactRetentionRecord{}, false, nil
	}
	if err != nil {
		return cloudworker.ArtifactRetentionRecord{}, false, err
	}
	result, err := tx.Exec(ctx, `UPDATE core_cloud_worker_artifacts SET
		retention_state='delete_started',retention_deletion_claim_id=$2,
		retention_deletion_lease_until=$3,retention_delete_attempts=retention_delete_attempts+1,
		retention_revision=retention_revision+1,retention_updated_at=$4
		WHERE artifact_id=$1 AND ((retention_state IN ('retained','delete_uncertain') AND retention_next_attempt_at <= $4)
			OR (retention_state='delete_started' AND retention_deletion_lease_until <= $4))`,
		artifactID, claim.DeletionClaimID, claim.LeaseUntil, claim.At)
	if err != nil || result.RowsAffected() != 1 {
		if err == nil {
			err = cloudworker.ErrConflict
		}
		return cloudworker.ArtifactRetentionRecord{}, false, err
	}
	record, _, err := loadCloudWorkerArtifactRetentionTx(ctx, tx, artifactID, true)
	if err != nil || record.State != cloudworker.ArtifactDeleteStarted ||
		record.DeletionClaimID != claim.DeletionClaimID || record.DeletionLeaseUntil != claim.LeaseUntil {
		return cloudworker.ArtifactRetentionRecord{}, false, errors.Join(cloudworker.ErrConflict, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.ArtifactRetentionRecord{}, false, err
	}
	return record, true, nil
}

func (s *CloudWorkerStore) RevalidateArtifactDeletion(ctx context.Context, fence cloudworker.ArtifactRetentionFence) (cloudworker.ArtifactRetentionRecord, error) {
	if s == nil || s.store == nil || ctx == nil || fence.Validate() != nil {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.ArtifactRetentionRecord{}, err
	}
	defer tx.Rollback(ctx)
	record, _, err := loadCloudWorkerArtifactRetentionTx(ctx, tx, fence.Identity.ArtifactID, false)
	if err != nil || !record.Identity.Equal(fence.Identity) || record.State != cloudworker.ArtifactDeleteStarted ||
		record.Revision != fence.Revision || record.DeletionClaimID != fence.DeletionClaimID {
		return cloudworker.ArtifactRetentionRecord{}, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.ArtifactRetentionRecord{}, err
	}
	return record, nil
}

func (s *CloudWorkerStore) MarkArtifactDeletionUncertain(ctx context.Context, fence cloudworker.ArtifactRetentionFence, retryAt, at time.Time) (cloudworker.ArtifactRetentionRecord, error) {
	if s == nil || s.store == nil || ctx == nil || fence.Validate() != nil || retryAt.IsZero() ||
		retryAt != retryAt.UTC() || !retryAt.Equal(retryAt.Truncate(time.Microsecond)) || at.IsZero() ||
		at != at.UTC() || !at.Equal(at.Truncate(time.Microsecond)) || retryAt.Before(at) {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.ErrInvalid
	}
	return s.updateArtifactRetention(ctx, fence, cloudworker.ArtifactDeleteUncertain, retryAt, at)
}

func (s *CloudWorkerStore) MarkArtifactVerifiedDeleted(ctx context.Context, fence cloudworker.ArtifactRetentionFence, at time.Time) (cloudworker.ArtifactRetentionRecord, error) {
	if s == nil || s.store == nil || ctx == nil || fence.Validate() != nil || at.IsZero() ||
		at != at.UTC() || !at.Equal(at.Truncate(time.Microsecond)) {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.ErrInvalid
	}
	return s.updateArtifactRetention(ctx, fence, cloudworker.ArtifactVerifiedDeleted, fence.Identity.ExpiresAt, at)
}

func (s *CloudWorkerStore) updateArtifactRetention(ctx context.Context, fence cloudworker.ArtifactRetentionFence, state cloudworker.ArtifactRetentionState, nextAttemptAt, at time.Time) (cloudworker.ArtifactRetentionRecord, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.ArtifactRetentionRecord{}, err
	}
	defer tx.Rollback(ctx)
	current, _, err := loadCloudWorkerArtifactRetentionTx(ctx, tx, fence.Identity.ArtifactID, true)
	if err != nil || !current.Identity.Equal(fence.Identity) || current.State != cloudworker.ArtifactDeleteStarted ||
		current.Revision != fence.Revision || current.DeletionClaimID != fence.DeletionClaimID {
		return cloudworker.ArtifactRetentionRecord{}, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	var verifiedAt any
	if state == cloudworker.ArtifactVerifiedDeleted {
		verifiedAt = at
	} else if state != cloudworker.ArtifactDeleteUncertain {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.ErrInvalid
	}
	identity := fence.Identity
	result, err := tx.Exec(ctx, `UPDATE core_cloud_worker_artifacts SET retention_state=$2,
		retention_deletion_claim_id=NULL,retention_deletion_lease_until=NULL,
		retention_next_attempt_at=$3,retention_revision=retention_revision+1,
		retention_updated_at=$4,retention_verified_deleted_at=$5
		WHERE artifact_id=$1 AND execution_id=$6 AND retention_owner_id=$7 AND retention_account_id=$8
		AND retention_account_generation=$9 AND retention_region=$10 AND retention_provider_id=$11
		AND retention_plan_id=$12 AND retention_plan_digest=$13 AND retention_key_prefix=$14
		AND s3_bucket=$15 AND s3_key=$16 AND s3_version_id=$17
		AND retention_state='delete_started' AND retention_revision=$18 AND retention_deletion_claim_id=$19`,
		identity.ArtifactID, string(state), nextAttemptAt, at, verifiedAt,
		identity.ExecutionID, identity.OwnerID, identity.AccountID, identity.AccountGeneration,
		identity.Region, identity.ProviderID, identity.PlanID, identity.PlanDigest, identity.KeyPrefix,
		identity.Claim.Bucket, identity.Claim.Key, identity.Claim.VersionID, fence.Revision, fence.DeletionClaimID)
	if err != nil || result.RowsAffected() != 1 {
		if err == nil {
			err = cloudworker.ErrStaleAuthorization
		}
		return cloudworker.ArtifactRetentionRecord{}, err
	}
	next, _, err := loadCloudWorkerArtifactRetentionTx(ctx, tx, identity.ArtifactID, true)
	if err != nil || next.State != state || !next.Identity.Equal(identity) || next.Revision != fence.Revision+1 {
		return cloudworker.ArtifactRetentionRecord{}, errors.Join(cloudworker.ErrConflict, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.ArtifactRetentionRecord{}, err
	}
	return next, nil
}

func loadCloudWorkerArtifactRetentionTx(ctx context.Context, tx pgx.Tx, artifactID string, lock bool) (cloudworker.ArtifactRetentionRecord, cloudworker.Artifact, error) {
	if !coretask.ValidUUID(artifactID) {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.Artifact{}, cloudworker.ErrInvalid
	}
	lockClause := ` FOR SHARE`
	if lock {
		lockClause = ` FOR UPDATE`
	}
	record, artifact, err := scanCloudWorkerArtifactRetention(tx.QueryRow(ctx, cloudWorkerArtifactRetentionSelect+` WHERE artifact_id=$1`+lockClause, artifactID))
	if err != nil {
		return record, artifact, err
	}
	execution, err := scanCloudWorkerExecution(tx.QueryRow(ctx, cloudWorkerExecutionSelect+` WHERE execution_id=$1 FOR SHARE`, record.Identity.ExecutionID))
	if err != nil {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.Artifact{}, err
	}
	plan, err := scanCloudWorkerPlan(tx.QueryRow(ctx, cloudWorkerPlanSelect+` WHERE plan_id=$1 FOR SHARE`, record.Identity.PlanID))
	if err != nil {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.Artifact{}, err
	}
	expectedExpiry := artifact.CreatedAt.UTC().Add(time.Duration(plan.ArtifactGrant.RetentionSeconds) * time.Second)
	if execution.OwnerID != record.Identity.OwnerID || execution.AccountGeneration != record.Identity.AccountGeneration ||
		execution.ExecutionID != record.Identity.ExecutionID || execution.PlanID != record.Identity.PlanID ||
		execution.PlanDigest != record.Identity.PlanDigest || plan.OwnerID != record.Identity.OwnerID ||
		plan.AccountGeneration != record.Identity.AccountGeneration || plan.ExecutionID != record.Identity.ExecutionID ||
		plan.Digest != record.Identity.PlanDigest || plan.AWS.AccountID != record.Identity.AccountID ||
		plan.AWS.Region != record.Identity.Region || plan.AWS.CredentialID != record.Identity.CredentialID ||
		plan.AWS.CredentialRevision != record.Identity.CredentialRevision ||
		plan.ArtifactGrant.Bucket != record.Identity.Claim.Bucket ||
		plan.ArtifactGrant.KeyPrefix != record.Identity.KeyPrefix ||
		plan.ArtifactGrant.KMSKeyARN != record.Identity.KMSKeyARN ||
		!record.Identity.ExpiresAt.Equal(expectedExpiry) {
		return cloudworker.ArtifactRetentionRecord{}, cloudworker.Artifact{}, cloudworker.ErrStaleAuthorization
	}
	return record, artifact, nil
}

func (s *CloudWorkerStore) ReadArtifactDownloadAuthority(
	ctx context.Context,
	request cloudworker.ArtifactDownloadRequest,
	at time.Time,
) (cloudworker.ArtifactDownloadAuthority, error) {
	if s == nil || s.store == nil || ctx == nil || request.Validate() != nil ||
		at.IsZero() || at != at.UTC() {
		return cloudworker.ArtifactDownloadAuthority{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.ArtifactDownloadAuthority{}, err
	}
	defer tx.Rollback(ctx)
	authority, err := readArtifactDownloadAuthorityTx(ctx, tx, request.ArtifactID, false)
	if err != nil {
		return cloudworker.ArtifactDownloadAuthority{}, err
	}
	if authority.Retention.Identity.OwnerID != request.OwnerID ||
		authority.Retention.Identity.AccountGeneration != request.AccountGeneration ||
		authority.ValidateAt(at) != nil {
		return cloudworker.ArtifactDownloadAuthority{}, cloudworker.ErrStaleAuthorization
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.ArtifactDownloadAuthority{}, err
	}
	return authority, nil
}

func (s *CloudWorkerStore) RevalidateArtifactDownload(
	ctx context.Context,
	expected cloudworker.ArtifactDownloadAuthority,
	at time.Time,
) error {
	if s == nil || s.store == nil || ctx == nil || expected.Retention.Identity.Validate() != nil ||
		at.IsZero() || at != at.UTC() {
		return cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	current, err := readArtifactDownloadAuthorityTx(ctx, tx, expected.Artifact.ArtifactID, false)
	if err != nil || current.ValidateAt(at) != nil || !current.Equal(expected) {
		return errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	return tx.Commit(ctx)
}

func readArtifactDownloadAuthorityTx(
	ctx context.Context,
	tx pgx.Tx,
	artifactID string,
	lock bool,
) (cloudworker.ArtifactDownloadAuthority, error) {
	record, artifact, err := loadCloudWorkerArtifactRetentionTx(ctx, tx, artifactID, lock)
	if err != nil {
		return cloudworker.ArtifactDownloadAuthority{}, err
	}
	lockClause := ` FOR SHARE`
	if lock {
		lockClause = ` FOR UPDATE`
	}
	execution, err := scanCloudWorkerExecution(tx.QueryRow(ctx, cloudWorkerExecutionSelect+` WHERE execution_id=$1`+lockClause, record.Identity.ExecutionID))
	if err != nil {
		return cloudworker.ArtifactDownloadAuthority{}, err
	}
	plan, err := scanCloudWorkerPlan(tx.QueryRow(ctx, cloudWorkerPlanSelect+` WHERE plan_id=$1`+lockClause, record.Identity.PlanID))
	if err != nil {
		return cloudworker.ArtifactDownloadAuthority{}, err
	}
	return cloudworker.ArtifactDownloadAuthority{
		Plan: plan, Execution: execution, Artifact: artifact, Retention: record,
	}, nil
}

var _ cloudworker.ArtifactRetentionStore = (*CloudWorkerStore)(nil)
var _ cloudworker.ArtifactDownloadAuthorityStore = (*CloudWorkerStore)(nil)

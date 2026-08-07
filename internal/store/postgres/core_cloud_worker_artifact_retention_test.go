package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	"github.com/google/uuid"
)

func TestCloudWorkerPostgresPersistsPrivateExactArtifactAndRestartSafeRetention(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	_, task, _, material := preparePGCloudLaunch(t, h)
	defer material.Destroy()

	resume, err := h.cloud.GetResumeContext(h.ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	plan, execution := resume.Plan, resume.Execution
	resume.Destroy()
	for _, state := range []cloudworker.ExecutionState{
		cloudworker.StateAwaitingWorker, cloudworker.StateRunning, cloudworker.StateCollecting,
	} {
		execution, err = h.cloud.TransitionExecution(h.ctx, task, execution.Revision, state)
		if err != nil {
			t.Fatalf("transition %s: %v", state, err)
		}
	}
	validatedAt := time.Now().UTC().Truncate(time.Microsecond)
	claim := cloudresult.ObjectClaim{
		Name: "final.json", Bucket: plan.ArtifactGrant.Bucket,
		Key: plan.ArtifactGrant.KeyPrefix + "final.json", VersionID: "pg-exact-version-1",
		SHA256: pgCloudDigest("pg-retained-final"), SizeBytes: 256, MediaType: "application/json",
	}
	artifact := cloudworker.Artifact{
		ArtifactID: uuid.NewString(), ExecutionID: plan.ExecutionID, Kind: "result",
		Name: claim.Name, MediaType: claim.MediaType, SizeBytes: uint64(claim.SizeBytes),
		SHA256: claim.SHA256, Status: cloudworker.ArtifactVerified, CreatedAt: validatedAt,
	}
	retention := cloudworker.ArtifactRetentionIdentity{
		ArtifactID: artifact.ArtifactID, OwnerID: plan.OwnerID, AccountID: plan.AWS.AccountID,
		AccountGeneration: plan.AccountGeneration, Region: plan.AWS.Region,
		CredentialID: plan.AWS.CredentialID, CredentialRevision: plan.AWS.CredentialRevision,
		ProviderID:  fmt.Sprintf("credential:%s:revision:%d", plan.AWS.CredentialID, plan.AWS.CredentialRevision),
		ExecutionID: plan.ExecutionID, PlanID: plan.PlanID, PlanDigest: plan.Digest,
		KeyPrefix: plan.ArtifactGrant.KeyPrefix, KMSKeyARN: plan.ArtifactGrant.KMSKeyARN,
		Claim: claim, ExpiresAt: validatedAt.Add(time.Duration(plan.ArtifactGrant.RetentionSeconds) * time.Second),
	}
	if err = retention.Validate(); err != nil {
		t.Fatal(err)
	}
	artifact.Retention = &retention
	execution, err = h.cloud.RecordArtifacts(h.ctx, task, execution.Revision, []cloudworker.Artifact{artifact}, cloudworker.StateValidating)
	if err != nil || len(execution.ArtifactIDs) != 1 {
		t.Fatalf("record artifacts execution=%+v err=%v", execution, err)
	}

	var bucket, key, version, owner, accountID, region, providerID, state string
	var generation uint64
	var expiresAt time.Time
	if err = h.store.pool.QueryRow(h.ctx, `SELECT s3_bucket,s3_key,s3_version_id,
		retention_owner_id,retention_account_id,retention_account_generation,
		retention_region,retention_provider_id,retention_expires_at,retention_state
		FROM core_cloud_worker_artifacts WHERE artifact_id=$1`, artifact.ArtifactID).Scan(
		&bucket, &key, &version, &owner, &accountID, &generation, &region, &providerID, &expiresAt, &state); err != nil {
		t.Fatal(err)
	}
	if bucket != claim.Bucket || key != claim.Key || version != claim.VersionID || owner != plan.OwnerID ||
		accountID != plan.AWS.AccountID || generation != plan.AccountGeneration || region != plan.AWS.Region ||
		providerID != retention.ProviderID || !expiresAt.Equal(retention.ExpiresAt) || state != string(cloudworker.ArtifactRetained) {
		t.Fatalf("private exact identity drifted bucket=%q key=%q version=%q owner=%q account=%q/%d region=%q provider=%q expires=%s state=%q",
			bucket, key, version, owner, accountID, generation, region, providerID, expiresAt, state)
	}
	public, err := h.cloud.GetArtifact(h.ctx, h.owner, artifact.ArtifactID)
	if err != nil || public.Retention != nil || public.ArtifactID != artifact.ArtifactID {
		t.Fatalf("public artifact leaked retention: %+v err=%v", public, err)
	}
	verifiedAt := validatedAt.Add(time.Second)
	execution.State, execution.Status, execution.Revision = cloudworker.StateSucceeded, cloudworker.StateSucceeded, execution.Revision+1
	execution.ProviderMutationStarted = true
	execution.TerminalIntent, execution.NeedsReconcile = "", false
	execution.Cleanup = cloudworker.CleanupSummary{
		VerifiedDestroyed: true, VerifiedAt: &verifiedAt,
		ResourcesTotal: uint64(len(cloudaws.AllResourceKinds())), ResourcesVerifiedDestroyed: uint64(len(cloudaws.AllResourceKinds())),
	}
	execution.UpdatedAt = verifiedAt
	if err = execution.Seal(); err != nil {
		t.Fatal(err)
	}
	executionRaw, err := marshalCloudWorkerExecution(execution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.pool.Exec(h.ctx, `UPDATE core_cloud_worker_executions SET
		state=$2,revision=$3,digest=$4,provider_mutation_started=$5,terminal_intent='',needs_reconcile=false,
		execution_json=$6,updated_at=$7 WHERE execution_id=$1`, execution.ExecutionID, execution.State,
		execution.Revision, execution.Digest, execution.ProviderMutationStarted, executionRaw, execution.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	downloadRequest := cloudworker.ArtifactDownloadRequest{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		ArtifactID: artifact.ArtifactID, MaxChunkBytes: cloudworker.MaxArtifactDownloadChunkBytes,
	}
	downloadAuthority, err := h.cloud.ReadArtifactDownloadAuthority(h.ctx, downloadRequest, validatedAt)
	if err != nil || downloadAuthority.Retention.Identity.Claim != claim || downloadAuthority.Execution.State != cloudworker.StateSucceeded {
		t.Fatalf("download authority=%+v err=%v", downloadAuthority, err)
	}
	foreign := downloadRequest
	foreign.AccountGeneration++
	if _, err = h.cloud.ReadArtifactDownloadAuthority(h.ctx, foreign, validatedAt); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("foreign generation read err=%v", err)
	}

	// Two independent store instances race the same due row. SKIP LOCKED makes
	// exactly one the durable owner; the other must return the expected negative
	// state instead of performing a second deletion mutation.
	restarted := NewCloudWorkerStore(h.store)
	due := retention.ExpiresAt
	claims := []cloudworker.ArtifactRetentionClaim{
		{DeletionClaimID: uuid.NewString(), At: due, LeaseUntil: due.Add(time.Minute)},
		{DeletionClaimID: uuid.NewString(), At: due, LeaseUntil: due.Add(time.Minute)},
	}
	type claimResult struct {
		record cloudworker.ArtifactRetentionRecord
		found  bool
		err    error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for index, store := range []*CloudWorkerStore{h.cloud, restarted} {
		index, store := index, store
		go func() {
			<-start
			record, found, claimErr := store.ClaimArtifactDeletion(context.Background(), claims[index])
			results <- claimResult{record: record, found: found, err: claimErr}
		}()
	}
	close(start)
	var claimed cloudworker.ArtifactRetentionRecord
	foundCount := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.found {
			foundCount++
			claimed = result.record
		}
	}
	if foundCount != 1 || claimed.State != cloudworker.ArtifactDeleteStarted {
		t.Fatalf("concurrent claims found=%d claimed=%+v", foundCount, claimed)
	}
	if err = restarted.RevalidateArtifactDownload(h.ctx, downloadAuthority, due.Add(-time.Second)); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("download survived cleaner retention CAS: %v", err)
	}
	fence, err := claimed.Fence()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.RevalidateArtifactDeletion(h.ctx, fence); err != nil {
		t.Fatalf("restart exact claim revalidation: %v", err)
	}
	retryAt := due.Add(2 * time.Minute)
	uncertain, err := restarted.MarkArtifactDeletionUncertain(h.ctx, fence, retryAt, due.Add(time.Second))
	if err != nil || uncertain.State != cloudworker.ArtifactDeleteUncertain {
		t.Fatalf("uncertain=%+v err=%v", uncertain, err)
	}
	reclaimed, found, err := h.cloud.ClaimArtifactDeletion(h.ctx, cloudworker.ArtifactRetentionClaim{
		DeletionClaimID: uuid.NewString(), At: retryAt, LeaseUntil: retryAt.Add(time.Minute),
	})
	if err != nil || !found || reclaimed.DeleteAttempts != 2 {
		t.Fatalf("reclaimed=%+v found=%t err=%v", reclaimed, found, err)
	}
	reclaimFence, _ := reclaimed.Fence()
	deleted, err := restarted.MarkArtifactVerifiedDeleted(h.ctx, reclaimFence, retryAt.Add(time.Second))
	if err != nil || deleted.State != cloudworker.ArtifactVerifiedDeleted || deleted.VerifiedDeletedAt.IsZero() {
		t.Fatalf("deleted=%+v err=%v", deleted, err)
	}
	if _, found, err = h.cloud.ClaimArtifactDeletion(h.ctx, cloudworker.ArtifactRetentionClaim{
		DeletionClaimID: uuid.NewString(), At: retryAt.Add(time.Hour), LeaseUntil: retryAt.Add(time.Hour + time.Minute),
	}); err != nil || found {
		t.Fatalf("verified row reclaimed found=%t err=%v", found, err)
	}
}

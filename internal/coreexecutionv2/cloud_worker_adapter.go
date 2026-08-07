package coreexecutionv2

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type cloudWorkerExecutionAdapter struct {
	store     CloudWorkerAuthorityStore
	downloads CloudWorkerArtifactDownloader
}

// NewCloudWorkerExecutionPort exposes only secret-free Cloud Worker
// projections through the existing Execution V2 product surface.
func NewCloudWorkerExecutionPort(store CloudWorkerAuthorityStore, downloads CloudWorkerArtifactDownloader) (CloudWorkerExecutionPort, error) {
	if store == nil || downloads == nil {
		return nil, ErrInvalid
	}
	return &cloudWorkerExecutionAdapter{store: store, downloads: downloads}, nil
}

func (a *cloudWorkerExecutionAdapter) GetPlan(ctx context.Context, request CloudWorkerPlanGetRequest) (CloudWorkerObject, error) {
	if a == nil || a.store == nil || !validCloudWorkerAuthority(request.Authority) || !coretask.ValidUUID(request.PlanID) {
		return nil, ErrInvalid
	}
	plan, err := a.store.GetPlanForAuthority(ctx, strings.TrimSpace(request.OwnerID), request.AccountGeneration, request.PlanID, request.Revision)
	if err != nil {
		return nil, mapCloudWorkerPortError(err)
	}
	return cloudWorkerPlanProjection(plan), nil
}

func (a *cloudWorkerExecutionAdapter) ListPlans(ctx context.Context, request CloudWorkerListRequest) (CloudWorkerPage, error) {
	if a == nil || a.store == nil || !validCloudWorkerAuthority(request.Authority) || !validCloudWorkerPageRequest(request) {
		return CloudWorkerPage{}, ErrInvalid
	}
	plans, next, err := a.store.ListPlansForAuthority(ctx, strings.TrimSpace(request.OwnerID), request.AccountGeneration, request.PageToken, request.PageSize)
	if err != nil {
		return CloudWorkerPage{}, mapCloudWorkerPortError(err)
	}
	items := make([]CloudWorkerObject, 0, len(plans))
	for _, plan := range plans {
		items = append(items, cloudWorkerPlanProjection(plan))
	}
	return CloudWorkerPage{Items: items, NextPageToken: next}, nil
}

func (a *cloudWorkerExecutionAdapter) GetRun(ctx context.Context, request CloudWorkerRunGetRequest) (CloudWorkerObject, error) {
	if a == nil || a.store == nil || !validCloudWorkerAuthority(request.Authority) || !coretask.ValidUUID(request.RunID) {
		return nil, ErrInvalid
	}
	execution, err := a.store.GetExecutionForAuthority(ctx, strings.TrimSpace(request.OwnerID), request.AccountGeneration, request.RunID)
	if err != nil {
		return nil, mapCloudWorkerPortError(err)
	}
	return cloudWorkerExecutionProjection(execution), nil
}

func (a *cloudWorkerExecutionAdapter) ListRuns(ctx context.Context, request CloudWorkerListRequest) (CloudWorkerPage, error) {
	if a == nil || a.store == nil || !validCloudWorkerAuthority(request.Authority) || !validCloudWorkerPageRequest(request) {
		return CloudWorkerPage{}, ErrInvalid
	}
	executions, next, err := a.store.ListExecutionsForAuthority(ctx, strings.TrimSpace(request.OwnerID), request.AccountGeneration, request.PageToken, request.PageSize)
	if err != nil {
		return CloudWorkerPage{}, mapCloudWorkerPortError(err)
	}
	items := make([]CloudWorkerObject, 0, len(executions))
	for _, execution := range executions {
		items = append(items, cloudWorkerExecutionProjection(execution))
	}
	return CloudWorkerPage{Items: items, NextPageToken: next}, nil
}

func (a *cloudWorkerExecutionAdapter) CancelRun(ctx context.Context, request CloudWorkerRunCancelRequest) (CloudWorkerObject, error) {
	if a == nil || a.store == nil || !validCloudWorkerAuthority(request.Authority) || !coretask.ValidUUID(request.RunID) || request.ExpectedRevision == 0 || !coretask.ValidUUID(request.IdempotencyKey) {
		return nil, ErrInvalid
	}
	execution, err := a.store.RequestCancel(ctx, strings.TrimSpace(request.OwnerID), request.AccountGeneration, request.RunID, request.ExpectedRevision, request.IdempotencyKey)
	if err != nil {
		return nil, mapCloudWorkerPortError(err)
	}
	return cloudWorkerExecutionProjection(execution), nil
}

func (a *cloudWorkerExecutionAdapter) RunEvents(ctx context.Context, request CloudWorkerRunEventsRequest) (CloudWorkerEventPage, error) {
	if a == nil || a.store == nil || !validCloudWorkerAuthority(request.Authority) || !coretask.ValidUUID(request.RunID) || request.Limit < 1 || request.Limit > 200 {
		return CloudWorkerEventPage{}, ErrInvalid
	}
	events, next, err := a.store.EventsForAuthority(ctx, strings.TrimSpace(request.OwnerID), request.AccountGeneration, request.RunID, request.AfterSequence, request.Limit)
	if err != nil {
		return CloudWorkerEventPage{}, mapCloudWorkerPortError(err)
	}
	items := make([]CloudWorkerObject, 0, len(events))
	for _, event := range events {
		items = append(items, cloudWorkerEventProjection(event))
	}
	return CloudWorkerEventPage{Events: items, NextSequence: next}, nil
}

func (a *cloudWorkerExecutionAdapter) GetArtifact(ctx context.Context, request CloudWorkerArtifactGetRequest) (CloudWorkerObject, error) {
	if a == nil || a.store == nil || !validCloudWorkerAuthority(request.Authority) || !coretask.ValidUUID(request.ArtifactID) {
		return nil, ErrInvalid
	}
	artifact, err := a.store.GetArtifactForAuthority(ctx, strings.TrimSpace(request.OwnerID), request.AccountGeneration, request.ArtifactID)
	if err != nil {
		return nil, mapCloudWorkerPortError(err)
	}
	return cloudWorkerArtifactProjection(artifact, request.Authority), nil
}

func (a *cloudWorkerExecutionAdapter) DownloadArtifact(ctx context.Context, request CloudWorkerArtifactDownloadRequest) (CloudWorkerArtifactChunk, error) {
	if a == nil || a.downloads == nil || !validCloudWorkerAuthority(request.Authority) ||
		!coretask.ValidUUID(request.ArtifactID) || request.OffsetBytes >= cloudworker.MaxCloudWorkerOutputBytes ||
		request.MaxChunkBytes == 0 || request.MaxChunkBytes > MaxCloudWorkerArtifactDownloadChunkBytes {
		return CloudWorkerArtifactChunk{}, ErrInvalid
	}
	chunk, err := a.downloads.DownloadArtifact(ctx, cloudworker.ArtifactDownloadRequest{
		OwnerID: strings.TrimSpace(request.OwnerID), AccountGeneration: request.AccountGeneration,
		ArtifactID: request.ArtifactID, OffsetBytes: request.OffsetBytes, MaxChunkBytes: request.MaxChunkBytes,
	})
	if err != nil {
		return CloudWorkerArtifactChunk{}, mapCloudWorkerPortError(err)
	}
	public := CloudWorkerArtifactChunk{
		Authority:  Authority{OwnerID: chunk.OwnerID, AccountGeneration: chunk.AccountGeneration},
		ArtifactID: chunk.ArtifactID, ExecutionID: chunk.ExecutionID, OffsetBytes: chunk.OffsetBytes,
		Data: append([]byte(nil), chunk.Data...), ChunkSHA256: chunk.ChunkSHA256,
		ArtifactSHA256: chunk.ArtifactSHA256, SizeBytes: chunk.SizeBytes,
		NextOffsetBytes: chunk.NextOffsetBytes, EOF: chunk.EOF,
	}
	if chunk.ValidateFor(cloudworker.ArtifactDownloadRequest{
		OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration, ArtifactID: request.ArtifactID,
		OffsetBytes: request.OffsetBytes, MaxChunkBytes: request.MaxChunkBytes,
	}) != nil {
		clear(public.Data)
		return CloudWorkerArtifactChunk{}, ErrUnsafeOutput
	}
	return public, nil
}

func validCloudWorkerAuthority(authority Authority) bool {
	return strings.TrimSpace(authority.OwnerID) != "" && authority.AccountGeneration > 0
}

func validCloudWorkerPageRequest(request CloudWorkerListRequest) bool {
	return request.PageSize >= 1 && request.PageSize <= 200 && len(request.PageToken) <= 2048 && !strings.ContainsAny(request.PageToken, "\r\n\x00")
}

func mapCloudWorkerPortError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, cloudworker.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, cloudworker.ErrInvalid):
		return ErrInvalid
	case errors.Is(err, cloudworker.ErrConflict), errors.Is(err, cloudworker.ErrRevisionConflict),
		errors.Is(err, cloudworker.ErrStaleAuthorization), errors.Is(err, cloudworker.ErrQuoteExpired),
		errors.Is(err, cloudworker.ErrLeaseConflict):
		return ErrConflict
	default:
		return err
	}
}

func cloudWorkerPlanProjection(plan cloudworker.Plan) CloudWorkerObject {
	publicGrants := cloudworker.ProjectPublicSecretGrants(plan.SecretGrants)
	secretGrants := make([]any, 0, len(publicGrants))
	for _, grant := range publicGrants {
		secretGrants = append(secretGrants, map[string]any{"purpose": grant.Purpose})
	}
	networkGrants := make([]any, 0, len(plan.NetworkGrants))
	for _, grant := range plan.NetworkGrants {
		networkGrants = append(networkGrants, grant)
	}
	return CloudWorkerObject{
		"owner_id": plan.OwnerID, "account_generation": plan.AccountGeneration,
		"plan_id": plan.PlanID, "revision": plan.Revision, "status": plan.Status, "digest": plan.Digest,
		"execution_id": plan.ExecutionID, "task_id": plan.TaskID, "confirmation_id": plan.ConfirmationID,
		"conversation_id": plan.ConversationID, "turn_id": plan.TurnID, "recipe_id": plan.RecipeID, "adapter": plan.Adapter,
		"objective_summary": plan.ObjectiveSummary, "proposal_reason": string(plan.ProposalReason),
		"input_manifest_digest": plan.InputManifestDigest, "input_manifest_item_count": plan.InputManifestItemCount,
		"workspace_mode": string(plan.WorkspaceMode),
		"model_authorization": map[string]any{
			"model_profile_id": plan.ModelAuthorization.ModelProfileID, "model_profile_revision": plan.ModelAuthorization.ModelProfileRevision,
			"provider": plan.ModelAuthorization.Provider, "model": plan.ModelAuthorization.Model,
			"interface": plan.ModelAuthorization.Interface, "credential_version": plan.ModelAuthorization.CredentialVersion,
		},
		"aws": map[string]any{
			"account_id": plan.AWS.AccountID, "region": plan.AWS.Region, "credential_revision": plan.AWS.CredentialRevision,
		},
		"compute": map[string]any{
			"instance_type": plan.Compute.InstanceType, "volume_gib": plan.Compute.VolumeGiB,
			"ami_id": plan.Compute.AMIID, "ami_digest": plan.Compute.AMIDigest,
			"worker_release_digest": plan.Compute.WorkerReleaseDigest, "pi_runtime_digest": plan.Compute.PiRuntimeDigest,
			"host_network_policy_sha256": plan.Compute.HostNetworkPolicySHA256, "architecture": plan.Compute.Architecture,
			"root_device_name": plan.Compute.RootDeviceName, "volume_type": plan.Compute.VolumeType,
			"volume_iops": plan.Compute.VolumeIOPS, "volume_throughput_mib": plan.Compute.VolumeThroughputMiB,
		},
		"limits": map[string]any{
			"max_runtime_seconds": plan.Limits.MaxRuntimeSeconds, "max_tokens": plan.Limits.MaxTokens, "max_output_bytes": plan.Limits.MaxOutputBytes,
		},
		"network_grants": networkGrants, "secret_grants": secretGrants,
		"artifact_retention_seconds": plan.ArtifactRetentionSeconds,
		"quote": map[string]any{
			"amount_micros": plan.Quote.AmountMicros, "currency": plan.Quote.Currency,
			"source_time": formatCloudWorkerTime(plan.Quote.SourceTime), "expires_at": formatCloudWorkerTime(plan.Quote.ExpiresAt),
			"maximum_authorized_cost_micros": plan.Quote.MaximumAuthorizedCostMicros,
			"digest":                         plan.Quote.Digest,
		},
		"execution_digest": plan.ExecutionDigest,
		"created_at":       formatCloudWorkerTime(plan.CreatedAt), "updated_at": formatCloudWorkerTime(plan.UpdatedAt),
	}
}

func cloudWorkerExecutionProjection(execution cloudworker.Execution) CloudWorkerObject {
	artifactIDs := make([]any, 0, len(execution.ArtifactIDs))
	for _, id := range execution.ArtifactIDs {
		artifactIDs = append(artifactIDs, id)
	}
	cleanup := map[string]any{
		"verified_destroyed":           execution.Cleanup.VerifiedDestroyed,
		"resources_total":              execution.Cleanup.ResourcesTotal,
		"resources_verified_destroyed": execution.Cleanup.ResourcesVerifiedDestroyed,
	}
	if execution.Cleanup.VerifiedAt != nil {
		cleanup["verified_at"] = formatCloudWorkerTime(*execution.Cleanup.VerifiedAt)
	}
	return CloudWorkerObject{
		"owner_id": execution.OwnerID, "account_generation": execution.AccountGeneration,
		"run_id": execution.RunID, "execution_id": execution.ExecutionID,
		"plan_id": execution.PlanID, "plan_revision": execution.PlanRevision, "plan_digest": execution.PlanDigest,
		"task_id": execution.TaskID, "confirmation_id": execution.ConfirmationID,
		"conversation_id": execution.ConversationID, "turn_id": execution.TurnID,
		"status": string(execution.State), "revision": execution.Revision, "digest": execution.Digest,
		"workspace_mode": string(execution.WorkspaceMode), "quote_digest": execution.QuoteDigest,
		"execution_digest": execution.ExecutionDigest, "cleanup": cleanup, "artifact_ids": artifactIDs,
		"failure_code": execution.FailureCode, "failure_summary": execution.FailureSummary,
		"cancellation_requested": execution.TerminalIntent == string(cloudworker.StateCanceled),
		"created_at":             formatCloudWorkerTime(execution.CreatedAt), "updated_at": formatCloudWorkerTime(execution.UpdatedAt),
	}
}

func cloudWorkerArtifactProjection(artifact cloudworker.Artifact, authority Authority) CloudWorkerObject {
	return CloudWorkerObject{
		"owner_id": authority.OwnerID, "account_generation": authority.AccountGeneration,
		"artifact_id": artifact.ArtifactID, "execution_id": artifact.ExecutionID,
		"kind": artifact.Kind, "name": artifact.Name, "media_type": artifact.MediaType,
		"size_bytes": artifact.SizeBytes, "sha256": artifact.SHA256, "status": string(artifact.Status),
		"created_at": formatCloudWorkerTime(artifact.CreatedAt),
	}
}

func cloudWorkerEventProjection(event cloudworker.Event) CloudWorkerObject {
	out := CloudWorkerObject{
		"event_id": event.EventID, "run_id": event.RunID, "owner_id": event.OwnerID,
		"account_generation": event.AccountGeneration,
		"revision":           event.Revision, "sequence": event.Sequence, "type": event.Type,
		"at": formatCloudWorkerTime(event.CreatedAt), "payload_digest": event.PayloadDigest,
	}
	if event.State != "" {
		out["status"] = string(event.State)
	}
	return out
}

func formatCloudWorkerTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

package cloudworker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

var privateWorkerResultPattern = regexp.MustCompile(`(?i)(?:s3://|arn:(?:aws|aws-cn|aws-us-gov):|\bi-[0-9a-f]{8,32}\b|\b(?:launch|provider|session|lease)[_-]?id\b|169\.254\.169\.254|\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com)`)

// ResultValidator is the sole Worker result -> Core projection. It verifies
// exact S3 versions, the complete execution/session fence, canonical Pi
// output, authorization limits and the public-text safety boundary before an
// artifact or conversation result can be frozen.
type ResultValidator struct {
	readers ResultObjectReaderFactory
	now     func() time.Time
}

type ResultObjectReaderFactory interface {
	ReaderForResult(context.Context, Plan, Execution, LaunchAuthorization) (cloudresult.ObjectReader, error)
}

type ResultObjectReaderFactoryFunc func(context.Context, Plan, Execution, LaunchAuthorization) (cloudresult.ObjectReader, error)

func (factory ResultObjectReaderFactoryFunc) ReaderForResult(ctx context.Context, plan Plan, execution Execution, authorization LaunchAuthorization) (cloudresult.ObjectReader, error) {
	return factory(ctx, plan, execution, authorization)
}

func NewResultValidator(reader cloudresult.ObjectReader, clocks ...func() time.Time) (*ResultValidator, error) {
	if reader == nil {
		return nil, ErrInvalid
	}
	return NewResultValidatorFactory(ResultObjectReaderFactoryFunc(func(context.Context, Plan, Execution, LaunchAuthorization) (cloudresult.ObjectReader, error) {
		return reader, nil
	}), clocks...)
}

// NewResultValidatorFactory is the production constructor. The reader is
// created only after the current Plan/execution/session fence is validated so
// one process-global S3 client can never silently widen an execution prefix.
func NewResultValidatorFactory(factory ResultObjectReaderFactory, clocks ...func() time.Time) (*ResultValidator, error) {
	if factory == nil {
		return nil, ErrInvalid
	}
	clock := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &ResultValidator{readers: factory, now: clock}, nil
}

func (validator *ResultValidator) Collect(
	ctx context.Context,
	plan Plan,
	execution Execution,
	authorization LaunchAuthorization,
	material RuntimeTaskMaterial,
	session control.Session,
) (ProviderResult, error) {
	if validator == nil || ctx == nil || validator.readers == nil ||
		validateResultCollectionAuthority(plan, execution, authorization, material, session) != nil {
		return ProviderResult{}, ErrStaleAuthorization
	}
	reader, err := validator.readers.ReaderForResult(ctx, plan, execution, authorization)
	if err != nil || reader == nil {
		logResultCollectionFailure("reader", plan, session, err)
		return ProviderResult{}, errors.Join(ErrInvalid, err)
	}
	scope := cloudresult.Scope{Bucket: plan.ArtifactGrant.Bucket, KeyPrefix: plan.ArtifactGrant.KeyPrefix}
	collector, err := cloudresult.NewCollector(reader, scope)
	if err != nil {
		logResultCollectionFailure("collector_initialize", plan, session, err)
		return ProviderResult{}, ErrInvalid
	}
	claim := cloudresult.ObjectClaim{
		Name: "result.json", Bucket: session.Result.Bucket, Key: session.Result.Key,
		VersionID: session.Result.VersionID, SHA256: session.Result.SHA256,
		SizeBytes: session.Result.SizeBytes, MediaType: session.Result.MediaType,
	}
	expectation := cloudresult.Expectation{
		ExecutionID: plan.ExecutionID, ExecutionSHA256: plan.ExecutionDigest,
		TaskID: plan.TaskID, TaskSHA256: material.RuntimeTaskSHA256,
		SessionID: session.SessionID, Attempt: int32(session.Fence.Attempt),
		LeaseEpoch: int64(session.Fence.LeaseEpoch), WorkspaceMode: cloudruntime.WorkspaceMode(plan.WorkspaceMode),
	}
	collected, err := collector.Collect(ctx, claim, expectation)
	if err != nil {
		logResultCollectionFailure("object_verification", plan, session, err)
		return ProviderResult{}, err
	}
	defer collected.Destroy()
	if err := validateCollectedLimits(plan, material, collected); err != nil {
		logResultCollectionFailure("limits", plan, session, err)
		return ProviderResult{}, err
	}
	if err := validateCentralResultText(plan, collected.Final); err != nil {
		logResultCollectionFailure("public_text", plan, session, err)
		return ProviderResult{}, err
	}

	// PostgreSQL timestamptz has microsecond precision. Freeze the validation
	// time at that precision so the private retention expiry has one canonical
	// value before and after a process restart.
	createdAt := validator.now().UTC().Truncate(time.Microsecond)
	artifacts := make([]Artifact, 0, len(collected.Artifacts))
	for _, value := range collected.Artifacts {
		kind := "result"
		switch value.Claim.Name {
		case "changes.patch":
			kind = "patch"
		case cloudruntime.WorkspaceDeltaArtifactName:
			kind = "archive"
		}
		artifacts = append(artifacts, Artifact{
			ArtifactID:  deterministicID("cloud-worker-artifact", plan.ExecutionID+":"+value.Claim.Name+":"+value.Claim.SHA256),
			ExecutionID: plan.ExecutionID, Kind: kind, Name: value.Claim.Name,
			MediaType: value.Claim.MediaType, SizeBytes: uint64(value.Claim.SizeBytes),
			SHA256: value.Claim.SHA256, Status: ArtifactVerified, CreatedAt: createdAt,
		})
		retention, retentionErr := artifactRetentionIdentity(plan, artifacts[len(artifacts)-1], value.Claim)
		if retentionErr != nil {
			return ProviderResult{}, retentionErr
		}
		artifacts[len(artifacts)-1].Retention = &retention
	}
	return ProviderResult{Artifacts: artifacts, Summary: centrallyQualifiedSummary(collected.Final)}, nil
}

func validateResultCollectionAuthority(plan Plan, execution Execution, authorization LaunchAuthorization, material RuntimeTaskMaterial, session control.Session) error {
	if plan.Seal() != nil || execution.Seal() != nil ||
		execution.ExecutionID != plan.ExecutionID || execution.PlanDigest != plan.Digest || execution.ExecutionDigest != plan.ExecutionDigest ||
		session.State != control.SessionCompleted || session.Result == nil ||
		session.Fence.ExecutionID != plan.ExecutionID || session.Fence.TaskID != plan.TaskID ||
		session.Fence.AccountGeneration != plan.AccountGeneration || session.Fence.Attempt == 0 || session.Fence.LeaseEpoch == 0 ||
		material.Fence.ExecutionID != session.Fence.ExecutionID || material.Fence.TaskID != session.Fence.TaskID ||
		material.Fence.AccountGeneration != session.Fence.AccountGeneration || material.Fence.Attempt != session.Fence.Attempt ||
		material.Fence.LeaseEpoch != session.Fence.LeaseEpoch ||
		material.RuntimeTaskSHA256 != authorization.RuntimeTaskSHA256 || material.InputManifestSHA256 != authorization.InputManifestSHA256 {
		return ErrStaleAuthorization
	}
	return nil
}

func validateCollectedLimits(
	plan Plan,
	material RuntimeTaskMaterial,
	collected cloudresult.Collected,
) error {
	usage := collected.Manifest.Usage
	if usage.Validate() != nil || usage.OutputTokens < 0 || usage.ReasoningOutputTokens < 0 ||
		uint64(usage.OutputTokens) > plan.Limits.MaxTokens ||
		usage.ReasoningOutputTokens > usage.OutputTokens {
		return ErrInvalid
	}
	var total uint64
	hasWorkspaceDelta := false
	for _, artifact := range collected.Artifacts {
		if artifact.Claim.SizeBytes <= 0 || uint64(artifact.Claim.SizeBytes) > plan.Limits.MaxOutputBytes-total {
			return ErrInvalid
		}
		total += uint64(artifact.Claim.SizeBytes)
		if artifact.Claim.Name == cloudruntime.WorkspaceDeltaArtifactName {
			if hasWorkspaceDelta || cloudruntime.ValidateWorkspaceDeltaArchive(
				artifact.Content,
				material.InputManifestSHA256,
				plan.Limits.MaxOutputBytes,
			) != nil {
				return ErrInvalid
			}
			hasWorkspaceDelta = true
		}
	}
	if total == 0 || total > plan.Limits.MaxOutputBytes {
		return ErrInvalid
	}
	if hasWorkspaceDelta != (plan.WorkspaceMode == WorkspaceWrite) {
		return ErrInvalid
	}
	return nil
}

func logResultCollectionFailure(phase string, plan Plan, session control.Session, err error) {
	class := "unknown"
	switch {
	case errors.Is(err, cloudresult.ErrUnavailable):
		class = "unavailable"
	case errors.Is(err, ErrStaleAuthorization):
		class = "stale_authorization"
	case errors.Is(err, cloudresult.ErrInvalid), errors.Is(err, ErrInvalid):
		class = "invalid"
	case err == nil:
		class = "missing_dependency"
	}
	slog.Warn("[cloud-worker.result] collection_failed",
		"phase", phase, "class", class,
		"execution_id", plan.ExecutionID, "task_id", plan.TaskID,
		"session_id", session.SessionID, "task_attempt", session.Fence.Attempt,
		"lease_epoch", session.Fence.LeaseEpoch)
}

func validateCentralResultText(plan Plan, final cloudruntime.PiFinalV1) error {
	values := []string{final.Summary}
	values = append(values, final.Deliverables...)
	values = append(values, final.Tests...)
	values = append(values, final.Risks...)
	privateValues := []string{
		plan.ArtifactGrant.Bucket, plan.ArtifactGrant.KeyPrefix, plan.AWS.CredentialID,
		plan.WorkerBootstrap.Endpoint, plan.ModelRelay.Endpoint,
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" || security.ContainsLikelySecret(value) || privateWorkerResultPattern.MatchString(value) {
			return ErrInvalid
		}
		for _, privateValue := range privateValues {
			if privateValue != "" && strings.Contains(value, privateValue) {
				return ErrInvalid
			}
		}
	}
	return nil
}

func centrallyQualifiedSummary(final cloudruntime.PiFinalV1) string {
	var output strings.Builder
	fmt.Fprintf(&output, "Cloud Worker result (%s; identity, schema, limits, and artifact integrity verified):\n%s", final.Status, final.Summary)
	if len(final.Deliverables) > 0 {
		output.WriteString("\n\nDeliverables:\n")
		for _, value := range final.Deliverables {
			fmt.Fprintf(&output, "- %s\n", value)
		}
	}
	if len(final.Tests) > 0 {
		output.WriteString("\nWorker-reported checks:\n")
		for _, value := range final.Tests {
			fmt.Fprintf(&output, "- %s\n", value)
		}
	}
	// Worker-authored risks are retained in the private, integrity-checked
	// final artifact but are not promoted as centrally validated conclusions.
	// This value is written into both the Execution projection and the
	// authoritative conversation message. Bound it before cleanup completes so
	// an otherwise valid large Pi final cannot make the terminal transaction
	// fail forever after the ephemeral resources have already been destroyed.
	return boundedSummary(output.String())
}

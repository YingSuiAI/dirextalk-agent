// Package workerresult verifies the transport integrity of completed Worker
// result manifests and fetches only bounded final artifacts for Central Agent
// synthesis. Worker claims remain untrusted until a separate Validator passes.
package workerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamresult"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

var (
	ErrInvalid     = errors.New("invalid Worker result")
	ErrUnavailable = errors.New("Worker result is unavailable")
)

type ObjectReader interface {
	Get(context.Context, string, int64) ([]byte, error)
}

type Collector struct {
	objects ObjectReader
}

func NewCollector(objects ObjectReader) (*Collector, error) {
	if objects == nil {
		return nil, ErrInvalid
	}
	return &Collector{objects: objects}, nil
}

type Collected struct {
	Manifest      workerrunner.ResultManifestV2
	ManifestClaim worker.ObjectClaim
	Finals        []workerruntime.Artifact
	FinalClaims   []worker.ObjectClaim
	Artifacts     []CollectedArtifact
}

type CollectedArtifact struct {
	ActionID string
	Adapter  workerruntime.Adapter
	Artifact workerruntime.Artifact
	Claim    worker.ObjectClaim
}

func (result *Collected) Destroy() {
	if result == nil {
		return
	}
	for index := range result.Artifacts {
		clear(result.Artifacts[index].Artifact.Content)
	}
	*result = Collected{}
}

// Collect verifies the final result claim and manifest, then downloads every
// bounded runtime artifact. Bytes remain transient in memory; verified object
// bindings are persisted separately before Worker cleanup begins.
func (collector *Collector) Collect(
	ctx context.Context,
	deployment worker.Deployment,
) (Collected, error) {
	if collector == nil || collector.objects == nil ||
		ctx == nil || deployment.State != worker.StateFinished ||
		deployment.Outcome != worker.OutcomeSucceeded ||
		deployment.ResultRef == "" ||
		deployment.Access.Validate() != nil ||
		deployment.Lease.Attempt < 1 || deployment.Lease.Epoch < 1 {
		return Collected{}, ErrInvalid
	}
	resultClaim, err := resultObjectClaim(deployment)
	if err != nil {
		return Collected{}, err
	}
	if !referenceWithinPrefix(
		resultClaim.Ref, deployment.Access.ArtifactPrefix,
	) {
		return Collected{}, ErrInvalid
	}
	raw, err := collector.verifiedObject(ctx, resultClaim)
	if err != nil {
		return Collected{}, err
	}
	defer clear(raw)
	if resultClaim.MediaType != "application/json" ||
		security.ContainsLikelySecret(string(raw)) {
		return Collected{}, ErrInvalid
	}
	expectation, err := expectationFromDeployment(deployment)
	if err != nil {
		return Collected{}, err
	}
	manifest, err := workerrunner.ParseResultManifestV2(
		raw, expectation,
	)
	if err != nil {
		return Collected{}, ErrInvalid
	}
	finals := make([]workerruntime.Artifact, 0, len(manifest.RuntimeResults))
	finalClaims := make(
		[]worker.ObjectClaim,
		0,
		len(manifest.RuntimeResults),
	)
	artifacts := make([]CollectedArtifact, 0)
	for _, runtimeResult := range manifest.RuntimeResults {
		foundFinal := false
		for _, remoteArtifact := range runtimeResult.Artifacts {
			claim, claimErr := objectClaimFromRuntime(remoteArtifact)
			if claimErr != nil {
				destroyCollectedArtifacts(artifacts)
				return Collected{}, claimErr
			}
			content, readErr := collector.verifiedObject(ctx, claim)
			if readErr != nil {
				destroyCollectedArtifacts(artifacts)
				return Collected{}, readErr
			}
			artifact := workerruntime.Artifact{
				Name:      remoteArtifact.Name,
				MediaType: remoteArtifact.MediaType,
				Content:   content,
			}
			if artifact.Validate() != nil {
				clear(content)
				destroyCollectedArtifacts(artifacts)
				return Collected{}, ErrInvalid
			}
			artifacts = append(artifacts, CollectedArtifact{
				ActionID: runtimeResult.ActionID,
				Adapter:  runtimeResult.Adapter,
				Artifact: artifact,
				Claim:    claim,
			})
			if artifact.Name == "final.json" {
				if foundFinal ||
					claim.SizeBytes > workerruntime.MaxFinalArtifactBytes {
					destroyCollectedArtifacts(artifacts)
					return Collected{}, ErrInvalid
				}
				foundFinal = true
				finals = append(finals, artifact)
				finalClaims = append(finalClaims, claim)
			}
		}
		if !foundFinal {
			destroyCollectedArtifacts(artifacts)
			return Collected{}, ErrInvalid
		}
	}
	return Collected{
		Manifest:      manifest,
		ManifestClaim: resultClaim,
		Finals:        finals,
		FinalClaims:   finalClaims,
		Artifacts:     artifacts,
	}, nil
}

// ValidateTeamRole turns transport-verified Worker bytes into bounded,
// durable Team result evidence. Only adapters with an independent final
// validator are accepted.
func ValidateTeamRole(
	intent teamdispatch.IntentV1,
	deployment worker.Deployment,
	collected Collected,
) (teamresult.EvidenceV1, error) {
	if intent.Validate() != nil ||
		deployment.DeploymentID != intent.DeploymentID ||
		deployment.OwnerID != intent.OwnerID ||
		deployment.TaskID != intent.TaskID ||
		deployment.StepID != intent.TaskStepID ||
		deployment.WorkerID != intent.ExpectedWorkerID ||
		deployment.State != worker.StateFinished ||
		deployment.Outcome != worker.OutcomeSucceeded ||
		deployment.ResultRef == "" ||
		deployment.ResultRef != collected.ManifestClaim.Ref ||
		collected.ManifestClaim.Validate() != nil ||
		len(collected.Manifest.RuntimeResults) == 0 ||
		len(collected.Manifest.RuntimeResults) != len(collected.Finals) ||
		len(collected.Finals) != len(collected.FinalClaims) {
		return teamresult.EvidenceV1{}, ErrInvalid
	}
	finals := make(
		[]teamresult.FinalV1,
		0,
		len(collected.Manifest.RuntimeResults),
	)
	for index, runtimeResult := range collected.Manifest.RuntimeResults {
		artifact := collected.Finals[index]
		claim := collected.FinalClaims[index]
		if artifact.Name != "final.json" ||
			artifact.MediaType != "application/json" ||
			claim.Validate() != nil ||
			claim.Ref == collected.ManifestClaim.Ref ||
			claim.MediaType != artifact.MediaType ||
			claim.SizeBytes != int64(len(artifact.Content)) {
			return teamresult.EvidenceV1{}, ErrInvalid
		}
		digest := sha256.Sum256(artifact.Content)
		if subtle.ConstantTimeCompare(
			digest[:],
			claim.SHA256[:],
		) != 1 {
			return teamresult.EvidenceV1{}, ErrInvalid
		}
		switch runtimeResult.Adapter {
		case workerruntime.AdapterCodexV1:
			final, canonical, err :=
				workerruntime.ParseCodexFinalV1(artifact.Content)
			if err != nil || !bytes.Equal(canonical, artifact.Content) {
				clear(canonical)
				return teamresult.EvidenceV1{}, ErrInvalid
			}
			clear(canonical)
			finals = append(finals, teamresult.FinalV1{
				ActionID:          runtimeResult.ActionID,
				Adapter:           runtimeResult.Adapter,
				Usage:             runtimeResult.Usage,
				Status:            final.Status,
				Summary:           final.Summary,
				Deliverables:      final.Deliverables,
				Tests:             final.Tests,
				Risks:             final.Risks,
				ArtifactRef:       claim.Ref,
				ArtifactSHA256:    claim.Digest(),
				ArtifactSizeBytes: claim.SizeBytes,
				ArtifactMediaType: claim.MediaType,
			})
		case workerruntime.AdapterPiV1:
			final, canonical, err :=
				workerruntime.ParsePiFinalV1(artifact.Content)
			if err != nil || !bytes.Equal(canonical, artifact.Content) {
				clear(canonical)
				return teamresult.EvidenceV1{}, ErrInvalid
			}
			clear(canonical)
			finals = append(finals, teamresult.FinalV1{
				ActionID:          runtimeResult.ActionID,
				Adapter:           runtimeResult.Adapter,
				Usage:             runtimeResult.Usage,
				Status:            final.Status,
				Summary:           final.Summary,
				Deliverables:      final.Deliverables,
				Tests:             final.Tests,
				Risks:             final.Risks,
				ArtifactRef:       claim.Ref,
				ArtifactSHA256:    claim.Digest(),
				ArtifactSizeBytes: claim.SizeBytes,
				ArtifactMediaType: claim.MediaType,
			})
		default:
			return teamresult.EvidenceV1{}, ErrInvalid
		}
	}
	evidence := teamresult.EvidenceV1{
		SchemaVersion:    teamresult.SchemaV1,
		OperationID:      intent.OperationID,
		ExecutionID:      intent.ExecutionID,
		RoleID:           intent.RoleID,
		DeploymentID:     intent.DeploymentID,
		ExpectedWorkerID: intent.ExpectedWorkerID,
		TaskID:           intent.TaskID,
		TaskStepID:       intent.TaskStepID,
		WorkerID:         deployment.WorkerID,
		Attempt:          deployment.Lease.Attempt,
		LeaseEpoch:       deployment.Lease.Epoch,
		ResultRef:        collected.ManifestClaim.Ref,
		ResultSHA256:     collected.ManifestClaim.Digest(),
		ResultSizeBytes:  collected.ManifestClaim.SizeBytes,
		ResultMediaType:  collected.ManifestClaim.MediaType,
		Finals:           finals,
	}
	if evidence.Validate() != nil {
		return teamresult.EvidenceV1{}, ErrInvalid
	}
	return evidence, nil
}

// VerifiedTeamArtifacts converts the transport-verified transient bytes into
// immutable registry facts. Every artifact is rebound to the approved Team
// identity, and each final.json must match the frozen role evidence exactly.
func VerifiedTeamArtifacts(
	intent teamdispatch.IntentV1,
	connectionID string,
	deployment worker.Deployment,
	evidence teamresult.EvidenceV1,
	collected Collected,
	createdAt time.Time,
	retention time.Duration,
) ([]teamartifact.ArtifactV1, error) {
	if intent.Validate() != nil ||
		evidence.Validate() != nil ||
		deployment.DeploymentID != intent.DeploymentID ||
		deployment.OwnerID != intent.OwnerID ||
		deployment.WorkerID != intent.ExpectedWorkerID ||
		evidence.OperationID != intent.OperationID ||
		evidence.ExecutionID != intent.ExecutionID ||
		evidence.RoleID != intent.RoleID ||
		evidence.DeploymentID != intent.DeploymentID ||
		len(collected.Artifacts) == 0 ||
		len(collected.Artifacts) > teamartifact.MaximumArtifactsPerRole ||
		retention <= 0 || retention > 366*24*time.Hour {
		return nil, ErrInvalid
	}
	createdAt = createdAt.UTC().Truncate(time.Microsecond)
	expiresAt := createdAt.Add(retention).UTC().Truncate(time.Microsecond)
	finals := make(map[string]teamresult.FinalV1, len(evidence.Finals))
	for _, final := range evidence.Finals {
		finals[final.ActionID] = final
	}
	registered := make([]teamartifact.ArtifactV1, 0, len(collected.Artifacts))
	seen := make(map[string]struct{}, len(collected.Artifacts))
	for _, item := range collected.Artifacts {
		if !teamActionArtifactMatchesManifest(collected.Manifest, item) ||
			item.Claim.Validate() != nil ||
			item.Artifact.Validate() != nil ||
			item.Claim.SizeBytes != int64(len(item.Artifact.Content)) ||
			item.Claim.MediaType != item.Artifact.MediaType {
			return nil, ErrInvalid
		}
		digest, err := item.Artifact.Digest()
		if err != nil || digest != item.Claim.Digest() {
			return nil, ErrInvalid
		}
		if item.Artifact.Name == "final.json" {
			final, found := finals[item.ActionID]
			if !found ||
				final.ArtifactRef != item.Claim.Ref ||
				final.ArtifactSHA256 != digest ||
				final.ArtifactSizeBytes != item.Claim.SizeBytes ||
				final.ArtifactMediaType != item.Claim.MediaType {
				return nil, ErrInvalid
			}
		}
		artifact, err := teamartifact.NewVerified(teamartifact.BuildRequest{
			AgentInstanceID:  intent.AgentInstanceID,
			OwnerID:          intent.OwnerID,
			ExecutionID:      intent.ExecutionID,
			OperationID:      intent.OperationID,
			TaskID:           intent.TaskID,
			PlanID:           intent.PlanID,
			PlanRevision:     intent.PlanRevision,
			ConnectionID:     connectionID,
			RoleID:           intent.RoleID,
			ActionID:         item.ActionID,
			DeploymentID:     intent.DeploymentID,
			Name:             item.Artifact.Name,
			MediaType:        item.Artifact.MediaType,
			SizeBytes:        item.Claim.SizeBytes,
			SHA256:           digest,
			ObjectRef:        item.Claim.Ref,
			CreatedAt:        createdAt,
			RetentionExpires: expiresAt,
		})
		if err != nil {
			return nil, ErrInvalid
		}
		if _, duplicate := seen[artifact.ArtifactID]; duplicate {
			return nil, ErrInvalid
		}
		seen[artifact.ArtifactID] = struct{}{}
		registered = append(registered, artifact)
	}
	for actionID := range finals {
		found := false
		for _, artifact := range registered {
			if artifact.ActionID == actionID && artifact.Name == "final.json" {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrInvalid
		}
	}
	return registered, nil
}

func teamActionArtifactMatchesManifest(
	manifest workerrunner.ResultManifestV2,
	item CollectedArtifact,
) bool {
	for _, result := range manifest.RuntimeResults {
		if result.ActionID != item.ActionID || result.Adapter != item.Adapter {
			continue
		}
		for _, claim := range result.Artifacts {
			if claim.Name == item.Artifact.Name &&
				claim.Ref == item.Claim.Ref &&
				claim.SHA256 == item.Claim.Digest() &&
				claim.SizeBytes == item.Claim.SizeBytes &&
				claim.MediaType == item.Claim.MediaType {
				return true
			}
		}
	}
	return false
}

func (collector *Collector) verifiedObject(
	ctx context.Context,
	claim worker.ObjectClaim,
) ([]byte, error) {
	if claim.Validate() != nil {
		return nil, ErrInvalid
	}
	raw, err := collector.objects.Get(
		ctx, claim.Ref, claim.SizeBytes,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	if int64(len(raw)) != claim.SizeBytes ||
		len(raw) > int(worker.MaximumObjectClaimBytes) {
		clear(raw)
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(digest[:], claim.SHA256[:]) != 1 {
		clear(raw)
		return nil, ErrInvalid
	}
	return raw, nil
}

func resultObjectClaim(
	deployment worker.Deployment,
) (worker.ObjectClaim, error) {
	var found *worker.EvidenceRef
	for index := range deployment.Evidence {
		evidence := &deployment.Evidence[index]
		if evidence.Kind != "artifact" ||
			evidence.Ref != deployment.ResultRef {
			continue
		}
		if found != nil {
			return worker.ObjectClaim{}, ErrInvalid
		}
		found = evidence
	}
	if found == nil || found.Trust != worker.TrustWorkerClaim ||
		found.Attempt != deployment.Lease.Attempt ||
		found.LeaseEpoch != deployment.Lease.Epoch {
		return worker.ObjectClaim{}, ErrInvalid
	}
	digest, err := parseDigest(found.ObjectSHA256)
	if err != nil {
		return worker.ObjectClaim{}, ErrInvalid
	}
	claim := worker.ObjectClaim{
		Ref: found.Ref, SHA256: digest, SizeBytes: found.SizeBytes,
		MediaType: found.MediaType,
	}
	if claim.Validate() != nil {
		return worker.ObjectClaim{}, ErrInvalid
	}
	return claim, nil
}

func objectClaimFromRuntime(
	value workerrunner.RuntimeArtifactClaimV1,
) (worker.ObjectClaim, error) {
	digest, err := parseDigest(value.SHA256)
	if err != nil {
		return worker.ObjectClaim{}, ErrInvalid
	}
	claim := worker.ObjectClaim{
		Ref: value.Ref, SHA256: digest, SizeBytes: value.SizeBytes,
		MediaType: value.MediaType,
	}
	if claim.Validate() != nil {
		return worker.ObjectClaim{}, ErrInvalid
	}
	return claim, nil
}

func expectationFromDeployment(
	deployment worker.Deployment,
) (workerrunner.ResultExpectationV2, error) {
	bucket, prefix, err := splitPrefix(deployment.Access.ArtifactPrefix)
	if err != nil {
		return workerrunner.ResultExpectationV2{}, ErrInvalid
	}
	return workerrunner.ResultExpectationV2{
		DeploymentID: deployment.DeploymentID,
		WorkerID:     deployment.WorkerID,
		TaskID:       deployment.TaskID,
		StepID:       deployment.StepID,
		Attempt:      deployment.Lease.Attempt,
		LeaseEpoch:   deployment.Lease.Epoch,
		RecipeSHA256: hex.EncodeToString(
			deployment.RecipeBundle.SHA256[:],
		),
		ExecutionSHA256: hex.EncodeToString(
			deployment.ExecutionBundle.SHA256[:],
		),
		ArtifactBucket: bucket, ArtifactPrefix: prefix,
	}, nil
}

func splitPrefix(reference string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(reference))
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" ||
		parsed.Path == "" || !strings.HasSuffix(parsed.Path, "/") ||
		parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return "", "", ErrInvalid
	}
	return parsed.Host, strings.TrimPrefix(parsed.Path, "/"), nil
}

func referenceWithinPrefix(reference, prefix string) bool {
	refURL, refErr := url.Parse(strings.TrimSpace(reference))
	prefixURL, prefixErr := url.Parse(strings.TrimSpace(prefix))
	if refErr != nil || prefixErr != nil ||
		refURL.Scheme != "s3" || prefixURL.Scheme != "s3" ||
		refURL.Host == "" || refURL.Host != prefixURL.Host ||
		refURL.User != nil || prefixURL.User != nil ||
		refURL.RawQuery != "" || prefixURL.RawQuery != "" ||
		refURL.Fragment != "" || prefixURL.Fragment != "" ||
		!strings.HasSuffix(prefixURL.Path, "/") ||
		!strings.HasPrefix(refURL.Path, prefixURL.Path) {
		return false
	}
	name := strings.TrimPrefix(refURL.Path, prefixURL.Path)
	return name != "" && !strings.Contains(name, "/") &&
		!strings.Contains(name, "..")
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if !strings.HasPrefix(value, "sha256:") {
		return digest, ErrInvalid
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return digest, ErrInvalid
	}
	copy(digest[:], decoded)
	clear(decoded)
	return digest, nil
}

func destroyCollectedArtifacts(values []CollectedArtifact) {
	for index := range values {
		clear(values[index].Artifact.Content)
	}
}

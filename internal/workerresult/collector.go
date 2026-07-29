// Package workerresult verifies the transport integrity of completed Worker
// result manifests and fetches only bounded final artifacts for Central Agent
// synthesis. Worker claims remain untrusted until a separate Validator passes.
package workerresult

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
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
	Manifest workerrunner.ResultManifestV2
	Finals   []workerruntime.Artifact
}

func (result *Collected) Destroy() {
	if result == nil {
		return
	}
	for index := range result.Finals {
		clear(result.Finals[index].Content)
	}
	*result = Collected{}
}

// Collect verifies the final result claim and manifest, then downloads only
// each runtime's final.json. Patches and other large artifacts remain remote
// and can be fetched later through their verified claims.
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
	for _, runtimeResult := range manifest.RuntimeResults {
		var finalClaim *workerrunner.RuntimeArtifactClaimV1
		for index := range runtimeResult.Artifacts {
			artifact := &runtimeResult.Artifacts[index]
			if artifact.Name == "final.json" {
				if finalClaim != nil {
					destroyArtifacts(finals)
					return Collected{}, ErrInvalid
				}
				finalClaim = artifact
			}
		}
		if finalClaim == nil ||
			finalClaim.SizeBytes > workerruntime.MaxFinalArtifactBytes {
			destroyArtifacts(finals)
			return Collected{}, ErrInvalid
		}
		claim, err := objectClaimFromRuntime(*finalClaim)
		if err != nil {
			destroyArtifacts(finals)
			return Collected{}, err
		}
		content, err := collector.verifiedObject(ctx, claim)
		if err != nil {
			destroyArtifacts(finals)
			return Collected{}, err
		}
		artifact := workerruntime.Artifact{
			Name: finalClaim.Name, MediaType: finalClaim.MediaType,
			Content: content,
		}
		if artifact.Validate() != nil {
			clear(content)
			destroyArtifacts(finals)
			return Collected{}, ErrInvalid
		}
		finals = append(finals, artifact)
	}
	return Collected{Manifest: manifest, Finals: finals}, nil
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

func destroyArtifacts(values []workerruntime.Artifact) {
	for index := range values {
		clear(values[index].Content)
	}
}

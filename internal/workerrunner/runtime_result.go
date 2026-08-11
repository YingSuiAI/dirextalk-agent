package workerrunner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/artifactmedia"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

var runtimeArtifactNamePattern = regexp.MustCompile(
	`^[a-z][a-z0-9._-]{0,127}$`,
)

const ResultManifestSchemaV2 = 2

const MaxRuntimeResultsPerManifest = 8

type RuntimeArtifactClaimV1 struct {
	Attempt    int32  `json:"attempt"`
	LeaseEpoch int64  `json:"lease_epoch"`
	Name       string `json:"name"`
	Ref        string `json:"ref"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	MediaType  string `json:"media_type"`
}

type RuntimeActionResultV1 struct {
	ActionID  string                   `json:"action_id"`
	TaskID    string                   `json:"task_id"`
	Adapter   workerruntime.Adapter    `json:"adapter"`
	Usage     workerruntime.Usage      `json:"usage"`
	Artifacts []RuntimeArtifactClaimV1 `json:"artifacts"`
}

type ResultManifestV2 struct {
	SchemaVersion    int                     `json:"schema_version"`
	DeploymentID     string                  `json:"deployment_id"`
	WorkerID         string                  `json:"worker_id"`
	TaskID           string                  `json:"task_id"`
	StepID           string                  `json:"step_id"`
	Attempt          int32                   `json:"attempt"`
	LeaseEpoch       int64                   `json:"lease_epoch"`
	RecipeSHA256     string                  `json:"recipe_sha256"`
	ExecutionSHA256  string                  `json:"execution_sha256"`
	Status           string                  `json:"status"`
	CompletedActions []string                `json:"completed_actions"`
	RuntimeResults   []RuntimeActionResultV1 `json:"runtime_results,omitempty"`
}

type ResultExpectationV2 struct {
	DeploymentID    string
	WorkerID        string
	TaskID          string
	StepID          string
	Attempt         int32
	LeaseEpoch      int64
	RecipeSHA256    string
	ExecutionSHA256 string
	ArtifactBucket  string
	ArtifactPrefix  string
}

func ParseResultManifestV2(
	raw []byte,
	expectation ResultExpectationV2,
) (ResultManifestV2, error) {
	if len(raw) == 0 || len(raw) > maxBundleBytes {
		return ResultManifestV2{}, ErrInvalidBundle
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest ResultManifestV2
	if err := decoder.Decode(&manifest); err != nil {
		return ResultManifestV2{}, ErrInvalidBundle
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ResultManifestV2{}, ErrInvalidBundle
	}
	if err := manifest.Validate(expectation); err != nil {
		return ResultManifestV2{}, err
	}
	return manifest, nil
}

func (manifest ResultManifestV2) Validate(
	expectation ResultExpectationV2,
) error {
	if manifest.SchemaVersion != ResultManifestSchemaV2 ||
		manifest.DeploymentID != expectation.DeploymentID ||
		manifest.WorkerID != expectation.WorkerID ||
		manifest.TaskID != expectation.TaskID ||
		manifest.StepID != expectation.StepID ||
		manifest.Attempt != expectation.Attempt ||
		manifest.LeaseEpoch != expectation.LeaseEpoch ||
		manifest.RecipeSHA256 != expectation.RecipeSHA256 ||
		manifest.ExecutionSHA256 != expectation.ExecutionSHA256 ||
		manifest.Status != "succeeded" ||
		!validResultExpectation(expectation) ||
		len(manifest.CompletedActions) == 0 ||
		len(manifest.CompletedActions) > maxActions ||
		len(manifest.RuntimeResults) > len(manifest.CompletedActions) ||
		len(manifest.RuntimeResults) > MaxRuntimeResultsPerManifest {
		return ErrInvalidBundle
	}
	actionOrder := make(map[string]int, len(manifest.CompletedActions))
	for index, actionID := range manifest.CompletedActions {
		if !actionIDPattern.MatchString(actionID) {
			return ErrInvalidBundle
		}
		if _, duplicate := actionOrder[actionID]; duplicate {
			return ErrInvalidBundle
		}
		actionOrder[actionID] = index
	}
	lastActionIndex := -1
	seenResults := make(map[string]struct{}, len(manifest.RuntimeResults))
	for _, result := range manifest.RuntimeResults {
		index, completed := actionOrder[result.ActionID]
		if !completed || index <= lastActionIndex ||
			result.TaskID != manifest.TaskID ||
			!canonicalResultUUID(result.TaskID) ||
			!result.Adapter.IsSupported() ||
			result.Usage.Validate() != nil ||
			len(result.Artifacts) == 0 ||
			len(result.Artifacts) > workerruntime.MaxArtifactsPerResult {
			return ErrInvalidBundle
		}
		if _, duplicate := seenResults[result.ActionID]; duplicate {
			return ErrInvalidBundle
		}
		seenResults[result.ActionID] = struct{}{}
		lastActionIndex = index
		var totalBytes int64
		hasFinal := false
		seenNames := make(map[string]struct{}, len(result.Artifacts))
		seenRefs := make(map[string]struct{}, len(result.Artifacts))
		for _, artifact := range result.Artifacts {
			if _, duplicate := seenNames[artifact.Name]; duplicate {
				return ErrInvalidBundle
			}
			if _, duplicate := seenRefs[artifact.Ref]; duplicate {
				return ErrInvalidBundle
			}
			seenNames[artifact.Name] = struct{}{}
			seenRefs[artifact.Ref] = struct{}{}
			if validateRuntimeArtifactClaimScope(
				artifact, result.ActionID,
				expectation.ArtifactBucket,
				expectation.ArtifactPrefix,
				manifest.Attempt, manifest.LeaseEpoch,
			) != nil {
				return ErrInvalidBundle
			}
			if artifact.Name == "final.json" {
				if artifact.MediaType != "application/json" ||
					artifact.SizeBytes >
						workerruntime.MaxFinalArtifactBytes {
					return ErrInvalidBundle
				}
				hasFinal = true
			}
			totalBytes += artifact.SizeBytes
			if totalBytes > workerruntime.MaxResultBytes {
				return ErrInvalidBundle
			}
		}
		if !hasFinal {
			return ErrInvalidBundle
		}
	}
	return nil
}

func validResultExpectation(value ResultExpectationV2) bool {
	return canonicalResultUUID(value.DeploymentID) &&
		canonicalResultUUID(value.WorkerID) &&
		canonicalResultUUID(value.TaskID) &&
		canonicalResultUUID(value.StepID) &&
		value.Attempt > 0 && value.LeaseEpoch > 0 &&
		exactHexDigest(value.RecipeSHA256) &&
		exactHexDigest(value.ExecutionSHA256) &&
		value.ArtifactBucket != "" &&
		validObjectPrefix(value.ArtifactPrefix)
}

func canonicalResultUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func exactHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size ||
		hex.EncodeToString(decoded) != value {
		clear(decoded)
		return false
	}
	clear(decoded)
	return true
}

func runtimeActionResultFrom(
	action ActionV1,
	attempt int32,
	leaseEpoch int64,
	claims []RuntimeArtifactClaimV1,
	usage workerruntime.Usage,
) (RuntimeActionResultV1, error) {
	if action.Runtime == nil || attempt < 1 || leaseEpoch < 1 ||
		len(claims) == 0 {
		return RuntimeActionResultV1{}, ErrInvalidBundle
	}
	value := RuntimeActionResultV1{
		ActionID: action.ID, TaskID: action.Runtime.Task.TaskID,
		Adapter: action.Runtime.Task.Adapter, Usage: usage,
		Artifacts: claims,
	}
	return value, nil
}

func validateRuntimeResults(
	bundle ExecutionBundleV1,
	actionIndex int,
	results []RuntimeActionResultV1,
	access *agentv1.WorkerAccessScope,
	checkpointAttempt int32,
	checkpointLeaseEpoch int64,
) error {
	if actionIndex < 0 || actionIndex >= len(bundle.Actions) ||
		checkpointAttempt < 1 || checkpointLeaseEpoch < 1 {
		return ErrInvalidBundle
	}
	resultIndex := 0
	for index := 0; index <= actionIndex; index++ {
		action := bundle.Actions[index]
		if action.Runtime == nil {
			continue
		}
		if resultIndex >= len(results) {
			return ErrInvalidBundle
		}
		result := results[resultIndex]
		if result.ActionID != action.ID ||
			result.TaskID != action.Runtime.Task.TaskID ||
			result.Adapter != action.Runtime.Task.Adapter ||
			result.Usage.Validate() != nil ||
			len(result.Artifacts) == 0 ||
			len(result.Artifacts) > workerruntime.MaxArtifactsPerResult {
			return ErrInvalidBundle
		}
		seenNames := make(map[string]struct{}, len(result.Artifacts))
		seenRefs := make(map[string]struct{}, len(result.Artifacts))
		var totalBytes int64
		hasFinal := false
		for _, artifact := range result.Artifacts {
			if _, duplicate := seenNames[artifact.Name]; duplicate {
				return ErrInvalidBundle
			}
			if _, duplicate := seenRefs[artifact.Ref]; duplicate {
				return ErrInvalidBundle
			}
			seenNames[artifact.Name] = struct{}{}
			seenRefs[artifact.Ref] = struct{}{}
			if validateRuntimeArtifactClaim(
				artifact, action.ID, access,
				checkpointAttempt, checkpointLeaseEpoch,
			) != nil {
				return ErrInvalidBundle
			}
			if artifact.Name == "final.json" {
				if artifact.MediaType != "application/json" ||
					artifact.SizeBytes >
						workerruntime.MaxFinalArtifactBytes {
					return ErrInvalidBundle
				}
				hasFinal = true
			}
			totalBytes += artifact.SizeBytes
			if totalBytes > workerruntime.MaxResultBytes {
				return ErrInvalidBundle
			}
		}
		if !hasFinal {
			return ErrInvalidBundle
		}
		resultIndex++
	}
	if resultIndex != len(results) {
		return ErrInvalidBundle
	}
	return nil
}

func validateRuntimeArtifactClaim(
	artifact RuntimeArtifactClaimV1,
	actionID string,
	access *agentv1.WorkerAccessScope,
	checkpointAttempt int32,
	checkpointLeaseEpoch int64,
) error {
	if access == nil {
		return ErrInvalidBundle
	}
	return validateRuntimeArtifactClaimScope(
		artifact, actionID, access.GetArtifactBucket(),
		access.GetArtifactPrefix(), checkpointAttempt,
		checkpointLeaseEpoch,
	)
}

func validateRuntimeArtifactClaimScope(
	artifact RuntimeArtifactClaimV1,
	actionID string,
	bucket string,
	prefix string,
	checkpointAttempt int32,
	checkpointLeaseEpoch int64,
) error {
	if artifact.Attempt < 1 || artifact.Attempt > checkpointAttempt ||
		artifact.LeaseEpoch < 1 ||
		artifact.LeaseEpoch > checkpointLeaseEpoch ||
		(artifact.Attempt == checkpointAttempt &&
			artifact.LeaseEpoch != checkpointLeaseEpoch) ||
		!runtimeArtifactNamePattern.MatchString(artifact.Name) ||
		artifact.SizeBytes < 1 ||
		artifact.SizeBytes > workerruntime.MaxArtifactBytes {
		return ErrInvalidBundle
	}
	digest, err := parseRuntimeDigest(artifact.SHA256)
	if err != nil {
		return ErrInvalidBundle
	}
	claim := worker.ObjectClaim{
		Ref: artifact.Ref, SHA256: digest,
		SizeBytes: artifact.SizeBytes, MediaType: artifact.MediaType,
	}
	expected, err := scopedRuntimeArtifactRef(
		&agentv1.WorkerAccessScope{
			ArtifactBucket: bucket, ArtifactPrefix: prefix,
		}, artifact.Attempt, artifact.LeaseEpoch,
		actionID, artifact.Name, artifact.MediaType, digest,
	)
	if err != nil || claim.Validate() != nil || expected != artifact.Ref ||
		!artifactRefWithinScopeValues(
			bucket, prefix, artifact.Ref,
		) {
		return ErrInvalidBundle
	}
	return nil
}

func runtimeArtifactManifest(
	attempt int32,
	leaseEpoch int64,
	artifact workerruntime.Artifact,
	claim worker.ObjectClaim,
) (RuntimeArtifactClaimV1, error) {
	if artifact.Validate() != nil || claim.Validate() != nil ||
		attempt < 1 || leaseEpoch < 1 ||
		claim.SizeBytes != int64(len(artifact.Content)) ||
		claim.MediaType != artifact.MediaType {
		return RuntimeArtifactClaimV1{}, ErrInvalidBundle
	}
	digest := sha256.Sum256(artifact.Content)
	if digest != claim.SHA256 {
		return RuntimeArtifactClaimV1{}, ErrInvalidBundle
	}
	return RuntimeArtifactClaimV1{
		Attempt: attempt, LeaseEpoch: leaseEpoch,
		Name: artifact.Name, Ref: claim.Ref,
		SHA256:    "sha256:" + hex.EncodeToString(digest[:]),
		SizeBytes: claim.SizeBytes, MediaType: claim.MediaType,
	}, nil
}

func scopedRuntimeArtifactRef(
	access *agentv1.WorkerAccessScope,
	attempt int32,
	leaseEpoch int64,
	actionID string,
	artifactName string,
	mediaType string,
	digest [sha256.Size]byte,
) (string, error) {
	if access == nil || attempt < 1 || leaseEpoch < 1 ||
		!actionIDPattern.MatchString(actionID) ||
		!runtimeArtifactNamePattern.MatchString(artifactName) {
		return "", errors.New("Worker runtime artifact scope is invalid")
	}
	extension, supported := artifactmedia.Extension(mediaType)
	if !supported {
		return "", errors.New("Worker runtime artifact media type is invalid")
	}
	nameDigest := sha256.Sum256([]byte(artifactName))
	name := fmt.Sprintf(
		"runtime-a%d-e%d-%s-%s-%s.%s",
		attempt, leaseEpoch, actionID,
		hex.EncodeToString(nameDigest[:8]),
		hex.EncodeToString(digest[:]), extension,
	)
	return scopedArtifactObjectRef(access, name)
}

func scopedArtifactObjectRef(
	access *agentv1.WorkerAccessScope,
	name string,
) (string, error) {
	if access == nil || access.GetArtifactBucket() == "" ||
		name == "" || strings.Contains(name, "..") ||
		strings.ContainsAny(name, "/\\\r\n") {
		return "", errors.New("Worker artifact output scope is invalid")
	}
	base := name
	if extension := strings.LastIndexByte(base, '.'); extension > 0 {
		base = base[:extension]
	}
	if !workerObjectNamePattern.MatchString(base) {
		return "", errors.New("Worker artifact output name is invalid")
	}
	prefix := access.GetArtifactPrefix()
	if !validObjectPrefix(prefix) {
		return "", errors.New("Worker artifact output prefix is invalid")
	}
	return "s3://" + access.GetArtifactBucket() + "/" + prefix + name, nil
}

func artifactRefWithinScope(
	access *agentv1.WorkerAccessScope,
	reference string,
) bool {
	if access == nil {
		return false
	}
	return artifactRefWithinScopeValues(
		access.GetArtifactBucket(), access.GetArtifactPrefix(),
		reference,
	)
}

func artifactRefWithinScopeValues(
	bucket string,
	objectPrefix string,
	reference string,
) bool {
	if bucket == "" || !validObjectPrefix(objectPrefix) {
		return false
	}
	scopePrefix := "s3://" + bucket + "/" + objectPrefix
	name := strings.TrimPrefix(reference, scopePrefix)
	return name != reference && name != "" &&
		!strings.ContainsAny(name, "/\\\r\n") &&
		!strings.Contains(name, "..")
}

func validObjectPrefix(value string) bool {
	return value != "" && !strings.HasPrefix(value, "/") &&
		strings.HasSuffix(value, "/") &&
		!strings.Contains(value, "..") &&
		!strings.ContainsAny(value, "\\\r\n")
}

func parseRuntimeDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if !strings.HasPrefix(value, "sha256:") {
		return digest, ErrInvalidBundle
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return digest, ErrInvalidBundle
	}
	copy(digest[:], decoded)
	clear(decoded)
	return digest, nil
}

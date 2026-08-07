package result

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/google/uuid"
)

const (
	ManifestSchemaV1  = "dirextalk.agent.cloud-worker-result/v1"
	MaxManifestBytes  = 512 << 10
	MaxManifestClaims = cloudruntime.MaxArtifactsPerResult
)

type Manifest struct {
	SchemaVersion   string                     `json:"schema_version"`
	ExecutionID     string                     `json:"execution_id"`
	ExecutionSHA256 string                     `json:"execution_sha256"`
	TaskID          string                     `json:"task_id"`
	TaskSHA256      string                     `json:"task_sha256"`
	SessionID       string                     `json:"session_id"`
	Attempt         int32                      `json:"attempt"`
	LeaseEpoch      int64                      `json:"lease_epoch"`
	Adapter         string                     `json:"adapter"`
	WorkspaceMode   cloudruntime.WorkspaceMode `json:"workspace_mode"`
	Status          string                     `json:"status"`
	Usage           cloudruntime.Usage         `json:"usage"`
	Artifacts       []ObjectClaim              `json:"artifacts"`
}

type Expectation struct {
	ExecutionID     string
	ExecutionSHA256 string
	TaskID          string
	TaskSHA256      string
	SessionID       string
	Attempt         int32
	LeaseEpoch      int64
	WorkspaceMode   cloudruntime.WorkspaceMode
}

func (expectation Expectation) validate() error {
	if !canonicalUUID(expectation.ExecutionID) ||
		!canonicalUUID(expectation.TaskID) || !canonicalUUID(expectation.SessionID) ||
		!validDigest(expectation.ExecutionSHA256) || !validDigest(expectation.TaskSHA256) ||
		expectation.Attempt < 1 || expectation.LeaseEpoch < 1 ||
		!expectation.WorkspaceMode.Valid() {
		return ErrInvalid
	}
	return nil
}

func ParseManifest(raw []byte, expectation Expectation, scope Scope) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes ||
		expectation.validate() != nil || scope.Validate() != nil {
		return Manifest{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if decoder.Decode(&manifest) != nil {
		return Manifest{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, ErrInvalid
	}
	if manifest.Validate(expectation, scope) != nil {
		return Manifest{}, ErrInvalid
	}
	return manifest, nil
}

func (manifest Manifest) Validate(expectation Expectation, scope Scope) error {
	if expectation.validate() != nil || scope.Validate() != nil ||
		manifest.SchemaVersion != ManifestSchemaV1 ||
		manifest.ExecutionID != expectation.ExecutionID ||
		manifest.ExecutionSHA256 != expectation.ExecutionSHA256 ||
		manifest.TaskID != expectation.TaskID || manifest.SessionID != expectation.SessionID ||
		manifest.TaskSHA256 != expectation.TaskSHA256 ||
		manifest.Attempt != expectation.Attempt || manifest.LeaseEpoch != expectation.LeaseEpoch ||
		manifest.Adapter != cloudruntime.AdapterPiJSONTaskV1 ||
		manifest.WorkspaceMode != expectation.WorkspaceMode || manifest.Status != "succeeded" ||
		manifest.Usage.Validate() != nil || len(manifest.Artifacts) == 0 ||
		len(manifest.Artifacts) > MaxManifestClaims {
		return ErrInvalid
	}
	seenNames := make(map[string]struct{}, len(manifest.Artifacts))
	seenObjects := make(map[string]struct{}, len(manifest.Artifacts))
	hasFinal := false
	var total int64
	for _, claim := range manifest.Artifacts {
		if claim.Validate() != nil || !scope.Contains(claim) {
			return ErrInvalid
		}
		if _, duplicate := seenNames[claim.Name]; duplicate {
			return ErrInvalid
		}
		objectIdentity := claim.Bucket + "\x00" + claim.Key + "\x00" + claim.VersionID
		if _, duplicate := seenObjects[objectIdentity]; duplicate {
			return ErrInvalid
		}
		seenNames[claim.Name] = struct{}{}
		seenObjects[objectIdentity] = struct{}{}
		total += claim.SizeBytes
		if total > cloudruntime.MaxResultBytes {
			return ErrInvalid
		}
		switch claim.Name {
		case "final.json":
			if claim.MediaType != "application/json" ||
				claim.SizeBytes > cloudruntime.MaxFinalArtifactBytes {
				return ErrInvalid
			}
			hasFinal = true
		case "changes.patch":
			if manifest.WorkspaceMode != cloudruntime.WorkspaceWrite ||
				claim.MediaType != "text/plain; charset=utf-8" ||
				claim.SizeBytes > cloudruntime.MaxPatchBytes {
				return ErrInvalid
			}
		case cloudruntime.WorkspaceDeltaArtifactName:
			if manifest.WorkspaceMode != cloudruntime.WorkspaceWrite ||
				claim.MediaType != "application/gzip" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	if !hasFinal {
		return ErrInvalid
	}
	return nil
}

type CollectedArtifact struct {
	Claim   ObjectClaim
	Content []byte
}

type Collected struct {
	Manifest Manifest
	// Final is structurally verified Worker-authored content. Risks is not a
	// central security or policy assessment.
	Final     cloudruntime.PiFinalV1
	Artifacts []CollectedArtifact
}

func (collected *Collected) Destroy() {
	if collected == nil {
		return
	}
	for index := range collected.Artifacts {
		clear(collected.Artifacts[index].Content)
	}
	*collected = Collected{}
}

type Collector struct{ verifier *Verifier }

func NewCollector(reader ObjectReader, scope Scope) (*Collector, error) {
	verifier, err := NewVerifier(reader, scope)
	if err != nil {
		return nil, err
	}
	return &Collector{verifier: verifier}, nil
}

// Collect first verifies the manifest's exact S3 version, then verifies every
// exact artifact version and parses final.json through the same canonical
// contract used by the Worker.
func (collector *Collector) Collect(
	ctx context.Context,
	manifestClaim ObjectClaim,
	expectation Expectation,
) (Collected, error) {
	if collector == nil || ctx == nil || manifestClaim.Name != "result.json" ||
		manifestClaim.MediaType != "application/json" ||
		manifestClaim.SizeBytes > MaxManifestBytes {
		return Collected{}, ErrInvalid
	}
	manifestObject, err := collector.verifier.Verify(ctx, manifestClaim)
	if err != nil {
		return Collected{}, err
	}
	defer manifestObject.Destroy()
	manifest, err := ParseManifest(
		manifestObject.Content,
		expectation,
		collector.verifier.Scope(),
	)
	if err != nil {
		return Collected{}, err
	}
	collected := Collected{Manifest: manifest}
	for _, claim := range manifest.Artifacts {
		object, verifyErr := collector.verifier.Verify(ctx, claim)
		if verifyErr != nil {
			collected.Destroy()
			return Collected{}, verifyErr
		}
		if claim.Name == "final.json" {
			final, canonical, parseErr := cloudruntime.ParsePiFinalV1(object.Content)
			if parseErr != nil || !bytes.Equal(canonical, object.Content) {
				clear(canonical)
				object.Destroy()
				collected.Destroy()
				return Collected{}, ErrInvalid
			}
			clear(canonical)
			collected.Final = final
		}
		collected.Artifacts = append(collected.Artifacts, CollectedArtifact{
			Claim: claim, Content: object.Content,
		})
		object.Content = nil
	}
	if collected.Final.SchemaVersion != cloudruntime.PiFinalSchemaV1 {
		collected.Destroy()
		return Collected{}, ErrInvalid
	}
	return collected, nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

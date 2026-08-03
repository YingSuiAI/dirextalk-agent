package workerprotocol

import (
	"slices"
	"time"
)

const (
	CheckpointSchemaV1     = "dirextalk.worker.checkpoint/v1"
	ResultManifestSchemaV1 = "dirextalk.worker.result-manifest/v1"
	CleanupReceiptSchemaV1 = "dirextalk.worker.cleanup-receipt/v1"
)

type CheckpointV1 struct {
	SchemaVersion   string        `json:"schema_version"`
	CheckpointID    string        `json:"checkpoint_id"`
	ExecutionID     string        `json:"execution_id"`
	WorkerID        string        `json:"worker_id"`
	WorkerReleaseID string        `json:"worker_release_id"`
	Attempt         uint32        `json:"attempt"`
	LeaseEpoch      uint64        `json:"lease_epoch"`
	Sequence        uint64        `json:"sequence"`
	State           ArtifactRefV1 `json:"state"`
	CompletedStages []string      `json:"completed_stages"`
	CreatedAt       time.Time     `json:"created_at"`
}

func (value CheckpointV1) Validate() error {
	for _, candidate := range []string{
		value.CheckpointID,
		value.ExecutionID,
		value.WorkerID,
		value.WorkerReleaseID,
	} {
		if !canonicalUUID(candidate) {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != CheckpointSchemaV1 ||
		value.Attempt == 0 ||
		value.LeaseEpoch == 0 ||
		value.Sequence == 0 ||
		value.State.ValidateOutput() != nil ||
		len(value.CompletedStages) > 128 ||
		!slices.IsSorted(value.CompletedStages) ||
		hasDuplicate(value.CompletedStages) ||
		!utcSecond(value.CreatedAt) {
		return ErrInvalid
	}
	for _, stage := range value.CompletedStages {
		if !validToken(stage, 64) {
			return ErrInvalid
		}
	}
	return nil
}

func (value CheckpointV1) Digest() (string, error) {
	return digestValidated(value, value.Validate)
}

type ResultOutcome string

const (
	ResultSucceeded   ResultOutcome = "succeeded"
	ResultFailed      ResultOutcome = "failed"
	ResultCanceled    ResultOutcome = "canceled"
	ResultTimedOut    ResultOutcome = "timed_out"
	ResultInterrupted ResultOutcome = "interrupted"
)

type ChangeSetV1 struct {
	Format string        `json:"format"`
	Patch  ArtifactRefV1 `json:"patch"`
}

func (value ChangeSetV1) Validate() error {
	if value.Format != "git_patch_v1" ||
		value.Patch.ValidateOutput() != nil ||
		value.Patch.MediaType != "text/x-diff" {
		return ErrInvalid
	}
	return nil
}

type TestEvidenceV1 struct {
	Name     string        `json:"name"`
	Status   string        `json:"status"`
	Evidence ArtifactRefV1 `json:"evidence"`
}

func (value TestEvidenceV1) Validate() error {
	if !validText(value.Name, 256) ||
		(value.Status != "passed" &&
			value.Status != "failed" &&
			value.Status != "skipped") ||
		value.Evidence.ValidateOutput() != nil {
		return ErrInvalid
	}
	return nil
}

type ResultManifestV1 struct {
	SchemaVersion          string           `json:"schema_version"`
	ResultID               string           `json:"result_id"`
	ExecutionID            string           `json:"execution_id"`
	OperationID            string           `json:"operation_id"`
	WorkerID               string           `json:"worker_id"`
	WorkerReleaseID        string           `json:"worker_release_id"`
	ImageDigest            string           `json:"image_digest"`
	Attempt                uint32           `json:"attempt"`
	LeaseEpoch             uint64           `json:"lease_epoch"`
	Outcome                ResultOutcome    `json:"outcome"`
	Summary                string           `json:"summary"`
	Artifacts              []ArtifactRefV1  `json:"artifacts"`
	ChangeSet              *ChangeSetV1     `json:"change_set,omitempty"`
	Tests                  []TestEvidenceV1 `json:"tests"`
	Usage                  TokenUsageV1     `json:"usage"`
	LatestCheckpointDigest string           `json:"latest_checkpoint_digest,omitempty"`
	StartedAt              time.Time        `json:"started_at"`
	CompletedAt            time.Time        `json:"completed_at"`
}

func (value ResultManifestV1) Validate() error {
	for _, candidate := range []string{
		value.ResultID,
		value.ExecutionID,
		value.OperationID,
		value.WorkerID,
		value.WorkerReleaseID,
	} {
		if !canonicalUUID(candidate) {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != ResultManifestSchemaV1 ||
		!validOCIDigest(value.ImageDigest) ||
		value.Attempt == 0 ||
		value.LeaseEpoch == 0 ||
		(value.Outcome != ResultSucceeded &&
			value.Outcome != ResultFailed &&
			value.Outcome != ResultCanceled &&
			value.Outcome != ResultTimedOut &&
			value.Outcome != ResultInterrupted) ||
		!validText(value.Summary, 16<<10) ||
		len(value.Artifacts) > 64 ||
		len(value.Tests) > 128 ||
		value.Usage.Validate() != nil ||
		(value.LatestCheckpointDigest != "" &&
			!validDigest(value.LatestCheckpointDigest)) ||
		!utcSecond(value.StartedAt) ||
		!utcSecond(value.CompletedAt) ||
		value.CompletedAt.Before(value.StartedAt) {
		return ErrInvalid
	}
	artifactIDs := make(map[string]struct{}, len(value.Artifacts)+1)
	paths := make(map[string]struct{}, len(value.Artifacts)+1)
	registerOutput := func(artifact ArtifactRefV1) bool {
		if _, found := artifactIDs[artifact.ArtifactID]; found {
			return false
		}
		if _, found := paths[artifact.LocalPath]; found {
			return false
		}
		artifactIDs[artifact.ArtifactID] = struct{}{}
		paths[artifact.LocalPath] = struct{}{}
		return true
	}
	previousArtifactID := ""
	for _, artifact := range value.Artifacts {
		if artifact.ValidateOutput() != nil {
			return ErrInvalid
		}
		if previousArtifactID != "" &&
			artifact.ArtifactID <= previousArtifactID {
			return ErrInvalid
		}
		if !registerOutput(artifact) {
			return ErrInvalid
		}
		previousArtifactID = artifact.ArtifactID
	}
	if value.ChangeSet != nil {
		if value.ChangeSet.Validate() != nil {
			return ErrInvalid
		}
		patch := value.ChangeSet.Patch
		if !registerOutput(patch) {
			return ErrInvalid
		}
	}
	previousTestName := ""
	for _, evidence := range value.Tests {
		if evidence.Validate() != nil {
			return ErrInvalid
		}
		if previousTestName != "" &&
			evidence.Name <= previousTestName {
			return ErrInvalid
		}
		if !registerOutput(evidence.Evidence) {
			return ErrInvalid
		}
		previousTestName = evidence.Name
	}
	if value.Outcome == ResultSucceeded &&
		len(value.Artifacts) == 0 &&
		value.ChangeSet == nil {
		return ErrInvalid
	}
	return nil
}

func (value ResultManifestV1) Digest() (string, error) {
	return digestValidated(value, value.Validate)
}

type CleanupReceiptV1 struct {
	SchemaVersion          string    `json:"schema_version"`
	ReceiptID              string    `json:"receipt_id"`
	ExecutionID            string    `json:"execution_id"`
	WorkerID               string    `json:"worker_id"`
	WorkerReleaseID        string    `json:"worker_release_id"`
	HarnessInstanceID      string    `json:"harness_instance_id"`
	Attempt                uint32    `json:"attempt"`
	LeaseEpoch             uint64    `json:"lease_epoch"`
	WorkerProcessExited    bool      `json:"worker_process_exited"`
	WorkspaceRemoved       bool      `json:"workspace_removed"`
	CredentialGrantRevoked bool      `json:"credential_grant_revoked"`
	NetworkLeaseRevoked    bool      `json:"network_lease_revoked"`
	OutputManifestDigest   string    `json:"output_manifest_digest,omitempty"`
	CompletedAt            time.Time `json:"completed_at"`
}

func (value CleanupReceiptV1) Validate() error {
	for _, candidate := range []string{
		value.ReceiptID,
		value.ExecutionID,
		value.WorkerID,
		value.WorkerReleaseID,
		value.HarnessInstanceID,
	} {
		if !canonicalUUID(candidate) {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != CleanupReceiptSchemaV1 ||
		value.Attempt == 0 ||
		value.LeaseEpoch == 0 ||
		!value.WorkerProcessExited ||
		!value.WorkspaceRemoved ||
		!value.CredentialGrantRevoked ||
		!value.NetworkLeaseRevoked ||
		(value.OutputManifestDigest != "" &&
			!validDigest(value.OutputManifestDigest)) ||
		!utcSecond(value.CompletedAt) {
		return ErrInvalid
	}
	return nil
}

func (value CleanupReceiptV1) Digest() (string, error) {
	return digestValidated(value, value.Validate)
}

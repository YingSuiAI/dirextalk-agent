package workerprotocol

import (
	"slices"
	"time"
)

const (
	ExecutionEnvelopeSchemaV1 = "dirextalk.worker.execution-envelope/v1"
	InputBundleSchemaV1       = "dirextalk.worker.input-bundle/v1"
	CredentialGrantSchemaV1   = "dirextalk.worker.credential-grant/v1"
)

type ExecutionEnvelopeV1 struct {
	SchemaVersion          string    `json:"schema_version"`
	ProtocolVersion        string    `json:"protocol_version"`
	ExecutionID            string    `json:"execution_id"`
	OperationID            string    `json:"operation_id"`
	DeploymentID           string    `json:"deployment_id"`
	WorkerID               string    `json:"worker_id"`
	WorkerTypeID           string    `json:"worker_type_id"`
	WorkerReleaseID        string    `json:"worker_release_id"`
	ImageDigest            string    `json:"image_digest"`
	RegistryRevision       string    `json:"registry_revision"`
	PlanDigest             string    `json:"plan_digest"`
	ApprovalID             string    `json:"approval_id"`
	RoleID                 string    `json:"role_id"`
	Attempt                uint32    `json:"attempt"`
	LeaseEpoch             uint64    `json:"lease_epoch"`
	IssuedAt               time.Time `json:"issued_at"`
	LeaseExpiresAt         time.Time `json:"lease_expires_at"`
	InputBundleDigest      string    `json:"input_bundle_digest"`
	CredentialGrantDigest  string    `json:"credential_grant_digest"`
	MaximumDurationSeconds uint64    `json:"maximum_duration_seconds"`
	MaximumCostMicros      uint64    `json:"maximum_cost_micros"`
}

func (value ExecutionEnvelopeV1) Validate() error {
	for _, candidate := range []string{
		value.ExecutionID,
		value.OperationID,
		value.DeploymentID,
		value.WorkerID,
		value.WorkerTypeID,
		value.WorkerReleaseID,
		value.ApprovalID,
	} {
		if !canonicalUUID(candidate) {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != ExecutionEnvelopeSchemaV1 ||
		value.ProtocolVersion != ProtocolVersion ||
		!validOCIDigest(value.ImageDigest) ||
		!validDigest(value.RegistryRevision) ||
		!validDigest(value.PlanDigest) ||
		!validRole(value.RoleID) ||
		value.Attempt == 0 ||
		value.LeaseEpoch == 0 ||
		!utcSecond(value.IssuedAt) ||
		!utcSecond(value.LeaseExpiresAt) ||
		!value.LeaseExpiresAt.After(value.IssuedAt) ||
		!validDigest(value.InputBundleDigest) ||
		!validDigest(value.CredentialGrantDigest) ||
		value.MaximumDurationSeconds == 0 ||
		value.MaximumDurationSeconds > 7*24*60*60 ||
		value.LeaseExpiresAt.After(
			value.IssuedAt.Add(
				time.Duration(value.MaximumDurationSeconds)*
					time.Second,
			),
		) ||
		value.MaximumCostMicros == 0 {
		return ErrInvalid
	}
	return nil
}

func (value ExecutionEnvelopeV1) Digest() (string, error) {
	return digestValidated(value, value.Validate)
}

type WorkspaceMountV1 struct {
	Mode     WorkspaceMode `json:"mode"`
	Artifact ArtifactRefV1 `json:"artifact"`
}

func (value WorkspaceMountV1) Validate() error {
	if (value.Mode != WorkspaceReadOnly &&
		value.Mode != WorkspaceIsolated) ||
		value.Artifact.ValidateInput() != nil {
		return ErrInvalid
	}
	return nil
}

type InputBundleV1 struct {
	SchemaVersion string            `json:"schema_version"`
	ExecutionID   string            `json:"execution_id"`
	RoleID        string            `json:"role_id"`
	Context       ArtifactRefV1     `json:"context"`
	Workspace     *WorkspaceMountV1 `json:"workspace,omitempty"`
	Dependencies  []ArtifactRefV1   `json:"dependencies"`
}

func (value InputBundleV1) Validate() error {
	if value.SchemaVersion != InputBundleSchemaV1 ||
		!canonicalUUID(value.ExecutionID) ||
		!validRole(value.RoleID) ||
		value.Context.ValidateInput() != nil ||
		len(value.Dependencies) > 64 {
		return ErrInvalid
	}
	if value.Workspace != nil && value.Workspace.Validate() != nil {
		return ErrInvalid
	}
	artifactIDs := map[string]struct{}{
		value.Context.ArtifactID: {},
	}
	paths := map[string]struct{}{
		value.Context.LocalPath: {},
	}
	if value.Workspace != nil {
		artifactIDs[value.Workspace.Artifact.ArtifactID] = struct{}{}
		paths[value.Workspace.Artifact.LocalPath] = struct{}{}
	}
	if len(artifactIDs) != 1+btoi(value.Workspace != nil) ||
		len(paths) != 1+btoi(value.Workspace != nil) {
		return ErrInvalid
	}
	previousArtifactID := ""
	for _, dependency := range value.Dependencies {
		if dependency.ValidateInput() != nil {
			return ErrInvalid
		}
		if previousArtifactID != "" &&
			dependency.ArtifactID <= previousArtifactID {
			return ErrInvalid
		}
		if _, found := artifactIDs[dependency.ArtifactID]; found {
			return ErrInvalid
		}
		if _, found := paths[dependency.LocalPath]; found {
			return ErrInvalid
		}
		artifactIDs[dependency.ArtifactID] = struct{}{}
		paths[dependency.LocalPath] = struct{}{}
		previousArtifactID = dependency.ArtifactID
	}
	return nil
}

func (value InputBundleV1) Digest() (string, error) {
	return digestValidated(value, value.Validate)
}

type CredentialGrantV1 struct {
	SchemaVersion       string          `json:"schema_version"`
	GrantID             string          `json:"grant_id"`
	ExecutionID         string          `json:"execution_id"`
	WorkerID            string          `json:"worker_id"`
	WorkerReleaseID     string          `json:"worker_release_id"`
	Audience            string          `json:"audience"`
	BrokerSocket        string          `json:"broker_socket"`
	ModelProfileID      string          `json:"model_profile_id"`
	ModelInterface      string          `json:"model_interface"`
	MaximumInputTokens  uint64          `json:"maximum_input_tokens"`
	MaximumOutputTokens uint64          `json:"maximum_output_tokens"`
	MaximumRequests     uint32          `json:"maximum_requests"`
	Permissions         PermissionSetV1 `json:"permissions"`
	IssuedAt            time.Time       `json:"issued_at"`
	ExpiresAt           time.Time       `json:"expires_at"`
}

func (value CredentialGrantV1) Validate() error {
	for _, candidate := range []string{
		value.GrantID,
		value.ExecutionID,
		value.WorkerID,
		value.WorkerReleaseID,
	} {
		if !canonicalUUID(candidate) {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != CredentialGrantSchemaV1 ||
		value.Audience != "dirextalk-model-gateway" ||
		value.BrokerSocket != FixedCredentialBroker ||
		!validToken(value.ModelProfileID, 160) ||
		!validToken(value.ModelInterface, 128) ||
		value.MaximumInputTokens == 0 ||
		value.MaximumOutputTokens == 0 ||
		value.MaximumRequests == 0 ||
		value.MaximumRequests > 10_000 ||
		value.Permissions.Validate() != nil ||
		!slices.Contains(
			value.Permissions.NetworkServices,
			NetworkModelGateway,
		) ||
		!utcSecond(value.IssuedAt) ||
		!utcSecond(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.IssuedAt) ||
		value.ExpiresAt.After(value.IssuedAt.Add(7*24*time.Hour)) {
		return ErrInvalid
	}
	return nil
}

func (value CredentialGrantV1) Digest() (string, error) {
	return digestValidated(value, value.Validate)
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}

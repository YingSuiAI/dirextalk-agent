// Package teaminput compiles one approved Team Execution role into the
// secret-free inputs consumed by a qualified Cloud Worker runtime.
package teaminput

import (
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

const (
	ContextSchemaV1  = "dirextalk.agent.team-worker-context/v1"
	ManifestSchemaV1 = "dirextalk.agent.team-worker-input/v1"

	MaxGoalSummaryBytes       = 32 << 10
	MaxConstraintBytes        = 2 << 10
	MaxConstraints            = 32
	MaxDependencySummaryBytes = 32 << 10
	MaxArtifacts              = 64
)

var ErrInvalid = errors.New("invalid Team Worker input")

type DependencyResultV1 struct {
	RoleID       string `json:"role_id"`
	TaskStepID   string `json:"task_step_id"`
	ResultDigest string `json:"result_digest"`
	Summary      string `json:"summary"`
}

type ArtifactRefV1 struct {
	ArtifactID string `json:"artifact_id"`
	Digest     string `json:"digest"`
	MediaType  string `json:"media_type"`
	Purpose    string `json:"purpose"`
}

// ContextInput is trusted Central Agent output. It contains bounded,
// de-secreted task context, never raw model reasoning, tool arguments, or
// credential material.
type ContextInput struct {
	SnapshotID   string               `json:"snapshot_id"`
	GoalDigest   string               `json:"goal_digest"`
	GoalSummary  string               `json:"goal_summary"`
	Constraints  []string             `json:"constraints"`
	Dependencies []DependencyResultV1 `json:"dependencies"`
	Artifacts    []ArtifactRefV1      `json:"artifacts"`
}

// WorkspaceSnapshot identifies an immutable workspace prepared by a trusted
// snapshot service. The source location remains outside the Worker task so a
// model or transport caller cannot inject a filesystem path or URL.
type WorkspaceSnapshot struct {
	SnapshotID string `json:"snapshot_id"`
	Digest     string `json:"digest"`
	SizeBytes  int64  `json:"size_bytes"`
}

type ContextDocumentV1 struct {
	SchemaVersion     string               `json:"schema_version"`
	ExecutionID       string               `json:"execution_id"`
	ExecutionDigest   string               `json:"execution_digest"`
	PlanID            string               `json:"plan_id"`
	PlanDigest        string               `json:"plan_digest"`
	TaskID            string               `json:"task_id"`
	TaskStepID        string               `json:"task_step_id"`
	RoleID            string               `json:"role_id"`
	ContextSnapshotID string               `json:"context_snapshot_id"`
	GoalDigest        string               `json:"goal_digest"`
	GoalSummary       string               `json:"goal_summary"`
	Objective         string               `json:"objective"`
	Constraints       []string             `json:"constraints"`
	Dependencies      []DependencyResultV1 `json:"dependencies"`
	Artifacts         []ArtifactRefV1      `json:"artifacts"`
}

// ManifestV1 is stored as the Worker's immutable Recipe bundle. It binds the
// context, workspace, runtime task, deployment, and model-token slot without
// carrying any secret or provider mutation input.
type ManifestV1 struct {
	SchemaVersion       string                      `json:"schema_version"`
	ExecutionID         string                      `json:"execution_id"`
	ExecutionDigest     string                      `json:"execution_digest"`
	PlanID              string                      `json:"plan_id"`
	PlanDigest          string                      `json:"plan_digest"`
	TaskID              string                      `json:"task_id"`
	TaskStepID          string                      `json:"task_step_id"`
	RoleID              string                      `json:"role_id"`
	RoleDigest          string                      `json:"role_digest"`
	DeploymentID        string                      `json:"deployment_id"`
	ExpectedWorkerID    string                      `json:"expected_worker_id"`
	ContextSnapshotID   string                      `json:"context_snapshot_id"`
	ContextDigest       string                      `json:"context_digest"`
	WorkspaceMode       workerruntime.WorkspaceMode `json:"workspace_mode"`
	WorkspaceSnapshotID string                      `json:"workspace_snapshot_id"`
	WorkspaceDigest     string                      `json:"workspace_digest"`
	CredentialSlot      string                      `json:"credential_slot"`
	RuntimeTaskDigest   string                      `json:"runtime_task_digest"`
}

// CredentialGrantRequest is sent only to the future task-token issuer. It
// describes a least-privilege model allowance and deliberately has no source
// credential reference or secret bytes.
type CredentialGrantRequest struct {
	ExecutionID            string                       `json:"execution_id"`
	RoleID                 string                       `json:"role_id"`
	DeploymentID           string                       `json:"deployment_id"`
	ExpectedWorkerID       string                       `json:"expected_worker_id"`
	CredentialSlot         string                       `json:"credential_slot"`
	ModelProfileID         string                       `json:"model_profile_id"`
	ModelProvider          string                       `json:"model_provider"`
	Model                  string                       `json:"model"`
	ModelInterface         workerruntime.ModelInterface `json:"model_interface"`
	MaximumInputTokens     uint64                       `json:"maximum_input_tokens"`
	MaximumOutputTokens    uint64                       `json:"maximum_output_tokens"`
	MaximumDurationSeconds uint64                       `json:"maximum_duration_seconds"`
}

type CompileRequest struct {
	Execution       teamexecution.ExecutionV1
	ExecutionDigest string
	RoleID          string
	Context         ContextInput
	Workspace       WorkspaceSnapshot
}

type CompiledInput struct {
	Manifest              ManifestV1
	ManifestBytes         []byte
	ManifestDigest        string
	Context               ContextDocumentV1
	ContextBytes          []byte
	RuntimeTask           workerruntime.TaskV1
	ExecutionBytes        []byte
	ExecutionBundleDigest string
	ContextObject         workerrunner.MaterializeObjectV1
	WorkspaceObject       workerrunner.MaterializeObjectV1
	CredentialGrant       CredentialGrantRequest
	CredentialGrantDigest string
	ContextTargetPath     string
	WorkspaceTargetPath   string
	CredentialTargetPath  string
}

func (compiled *CompiledInput) Destroy() {
	if compiled == nil {
		return
	}
	clear(compiled.ManifestBytes)
	clear(compiled.ContextBytes)
	clear(compiled.ExecutionBytes)
	*compiled = CompiledInput{}
}

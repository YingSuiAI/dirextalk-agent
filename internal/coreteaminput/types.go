// Package coreteaminput compiles the exact, de-secreted input for one approved
// Agent Core Team role and binds it to the credential bytes materialized for a
// qualified official Worker.
package coreteaminput

import (
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
)

const (
	ContextSchemaV1        = "dirextalk.agent.core-team-context/v1"
	ManifestSchemaV1       = "dirextalk.agent.core-team-input/v1"
	RuntimeContextSchemaV1 = "dirextalk.agent.core-team-runtime-context/v1"

	MaxContextBytes           = 512 << 10
	MaxManifestBytes          = 256 << 10
	MaxCredentialBytes        = 64 << 10
	MaxGoalSummaryBytes       = 32 << 10
	MaxConstraintBytes        = 2 << 10
	MaxConstraints            = 32
	MaxDependencySummaryBytes = 32 << 10
	MaxDependencies           = 3
	MaxArtifacts              = 64
)

var ErrInvalid = errors.New("core Team Worker input is invalid")

type DependencyResultV1 struct {
	RoleID       string `json:"role_id"`
	ResultDigest string `json:"result_digest"`
	Summary      string `json:"summary"`
}

type ArtifactRefV1 struct {
	ArtifactID string `json:"artifact_id"`
	Digest     string `json:"digest"`
	MediaType  string `json:"media_type"`
	Purpose    string `json:"purpose"`
}

type ContextInput struct {
	GoalSummary  string               `json:"goal_summary"`
	Constraints  []string             `json:"constraints"`
	Dependencies []DependencyResultV1 `json:"dependencies"`
	Artifacts    []ArtifactRefV1      `json:"artifacts"`
}

type ContextDocumentV1 struct {
	SchemaVersion string               `json:"schema_version"`
	ExecutionID   string               `json:"execution_id"`
	PlanID        string               `json:"plan_id"`
	PlanDigest    string               `json:"plan_digest"`
	RoleID        string               `json:"role_id"`
	GoalSummary   string               `json:"goal_summary"`
	Constraints   []string             `json:"constraints"`
	Dependencies  []DependencyResultV1 `json:"dependencies"`
	Artifacts     []ArtifactRefV1      `json:"artifacts"`
}

type ModelBindingV1 struct {
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	Interface string `json:"interface"`
	Revision  uint64 `json:"revision"`
}

type ManifestV1 struct {
	SchemaVersion       string                `json:"schema_version"`
	ExecutionID         string                `json:"execution_id"`
	PlanID              string                `json:"plan_id"`
	RoleID              string                `json:"role_id"`
	Attempt             uint32                `json:"attempt"`
	PlanDigest          string                `json:"plan_digest"`
	GoalDigest          string                `json:"goal_digest"`
	Capabilities        []coreteam.Capability `json:"capabilities"`
	RuntimeID           string                `json:"runtime_id"`
	OutputTokens        uint32                `json:"output_tokens"`
	ResultSchemaVersion uint32                `json:"result_schema_version"`
	Model               ModelBindingV1        `json:"model"`
	CredentialRevision  uint64                `json:"credential_revision"`
	ContextDigest       string                `json:"context_digest"`
	WorkspaceDigest     string                `json:"workspace_digest"`
}

type runtimeContextV1 struct {
	SchemaVersion  string `json:"schema_version"`
	ManifestDigest string `json:"manifest_digest"`
	CredentialHash string `json:"credential_hash"`
}

type CompileRequest struct {
	Assignment         coreteamworker.Assignment
	Model              ModelBindingV1
	CredentialRevision uint64
	Context            ContextInput
	DependencyRoles    []string
	WorkspaceDigest    string
	Credential         []byte
}

type CompiledInput struct {
	Assignment           coreteamworker.Assignment
	Manifest             ManifestV1
	ContextJSON          []byte
	ManifestJSON         []byte
	RuntimeContextDigest string
}

func (compiled *CompiledInput) Destroy() {
	if compiled == nil {
		return
	}
	clear(compiled.ContextJSON)
	clear(compiled.ManifestJSON)
	*compiled = CompiledInput{}
}

type MaterializedInput struct {
	Assignment         coreteamworker.Assignment
	Model              ModelBindingV1
	CredentialRevision uint64
	ContextJSON        []byte
	ManifestJSON       []byte
	WorkspaceDigest    string
	Credential         []byte
}

func (input MaterializedInput) Clone() MaterializedInput {
	input.Assignment.Capabilities = append([]coreteam.Capability(nil), input.Assignment.Capabilities...)
	input.ContextJSON = append([]byte(nil), input.ContextJSON...)
	input.ManifestJSON = append([]byte(nil), input.ManifestJSON...)
	input.Credential = append([]byte(nil), input.Credential...)
	return input
}

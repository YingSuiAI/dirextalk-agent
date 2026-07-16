// Package installer implements the deliberately narrow privileged boundary on
// an exclusive Cloud Worker VM. It verifies approval-bound artifacts; it does
// not expose a shell, a package manager, or an arbitrary file operation.
package installer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

const (
	PlanSchemaV1       = "dirextalk.agent.installer-plan/v1"
	RequestSchemaV1    = "dirextalk.agent.installer-request/v1"
	ResponseSchemaV1   = "dirextalk.agent.installer-response/v1"
	DaemonConfigSchema = "dirextalk.agent.installer-daemon-config/v1"

	ActionVerify  = "installer.verify"
	ActionExecute = "installer.execute"

	StatusVerified    = "verified"
	StatusExecuted    = "executed"
	StatusFailed      = "failed"
	StatusInterrupted = "interrupted"
	StatusRejected    = "rejected"
)

// BindingV1 is repeated in the local request, the signed installer plan, and
// the root-owned daemon configuration. All three copies must match exactly.
type BindingV1 struct {
	AgentInstanceID string `json:"agent_instance_id"`
	DeploymentID    string `json:"deployment_id"`
	TaskID          string `json:"task_id"`
	PlanHash        string `json:"plan_hash"`
	ApprovalID      string `json:"approval_id"`
	LeaseEpoch      int64  `json:"lease_epoch"`
	RecipeDigest    string `json:"recipe_digest"`
}

type ArtifactV1 struct {
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	TargetPath string `json:"target_path"`
}

type NetworkV1 struct {
	PublicInbound      bool     `json:"public_inbound"`
	OutboundHTTPSHosts []string `json:"outbound_https_hosts"`
}

type PortV1 struct {
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
	Port      uint32 `json:"port"`
}

type VolumeV1 struct {
	Name      string `json:"name"`
	MountPath string `json:"mount_path"`
	ReadOnly  bool   `json:"read_only"`
	SizeGiB   uint32 `json:"size_gib"`
}

// CommandV1 is an exact, approval-bound process invocation. Runtime requests
// select it only by ID; they cannot add argv, environment, paths, or refs.
type CommandV1 struct {
	CommandID        string   `json:"command_id"`
	Argv             []string `json:"argv"`
	WorkingDirectory string   `json:"working_directory"`
	TimeoutSeconds   uint32   `json:"timeout_seconds"`
	ArtifactRefs     []string `json:"artifact_refs"`
	VolumeRefs       []string `json:"volume_refs"`
	SecretRefs       []string `json:"secret_refs"`
}

// InstallerPlanV1 is the complete approval-bound capability presented to the
// root daemon. Execute commands can reference only the artifact, secret, and
// volume declarations carried by this same signature; network and port scope
// also remains bound for later separately typed actions.
type InstallerPlanV1 struct {
	SchemaVersion string       `json:"schema_version"`
	Binding       BindingV1    `json:"binding"`
	Artifacts     []ArtifactV1 `json:"artifacts"`
	SecretRefs    []string     `json:"secret_refs"`
	Network       NetworkV1    `json:"network"`
	Ports         []PortV1     `json:"ports"`
	Volumes       []VolumeV1   `json:"volumes"`
	Commands      []CommandV1  `json:"commands,omitempty"`
	ExpiresAt     string       `json:"expires_at"`
}

type SignedInstallerPlanV1 struct {
	Plan        InstallerPlanV1 `json:"plan"`
	SignerKeyID string          `json:"signer_key_id"`
	Signature   []byte          `json:"signature"`
}

type RequestV1 struct {
	SchemaVersion  string                `json:"schema_version"`
	RequestID      string                `json:"request_id"`
	IdempotencyKey string                `json:"idempotency_key"`
	Action         string                `json:"action"`
	Binding        BindingV1             `json:"binding"`
	SignedPlan     SignedInstallerPlanV1 `json:"signed_plan"`
	ArtifactName   string                `json:"artifact_name,omitempty"`
	CommandID      string                `json:"command_id,omitempty"`
}

// ResponseV1 intentionally contains no path, secret reference, command text,
// internal error, or provider identifier.
type ResponseV1 struct {
	SchemaVersion string    `json:"schema_version"`
	RequestID     string    `json:"request_id"`
	Action        string    `json:"action"`
	Status        string    `json:"status"`
	ArtifactName  string    `json:"artifact_name,omitempty"`
	CommandID     string    `json:"command_id,omitempty"`
	SHA256        string    `json:"sha256"`
	Replayed      bool      `json:"replayed"`
	ErrorCode     ErrorCode `json:"error_code"`
}

// DaemonConfigV1 is provisioned by a trusted, root-owned bootstrap path. The
// unprivileged Worker cannot write it.
type DaemonConfigV1 struct {
	SchemaVersion string    `json:"schema_version"`
	Binding       BindingV1 `json:"binding"`
	TargetRoot    string    `json:"target_root"`
}

func PlanSigningBytes(plan InstallerPlanV1) ([]byte, error) {
	return canonical.Marshal(plan)
}

func SignerKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return digestString(sum)
}

func digestString(sum [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(sum[:])
}

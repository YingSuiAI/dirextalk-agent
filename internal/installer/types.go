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
	LeaseGrantSchemaV1 = "dirextalk.agent.installer-lease-grant/v1"
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

// BindingV1 is the stable approval capability repeated in the local request,
// signed installer plan, and root-owned daemon configuration. Runtime lease
// epoch and expiry are carried by a separate short-lived LeaseGrantV1.
type BindingV1 struct {
	AgentInstanceID string `json:"agent_instance_id"`
	DeploymentID    string `json:"deployment_id"`
	TaskID          string `json:"task_id"`
	PlanHash        string `json:"plan_hash"`
	ApprovalID      string `json:"approval_id"`
	RecipeDigest    string `json:"recipe_digest"`
}

type LeaseGrantV1 struct {
	SchemaVersion string    `json:"schema_version"`
	TrustID       string    `json:"trust_id"`
	Binding       BindingV1 `json:"binding"`
	PlanDigest    string    `json:"plan_digest"`
	OperationID   string    `json:"operation_id"`
	CommandID     string    `json:"command_id"`
	LeaseEpoch    int64     `json:"lease_epoch"`
	IssuedAt      string    `json:"issued_at"`
	ExpiresAt     string    `json:"expires_at"`
}

type SignedLeaseGrantV1 struct {
	Grant       LeaseGrantV1 `json:"grant"`
	SignerKeyID string       `json:"signer_key_id"`
	Signature   []byte       `json:"signature"`
}

type ArtifactV1 struct {
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	TargetPath string `json:"target_path"`
}

// SecretV1 is the complete, device-approved root materialization boundary.
// SecretRef and VersionID are non-secret identifiers; plaintext is never
// carried by a signed plan, bundle, event, log, or EC2 user-data document.
type SecretV1 struct {
	SlotID     string `json:"slot_id"`
	SecretRef  string `json:"secret_ref"`
	SecretName string `json:"secret_name"`
	VersionID  string `json:"version_id"`
	TargetPath string `json:"target_path"`
	FileMode   uint32 `json:"file_mode"`
	OwnerUID   uint32 `json:"owner_uid"`
	OwnerGID   uint32 `json:"owner_gid"`
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
	Name        string `json:"name"`
	DeviceName  string `json:"device_name"`
	MountPath   string `json:"mount_path"`
	ReadOnly    bool   `json:"read_only"`
	Persistent  bool   `json:"persistent"`
	Disposition string `json:"disposition"`
	SizeGiB     uint32 `json:"size_gib"`
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
	Secrets       []SecretV1   `json:"secrets,omitempty"`
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
	OperationID    string                `json:"operation_id,omitempty"`
	LeaseGrant     *SignedLeaseGrantV1   `json:"lease_grant,omitempty"`
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

func LeaseGrantSigningBytes(grant LeaseGrantV1) ([]byte, error) {
	return canonical.Marshal(grant)
}

func SignerKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return digestString(sum)
}

func digestString(sum [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(sum[:])
}

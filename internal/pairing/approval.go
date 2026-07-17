package pairing

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

const (
	ResumeScopeSchemaV1     = "dirextalk.agent.pairing-resume-scope/v1"
	ResumeChallengeSchemaV1 = "dirextalk.agent.pairing-resume-challenge/v1"
	ResumeApprovalSchemaV1  = "cloud-orchestrator/v1"
	ResumeSigningPayloadV1  = "pairing-resume-signing-payload/v1"
	ResumeHashAlgorithmV1   = "deterministic-cbor-sha256"
	ResumeIntent            = "deployment_pairing_resume"
)

var ErrApprovalRequired = errors.New("pairing resume requires device approval")

type ResumeScopeV1 struct {
	SchemaVersion           string `json:"schema_version"`
	Intent                  string `json:"intent"`
	PairingID               string `json:"pairing_id"`
	OwnerID                 string `json:"owner_id"`
	DeploymentID            string `json:"deployment_id"`
	DeploymentRevision      int64  `json:"deployment_revision"`
	PlanID                  string `json:"plan_id"`
	ConnectionID            string `json:"connection_id"`
	TaskID                  string `json:"task_id"`
	StepID                  string `json:"step_id"`
	RecipeDigest            string `json:"recipe_digest"`
	ExecutionManifestDigest string `json:"execution_manifest_digest"`
	PairingRevision         int64  `json:"pairing_revision"`
}

func (value ResumeScopeV1) Validate() error {
	if value.SchemaVersion != ResumeScopeSchemaV1 || value.Intent != ResumeIntent || !validUUID(value.PairingID) ||
		!validRef(value.OwnerID) || !validUUID(value.DeploymentID) || value.DeploymentRevision < 1 ||
		!validUUID(value.PlanID) || !validUUID(value.ConnectionID) || !validUUID(value.TaskID) || !validUUID(value.StepID) ||
		!validDigest(value.RecipeDigest) || !validDigest(value.ExecutionManifestDigest) || value.PairingRevision < 1 {
		return ErrInvalid
	}
	return nil
}

type ResumeChallengeV1 struct {
	SchemaVersion string        `json:"schema_version"`
	ChallengeID   string        `json:"challenge_id"`
	ApprovalID    string        `json:"approval_id"`
	SignerKeyID   string        `json:"signer_key_id"`
	Scope         ResumeScopeV1 `json:"scope"`
	ScopeDigest   string        `json:"scope_digest"`
	IssuedAt      time.Time     `json:"issued_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
}

func (value ResumeChallengeV1) Validate() error {
	if value.SchemaVersion != ResumeChallengeSchemaV1 || !validUUID(value.ChallengeID) || !validUUID(value.ApprovalID) ||
		!validRef(value.SignerKeyID) || value.Scope.Validate() != nil || !validDigest(value.ScopeDigest) ||
		value.IssuedAt.IsZero() || !value.IssuedAt.Before(value.ExpiresAt) || value.ExpiresAt.Sub(value.IssuedAt) > 5*time.Minute {
		return ErrInvalid
	}
	digest, err := canonical.Digest(value.Scope)
	if err != nil || digest != value.ScopeDigest {
		return ErrInvalid
	}
	return nil
}

type ApprovalSignatureV1 struct {
	ChallengeID string `json:"challenge_id"`
	SignerKeyID string `json:"signer_key_id"`
	Signature   []byte `json:"signature"`
}

type ResumeApprovalV1 struct {
	Challenge  ResumeChallengeV1   `json:"challenge"`
	Signature  ApprovalSignatureV1 `json:"signature"`
	ApprovedAt time.Time           `json:"approved_at"`
	Revision   int64               `json:"revision"`
}

func ResumeSigningBytes(challenge ResumeChallengeV1) ([]byte, error) {
	if challenge.Validate() != nil {
		return nil, ErrInvalid
	}
	scope := challenge.Scope
	return canonical.Marshal(struct {
		SchemaVersion                 string    `json:"schema_version"`
		PayloadVersion                string    `json:"payload_version"`
		HashAlgorithm                 string    `json:"hash_algorithm"`
		Intent                        string    `json:"intent"`
		ApprovalID                    string    `json:"approval_id"`
		ChallengeID                   string    `json:"challenge_id"`
		SignerKeyID                   string    `json:"signer_key_id"`
		DeploymentID                  string    `json:"deployment_id"`
		DeploymentRevision            int64     `json:"deployment_revision"`
		PlanID                        string    `json:"plan_id"`
		CloudConnectionID             string    `json:"cloud_connection_id"`
		ExecutionID                   string    `json:"execution_id"`
		RecipeExecutionManifestDigest string    `json:"recipe_execution_manifest_digest"`
		JobID                         string    `json:"job_id"`
		JobRevision                   int64     `json:"job_revision"`
		IssuedAt                      time.Time `json:"issued_at"`
		ExpiresAt                     time.Time `json:"expires_at"`
	}{
		ResumeApprovalSchemaV1, ResumeSigningPayloadV1, ResumeHashAlgorithmV1, ResumeIntent,
		challenge.ApprovalID, challenge.ChallengeID, challenge.SignerKeyID,
		scope.DeploymentID, scope.DeploymentRevision, scope.PlanID, scope.ConnectionID,
		scope.TaskID, scope.ExecutionManifestDigest, scope.PairingID, scope.PairingRevision,
		challenge.IssuedAt.UTC(), challenge.ExpiresAt.UTC(),
	})
}

func VerifyResumeSignature(challenge ResumeChallengeV1, signature ApprovalSignatureV1, publicKey ed25519.PublicKey, now time.Time) error {
	if challenge.Validate() != nil || signature.ChallengeID != challenge.ChallengeID || signature.SignerKeyID != challenge.SignerKeyID ||
		len(signature.Signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize || now.Before(challenge.IssuedAt) || !now.Before(challenge.ExpiresAt) {
		return ErrApprovalRequired
	}
	payload, err := ResumeSigningBytes(challenge)
	if err != nil || !ed25519.Verify(publicKey, payload, signature.Signature) {
		clear(payload)
		return ErrApprovalRequired
	}
	clear(payload)
	return nil
}

type ChallengeRepository interface {
	CreateResumeChallenge(context.Context, Mutation, ResumeChallengeV1) (ResumeChallengeV1, error)
	GetResumeChallenge(context.Context, string, string) (ResumeChallengeV1, error)
	GetResumeApproval(context.Context, string, string) (ResumeApprovalV1, error)
	RecordResumeApproval(context.Context, Mutation, ResumeChallengeV1, ApprovalSignatureV1, time.Time) (ResumeApprovalV1, error)
}

type DeviceKeyV1 struct {
	KeyID, AgentInstanceID, OwnerID string
	PublicKey                       ed25519.PublicKey
	Active                          bool
	NotBefore                       time.Time
	ExpiresAt                       time.Time
}

func (value DeviceKeyV1) ValidAt(now time.Time) bool {
	return validRef(value.KeyID) && validUUID(value.AgentInstanceID) && validRef(value.OwnerID) &&
		len(value.PublicKey) == ed25519.PublicKeySize && value.Active && !value.NotBefore.IsZero() &&
		!now.Before(value.NotBefore) && !value.ExpiresAt.IsZero() && now.Before(value.ExpiresAt)
}

type DeviceRepository interface {
	GetPairingDeviceKey(context.Context, string) (DeviceKeyV1, error)
}

type CurrentDeviceRepository interface {
	GetCurrentPairingDeviceKey(context.Context, string, time.Time) (DeviceKeyV1, error)
}

type ResumeScopeBuilder interface {
	BuildPairingResumeScope(context.Context, string, string) (ResumeScopeV1, error)
}

func SameResumeScope(left, right ResumeScopeV1) bool { return left == right }

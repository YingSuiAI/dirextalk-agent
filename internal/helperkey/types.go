package helperkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

const (
	SchemaV1               = "dirextalk.agent.root-helper-key/v1"
	DefaultHelperID        = "root-helper"
	SecretSlot             = "__dirextalk_root_helper_key"
	SecretTarget           = "/etc/dirextalk-root-helper/signing.key"
	SecretMode      uint32 = 0o400

	StateDraft           State = "draft"
	StateGrant           State = "grant"
	StateProof           State = "proof"
	StateRevoking        State = "revoking"
	StateVerifiedRevoked State = "verified_revoked"
	StateReady           State = "ready"
	StateFailed          State = "failed"
	StateRevoked         State = "revoked"
)

var (
	ErrInvalid        = errors.New("root helper key delivery is invalid")
	ErrNotFound       = errors.New("root helper key delivery was not found")
	ErrConflict       = errors.New("root helper key delivery conflict")
	ErrNotReady       = errors.New("root helper key delivery is not ready")
	ErrUnavailable    = errors.New("root helper key delivery is unavailable")
	digestPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	instancePattern   = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	accountPattern    = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern     = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d$`)
)

type State string

// SecretCoordinate is metadata only. Secret material is never serialised in a
// Record, request hash, event, log, or ordinary database column.
type SecretCoordinate struct {
	ARN       string
	Name      string
	VersionID string
	KMSKeyARN string
}

// SecretPlan is deterministic public metadata approved before any cloud
// secret exists. The provider must create exactly this name/version under this
// KMS key after approval and independently read back the resulting ARN.
type SecretPlan struct {
	Partition  string
	AccountID  string
	Region     string
	Name       string
	VersionID  string
	KMSKeyARN  string
	TargetPath string
	FileMode   uint32
}

type DeviceBinding struct {
	SchemaVersion     string
	AgentInstanceID   string
	OwnerID           string
	DeliveryID        string
	DeploymentID      string
	BindingRevision   int64
	InstanceID        string
	WorkerRoleARN     string
	WorkerPrincipalID string
	HelperID          string
	SignerKeyID       string
	PublicKeyDigest   string
	SecretPlan        SecretPlan
	Secret            SecretCoordinate
	NonceDigest       string
}

type Record struct {
	Binding         DeviceBinding
	PublicKey       []byte
	Nonce           []byte
	State           State
	Revision        int64
	FailureCode     string
	ProofObservedAt time.Time
	RevokedAt       time.Time
	ReadyAt         time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (r Record) Clone() Record {
	r.PublicKey = bytes.Clone(r.PublicKey)
	r.Nonce = bytes.Clone(r.Nonce)
	return r
}

func (r Record) Validate() error {
	if ValidateBinding(r.Binding, r.PublicKey) != nil || len(r.Nonce) != 32 || digest(r.Nonce) != r.Binding.NonceDigest ||
		r.Revision < 1 || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) {
		return ErrInvalid
	}
	switch r.State {
	case StateDraft, StateGrant:
		if !r.ProofObservedAt.IsZero() || !r.RevokedAt.IsZero() || !r.ReadyAt.IsZero() || r.FailureCode != "" {
			return ErrInvalid
		}
	case StateProof, StateRevoking:
		if r.ProofObservedAt.IsZero() || !r.RevokedAt.IsZero() || !r.ReadyAt.IsZero() || r.FailureCode != "" {
			return ErrInvalid
		}
	case StateVerifiedRevoked:
		if r.ProofObservedAt.IsZero() || r.RevokedAt.IsZero() || !r.ReadyAt.IsZero() || r.FailureCode != "" {
			return ErrInvalid
		}
	case StateReady:
		if r.ProofObservedAt.IsZero() || r.RevokedAt.IsZero() || r.ReadyAt.IsZero() || r.FailureCode != "" {
			return ErrInvalid
		}
	case StateFailed:
		if !identifierPattern.MatchString(r.FailureCode) || !r.ReadyAt.IsZero() {
			return ErrInvalid
		}
	case StateRevoked:
		if r.RevokedAt.IsZero() || !r.ReadyAt.IsZero() || r.FailureCode != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateBinding(b DeviceBinding, publicKey []byte) error {
	if ValidateApprovalBinding(b, publicKey) != nil || !validCoordinate(b.Secret, b.SecretPlan) {
		return ErrInvalid
	}
	return nil
}

func ValidateApprovalBinding(b DeviceBinding, publicKey []byte) error {
	if b.SchemaVersion != SchemaV1 || !validUUID(b.AgentInstanceID) || !validUUID(b.DeliveryID) || !validUUID(b.DeploymentID) ||
		!validOwner(b.OwnerID) || b.BindingRevision < 1 ||
		!instancePattern.MatchString(b.InstanceID) || b.WorkerRoleARN == "" || b.WorkerPrincipalID == "" ||
		!strings.HasSuffix(b.WorkerPrincipalID, ":"+b.InstanceID) || !identifierPattern.MatchString(b.HelperID) ||
		!identifierPattern.MatchString(b.SignerKeyID) || !digestPattern.MatchString(b.PublicKeyDigest) ||
		!digestPattern.MatchString(b.NonceDigest) || len(publicKey) != ed25519.PublicKeySize ||
		digest(publicKey) != b.PublicKeyDigest || !validSecretPlan(b.SecretPlan, b) {
		return ErrInvalid
	}
	return nil
}

func (b DeviceBinding) SigningPayload() ([]byte, error) {
	type signingScope struct {
		SchemaVersion     string `json:"schema_version"`
		AgentInstanceID   string `json:"agent_instance_id"`
		OwnerID           string `json:"owner_id"`
		DeliveryID        string `json:"delivery_id"`
		DeploymentID      string `json:"deployment_id"`
		BindingRevision   int64  `json:"binding_revision"`
		InstanceID        string `json:"instance_id"`
		WorkerRoleARN     string `json:"worker_role_arn"`
		WorkerPrincipalID string `json:"worker_principal_id"`
		HelperID          string `json:"helper_id"`
		SignerKeyID       string `json:"signer_key_id"`
		PublicKeyDigest   string `json:"public_key_digest"`
		SecretPartition   string `json:"secret_partition"`
		SecretAccountID   string `json:"secret_account_id"`
		SecretRegion      string `json:"secret_region"`
		SecretName        string `json:"secret_name"`
		SecretVersionID   string `json:"secret_version_id"`
		SecretKMSKeyARN   string `json:"secret_kms_key_arn"`
		TargetPath        string `json:"target_path"`
		FileMode          uint32 `json:"file_mode"`
		NonceDigest       string `json:"nonce_digest"`
	}
	fields := []string{b.SchemaVersion, b.AgentInstanceID, b.OwnerID, b.DeliveryID, b.DeploymentID, b.InstanceID,
		b.WorkerRoleARN, b.WorkerPrincipalID, b.HelperID, b.SignerKeyID, b.PublicKeyDigest, b.SecretPlan.Partition,
		b.SecretPlan.AccountID, b.SecretPlan.Region, b.SecretPlan.Name, b.SecretPlan.VersionID, b.SecretPlan.KMSKeyARN,
		b.SecretPlan.TargetPath, b.NonceDigest}
	for _, field := range fields {
		if field == "" || strings.ContainsAny(field, "\x00\r\n") {
			return nil, ErrInvalid
		}
	}
	if b.BindingRevision < 1 || b.SecretPlan.FileMode != SecretMode {
		return nil, ErrInvalid
	}
	return canonical.Marshal(signingScope{
		b.SchemaVersion, b.AgentInstanceID, b.OwnerID, b.DeliveryID, b.DeploymentID, b.BindingRevision,
		b.InstanceID, b.WorkerRoleARN, b.WorkerPrincipalID, b.HelperID, b.SignerKeyID, b.PublicKeyDigest,
		b.SecretPlan.Partition, b.SecretPlan.AccountID, b.SecretPlan.Region, b.SecretPlan.Name,
		b.SecretPlan.VersionID, b.SecretPlan.KMSKeyARN, b.SecretPlan.TargetPath, b.SecretPlan.FileMode, b.NonceDigest,
	})
}

func PossessionPayload(binding DeviceBinding, nonce []byte) ([]byte, error) {
	if len(nonce) != 32 || digest(nonce) != binding.NonceDigest {
		return nil, ErrInvalid
	}
	payload, err := binding.SigningPayload()
	if err != nil {
		return nil, err
	}
	return append(append([]byte("possession\x00"), payload...), nonce...), nil
}

func CanaryPayload(binding DeviceBinding, observedAt time.Time) ([]byte, error) {
	if observedAt.IsZero() || observedAt.Location() != time.UTC {
		return nil, ErrInvalid
	}
	payload, err := binding.SigningPayload()
	if err != nil {
		return nil, err
	}
	return append(append([]byte("access-denied\x00"), payload...), []byte(observedAt.Format(time.RFC3339Nano))...), nil
}

func validCoordinate(c SecretCoordinate, plan SecretPlan) bool {
	return c.ARN != "" && c.Name != "" && c.VersionID != "" && c.KMSKeyARN != "" &&
		c.Name == plan.Name && c.VersionID == plan.VersionID && c.KMSKeyARN == plan.KMSKeyARN &&
		strings.Contains(c.ARN, ":"+plan.Region+":"+plan.AccountID+":secret:"+plan.Name+"-") &&
		!strings.ContainsAny(c.ARN+c.Name+c.VersionID+c.KMSKeyARN, "\x00\r\n")
}

func validSecretPlan(plan SecretPlan, binding DeviceBinding) bool {
	expectedName := "dtx/" + binding.AgentInstanceID + "/deployments/" + binding.DeploymentID + "/" + SecretSlot
	return (plan.Partition == "aws" || plan.Partition == "aws-us-gov" || plan.Partition == "aws-cn") &&
		accountPattern.MatchString(plan.AccountID) && regionPattern.MatchString(plan.Region) &&
		plan.Name == expectedName && plan.VersionID == binding.DeliveryID &&
		strings.HasPrefix(plan.KMSKeyARN, "arn:"+plan.Partition+":kms:"+plan.Region+":"+plan.AccountID+":key/") &&
		plan.TargetPath == SecretTarget && plan.FileMode == SecretMode
}

func validOwner(value string) bool {
	return strings.TrimSpace(value) == value && len(value) >= 1 && len(value) <= 255 && !strings.ContainsAny(value, "\x00\r\n")
}

func validUUID(value string) bool {
	id, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && id != uuid.Nil && id.String() == value
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

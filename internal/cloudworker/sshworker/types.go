// Package sshworker runs one confirmed task on one temporary EC2 instance.
//
// The package deliberately has no S3, KMS, custom AMI, callback listener, or
// pricing catalog dependency. Discovery is read-only. Every AWS mutation
// carries the confirmation that authorized the exact execution.
package sshworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrInvalid        = errors.New("invalid ssh worker request")
	ErrNotConfirmed   = errors.New("ssh worker execution is not confirmed")
	ErrIdentity       = errors.New("AWS credential identity mismatch")
	ErrAmbiguous      = errors.New("AWS operation outcome is ambiguous")
	ErrResultTooLarge = errors.New("ssh worker result exceeds its limit")
)

const (
	maxWorkerScriptBytes = 1 << 20
	maxWorkspaceBytes    = 512 << 20
	maxResultBytes       = 64 << 20
)

type CredentialIdentity struct {
	CredentialID       string
	CredentialRevision uint64
	AccountID          string
	Region             string
}

func (identity CredentialIdentity) validate() error {
	if strings.TrimSpace(identity.CredentialID) == "" || identity.CredentialRevision == 0 ||
		len(identity.AccountID) != 12 || strings.TrimSpace(identity.Region) == "" {
		return ErrInvalid
	}
	for _, digit := range identity.AccountID {
		if digit < '0' || digit > '9' {
			return ErrInvalid
		}
	}
	return nil
}

// Confirmation is created only after the owner accepts the live quote for an
// exact execution. Proof is the durable confirmation identifier/digest.
type Confirmation struct {
	Confirmed bool
	Proof     string
}

func (confirmation Confirmation) validate() error {
	if !confirmation.Confirmed || strings.TrimSpace(confirmation.Proof) == "" {
		return ErrNotConfirmed
	}
	return nil
}

type Discovery struct {
	ImageID          string
	ImageName        string
	ImageCreatedAt   time.Time
	SSHUser          string
	VPCID            string
	SubnetID         string
	PublicEgressCIDR string
	ObservedAt       time.Time
}

func (discovery Discovery) validate() error {
	prefix, err := netip.ParsePrefix(discovery.PublicEgressCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 ||
		strings.TrimSpace(discovery.ImageID) == "" || strings.TrimSpace(discovery.SSHUser) == "" ||
		strings.TrimSpace(discovery.VPCID) == "" || strings.TrimSpace(discovery.SubnetID) == "" ||
		discovery.ObservedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type ExecuteRequest struct {
	ExecutionID        string
	Credential         CredentialIdentity
	Confirmation       Confirmation
	Discovery          Discovery
	InstanceType       string
	VolumeGiB          int32
	WorkerScript       []byte
	WorkerScriptSHA256 string
	WorkspacePath      string
	MaxWorkspaceBytes  int64
	MaxResultBytes     int64
	Sink               ResultSink
}

func (request ExecuteRequest) validate() error {
	if request.Credential.validate() != nil || request.Confirmation.validate() != nil || request.Discovery.validate() != nil ||
		strings.TrimSpace(request.ExecutionID) == "" || len(request.ExecutionID) > 128 ||
		strings.TrimSpace(request.InstanceType) == "" || request.VolumeGiB < 8 || request.VolumeGiB > 16_384 ||
		len(request.WorkerScript) == 0 || len(request.WorkerScript) > maxWorkerScriptBytes ||
		request.MaxWorkspaceBytes <= 0 || request.MaxWorkspaceBytes > maxWorkspaceBytes ||
		request.MaxResultBytes <= 0 || request.MaxResultBytes > maxResultBytes || request.Sink == nil {
		return ErrInvalid
	}
	for _, character := range request.ExecutionID {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return ErrInvalid
		}
	}
	digest := sha256.Sum256(request.WorkerScript)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), strings.TrimSpace(request.WorkerScriptSHA256)) {
		return ErrInvalid
	}
	if request.WorkspacePath != "" && !filepath.IsAbs(request.WorkspacePath) {
		return ErrInvalid
	}
	return nil
}

type ResourceTags map[string]string

type KeyPair struct {
	ID   string
	Name string
}

type SecurityGroup struct {
	ID   string
	Name string
}

type Instance struct {
	ID          string
	PublicIP    string
	State       string
	ClientToken string
}

type LaunchRequest struct {
	ExecutionID     string
	ClientToken     string
	Discovery       Discovery
	InstanceType    string
	VolumeGiB       int32
	KeyName         string
	SecurityGroupID string
	Tags            ResourceTags
}

type AWS interface {
	VerifyIdentity(context.Context, CredentialIdentity) error
	Discover(context.Context, CredentialIdentity) (Discovery, error)
	FindKeyPair(context.Context, CredentialIdentity, string, ResourceTags) (KeyPair, bool, error)
	ImportKeyPair(context.Context, CredentialIdentity, Confirmation, string, []byte, ResourceTags) (KeyPair, error)
	DeleteKeyPair(context.Context, CredentialIdentity, Confirmation, KeyPair, ResourceTags) error
	FindSecurityGroup(context.Context, CredentialIdentity, string, ResourceTags) (SecurityGroup, bool, error)
	CreateSecurityGroup(context.Context, CredentialIdentity, Confirmation, string, string, ResourceTags) (SecurityGroup, error)
	AuthorizeSSH(context.Context, CredentialIdentity, Confirmation, SecurityGroup, string) error
	DeleteSecurityGroup(context.Context, CredentialIdentity, Confirmation, SecurityGroup, ResourceTags) error
	FindInstance(context.Context, CredentialIdentity, string, ResourceTags) (Instance, bool, error)
	RunInstance(context.Context, CredentialIdentity, Confirmation, LaunchRequest) (Instance, error)
	ObserveInstance(context.Context, CredentialIdentity, string, ResourceTags) (Instance, bool, error)
	TerminateInstance(context.Context, CredentialIdentity, Confirmation, Instance, ResourceTags) error
}

type KeyMaterial interface {
	Ensure(context.Context, string) (privateKeyPath string, authorizedKey []byte, err error)
	Delete(context.Context, string) error
}

type SSHRequest struct {
	ExecutionID        string
	Host               string
	User               string
	PrivateKeyPath     string
	WorkerScript       []byte
	WorkerScriptSHA256 string
	WorkspacePath      string
	MaxWorkspaceBytes  int64
	MaxResultBytes     int64
	Sink               ResultSink
}

type SSHExecutor interface {
	Execute(context.Context, SSHRequest) (ExecutionResult, error)
}

type ResultSink interface {
	StoreText(context.Context, []byte, []byte, int) error
	StoreArtifact(context.Context, string, io.Reader, int64) error
}

type ExecutionResult struct {
	ExitCode      int
	StdoutBytes   int64
	StderrBytes   int64
	ArtifactCount int
}

type Phase string

const (
	PhaseProvisioning Phase = "provisioning"
	PhaseRunning      Phase = "running"
	PhaseCleaning     Phase = "cleaning"
	PhaseCompleted    Phase = "completed"
)

type Record struct {
	ExecutionID       string             `json:"execution_id"`
	Credential        CredentialIdentity `json:"credential"`
	ConfirmationProof string             `json:"confirmation_proof"`
	Phase             Phase              `json:"phase"`
	KeyPair           KeyPair            `json:"key_pair"`
	SecurityGroup     SecurityGroup      `json:"security_group"`
	Instance          Instance           `json:"instance"`
	Result            ExecutionResult    `json:"result"`
	Executed          bool               `json:"executed"`
	InstanceGone      bool               `json:"instance_gone"`
	SecurityGroupGone bool               `json:"security_group_gone"`
	KeyPairGone       bool               `json:"key_pair_gone"`
	UpdatedAt         time.Time          `json:"updated_at"`
}

type Store interface {
	Load(context.Context, string) (Record, bool, error)
	Save(context.Context, Record) error
}

func resourceNames(executionID string) (string, string, string) {
	digest := sha256.Sum256([]byte(executionID))
	suffix := hex.EncodeToString(digest[:8])
	return "dtx-worker-key-" + suffix, "dtx-worker-sg-" + suffix, "dtx-worker-" + suffix
}

func resourceTags(request ExecuteRequest) ResourceTags {
	return ResourceTags{
		"dirextalk:managed-by":          "sshworker",
		"dirextalk:execution":           request.ExecutionID,
		"dirextalk:credential-revision": fmt.Sprint(request.Credential.CredentialRevision),
		"dirextalk:confirmation":        request.Confirmation.Proof,
	}
}

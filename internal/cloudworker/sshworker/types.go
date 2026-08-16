// Package sshworker runs confirmed tasks on a small persistent EC2 worker pool.
// It deliberately has no S3, KMS, custom AMI, callback, or pricing-catalog dependency.
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
	ErrNotConfirmed   = errors.New("ssh worker creation is not confirmed")
	ErrNotAuthorized  = errors.New("ssh worker destruction is not authorized")
	ErrIdentity       = errors.New("AWS worker identity mismatch")
	ErrAmbiguous      = errors.New("AWS operation outcome is ambiguous")
	ErrCapacity       = errors.New("AWS worker capacity reached")
	ErrBusy           = errors.New("ssh worker is busy")
	ErrResultTooLarge = errors.New("ssh worker result exceeds its limit")
)

const (
	MaxWorkers            = 5
	MaxLinkedArtifacts    = 128
	reservedTextArtifacts = 2
	maxWorkerScriptBytes  = 1 << 20
	maxWorkspaceBytes     = 512 << 20
	maxResultBytes        = 64 << 20
)

type CredentialIdentity struct {
	CredentialID       string
	CredentialRevision uint64
	AccountID          string
	Region             string
}

func sameLogicalCredential(left, right CredentialIdentity) bool {
	return left.CredentialID == right.CredentialID && left.AccountID == right.AccountID && left.Region == right.Region
}

type OwnerAuthority struct {
	OwnerID           string `json:"owner_id"`
	AccountGeneration uint64 `json:"account_generation"`
}

func (authority OwnerAuthority) validate() error {
	if strings.TrimSpace(authority.OwnerID) == "" || authority.AccountGeneration == 0 {
		return ErrInvalid
	}
	return nil
}

func (identity CredentialIdentity) validate() error {
	if strings.TrimSpace(identity.CredentialID) == "" || identity.CredentialRevision == 0 || len(identity.AccountID) != 12 || strings.TrimSpace(identity.Region) == "" {
		return ErrInvalid
	}
	for _, digit := range identity.AccountID {
		if digit < '0' || digit > '9' {
			return ErrInvalid
		}
	}
	return nil
}

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

type DestroyAuthorization struct {
	Authorized bool
	Proof      string
}

func (authorization DestroyAuthorization) validate() error {
	if !authorization.Authorized || strings.TrimSpace(authorization.Proof) == "" {
		return ErrNotAuthorized
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
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || strings.TrimSpace(discovery.ImageID) == "" ||
		strings.TrimSpace(discovery.SSHUser) == "" || strings.TrimSpace(discovery.VPCID) == "" || strings.TrimSpace(discovery.SubnetID) == "" || discovery.ObservedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type ExecuteRequest struct {
	ExecutionID        string
	Authority          OwnerAuthority
	Credential         CredentialIdentity
	Confirmation       Confirmation // consumed only when a new worker is required
	Discovery          Discovery
	InstanceType       string
	VCPU               uint32
	MemoryGiB          uint32
	VolumeGiB          int32
	WorkerScript       []byte
	WorkerScriptSHA256 string
	Runtime            RuntimeProtocol
	WorkspacePath      string
	MaxWorkspaceBytes  int64
	MaxResultBytes     int64
	Sink               ResultSink
	ResolveGuidance    func(context.Context) (RuntimeGuidance, error)
	ReportProgress     func(context.Context, string, string) error
	Finalize           func(context.Context, string) error
	ReuseOnly          bool
	ReuseWorkerID      string
}

func (request ExecuteRequest) validate() error {
	if request.Authority.validate() != nil || request.Credential.validate() != nil || request.Discovery.validate() != nil || !validID(request.ExecutionID) || strings.TrimSpace(request.InstanceType) == "" || request.VCPU == 0 || request.MemoryGiB == 0 ||
		request.VolumeGiB < 8 || request.VolumeGiB > 16_384 || len(request.WorkerScript) == 0 || len(request.WorkerScript) > maxWorkerScriptBytes || !request.Runtime.valid() || request.Runtime.TaskID != request.ExecutionID ||
		request.MaxWorkspaceBytes <= 0 || request.MaxWorkspaceBytes > maxWorkspaceBytes || request.MaxResultBytes <= 0 || request.MaxResultBytes > maxResultBytes || request.Sink == nil {
		return ErrInvalid
	}
	digest := sha256.Sum256(request.WorkerScript)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), strings.TrimSpace(request.WorkerScriptSHA256)) || (request.WorkspacePath != "" && !filepath.IsAbs(request.WorkspacePath)) {
		return ErrInvalid
	}
	if (request.ReuseOnly && !validID(request.ReuseWorkerID)) || (!request.ReuseOnly && request.ReuseWorkerID != "") {
		return ErrInvalid
	}
	return nil
}

type ResourceTags map[string]string
type KeyPair struct{ ID, Name string }
type SecurityGroup struct{ ID, Name string }
type Instance struct{ ID, PrivateIP, PublicIP, State, ClientToken string }

type LaunchRequest struct {
	WorkerID, ClientToken, InstanceType, KeyName, SecurityGroupID string
	Discovery                                                     Discovery
	VolumeGiB                                                     int32
	Tags                                                          ResourceTags
}

type AWS interface {
	VerifyIdentity(context.Context, CredentialIdentity) error
	Discover(context.Context, CredentialIdentity) (Discovery, error)
	ListInstances(context.Context, CredentialIdentity, ResourceTags) ([]Instance, error)
	FindKeyPair(context.Context, CredentialIdentity, string, ResourceTags) (KeyPair, bool, error)
	ImportKeyPair(context.Context, CredentialIdentity, Confirmation, string, []byte, ResourceTags) (KeyPair, error)
	DeleteKeyPair(context.Context, CredentialIdentity, DestroyAuthorization, KeyPair, ResourceTags) error
	FindSecurityGroup(context.Context, CredentialIdentity, string, ResourceTags) (SecurityGroup, bool, error)
	CreateSecurityGroup(context.Context, CredentialIdentity, Confirmation, string, string, ResourceTags) (SecurityGroup, error)
	AuthorizeSSH(context.Context, CredentialIdentity, Confirmation, SecurityGroup, string) error
	DeleteSecurityGroup(context.Context, CredentialIdentity, DestroyAuthorization, SecurityGroup, ResourceTags) error
	FindInstance(context.Context, CredentialIdentity, string, ResourceTags) (Instance, bool, error)
	RunInstance(context.Context, CredentialIdentity, Confirmation, LaunchRequest) (Instance, error)
	ObserveInstance(context.Context, CredentialIdentity, string, ResourceTags) (Instance, bool, error)
	TerminateInstance(context.Context, CredentialIdentity, DestroyAuthorization, Instance, ResourceTags) error
}

type KeyMaterial interface {
	Ensure(context.Context, string) (privateKeyPath string, authorizedKey []byte, err error)
	LookupPrivate(context.Context, string) (privateKeyPath string, found bool, err error)
	Delete(context.Context, string) error
}

type SSHRequest struct {
	ExecutionID, Host, User, PrivateKeyPath, WorkerScriptSHA256, WorkspacePath string
	WorkerScript                                                               []byte
	Runtime                                                                    RuntimeProtocol
	MaxWorkspaceBytes, MaxResultBytes                                          int64
	Sink                                                                       ResultSink
	ResolveGuidance                                                            func(context.Context) (RuntimeGuidance, error)
	ReportProgress                                                             func(context.Context, string, string) error
	Resume                                                                     bool
}
type SSHExecutor interface {
	Execute(context.Context, SSHRequest) (ExecutionResult, error)
}
type ConnectionTargetResolver interface {
	Resolve(Instance) (string, error)
}
type PublicIPTarget struct{}

func (PublicIPTarget) Resolve(instance Instance) (string, error) {
	address, err := netip.ParseAddr(instance.PublicIP)
	if err != nil || !address.Is4() {
		return "", ErrInvalid
	}
	return address.String(), nil
}

type ResultSink interface {
	StoreText(context.Context, []byte, []byte, int) error
	StoreArtifact(context.Context, string, io.Reader, int64) error
}
type ExecutionResult struct {
	WorkerID                 string
	Summary                  string
	ExitCode                 int
	StdoutBytes, StderrBytes int64
	ArtifactCount            int
	AppliedSteerIDs          []string
}

type RuntimeGuidance struct {
	SteerIDs []string
	Text     string
}

type WorkerPhase string

const (
	WorkerProvisioning WorkerPhase = "provisioning"
	WorkerIdle         WorkerPhase = "idle"
	WorkerBusy         WorkerPhase = "busy"
	WorkerDestroying   WorkerPhase = "destroying"
	WorkerDestroyed    WorkerPhase = "destroyed"
)

type TaskPhase string

const (
	TaskRunning   TaskPhase = "running"
	TaskCompleted TaskPhase = "completed"
	TaskFailed    TaskPhase = "failed"
)

type WorkerRecord struct {
	WorkerID             string             `json:"worker_id"`
	OwnerID              string             `json:"owner_id"`
	AccountGeneration    uint64             `json:"account_generation"`
	Credential           CredentialIdentity `json:"credential"`
	CreationProof        string             `json:"creation_proof"`
	Phase                WorkerPhase        `json:"phase"`
	SSHUser              string             `json:"ssh_user"`
	InstanceType         string             `json:"instance_type"`
	VCPU                 uint32             `json:"vcpu,omitempty"`
	MemoryGiB            uint32             `json:"memory_gib,omitempty"`
	VolumeGiB            int32              `json:"volume_gib"`
	KeyPair              KeyPair            `json:"key_pair"`
	SecurityGroup        SecurityGroup      `json:"security_group"`
	Instance             Instance           `json:"instance"`
	ResourcesDestroyed   bool               `json:"resources_destroyed,omitempty"`
	CurrentExecutionID   string             `json:"current_execution_id,omitempty"`
	CreatedAt, UpdatedAt time.Time
}

type ExecutionRecord struct {
	ExecutionID       string             `json:"execution_id"`
	WorkerID          string             `json:"worker_id"`
	OwnerID           string             `json:"owner_id"`
	AccountGeneration uint64             `json:"account_generation"`
	Credential        CredentialIdentity `json:"credential"`
	Phase             TaskPhase          `json:"phase"`
	Result            ExecutionResult    `json:"result"`
	UpdatedAt         time.Time          `json:"updated_at"`
}

type Store interface {
	LoadExecution(context.Context, string) (ExecutionRecord, bool, error)
	SaveExecution(context.Context, ExecutionRecord) error
	LoadWorker(context.Context, string) (WorkerRecord, bool, error)
	ListWorkers(context.Context) ([]WorkerRecord, error)
	SaveWorker(context.Context, WorkerRecord) error
	SaveWorkerIntent(context.Context, WorkerRecord, func(context.Context) error) error
}

type WorkerIdentity struct {
	WorkerID, InstanceID, KeyPairID, SecurityGroupID string
	OwnerID                                          string
	AccountGeneration                                uint64
	Credential                                       CredentialIdentity
}

func (record WorkerRecord) authority() OwnerAuthority {
	return OwnerAuthority{OwnerID: record.OwnerID, AccountGeneration: record.AccountGeneration}
}

func (record WorkerRecord) validate() error {
	if !validID(record.WorkerID) || record.authority().validate() != nil || record.Credential.validate() != nil {
		return ErrIdentity
	}
	return nil
}

func (record ExecutionRecord) authority() OwnerAuthority {
	return OwnerAuthority{OwnerID: record.OwnerID, AccountGeneration: record.AccountGeneration}
}

func (record ExecutionRecord) validate() error {
	if !validID(record.ExecutionID) || !validID(record.WorkerID) || record.authority().validate() != nil || record.Credential.validate() != nil {
		return ErrIdentity
	}
	return nil
}

func (identity WorkerIdentity) authority() OwnerAuthority {
	return OwnerAuthority{OwnerID: identity.OwnerID, AccountGeneration: identity.AccountGeneration}
}

type DestroyRequest struct {
	Identity      WorkerIdentity
	Authorization DestroyAuthorization
}

type RunnerMetrics struct {
	LastSeen             time.Time
	Load1, Load5, Load15 float64
}
type HourlyQuote struct {
	Currency              string
	MicrosPerHour         uint64
	ObservedAt, ExpiresAt time.Time
}
type StatusSource interface {
	Observe(context.Context, WorkerRecord) (RunnerMetrics, error)
	HourlyQuote(context.Context, WorkerRecord) (HourlyQuote, error)
}

type WorkerAvailability string

const (
	WorkerAvailable   WorkerAvailability = "available"
	WorkerUnavailable WorkerAvailability = "unavailable"
)

type WorkerStatus struct {
	Identity           WorkerIdentity
	InstanceType       string
	VCPU, MemoryGiB    uint32
	VolumeGiB          int32
	Availability       WorkerAvailability
	Error              string
	EC2State, PublicIP string
	WorkerPhase        WorkerPhase
	TaskPhase          TaskPhase
	CurrentExecutionID string
	Runner             RunnerMetrics
	Quote              HourlyQuote
	ObservedAt         time.Time
}

func UnavailableStatus(worker WorkerRecord, observedAt time.Time, message string) WorkerStatus {
	return WorkerStatus{Identity: workerIdentity(worker), InstanceType: worker.InstanceType, VCPU: worker.VCPU,
		MemoryGiB: worker.MemoryGiB, VolumeGiB: worker.VolumeGiB, Availability: WorkerUnavailable, Error: message,
		EC2State: "unknown", WorkerPhase: worker.Phase, CurrentExecutionID: worker.CurrentExecutionID, ObservedAt: observedAt.UTC()}
}

func resourceNames(workerID string) (string, string, string) {
	digest := sha256.Sum256([]byte(workerID))
	suffix := hex.EncodeToString(digest[:8])
	return "dtx-worker-key-" + suffix, "dtx-worker-sg-" + suffix, "dtx-worker-" + suffix
}
func resourceTags(workerID string, authority OwnerAuthority, credential CredentialIdentity, creationProof string) ResourceTags {
	ownerDigest := sha256.Sum256([]byte(authority.OwnerID))
	return ResourceTags{"dirextalk:managed-by": "sshworker", "dirextalk:worker": workerID,
		"dirextalk:owner": hex.EncodeToString(ownerDigest[:]), "dirextalk:account-generation": fmt.Sprint(authority.AccountGeneration),
		"dirextalk:credential-revision": fmt.Sprint(credential.CredentialRevision), "dirextalk:confirmation": creationProof}
}
func poolTags(authority OwnerAuthority) ResourceTags {
	ownerDigest := sha256.Sum256([]byte(authority.OwnerID))
	return ResourceTags{"dirextalk:managed-by": "sshworker", "dirextalk:owner": hex.EncodeToString(ownerDigest[:]),
		"dirextalk:account-generation": fmt.Sprint(authority.AccountGeneration)}
}
func validID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// validExecutionID is retained for the adjacent immutable runtime-material
// boundary; Worker and execution identifiers intentionally share one grammar.
func validExecutionID(value string) bool { return validID(value) }

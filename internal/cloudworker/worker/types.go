// Package worker composes exactly one ephemeral Cloud Worker task. It owns no
// Team, DAG, installer, maintenance, MCP, Skill, or local Agent fallback path.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	PiRuntimeUID uint32 = 65532
	PiRuntimeGID uint32 = 65532
)

var (
	ErrInvalid         = errors.New("invalid cloud Worker request")
	ErrIdentityChanged = errors.New("cloud Worker identity changed")
	ErrCanceled        = errors.New("cloud Worker task canceled")
	ErrExpired         = errors.New("cloud Worker task expired")
	ErrNotReady        = errors.New("cloud Worker launch expectation is not ready")
	ErrStaleLease      = errors.New("cloud Worker lease is stale")
	ErrUnavailable     = errors.New("cloud Worker dependency unavailable")
	ErrUploadUncertain = errors.New("cloud Worker upload outcome is uncertain")
	ErrSensitiveProof  = errors.New("cloud Worker identity proof cannot be encoded")

	accountPattern  = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern   = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	instancePattern = regexp.MustCompile(`^i-[0-9a-f]{8,32}$`)
	digestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// BootstrapBinding is copied from immutable launch data. Attempt and lease
// epoch are deliberately absent: a controller restart may reclaim the same
// task for the same instance without provisioning a replacement instance.
type BootstrapBinding struct {
	OwnerID             string `json:"owner_id"`
	AccountID           string `json:"account_id"`
	AccountGeneration   uint64 `json:"account_generation"`
	Region              string `json:"region"`
	InstanceID          string `json:"instance_id"`
	LaunchIdentity      string `json:"launch_identity"`
	ExecutionID         string `json:"execution_id"`
	ExecutionSHA256     string `json:"execution_sha256"`
	TaskID              string `json:"task_id"`
	TaskSHA256          string `json:"task_sha256"`
	InputManifestSHA256 string `json:"input_manifest_sha256"`
	ModelBindingSHA256  string `json:"model_binding_sha256"`
}

func (binding BootstrapBinding) Validate() error {
	if binding.validateWithoutInstance() != nil ||
		!instancePattern.MatchString(binding.InstanceID) {
		return ErrInvalid
	}
	return nil
}

func (binding BootstrapBinding) validateWithoutInstance() error {
	if binding.OwnerID == "" || binding.OwnerID != strings.TrimSpace(binding.OwnerID) ||
		len(binding.OwnerID) > 255 || security.ContainsLikelySecret(binding.OwnerID) ||
		!accountPattern.MatchString(binding.AccountID) || binding.AccountGeneration == 0 ||
		!regionPattern.MatchString(binding.Region) ||
		!validDigest(binding.LaunchIdentity) || !canonicalUUID(binding.ExecutionID) ||
		!validDigest(binding.ExecutionSHA256) || !canonicalUUID(binding.TaskID) ||
		!validDigest(binding.TaskSHA256) ||
		!validDigest(binding.InputManifestSHA256) || !validDigest(binding.ModelBindingSHA256) {
		return ErrInvalid
	}
	return nil
}

// Binding combines immutable launch identity with the current server-issued
// task fence. It is created only from a validated challenge response.
type Binding struct {
	BootstrapBinding
	Attempt    uint32 `json:"attempt"`
	LeaseEpoch uint64 `json:"lease_epoch"`
}

func (binding Binding) Validate() error {
	if binding.BootstrapBinding.Validate() != nil || binding.Attempt == 0 ||
		binding.LeaseEpoch == 0 {
		return ErrInvalid
	}
	return nil
}

type Fence struct {
	ExecutionID       string `json:"execution_id"`
	TaskID            string `json:"task_id"`
	AccountGeneration uint64 `json:"account_generation"`
	Attempt           uint32 `json:"attempt"`
	LeaseEpoch        uint64 `json:"lease_epoch"`
}

func (fence Fence) Validate() error {
	if !canonicalUUID(fence.ExecutionID) || !canonicalUUID(fence.TaskID) ||
		fence.AccountGeneration == 0 || fence.Attempt == 0 || fence.LeaseEpoch == 0 {
		return ErrInvalid
	}
	return nil
}

func (binding Binding) Fence() Fence {
	return Fence{
		ExecutionID: binding.ExecutionID, TaskID: binding.TaskID,
		AccountGeneration: binding.AccountGeneration,
		Attempt:           binding.Attempt, LeaseEpoch: binding.LeaseEpoch,
	}
}

func (binding BootstrapBinding) Bind(fence Fence) (Binding, error) {
	if binding.Validate() != nil || fence.Validate() != nil ||
		fence.ExecutionID != binding.ExecutionID || fence.TaskID != binding.TaskID ||
		fence.AccountGeneration != binding.AccountGeneration {
		return Binding{}, ErrInvalid
	}
	return Binding{
		BootstrapBinding: binding,
		Attempt:          fence.Attempt,
		LeaseEpoch:       fence.LeaseEpoch,
	}, nil
}

type InstanceIdentity struct {
	AccountID  string
	Region     string
	InstanceID string
	Document   []byte
	PKCS7      []byte
}

func (identity *InstanceIdentity) Destroy() {
	if identity == nil {
		return
	}
	clear(identity.Document)
	clear(identity.PKCS7)
	*identity = InstanceIdentity{}
}

type IdentitySource interface {
	ReadIdentity(context.Context) (InstanceIdentity, error)
}

// IdentityProof is bearer-equivalent during its short SigV4 lifetime. It is
// intentionally not JSON-marshallable here; transport adapters must map and
// immediately destroy it.
type IdentityProof struct {
	Region        string
	Endpoint      string
	Method        string
	Host          string
	ContentType   string
	ContentSHA256 string
	AmzDate       string
	Challenge     string
	Body          []byte
	Authorization []byte
	SessionToken  []byte
	IMDSDocument  []byte
	IMDSPKCS7     []byte
}

func (proof *IdentityProof) Destroy() {
	if proof == nil {
		return
	}
	clear(proof.Body)
	clear(proof.Authorization)
	clear(proof.SessionToken)
	clear(proof.IMDSDocument)
	clear(proof.IMDSPKCS7)
	*proof = IdentityProof{}
}

func (IdentityProof) String() string   { return "[redacted-cloud-worker-identity-proof]" }
func (IdentityProof) GoString() string { return "worker.IdentityProof{[redacted]}" }
func (IdentityProof) LogValue() slog.Value {
	return slog.StringValue("[redacted-cloud-worker-identity-proof]")
}
func (IdentityProof) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveProof }

var _ json.Marshaler = IdentityProof{}

type ProofGenerator interface {
	Generate(context.Context, string, Binding, InstanceIdentity) (IdentityProof, error)
}

type Challenge struct {
	ChallengeID string
	Nonce       string
	Fence       Fence
	ExpiresAt   time.Time
}

type ChallengeRequest struct {
	ExecutionID       string
	TaskID            string
	AccountGeneration uint64
	InstanceID        string
	LaunchIdentity    string
	IdempotencyKey    string
}

func (binding BootstrapBinding) ChallengeRequest(idempotencyKey string) ChallengeRequest {
	return ChallengeRequest{
		ExecutionID: binding.ExecutionID, TaskID: binding.TaskID,
		AccountGeneration: binding.AccountGeneration,
		InstanceID:        binding.InstanceID, LaunchIdentity: binding.LaunchIdentity,
		IdempotencyKey: idempotencyKey,
	}
}

func (request ChallengeRequest) Validate() error {
	if !canonicalUUID(request.ExecutionID) || !canonicalUUID(request.TaskID) ||
		request.AccountGeneration == 0 || !instancePattern.MatchString(request.InstanceID) ||
		!validDigest(request.LaunchIdentity) || !canonicalUUID(request.IdempotencyKey) {
		return ErrInvalid
	}
	return nil
}

type LeaseState string

const (
	LeaseActive   LeaseState = "active"
	LeaseCanceled LeaseState = "canceled"
	LeaseExpired  LeaseState = "expired"
)

type ProgressPhase string

const (
	ProgressClaimed         ProgressPhase = "claimed"
	ProgressPreparingInputs ProgressPhase = "preparing_inputs"
	ProgressRunningPi       ProgressPhase = "running_pi"
	ProgressUploadingResult ProgressPhase = "uploading_result"
	ProgressCompleting      ProgressPhase = "completing"
)

// ProgressReporter is an optional extension implemented by the real gRPC
// control client. Keeping it separate preserves the small five-RPC test and
// worker boundary while allowing Workflow to advance a closed progress phase.
type ProgressReporter interface {
	SetProgressPhase(ProgressPhase)
	SetUploadedBytes(uint64)
	SetOutputTruncated()
}

type ClaimedTask struct {
	Binding           Binding
	SessionID         string
	SessionToken      []byte
	Task              cloudruntime.Task
	ModelGrant        cloudruntime.ModelGrant
	InputManifestJSON []byte
	ArtifactScope     cloudresult.Scope
	HeartbeatInterval time.Duration
	NotAfter          time.Time
}

func (task *ClaimedTask) Destroy() {
	if task == nil {
		return
	}
	clear(task.SessionToken)
	task.ModelGrant.Destroy()
	clear(task.InputManifestJSON)
	*task = ClaimedTask{}
}

type HeartbeatResult struct {
	State    LeaseState
	NotAfter time.Time
	Sequence uint64
}

type CompleteRequest struct {
	Fence           Fence
	SessionID       string
	SessionToken    []byte
	ManifestClaim   cloudresult.ObjectClaim
	RuntimeTopology execgate.Proof
	IdempotencyKey  string
}

type FailRequest struct {
	Fence          Fence
	SessionID      string
	SessionToken   []byte
	Code           string
	IdempotencyKey string
}

// ControlClient is intentionally the five-RPC WorkerControl surface. Issue
// carries no IdentityExpectation; the server resolves that from its durable
// dispatch ledger and returns the current attempt/lease fence.
type ControlClient interface {
	ProgressReporter
	IssueIdentityChallenge(context.Context, ChallengeRequest) (Challenge, error)
	Claim(context.Context, Fence, string, *IdentityProof) (ClaimedTask, error)
	Heartbeat(context.Context, Fence, string, []byte, uint64, string) (HeartbeatResult, error)
	Complete(context.Context, CompleteRequest) error
	Fail(context.Context, FailRequest) error
}

type TaskExecutor interface {
	Run(context.Context, ClaimedTask, func(ProgressPhase) error) (cloudruntime.Result, error)
}

type RuntimeTopologySource interface {
	TerminalRuntimeTopology() (execgate.Proof, error)
}

type ResultUploader interface {
	Upload(context.Context, ClaimedTask, cloudruntime.Result) (cloudresult.ObjectClaim, error)
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

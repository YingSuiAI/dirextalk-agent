// Package cloudworker owns the single ephemeral Pi Worker execution domain.
// It deliberately keeps provider credentials, secret values and executable
// command text out of durable plans, task payloads and public projections.
package cloudworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/workspacearchive"
)

const (
	RecipeEphemeralPiTask       = "ephemeral-pi-task"
	AdapterPiJSONTaskV1         = "pi_json_task_v1"
	OperationDomain             = "cloud_worker.execute"
	InputManifestSchema         = "cloud_worker_input_manifest/v1"
	StagedInputManifestSchemaV1 = "cloud_worker_staged_input_manifest/v1"
	// MaxCloudWorkerOutputBytes is the authorization-visible hard cap shared
	// with the Pi runtime/result collector. A quote must never authorize an
	// output the Worker cannot upload and the Agent cannot centrally verify.
	MaxCloudWorkerOutputBytes uint64 = 64 << 20
)

var (
	ErrInvalid                        = errors.New("cloudworker: invalid")
	ErrNotFound                       = errors.New("cloudworker: not found")
	ErrConflict                       = errors.New("cloudworker: conflict")
	ErrRevisionConflict               = errors.New("cloudworker: revision conflict")
	ErrStaleAuthorization             = errors.New("cloudworker: stale authorization")
	ErrQuoteExpired                   = errors.New("cloudworker: quote expired")
	ErrPricingCatalogStale            = errors.New("cloudworker: pricing catalog stale")
	ErrProviderUnavailable            = errors.New("cloudworker: provider unavailable")
	ErrArtifactDestinationUnavailable = errors.New("cloudworker: artifact destination unavailable")
	ErrLeaseConflict                  = errors.New("cloudworker: task lease conflict")
)

type WorkspaceMode string

const (
	WorkspaceNone     WorkspaceMode = "none"
	WorkspaceReadOnly WorkspaceMode = "read_only"
	WorkspaceWrite    WorkspaceMode = "write"
)

type ProposalReason string

const (
	ProposalReasonExplicitUserCloud   ProposalReason = "explicit_user_cloud"
	ProposalReasonCentralDelegation   ProposalReason = "central_delegation"
	ProposalReasonLocalBudgetExceeded ProposalReason = "local_budget_exceeded"
)

// LocalBudgetEvidence is an immutable proof emitted by the local scheduler.
// A model assertion or a local execution failure is not budget evidence.
type LocalBudgetEvidence struct {
	BudgetID string `json:"budget_id"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}

// ModelAuthorization binds a plan to an Agent-owned model profile, endpoint,
// and credential revision without making the long-lived credential
// representable. The credential itself is resolved only after a verified
// Worker claims this exact task.
type ModelAuthorization struct {
	ModelProfileID          string `json:"model_profile_id"`
	ModelProfileRevision    uint64 `json:"model_profile_revision"`
	Provider                string `json:"provider"`
	BaseURL                 string `json:"base_url,omitempty"`
	Model                   string `json:"model"`
	Interface               string `json:"interface"`
	MaximumOutputTokens     uint64 `json:"maximum_output_tokens"`
	ContextWindow           uint64 `json:"context_window"`
	CredentialVersion       uint64 `json:"credential_version"`
	CredentialBindingDigest string `json:"credential_binding_digest"`
	BindingDigest           string `json:"binding_digest"`
}

type modelAuthorizationPlanDigestV1 struct {
	ModelProfileID          string `json:"model_profile_id"`
	ModelProfileRevision    uint64 `json:"model_profile_revision"`
	Provider                string `json:"provider"`
	Model                   string `json:"model"`
	Interface               string `json:"interface"`
	MaximumOutputTokens     uint64 `json:"maximum_output_tokens"`
	CredentialVersion       uint64 `json:"credential_version"`
	CredentialBindingDigest string `json:"credential_binding_digest"`
	BindingDigest           string `json:"binding_digest"`
}

type modelAuthorizationPlanDigestV2 struct {
	ModelProfileID          string `json:"model_profile_id"`
	ModelProfileRevision    uint64 `json:"model_profile_revision"`
	Provider                string `json:"provider"`
	Model                   string `json:"model"`
	Interface               string `json:"interface"`
	MaximumOutputTokens     uint64 `json:"maximum_output_tokens"`
	ContextWindow           uint64 `json:"context_window"`
	CredentialVersion       uint64 `json:"credential_version"`
	CredentialBindingDigest string `json:"credential_binding_digest"`
	BindingDigest           string `json:"binding_digest"`
}

type modelAuthorizationPlanDigestV3 struct {
	ModelProfileID          string `json:"model_profile_id"`
	ModelProfileRevision    uint64 `json:"model_profile_revision"`
	Provider                string `json:"provider"`
	BaseURL                 string `json:"base_url"`
	Model                   string `json:"model"`
	Interface               string `json:"interface"`
	MaximumOutputTokens     uint64 `json:"maximum_output_tokens"`
	ContextWindow           uint64 `json:"context_window"`
	CredentialVersion       uint64 `json:"credential_version"`
	CredentialBindingDigest string `json:"credential_binding_digest"`
	BindingDigest           string `json:"binding_digest"`
}

func (a ModelAuthorization) planDigestProjection() any {
	if a.BaseURL != "" {
		return modelAuthorizationPlanDigestV3{
			a.ModelProfileID, a.ModelProfileRevision, a.Provider, a.BaseURL,
			a.Model, a.Interface, a.MaximumOutputTokens, a.ContextWindow,
			a.CredentialVersion, a.CredentialBindingDigest, a.BindingDigest,
		}
	}
	if a.ContextWindow == 0 {
		return modelAuthorizationPlanDigestV1{
			a.ModelProfileID, a.ModelProfileRevision, a.Provider, a.Model, a.Interface,
			a.MaximumOutputTokens, a.CredentialVersion, a.CredentialBindingDigest, a.BindingDigest,
		}
	}
	return modelAuthorizationPlanDigestV2{
		a.ModelProfileID, a.ModelProfileRevision, a.Provider, a.Model, a.Interface,
		a.MaximumOutputTokens, a.ContextWindow, a.CredentialVersion, a.CredentialBindingDigest, a.BindingDigest,
	}
}

// InputManifest is the private authorization-time workspace authority. It
// binds immutable Agent-owned sources without causing an AWS write before the
// owner confirms the quote. After confirmation, a stager reads these exact
// source revisions and records exact S3 versions in StagedInputManifest.
type InputManifest struct {
	Schema string              `json:"schema"`
	Items  []InputManifestItem `json:"items"`
}

type InputManifestItem struct {
	InputID        string `json:"input_id"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	MountPath      string `json:"mount_path"`
	MediaType      string `json:"media_type"`
	SizeBytes      uint64 `json:"size_bytes"`
	SHA256         string `json:"sha256"`
	SourceRef      string `json:"source_ref"`
	SourceRevision uint64 `json:"source_revision"`
}

// StagedInputManifest is private launch material produced only after generic
// confirmation consumption. Every object is read by exact S3 VersionId; its
// content identity must match the authorization-time source descriptor.
type StagedInputManifest struct {
	Schema               string                    `json:"schema"`
	ExecutionID          string                    `json:"execution_id"`
	SourceManifestDigest string                    `json:"source_manifest_digest"`
	Items                []StagedInputManifestItem `json:"items"`
	Digest               string                    `json:"-"`
}

type StagedInputManifestItem struct {
	InputID     string `json:"input_id"`
	MountPath   string `json:"mount_path"`
	MediaType   string `json:"media_type"`
	SizeBytes   uint64 `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	S3Bucket    string `json:"s3_bucket"`
	S3Key       string `json:"s3_key"`
	S3VersionID string `json:"s3_version_id"`
}

type ExecutionState string

const (
	StateWaitingUser    ExecutionState = "waiting_user"
	StateQueued         ExecutionState = "queued"
	StateProvisioning   ExecutionState = "provisioning"
	StateAwaitingWorker ExecutionState = "awaiting_worker"
	StateRunning        ExecutionState = "running"
	StateCollecting     ExecutionState = "collecting"
	StateValidating     ExecutionState = "validating"
	StateCleaning       ExecutionState = "cleaning"
	StateSucceeded      ExecutionState = "succeeded"
	StateFailed         ExecutionState = "failed"
	StateCanceled       ExecutionState = "canceled"
	StateRejected       ExecutionState = "rejected"
	StateExpired        ExecutionState = "expired"
)

type ResourceState string

const (
	ResourcePlanned           ResourceState = "planned"
	ResourceCreated           ResourceState = "created"
	ResourceDeleteRequested   ResourceState = "delete_requested"
	ResourceVerifiedDestroyed ResourceState = "verified_destroyed"
)

type ArtifactStatus string

const (
	ArtifactPending  ArtifactStatus = "pending"
	ArtifactVerified ArtifactStatus = "verified"
	ArtifactRejected ArtifactStatus = "rejected"
)

type AWSBinding struct {
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
	CredentialID       string `json:"credential_id"`
	CredentialRevision uint64 `json:"credential_revision"`
}

type PlacementSpec struct {
	VPCID           string `json:"vpc_id"`
	SubnetID        string `json:"subnet_id"`
	IAMPolicyDigest string `json:"iam_policy_digest"`
}

type NetworkPolicy struct {
	DNSResolverCIDRs               []string `json:"dns_resolver_cidrs"`
	TLSProxyCIDRs                  []string `json:"tls_proxy_cidrs"`
	AllowedFQDNs                   []string `json:"allowed_fqdns"`
	FQDNPolicyDigest               string   `json:"fqdn_policy_digest"`
	OutboundProxyURL               string   `json:"outbound_proxy_url"`
	OutboundProxyServerName        string   `json:"outbound_proxy_server_name"`
	OutboundProxyTrustBundleSHA256 string   `json:"outbound_proxy_trust_bundle_sha256"`
	OutboundProxyBindingDigest     string   `json:"outbound_proxy_binding_digest"`
}

type ArtifactGrant struct {
	Bucket           string `json:"bucket"`
	KeyPrefix        string `json:"key_prefix"`
	KMSKeyARN        string `json:"kms_key_arn,omitempty"`
	Versioned        bool   `json:"versioned"`
	RetentionSeconds uint64 `json:"retention_seconds"`
	Digest           string `json:"digest"`
}

const WorkerControlProtocolV1 = "worker_control_v1"

type WorkerBootstrap struct {
	Protocol          string `json:"protocol"`
	Endpoint          string `json:"endpoint"`
	TLSServerName     string `json:"tls_server_name"`
	TrustBundleDigest string `json:"trust_bundle_digest"`
	BindingDigest     string `json:"binding_digest"`
}

type ModelEndpointBinding struct {
	Endpoint      string `json:"endpoint"`
	TLSServerName string `json:"tls_server_name"`
	BindingDigest string `json:"binding_digest"`
}

type ComputeSpec struct {
	InstanceType            string `json:"instance_type"`
	Architecture            string `json:"architecture"`
	RootDeviceName          string `json:"root_device_name"`
	VolumeGiB               uint64 `json:"volume_gib"`
	VolumeType              string `json:"volume_type"`
	VolumeIOPS              uint64 `json:"volume_iops"`
	VolumeThroughputMiB     uint64 `json:"volume_throughput_mib"`
	AMIID                   string `json:"ami_id"`
	AMIDigest               string `json:"ami_digest"`
	WorkerReleaseDigest     string `json:"worker_release_digest"`
	PiRuntimeDigest         string `json:"pi_runtime_digest"`
	HostNetworkPolicySHA256 string `json:"host_network_policy_sha256"`
}

// RuntimeEstimate is Central's task-specific schedule proposal. Trusted code
// checks it against the server policy before copying it into an immutable Plan.
type RuntimeEstimate struct {
	MinimumSeconds  uint64 `json:"minimum_seconds"`
	ExpectedSeconds uint64 `json:"expected_seconds"`
	MaximumSeconds  uint64 `json:"maximum_seconds"`
}

func (value RuntimeEstimate) validate(policyMaximum uint64) error {
	if value.MinimumSeconds < 60 ||
		value.MinimumSeconds > value.ExpectedSeconds ||
		value.ExpectedSeconds > value.MaximumSeconds ||
		value.MaximumSeconds > policyMaximum ||
		policyMaximum > uint64((24*time.Hour)/time.Second) {
		return ErrInvalid
	}
	return nil
}

type Limits struct {
	// MinimumRuntimeSeconds and ExpectedRuntimeSeconds were added after the
	// first production Plan schema. Zero for both preserves legacy Plan digests;
	// every newly compiled Plan carries a complete task-specific estimate.
	MinimumRuntimeSeconds  uint64 `json:"minimum_runtime_seconds,omitempty"`
	ExpectedRuntimeSeconds uint64 `json:"expected_runtime_seconds,omitempty"`
	MaxRuntimeSeconds      uint64 `json:"max_runtime_seconds"`
	// MaxTokens is present only when reading or validating a legacy Plan. New
	// Plans leave it at zero and are bounded by runtime/cancellation plus the
	// selected model profile's per-request output limit.
	MaxTokens      uint64 `json:"max_tokens,omitempty"`
	MaxOutputBytes uint64 `json:"max_output_bytes"`
}

type SecretGrant struct {
	ReferenceID   string `json:"reference_id"`
	Purpose       string `json:"purpose"`
	BindingDigest string `json:"binding_digest"`
}

type Quote struct {
	AmountMicros                int64     `json:"amount_micros"`
	Currency                    string    `json:"currency"`
	SourceTime                  time.Time `json:"source_time"`
	ExpiresAt                   time.Time `json:"expires_at"`
	MaximumAuthorizedCostMicros int64     `json:"maximum_authorized_cost_micros"`
	BasisDigest                 string    `json:"basis_digest"`
	CatalogRevisionDigest       string    `json:"catalog_revision_digest"`
	Digest                      string    `json:"digest"`
}

type Plan struct {
	OwnerID                  string               `json:"owner_id"`
	AccountGeneration        uint64               `json:"account_generation"`
	PlanID                   string               `json:"plan_id"`
	Revision                 uint64               `json:"revision"`
	Status                   string               `json:"status"`
	Digest                   string               `json:"digest"`
	ExecutionID              string               `json:"execution_id"`
	TaskID                   string               `json:"task_id"`
	ConfirmationID           string               `json:"confirmation_id"`
	ConversationID           string               `json:"conversation_id"`
	TurnID                   string               `json:"turn_id"`
	RecipeID                 string               `json:"recipe_id"`
	Adapter                  string               `json:"adapter"`
	Objective                string               `json:"-"`
	ObjectiveSummary         string               `json:"objective_summary"`
	ObjectiveDigest          string               `json:"objective_digest"`
	UserPromptDigest         string               `json:"user_prompt_digest"`
	ProposalReason           ProposalReason       `json:"proposal_reason"`
	LocalBudgetEvidence      *LocalBudgetEvidence `json:"local_budget_evidence,omitempty"`
	InputManifest            InputManifest        `json:"-"`
	InputManifestDigest      string               `json:"input_manifest_digest"`
	InputManifestItemCount   uint64               `json:"input_manifest_item_count"`
	WorkspaceMode            WorkspaceMode        `json:"workspace_mode"`
	ModelAuthorization       ModelAuthorization   `json:"model_authorization"`
	AWS                      AWSBinding           `json:"aws"`
	Compute                  ComputeSpec          `json:"compute"`
	Placement                PlacementSpec        `json:"-"`
	NetworkPolicy            NetworkPolicy        `json:"-"`
	ArtifactGrant            ArtifactGrant        `json:"-"`
	WorkerBootstrap          WorkerBootstrap      `json:"-"`
	ModelEndpoint            ModelEndpointBinding `json:"-"`
	AWSInfrastructureDigest  string               `json:"aws_infrastructure_digest"`
	AuthorizationBasisDigest string               `json:"authorization_basis_digest"`
	Limits                   Limits               `json:"limits"`
	NetworkGrants            []string             `json:"network_grants"`
	SecretGrants             []SecretGrant        `json:"secret_grants"`
	ArtifactRetentionSeconds uint64               `json:"artifact_retention_seconds"`
	Quote                    Quote                `json:"quote"`
	ExecutionDigest          string               `json:"execution_digest"`
	CreatedAt                time.Time            `json:"created_at"`
	UpdatedAt                time.Time            `json:"updated_at"`
}

type CleanupSummary struct {
	VerifiedDestroyed          bool       `json:"verified_destroyed"`
	VerifiedAt                 *time.Time `json:"verified_at,omitempty"`
	ResourcesTotal             uint64     `json:"resources_total"`
	ResourcesVerifiedDestroyed uint64     `json:"resources_verified_destroyed"`
}

type Execution struct {
	OwnerID                 string         `json:"owner_id"`
	AccountGeneration       uint64         `json:"account_generation"`
	RunID                   string         `json:"run_id"`
	ExecutionID             string         `json:"execution_id"`
	PlanID                  string         `json:"plan_id"`
	PlanRevision            uint64         `json:"plan_revision"`
	PlanDigest              string         `json:"plan_digest"`
	TaskID                  string         `json:"task_id"`
	ConfirmationID          string         `json:"confirmation_id"`
	ConversationID          string         `json:"conversation_id"`
	TurnID                  string         `json:"turn_id"`
	Status                  ExecutionState `json:"status"`
	State                   ExecutionState `json:"state"`
	Revision                uint64         `json:"revision"`
	Digest                  string         `json:"digest"`
	WorkspaceMode           WorkspaceMode  `json:"workspace_mode"`
	ModelBindingDigest      string         `json:"model_binding_digest"`
	QuoteDigest             string         `json:"quote_digest"`
	ExecutionDigest         string         `json:"execution_digest"`
	ProviderMutationStarted bool           `json:"-"`
	TerminalIntent          string         `json:"-"`
	NeedsReconcile          bool           `json:"-"`
	Cleanup                 CleanupSummary `json:"cleanup"`
	ArtifactIDs             []string       `json:"artifact_ids"`
	FailureCode             string         `json:"failure_code"`
	FailureSummary          string         `json:"failure_summary"`
	CreatedAt               time.Time      `json:"created_at"`
	UpdatedAt               time.Time      `json:"updated_at"`
}

type Resource struct {
	ResourceID        string        `json:"resource_id"`
	ExecutionID       string        `json:"execution_id"`
	AccountGeneration uint64        `json:"account_generation"`
	Provider          string        `json:"provider"`
	Kind              string        `json:"kind"`
	ProviderID        string        `json:"provider_id"`
	PrivateIP         string        `json:"private_ip,omitempty"`
	PublicIP          string        `json:"public_ip,omitempty"`
	AccountID         string        `json:"account_id"`
	Region            string        `json:"region"`
	LaunchIdentity    string        `json:"launch_identity"`
	State             ResourceState `json:"state"`
	Revision          uint64        `json:"revision"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	VerifiedAt        *time.Time    `json:"verified_at,omitempty"`
}

func (r Resource) ValidateObservedAddresses() error {
	if r.PrivateIP != "" {
		parsed := net.ParseIP(strings.TrimSpace(r.PrivateIP))
		if r.Kind != "ec2" || parsed == nil || parsed.To4() == nil || r.PrivateIP != parsed.String() {
			return ErrInvalid
		}
	}
	if r.PublicIP != "" {
		parsed := net.ParseIP(strings.TrimSpace(r.PublicIP))
		if r.Kind != "eip" || parsed == nil || parsed.To4() == nil || r.PublicIP != parsed.String() {
			return ErrInvalid
		}
	}
	return nil
}

type Artifact struct {
	ArtifactID  string         `json:"artifact_id"`
	ExecutionID string         `json:"execution_id"`
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	MediaType   string         `json:"media_type"`
	SizeBytes   uint64         `json:"size_bytes"`
	SHA256      string         `json:"sha256"`
	Status      ArtifactStatus `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`

	// Retention is the private, exact-version object identity accepted by the
	// central ResultValidator. It is deliberately excluded from every JSON
	// projection: Execution V2 exposes only the integrity-checked Artifact
	// fields above and never an S3 bucket, key, version, credential identity, or
	// cleanup lease.
	Retention *ArtifactRetentionIdentity `json:"-"`
}

type Event struct {
	OwnerID           string          `json:"owner_id"`
	AccountGeneration uint64          `json:"account_generation"`
	RunID             string          `json:"run_id"`
	ExecutionID       string          `json:"execution_id"`
	Sequence          uint64          `json:"sequence"`
	EventID           string          `json:"event_id"`
	Type              string          `json:"type"`
	State             ExecutionState  `json:"status,omitempty"`
	Revision          uint64          `json:"revision"`
	PayloadDigest     string          `json:"payload_digest"`
	Progress          *WorkerProgress `json:"progress,omitempty"`
	CreatedAt         time.Time       `json:"at"`
}

const MaxRetainedRunEvents uint64 = 4096

// WorkerProgress is the public, secret-free projection of a private heartbeat.
// It intentionally contains no model text, paths, environment, or object keys.
type WorkerProgress struct {
	Phase                string    `json:"phase"`
	ElapsedMS            uint64    `json:"elapsed_ms"`
	LastActivityAt       time.Time `json:"last_activity_at"`
	CPUTimeMS            uint64    `json:"cpu_time_ms"`
	MemoryHighWaterBytes uint64    `json:"memory_high_water_bytes"`
	InvocationCount      uint64    `json:"invocation_count"`
	UploadedBytes        uint64    `json:"uploaded_bytes"`
	OutputTruncated      bool      `json:"output_truncated"`
}

// CompletionOutbox is the only payload allowed across the Agent -> Product
// Capability completion boundary. Plan/task/artifact details are read back
// from Agent authority after this invalidation is received.
type CompletionOutbox struct {
	EventID         string    `json:"event_id"`
	ExecutionID     string    `json:"execution_id"`
	RunID           string    `json:"run_id"`
	ConversationID  string    `json:"conversation_id"`
	TurnID          string    `json:"turn_id"`
	ResultMessageID string    `json:"result_message_id"`
	TerminalState   string    `json:"terminal_state"`
	CompletedAt     time.Time `json:"completed_at"`
	PayloadDigest   string    `json:"payload_digest"`
}

type Offer struct {
	Plan         Plan                          `json:"plan"`
	Execution    Execution                     `json:"run"`
	Task         coretask.Task                 `json:"task"`
	Confirmation coreconfirmation.Confirmation `json:"confirmation"`
}

func digestValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validDigest(value string) bool { return coretask.ValidDigest(strings.TrimSpace(value)) }
func validUUID(value string) bool   { return coretask.ValidUUID(strings.TrimSpace(value)) }

func normalizeStrings(values []string, max int) ([]string, error) {
	if len(values) > max {
		return nil, ErrInvalid
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, ErrInvalid
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func (e *LocalBudgetEvidence) normalize() error {
	if e == nil {
		return ErrInvalid
	}
	e.BudgetID = strings.TrimSpace(e.BudgetID)
	e.Digest = strings.TrimSpace(e.Digest)
	if !validUUID(e.BudgetID) || e.Revision == 0 || !validDigest(e.Digest) {
		return ErrInvalid
	}
	return nil
}

func (a *ModelAuthorization) Seal() error {
	if a == nil {
		return ErrInvalid
	}
	a.ModelProfileID = strings.TrimSpace(a.ModelProfileID)
	a.Provider = strings.TrimSpace(a.Provider)
	a.BaseURL = strings.TrimSpace(a.BaseURL)
	a.Model = strings.TrimSpace(a.Model)
	a.Interface = strings.TrimSpace(a.Interface)
	a.CredentialBindingDigest = strings.TrimSpace(a.CredentialBindingDigest)
	parsedBaseURL, baseURLErr := url.Parse(a.BaseURL)
	baseURLValid := a.BaseURL == "" || (baseURLErr == nil && parsedBaseURL.Scheme == "https" &&
		parsedBaseURL.Host != "" && parsedBaseURL.User == nil && parsedBaseURL.RawQuery == "" &&
		parsedBaseURL.Fragment == "" && parsedBaseURL.RawPath == "" &&
		parsedBaseURL.String() == a.BaseURL && parsedBaseURL.Host == strings.ToLower(parsedBaseURL.Host) &&
		net.ParseIP(parsedBaseURL.Hostname()) == nil)
	if !validUUID(a.ModelProfileID) || a.ModelProfileRevision == 0 || a.CredentialVersion == 0 ||
		a.Provider == "" || len(a.Provider) > 128 || strings.ContainsAny(a.Provider, "\r\n\x00") ||
		!baseURLValid ||
		a.Model == "" || len(a.Model) > 256 || strings.ContainsAny(a.Model, "\r\n\x00") ||
		a.Interface == "" || len(a.Interface) > 128 || strings.ContainsAny(a.Interface, "\r\n\x00") ||
		a.MaximumOutputTokens > 10_000_000 ||
		a.ContextWindow > 100_000_000 ||
		(a.ContextWindow > 0 && (a.MaximumOutputTokens == 0 || a.MaximumOutputTokens >= a.ContextWindow)) ||
		!validDigest(a.CredentialBindingDigest) ||
		!((a.Provider == "openai" && a.Interface == "openai_responses") ||
			(a.Provider == "openai_compatible" && a.Interface == "openai_compatible")) {
		return ErrInvalid
	}
	if a.BaseURL == "" && a.ContextWindow == 0 {
		a.BindingDigest = digestValue(struct {
			ModelProfileID          string
			ModelProfileRevision    uint64
			Provider                string
			Model                   string
			Interface               string
			MaximumOutputTokens     uint64
			CredentialVersion       uint64
			CredentialBindingDigest string
		}{a.ModelProfileID, a.ModelProfileRevision, a.Provider, a.Model, a.Interface, a.MaximumOutputTokens, a.CredentialVersion, a.CredentialBindingDigest})
		return nil
	}
	if a.BaseURL == "" {
		a.BindingDigest = digestValue(struct {
			ModelProfileID          string
			ModelProfileRevision    uint64
			Provider                string
			Model                   string
			Interface               string
			MaximumOutputTokens     uint64
			ContextWindow           uint64
			CredentialVersion       uint64
			CredentialBindingDigest string
		}{a.ModelProfileID, a.ModelProfileRevision, a.Provider, a.Model, a.Interface, a.MaximumOutputTokens, a.ContextWindow, a.CredentialVersion, a.CredentialBindingDigest})
		return nil
	}
	a.BindingDigest = digestValue(struct {
		ModelProfileID          string
		ModelProfileRevision    uint64
		Provider                string
		BaseURL                 string
		Model                   string
		Interface               string
		MaximumOutputTokens     uint64
		ContextWindow           uint64
		CredentialVersion       uint64
		CredentialBindingDigest string
	}{a.ModelProfileID, a.ModelProfileRevision, a.Provider, a.BaseURL, a.Model, a.Interface, a.MaximumOutputTokens, a.ContextWindow, a.CredentialVersion, a.CredentialBindingDigest})
	return nil
}

func (m *InputManifest) Seal() (string, error) {
	if m == nil {
		return "", ErrInvalid
	}
	m.Schema = strings.TrimSpace(m.Schema)
	if m.Schema == "" && len(m.Items) == 0 {
		m.Schema = InputManifestSchema
	}
	if m.Schema != InputManifestSchema || len(m.Items) > 256 {
		return "", ErrInvalid
	}
	seenIDs := make(map[string]struct{}, len(m.Items))
	seenPaths := make(map[string]struct{}, len(m.Items))
	seenFoldedPaths := make(map[string]string, len(m.Items))
	items := append([]InputManifestItem(nil), m.Items...)
	archiveCount := 0
	var totalBytes uint64
	for index := range items {
		item := &items[index]
		item.InputID = strings.TrimSpace(item.InputID)
		item.Kind = strings.TrimSpace(item.Kind)
		item.Name = strings.TrimSpace(item.Name)
		item.MountPath = strings.TrimSpace(item.MountPath)
		item.MediaType = strings.TrimSpace(item.MediaType)
		item.SHA256 = strings.TrimSpace(item.SHA256)
		item.SourceRef = strings.TrimSpace(item.SourceRef)
		cleanPath := path.Clean(item.MountPath)
		if !validUUID(item.InputID) || (item.Kind != "file" && item.Kind != "archive") ||
			item.Name == "" || len(item.Name) > 255 || strings.ContainsAny(item.Name, "\r\n\x00") ||
			item.MountPath == "" || len(item.MountPath) > 1024 || cleanPath != item.MountPath || cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, "../") || strings.HasPrefix(cleanPath, "/") ||
			item.MediaType == "" || len(item.MediaType) > 255 || strings.ContainsAny(item.MediaType, "\r\n\x00") ||
			item.SizeBytes == 0 || item.SizeBytes > 16<<30 || !validDigest(item.SHA256) ||
			!validUUID(item.SourceRef) || item.SourceRevision == 0 {
			return "", ErrInvalid
		}
		if item.Kind == "archive" {
			archiveCount++
			if archiveCount > 1 || item.MountPath != "workspace" || item.MediaType != workspacearchive.MediaType {
				return "", ErrInvalid
			}
		} else if item.MediaType == workspacearchive.MediaType || item.MountPath == "workspace" || strings.HasPrefix(item.MountPath, "workspace/") {
			return "", ErrInvalid
		}
		totalBytes += item.SizeBytes
		if totalBytes > 8<<20 {
			return "", ErrInvalid
		}
		if _, exists := seenIDs[item.InputID]; exists {
			return "", ErrInvalid
		}
		if _, exists := seenPaths[item.MountPath]; exists {
			return "", ErrInvalid
		}
		foldedPath := strings.ToLower(item.MountPath)
		if existing, exists := seenFoldedPaths[foldedPath]; exists && existing != item.MountPath {
			return "", ErrInvalid
		}
		for existing := range seenPaths {
			if strings.HasPrefix(existing, item.MountPath+"/") || strings.HasPrefix(item.MountPath, existing+"/") ||
				strings.HasPrefix(strings.ToLower(existing), foldedPath+"/") ||
				strings.HasPrefix(foldedPath, strings.ToLower(existing)+"/") {
				return "", ErrInvalid
			}
		}
		seenIDs[item.InputID] = struct{}{}
		seenPaths[item.MountPath] = struct{}{}
		seenFoldedPaths[foldedPath] = item.MountPath
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].MountPath == items[j].MountPath {
			return items[i].InputID < items[j].InputID
		}
		return items[i].MountPath < items[j].MountPath
	})
	m.Items = items
	return digestValue(*m), nil
}

func (m *StagedInputManifest) Seal(source InputManifest) (string, error) {
	if m == nil || !validUUID(m.ExecutionID) {
		return "", ErrInvalid
	}
	sourceDigest, err := source.Seal()
	if err != nil {
		return "", err
	}
	m.Schema = strings.TrimSpace(m.Schema)
	if m.Schema == "" {
		m.Schema = StagedInputManifestSchemaV1
	}
	m.SourceManifestDigest = strings.TrimSpace(m.SourceManifestDigest)
	if m.Schema != StagedInputManifestSchemaV1 || (m.SourceManifestDigest != "" && m.SourceManifestDigest != sourceDigest) || len(m.Items) != len(source.Items) {
		return "", ErrInvalid
	}
	m.SourceManifestDigest = sourceDigest
	sources := make(map[string]InputManifestItem, len(source.Items))
	for _, item := range source.Items {
		sources[item.InputID] = item
	}
	items := append([]StagedInputManifestItem(nil), m.Items...)
	seen := make(map[string]struct{}, len(items))
	for index := range items {
		item := &items[index]
		item.InputID = strings.TrimSpace(item.InputID)
		item.MountPath = strings.TrimSpace(item.MountPath)
		item.MediaType = strings.TrimSpace(item.MediaType)
		item.SHA256 = strings.TrimSpace(item.SHA256)
		item.S3Bucket = strings.TrimSpace(item.S3Bucket)
		item.S3Key = strings.TrimSpace(item.S3Key)
		item.S3VersionID = strings.TrimSpace(item.S3VersionID)
		expected, ok := sources[item.InputID]
		if !ok || item.MountPath != expected.MountPath || item.MediaType != expected.MediaType || item.SizeBytes != expected.SizeBytes || item.SHA256 != expected.SHA256 ||
			len(item.S3Bucket) < 3 || len(item.S3Bucket) > 63 || strings.ContainsAny(item.S3Bucket, "/:*?#\r\n\x00") ||
			item.S3Key == "" || len(item.S3Key) > 1024 || strings.HasPrefix(item.S3Key, "/") || strings.Contains(item.S3Key, "..") || strings.ContainsAny(item.S3Key, "\r\n\x00") || !strings.Contains(item.S3Key, m.ExecutionID) ||
			item.S3VersionID == "" || len(item.S3VersionID) > 1024 || strings.ContainsAny(item.S3VersionID, "\r\n\x00") {
			return "", ErrInvalid
		}
		if _, duplicate := seen[item.InputID]; duplicate {
			return "", ErrInvalid
		}
		seen[item.InputID] = struct{}{}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].MountPath == items[j].MountPath {
			return items[i].InputID < items[j].InputID
		}
		return items[i].MountPath < items[j].MountPath
	})
	m.Items = items
	m.Digest = digestValue(*m)
	return m.Digest, nil
}

func (m StagedInputManifest) CanonicalJSON(source InputManifest) ([]byte, error) {
	copy := m
	digest, err := copy.Seal(source)
	if err != nil || (m.Digest != "" && m.Digest != digest) {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(copy)
	if err != nil || len(raw) > 512<<10 {
		return nil, ErrInvalid
	}
	return raw, nil
}

func (q *Quote) Seal() error {
	if q == nil {
		return ErrInvalid
	}
	q.Currency = strings.ToUpper(strings.TrimSpace(q.Currency))
	q.BasisDigest = strings.TrimSpace(q.BasisDigest)
	q.CatalogRevisionDigest = strings.TrimSpace(q.CatalogRevisionDigest)
	q.SourceTime = q.SourceTime.UTC()
	q.ExpiresAt = q.ExpiresAt.UTC()
	if q.AmountMicros < 0 || q.MaximumAuthorizedCostMicros < q.AmountMicros || len(q.Currency) != 3 ||
		!validDigest(q.BasisDigest) || !validDigest(q.CatalogRevisionDigest) || q.SourceTime.IsZero() || !q.ExpiresAt.After(q.SourceTime) {
		return ErrInvalid
	}
	q.Digest = digestValue(struct {
		AmountMicros, MaximumAuthorizedCostMicros int64
		Currency                                  string
		SourceTime, ExpiresAt                     time.Time
		BasisDigest, CatalogRevisionDigest        string
	}{q.AmountMicros, q.MaximumAuthorizedCostMicros, q.Currency, q.SourceTime, q.ExpiresAt, q.BasisDigest, q.CatalogRevisionDigest})
	return nil
}

func (p *Plan) Seal() error {
	if p == nil {
		return ErrInvalid
	}
	p.OwnerID = strings.TrimSpace(p.OwnerID)
	p.Objective = strings.TrimSpace(p.Objective)
	p.ObjectiveSummary = strings.TrimSpace(p.ObjectiveSummary)
	p.RecipeID = strings.TrimSpace(p.RecipeID)
	p.Adapter = strings.TrimSpace(p.Adapter)
	p.Status = strings.TrimSpace(p.Status)
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	if p.OwnerID == "" || len(p.OwnerID) > 512 || p.AccountGeneration == 0 || !validUUID(p.PlanID) || !validUUID(p.ExecutionID) || !validUUID(p.TaskID) || !validUUID(p.ConfirmationID) || !validUUID(p.ConversationID) || !validUUID(p.TurnID) || p.Revision == 0 || p.Status != string(StateWaitingUser) || p.RecipeID != RecipeEphemeralPiTask || p.Adapter != AdapterPiJSONTaskV1 || p.Objective == "" || len(p.Objective) > coretask.MaxGoalBytes || !utf8.ValidString(p.Objective) || p.ObjectiveSummary == "" || len(p.ObjectiveSummary) > coretask.MaxSummaryBytes || !utf8.ValidString(p.ObjectiveSummary) || !validDigest(p.UserPromptDigest) || !validateWorkspaceMode(p.WorkspaceMode) || p.ArtifactRetentionSeconds == 0 || p.ArtifactRetentionSeconds > uint64((30*24*time.Hour)/time.Second) || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	if err := p.sealAuthorizationBasis(); err != nil {
		return err
	}
	if p.Quote.BasisDigest != p.AuthorizationBasisDigest {
		return ErrInvalid
	}
	if err := p.Quote.Seal(); err != nil {
		return err
	}
	p.ExecutionDigest = digestValue(struct {
		OwnerID, PlanID, ExecutionID, ConversationID, TurnID                 string
		AccountGeneration, Revision                                          uint64
		RecipeID, Adapter, ObjectiveDigest, UserPromptDigest, ManifestDigest string
		ProposalReason                                                       ProposalReason
		BudgetEvidence                                                       *LocalBudgetEvidence
		WorkspaceMode                                                        WorkspaceMode
		ModelAuthorization                                                   any
		AWS                                                                  AWSBinding
		Compute                                                              ComputeSpec
		AWSInfrastructureDigest                                              string
		Limits                                                               Limits
		Network                                                              []string
		Secrets                                                              []SecretGrant
		Retention                                                            uint64
		QuoteDigest                                                          string
	}{p.OwnerID, p.PlanID, p.ExecutionID, p.ConversationID, p.TurnID, p.AccountGeneration, p.Revision, p.RecipeID, p.Adapter, p.ObjectiveDigest, p.UserPromptDigest, p.InputManifestDigest, p.ProposalReason, p.LocalBudgetEvidence, p.WorkspaceMode, p.ModelAuthorization.planDigestProjection(), p.AWS, p.Compute, p.AWSInfrastructureDigest, p.Limits, p.NetworkGrants, p.SecretGrants, p.ArtifactRetentionSeconds, p.Quote.Digest})
	p.Digest = digestValue(struct {
		ExecutionDigest, TaskID, ConfirmationID string
	}{p.ExecutionDigest, p.TaskID, p.ConfirmationID})
	return nil
}

func (p *Plan) sealAuthorizationBasis() error {
	switch p.ProposalReason {
	case ProposalReasonExplicitUserCloud, ProposalReasonCentralDelegation:
		if p.LocalBudgetEvidence != nil {
			return ErrInvalid
		}
	case ProposalReasonLocalBudgetExceeded:
		if p.LocalBudgetEvidence == nil || p.LocalBudgetEvidence.normalize() != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	manifestDigest, err := p.InputManifest.Seal()
	if err != nil || (p.InputManifestDigest != "" && p.InputManifestDigest != manifestDigest) {
		return ErrInvalid
	}
	p.InputManifestDigest = manifestDigest
	p.InputManifestItemCount = uint64(len(p.InputManifest.Items))
	if !validWorkspaceInputCardinality(p.WorkspaceMode, len(p.InputManifest.Items)) {
		return ErrInvalid
	}
	if err := p.ModelAuthorization.Seal(); err != nil {
		return err
	}
	p.ObjectiveDigest = digestValue(p.Objective)
	if err := validateAWS(p.AWS); err != nil {
		return err
	}
	if err := validateCompute(p.Compute); err != nil {
		return err
	}
	if err := p.sealInfrastructure(); err != nil {
		return err
	}
	if err := validateLimits(p.Limits); err != nil {
		return err
	}
	p.NetworkGrants, err = normalizeStrings(p.NetworkGrants, 64)
	if err != nil {
		return err
	}
	if err := normalizeSecretGrants(&p.SecretGrants); err != nil {
		return err
	}
	p.AuthorizationBasisDigest = digestValue(struct {
		OwnerID, ConversationID, TurnID, RecipeID, Adapter     string
		AccountGeneration                                      uint64
		ObjectiveDigest, UserPromptDigest, InputManifestDigest string
		ProposalReason                                         ProposalReason
		BudgetEvidence                                         *LocalBudgetEvidence
		WorkspaceMode                                          WorkspaceMode
		ModelAuthorization                                     any
		AWS                                                    AWSBinding
		Compute                                                ComputeSpec
		AWSInfrastructureDigest                                string
		Limits                                                 Limits
		Network                                                []string
		Secrets                                                []SecretGrant
		Retention                                              uint64
	}{p.OwnerID, p.ConversationID, p.TurnID, p.RecipeID, p.Adapter, p.AccountGeneration, p.ObjectiveDigest, p.UserPromptDigest, p.InputManifestDigest, p.ProposalReason, p.LocalBudgetEvidence, p.WorkspaceMode, p.ModelAuthorization.planDigestProjection(), p.AWS, p.Compute, p.AWSInfrastructureDigest, p.Limits, p.NetworkGrants, p.SecretGrants, p.ArtifactRetentionSeconds})
	return nil
}

func (p *Plan) sealInfrastructure() error {
	if p == nil || !validAWSID(p.Placement.VPCID, "vpc") || !validAWSID(p.Placement.SubnetID, "subnet") {
		return ErrInvalid
	}
	if err := p.NetworkPolicy.Seal(); err != nil {
		return err
	}
	if err := p.ArtifactGrant.Seal(p.ExecutionID); err != nil || p.ArtifactGrant.RetentionSeconds != p.ArtifactRetentionSeconds {
		return ErrInvalid
	}
	if err := p.WorkerBootstrap.Seal(p.NetworkPolicy); err != nil {
		return err
	}
	if err := p.ModelEndpoint.Seal(p.NetworkPolicy, p.ModelAuthorization, p.Limits); err != nil {
		return err
	}
	iamDigest := digestValue(struct {
		ExecutionID        string
		InputManifest      InputManifest
		ArtifactGrant      ArtifactGrant
		NetworkPolicy      NetworkPolicy
		WorkerBootstrap    WorkerBootstrap
		ModelEndpoint      ModelEndpointBinding
		ModelBindingDigest string
	}{p.ExecutionID, p.InputManifest, p.ArtifactGrant, p.NetworkPolicy, p.WorkerBootstrap, p.ModelEndpoint, p.ModelAuthorization.BindingDigest})
	if p.Placement.IAMPolicyDigest != "" && p.Placement.IAMPolicyDigest != iamDigest {
		return ErrInvalid
	}
	p.Placement.IAMPolicyDigest = iamDigest
	infrastructureDigest := digestValue(struct {
		AccountGeneration uint64
		AWS               AWSBinding
		Compute           ComputeSpec
		Placement         PlacementSpec
		NetworkPolicy     NetworkPolicy
		ArtifactGrant     ArtifactGrant
		WorkerBootstrap   WorkerBootstrap
		ModelEndpoint     ModelEndpointBinding
	}{p.AccountGeneration, p.AWS, p.Compute, p.Placement, p.NetworkPolicy, p.ArtifactGrant, p.WorkerBootstrap, p.ModelEndpoint})
	if p.AWSInfrastructureDigest != "" && p.AWSInfrastructureDigest != infrastructureDigest {
		return ErrInvalid
	}
	p.AWSInfrastructureDigest = infrastructureDigest
	return nil
}

func validateWorkspaceMode(mode WorkspaceMode) bool {
	return mode == WorkspaceNone || mode == WorkspaceReadOnly || mode == WorkspaceWrite
}

func validWorkspaceInputCardinality(mode WorkspaceMode, count int) bool {
	switch mode {
	case WorkspaceNone:
		return count == 0
	case WorkspaceReadOnly:
		return count > 0
	case WorkspaceWrite:
		return true
	default:
		return false
	}
}

func validateAWS(value AWSBinding) error {
	if len(strings.TrimSpace(value.AccountID)) != 12 || strings.Trim(value.AccountID, "0123456789") != "" || strings.TrimSpace(value.Region) == "" || len(value.Region) > 64 || !validUUID(value.CredentialID) || value.CredentialRevision == 0 {
		return ErrInvalid
	}
	return nil
}

func validateCompute(value ComputeSpec) error {
	if strings.TrimSpace(value.InstanceType) == "" || (value.Architecture != "x86_64" && value.Architecture != "arm64") || !strings.HasPrefix(value.RootDeviceName, "/dev/") || len(value.RootDeviceName) > 64 || strings.ContainsAny(value.RootDeviceName, "\r\n\x00") || value.VolumeGiB < 8 || value.VolumeGiB > 16384 || value.VolumeType != "gp3" || value.VolumeIOPS < 3000 || value.VolumeIOPS > 16000 || value.VolumeThroughputMiB < 125 || value.VolumeThroughputMiB > 1000 || strings.TrimSpace(value.AMIID) == "" || !validDigest(value.AMIDigest) || !validDigest(value.WorkerReleaseDigest) || !validDigest(value.PiRuntimeDigest) || !validDigest(value.HostNetworkPolicySHA256) {
		return ErrInvalid
	}
	return nil
}

func validAWSID(value, prefix string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, prefix+"-") {
		return false
	}
	suffix := strings.TrimPrefix(value, prefix+"-")
	if len(suffix) < 8 || len(suffix) > 17 {
		return false
	}
	for _, r := range suffix {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (n *NetworkPolicy) Seal() error {
	if n == nil {
		return ErrInvalid
	}
	var err error
	n.DNSResolverCIDRs, err = normalizeStrings(n.DNSResolverCIDRs, 16)
	if err != nil {
		return err
	}
	n.TLSProxyCIDRs, err = normalizeStrings(n.TLSProxyCIDRs, 16)
	if err != nil {
		return err
	}
	n.AllowedFQDNs, err = normalizeStrings(n.AllowedFQDNs, 64)
	if err != nil || len(n.DNSResolverCIDRs) == 0 || len(n.TLSProxyCIDRs) == 0 || len(n.AllowedFQDNs) == 0 {
		return ErrInvalid
	}
	n.OutboundProxyURL = strings.TrimSpace(n.OutboundProxyURL)
	n.OutboundProxyServerName = strings.ToLower(strings.TrimSpace(n.OutboundProxyServerName))
	n.OutboundProxyTrustBundleSHA256 = strings.TrimSpace(n.OutboundProxyTrustBundleSHA256)
	n.OutboundProxyBindingDigest = strings.TrimSpace(n.OutboundProxyBindingDigest)
	for _, cidr := range append(append([]string(nil), n.DNSResolverCIDRs...), n.TLSProxyCIDRs...) {
		ip, network, parseErr := net.ParseCIDR(cidr)
		if parseErr != nil || ip.To4() == nil || network.String() != cidr || cidr == "0.0.0.0/0" {
			return ErrInvalid
		}
	}
	for _, fqdn := range n.AllowedFQDNs {
		if fqdn != strings.ToLower(fqdn) || len(fqdn) > 253 || !strings.Contains(fqdn, ".") || strings.ContainsAny(fqdn, "*/:@\r\n\x00") || net.ParseIP(fqdn) != nil {
			return ErrInvalid
		}
	}
	parsedProxy, parseErr := url.Parse(n.OutboundProxyURL)
	if parseErr != nil || parsedProxy.Scheme != "https" || parsedProxy.User != nil || parsedProxy.RawQuery != "" || parsedProxy.Fragment != "" ||
		parsedProxy.Path != "" || parsedProxy.RawPath != "" || parsedProxy.Port() != "443" || parsedProxy.Hostname() != n.OutboundProxyServerName ||
		n.OutboundProxyServerName == "" || len(n.OutboundProxyServerName) > 253 || !strings.Contains(n.OutboundProxyServerName, ".") ||
		strings.ContainsAny(n.OutboundProxyServerName, "*/:@\r\n\x00") || net.ParseIP(n.OutboundProxyServerName) != nil ||
		parsedProxy.String() != n.OutboundProxyURL || !validDigest(n.OutboundProxyTrustBundleSHA256) {
		return ErrInvalid
	}
	expectedProxyBinding := digestValue(struct {
		URL               string `json:"url"`
		ServerName        string `json:"server_name"`
		TrustBundleSHA256 string `json:"trust_bundle_sha256"`
	}{n.OutboundProxyURL, n.OutboundProxyServerName, n.OutboundProxyTrustBundleSHA256})
	if n.OutboundProxyBindingDigest != "" && n.OutboundProxyBindingDigest != expectedProxyBinding {
		return ErrInvalid
	}
	n.OutboundProxyBindingDigest = expectedProxyBinding
	n.FQDNPolicyDigest = digestValue(n.AllowedFQDNs)
	return nil
}

func (g *ArtifactGrant) Seal(executionID string) error {
	if g == nil {
		return ErrInvalid
	}
	g.Bucket = strings.TrimSpace(g.Bucket)
	g.KeyPrefix = strings.TrimSpace(g.KeyPrefix)
	g.KMSKeyARN = strings.TrimSpace(g.KMSKeyARN)
	if len(g.Bucket) < 3 || len(g.Bucket) > 63 || strings.ContainsAny(g.Bucket, "/:*?#\r\n\x00") || g.KeyPrefix == "" || len(g.KeyPrefix) > 900 || strings.HasPrefix(g.KeyPrefix, "/") || !strings.HasSuffix(g.KeyPrefix, "/") || strings.Contains(g.KeyPrefix, "..") || strings.ContainsAny(g.KeyPrefix, "\r\n\x00") || !strings.Contains(g.KeyPrefix, executionID) || !g.Versioned || g.RetentionSeconds == 0 || g.RetentionSeconds > uint64((30*24*time.Hour)/time.Second) || !strings.HasPrefix(g.KMSKeyARN, "arn:aws:kms:") || len(g.KMSKeyARN) > 2048 {
		return ErrInvalid
	}
	g.Digest = digestValue(struct {
		Bucket, KeyPrefix, KMSKeyARN string
		Versioned                    bool
		RetentionSeconds             uint64
	}{g.Bucket, g.KeyPrefix, g.KMSKeyARN, g.Versioned, g.RetentionSeconds})
	return nil
}

func (b *WorkerBootstrap) Seal(network NetworkPolicy) error {
	if b == nil {
		return ErrInvalid
	}
	b.Protocol = strings.TrimSpace(b.Protocol)
	b.Endpoint = strings.TrimSpace(b.Endpoint)
	b.TLSServerName = strings.ToLower(strings.TrimSpace(b.TLSServerName))
	b.TrustBundleDigest = strings.TrimSpace(b.TrustBundleDigest)
	parsed, err := url.Parse(b.Endpoint)
	if err != nil || b.Protocol != WorkerControlProtocolV1 || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() != b.TLSServerName || !validDigest(b.TrustBundleDigest) {
		return ErrInvalid
	}
	allowed := false
	for _, fqdn := range network.AllowedFQDNs {
		if fqdn == b.TLSServerName {
			allowed = true
			break
		}
	}
	if !allowed {
		return ErrInvalid
	}
	b.BindingDigest = digestValue(struct {
		Protocol, Endpoint, TLSServerName, TrustBundleDigest string
	}{b.Protocol, b.Endpoint, b.TLSServerName, b.TrustBundleDigest})
	return nil
}

func (r *ModelEndpointBinding) Seal(network NetworkPolicy, model ModelAuthorization, limits Limits) error {
	if r == nil {
		return ErrInvalid
	}
	r.Endpoint = strings.TrimSpace(r.Endpoint)
	r.TLSServerName = strings.ToLower(strings.TrimSpace(r.TLSServerName))
	parsed, err := url.Parse(r.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() != r.TLSServerName ||
		(model.BaseURL != "" && r.Endpoint != model.BaseURL) || !validDigest(model.BindingDigest) {
		return ErrInvalid
	}
	allowed := false
	for _, fqdn := range network.AllowedFQDNs {
		if fqdn == r.TLSServerName {
			allowed = true
			break
		}
	}
	if !allowed {
		return ErrInvalid
	}
	if limits.MaxTokens > 0 {
		// Preserve the exact v1 digest so persisted Plans and artifacts remain
		// readable after cumulative budgeting is retired.
		r.BindingDigest = digestValue(struct {
			Endpoint, TLSServerName, ModelBindingDigest string
			MaxTokens                                   uint64
		}{r.Endpoint, r.TLSServerName, model.BindingDigest, limits.MaxTokens})
		return nil
	}
	r.BindingDigest = digestValue(struct {
		Endpoint, TLSServerName, ModelBindingDigest string
	}{r.Endpoint, r.TLSServerName, model.BindingDigest})
	return nil
}

func validateLimits(value Limits) error {
	if value.MaxRuntimeSeconds == 0 || value.MaxRuntimeSeconds > uint64((24*time.Hour)/time.Second) ||
		value.MaxTokens > 10_000_000 || value.MaxOutputBytes == 0 || value.MaxOutputBytes > MaxCloudWorkerOutputBytes {
		return ErrInvalid
	}
	legacy := value.MinimumRuntimeSeconds == 0 && value.ExpectedRuntimeSeconds == 0
	if !legacy && (RuntimeEstimate{
		MinimumSeconds:  value.MinimumRuntimeSeconds,
		ExpectedSeconds: value.ExpectedRuntimeSeconds,
		MaximumSeconds:  value.MaxRuntimeSeconds,
	}).validate(value.MaxRuntimeSeconds) != nil {
		return ErrInvalid
	}
	return nil
}

func normalizeSecretGrants(values *[]SecretGrant) error {
	if values == nil || len(*values) > 32 {
		return ErrInvalid
	}
	seen := map[string]struct{}{}
	out := make([]SecretGrant, 0, len(*values))
	for _, value := range *values {
		value.ReferenceID = strings.TrimSpace(value.ReferenceID)
		value.Purpose = strings.TrimSpace(value.Purpose)
		value.BindingDigest = strings.TrimSpace(value.BindingDigest)
		if !validUUID(value.ReferenceID) || value.Purpose == "" || len(value.Purpose) > 64 || !validDigest(value.BindingDigest) {
			return ErrInvalid
		}
		key := value.ReferenceID + "\x00" + value.Purpose
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReferenceID == out[j].ReferenceID {
			return out[i].Purpose < out[j].Purpose
		}
		return out[i].ReferenceID < out[j].ReferenceID
	})
	*values = out
	return nil
}

func NewExecution(plan Plan) (Execution, error) {
	if err := plan.Seal(); err != nil {
		return Execution{}, err
	}
	execution := Execution{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		RunID: plan.ExecutionID, ExecutionID: plan.ExecutionID,
		PlanID: plan.PlanID, PlanRevision: plan.Revision, PlanDigest: plan.Digest,
		TaskID: plan.TaskID, ConfirmationID: plan.ConfirmationID,
		ConversationID: plan.ConversationID, TurnID: plan.TurnID,
		Status: StateWaitingUser, State: StateWaitingUser, Revision: 1,
		WorkspaceMode: plan.WorkspaceMode, ModelBindingDigest: plan.ModelAuthorization.BindingDigest,
		QuoteDigest:     plan.Quote.Digest,
		ExecutionDigest: plan.ExecutionDigest, ArtifactIDs: []string{},
		CreatedAt: plan.CreatedAt, UpdatedAt: plan.UpdatedAt,
	}
	if err := execution.Seal(); err != nil {
		return Execution{}, err
	}
	return execution, nil
}

func (e *Execution) Seal() error {
	if e == nil || strings.TrimSpace(e.OwnerID) == "" || e.AccountGeneration == 0 || !validUUID(e.RunID) || e.RunID != e.ExecutionID || !validUUID(e.PlanID) || !validUUID(e.TaskID) || !validUUID(e.ConfirmationID) || !validUUID(e.ConversationID) || !validUUID(e.TurnID) || e.PlanRevision == 0 || e.Revision == 0 || !validDigest(e.PlanDigest) || !validDigest(e.ModelBindingDigest) || !validDigest(e.QuoteDigest) || !validDigest(e.ExecutionDigest) || e.Status != e.State || !validExecutionState(e.State) || !validateWorkspaceMode(e.WorkspaceMode) || e.CreatedAt.IsZero() || e.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	e.CreatedAt, e.UpdatedAt = e.CreatedAt.UTC(), e.UpdatedAt.UTC()
	if e.TerminalIntent != "" && e.TerminalIntent != string(StateSucceeded) && e.TerminalIntent != string(StateFailed) && e.TerminalIntent != string(StateCanceled) {
		return ErrInvalid
	}
	if e.NeedsReconcile && e.State != StateCleaning {
		return ErrInvalid
	}
	ids, err := normalizeStrings(e.ArtifactIDs, 128)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if !validUUID(id) {
			return ErrInvalid
		}
	}
	e.ArtifactIDs = ids
	fullyDestroyed := e.Cleanup.ResourcesTotal > 0 && e.Cleanup.ResourcesTotal == e.Cleanup.ResourcesVerifiedDestroyed
	if e.Cleanup.ResourcesVerifiedDestroyed > e.Cleanup.ResourcesTotal || e.Cleanup.VerifiedDestroyed != fullyDestroyed {
		return ErrInvalid
	}
	if e.Cleanup.VerifiedDestroyed && e.Cleanup.VerifiedAt == nil {
		return ErrInvalid
	}
	if e.Cleanup.ResourcesTotal > 0 && isTerminalExecutionState(e.State) && !e.Cleanup.VerifiedDestroyed {
		return ErrInvalid
	}
	if isTerminalExecutionState(e.State) && e.ProviderMutationStarted &&
		e.Cleanup.ResourcesTotal != expectedEphemeralAWSResourceCount() {
		return ErrInvalid
	}
	if (e.State == StateSucceeded && (!e.ProviderMutationStarted || !e.Cleanup.VerifiedDestroyed)) ||
		((e.State == StateFailed || e.State == StateCanceled) && e.ProviderMutationStarted && !e.Cleanup.VerifiedDestroyed) ||
		((e.State == StateRejected || e.State == StateExpired) && (e.ProviderMutationStarted || e.Cleanup.ResourcesTotal != 0)) {
		return ErrInvalid
	}
	e.Digest = digestValue(struct {
		ExecutionID, PlanDigest, ModelBindingDigest, QuoteDigest, ExecutionDigest string
		AccountGeneration                                                         uint64
		State                                                                     ExecutionState
		Revision                                                                  uint64
		ProviderMutationStarted                                                   bool
		TerminalIntent                                                            string
		NeedsReconcile                                                            bool
		Cleanup                                                                   CleanupSummary
		Artifacts                                                                 []string
		FailureCode, FailureSummary                                               string
	}{e.ExecutionID, e.PlanDigest, e.ModelBindingDigest, e.QuoteDigest, e.ExecutionDigest, e.AccountGeneration, e.State, e.Revision, e.ProviderMutationStarted, e.TerminalIntent, e.NeedsReconcile, e.Cleanup, e.ArtifactIDs, e.FailureCode, e.FailureSummary})
	return nil
}

func isTerminalExecutionState(state ExecutionState) bool {
	switch state {
	case StateSucceeded, StateFailed, StateCanceled, StateRejected, StateExpired:
		return true
	default:
		return false
	}
}

func validExecutionState(state ExecutionState) bool {
	switch state {
	case StateWaitingUser, StateQueued, StateProvisioning, StateAwaitingWorker, StateRunning, StateCollecting, StateValidating, StateCleaning, StateSucceeded, StateFailed, StateCanceled, StateRejected, StateExpired:
		return true
	default:
		return false
	}
}

func canTransition(from, to ExecutionState) bool {
	switch from {
	case StateWaitingUser:
		return to == StateQueued || to == StateRejected || to == StateExpired || to == StateCanceled
	case StateQueued:
		return to == StateProvisioning || to == StateExpired || to == StateCanceled || to == StateCleaning
	case StateProvisioning:
		return to == StateAwaitingWorker || to == StateExpired || to == StateCleaning
	case StateAwaitingWorker:
		return to == StateRunning || to == StateCleaning
	case StateRunning:
		return to == StateCollecting || to == StateCleaning
	case StateCollecting:
		return to == StateValidating || to == StateCleaning
	case StateValidating:
		return to == StateCleaning
	case StateCleaning:
		return to == StateSucceeded || to == StateFailed || to == StateCanceled
	default:
		return false
	}
}

func (e Execution) Transition(next ExecutionState, at time.Time) (Execution, error) {
	if !canTransition(e.State, next) || at.IsZero() {
		return Execution{}, ErrConflict
	}
	e.State, e.Status, e.Revision, e.UpdatedAt = next, next, e.Revision+1, at.UTC()
	if err := e.Seal(); err != nil {
		return Execution{}, err
	}
	return e, nil
}

func BindingForPlan(plan Plan) (coreconfirmation.Binding, error) {
	if err := plan.Seal(); err != nil {
		return coreconfirmation.Binding{}, err
	}
	execution, err := NewExecution(plan)
	if err != nil {
		return coreconfirmation.Binding{}, err
	}
	secretGrants := make([]coreconfirmation.SecretGrant, 0, len(plan.SecretGrants))
	for _, grant := range plan.SecretGrants {
		purpose := coreconfirmation.SecretPurposeOtherExtensionSecret
		switch grant.Purpose {
		case string(coreconfirmation.SecretPurposeModelAPIKey):
			purpose = coreconfirmation.SecretPurposeModelAPIKey
		case string(coreconfirmation.SecretPurposeAWSCredential):
			purpose = coreconfirmation.SecretPurposeAWSCredential
		}
		secretGrants = append(secretGrants, coreconfirmation.SecretGrant{ReferenceID: grant.ReferenceID, Purpose: purpose, BindingDigest: coreconfirmation.Digest(grant.BindingDigest)})
	}
	binding := coreconfirmation.Binding{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration, OperationDomain: OperationDomain,
		TargetID: plan.ExecutionID, TargetRevision: int64(plan.Revision),
		TargetKind: "ephemeral_pi_worker", SourceVersion: plan.RecipeID,
		SourceCommit:    plan.Compute.WorkerReleaseDigest,
		ContentDigest:   coreconfirmation.Digest(plan.ObjectiveDigest),
		ManifestDigest:  coreconfirmation.Digest(plan.InputManifestDigest),
		ExecutionDigest: coreconfirmation.Digest(plan.ExecutionDigest),
		PermissionDigest: coreconfirmation.Digest(digestValue(struct {
			Network            []string
			Secrets            []SecretGrant
			ModelBindingDigest string
		}{plan.NetworkGrants, plan.SecretGrants, plan.ModelAuthorization.BindingDigest})),
		ParameterDigest:   coreconfirmation.Digest(plan.Digest),
		NetworkDigest:     coreconfirmation.Digest(digestValue(plan.NetworkGrants)),
		SecretGrantDigest: coreconfirmation.Digest(digestValue(plan.SecretGrants)),
		SelectedTool:      "cloud_worker_propose",
		SelectedCommand:   []string{},
		NetworkGrants:     append(make([]string, 0, len(plan.NetworkGrants)), plan.NetworkGrants...),
		SecretGrants:      secretGrants,
		ExecutionID:       plan.ExecutionID, PlanID: plan.PlanID, PlanRevision: int64(plan.Revision), PlanDigest: coreconfirmation.Digest(plan.Digest),
		RunID: execution.RunID, RunRevision: int64(execution.Revision), RunDigest: coreconfirmation.Digest(execution.Digest), QuoteDigest: coreconfirmation.Digest(plan.Quote.Digest),
	}
	binding.Digest = coreconfirmation.Digest(digestValue(binding))
	return binding.Normalize()
}

func CompletionDigest(value CompletionOutbox) string {
	return digestValue(struct {
		EventID         string `json:"event_id"`
		ExecutionID     string `json:"execution_id"`
		RunID           string `json:"run_id"`
		ConversationID  string `json:"conversation_id"`
		TurnID          string `json:"turn_id"`
		ResultMessageID string `json:"result_message_id"`
		TerminalState   string `json:"terminal_state"`
		CompletedAt     string `json:"completed_at"`
	}{value.EventID, value.ExecutionID, value.RunID, value.ConversationID, value.TurnID, value.ResultMessageID, value.TerminalState, value.CompletedAt.UTC().Format(time.RFC3339Nano)})
}

func (o CompletionOutbox) Validate() error {
	if !validUUID(o.EventID) || !validUUID(o.ExecutionID) || o.RunID != o.ExecutionID || !validUUID(o.ConversationID) || !validUUID(o.TurnID) || !validUUID(o.ResultMessageID) || o.CompletedAt.IsZero() || o.CompletedAt.Location() != time.UTC || !validDigest(o.PayloadDigest) || o.PayloadDigest != CompletionDigest(o) {
		return ErrInvalid
	}
	switch o.TerminalState {
	case string(StateSucceeded), string(StateFailed), string(StateCanceled):
		return nil
	default:
		return fmt.Errorf("%w: unsupported completion terminal state", ErrInvalid)
	}
}

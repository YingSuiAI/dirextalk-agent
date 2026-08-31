// Package cloudworker owns the retained SSH Worker execution domain.
// It deliberately keeps provider credentials, secret values and executable
// command text out of durable plans, task payloads and public projections.
package cloudworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/workspacearchive"
)

const (
	RecipeEphemeralPiTask = "ephemeral-pi-task"
	AdapterPiJSONTaskV1   = "pi_json_task_v1"
	OperationDomain       = "cloud_worker.execute"
	InputManifestSchema   = "cloud_worker_input_manifest/v1"
	// MaxCloudWorkerOutputBytes is the authorization-visible hard cap shared
	// with the Pi runtime/result collector. A quote must never authorize an
	// output the Worker cannot upload and the Agent cannot centrally verify.
	MaxCloudWorkerOutputBytes uint64 = 8 << 20
)

var (
	ErrInvalid             = errors.New("cloudworker: invalid")
	ErrNotFound            = errors.New("cloudworker: not found")
	ErrConflict            = errors.New("cloudworker: conflict")
	ErrRevisionConflict    = errors.New("cloudworker: revision conflict")
	ErrStaleAuthorization  = errors.New("cloudworker: stale authorization")
	ErrQuoteExpired        = errors.New("cloudworker: quote expired")
	ErrPricingCatalogStale = errors.New("cloudworker: pricing catalog stale")
	ErrProviderUnavailable = errors.New("cloudworker: provider unavailable")
	ErrLeaseConflict       = errors.New("cloudworker: task lease conflict")
)

type WorkspaceMode string

const (
	WorkspaceNone     WorkspaceMode = "none"
	WorkspaceReadOnly WorkspaceMode = "read_only"
	WorkspaceWrite    WorkspaceMode = "write"
)

type ProposalReason string

const (
	ProposalReasonLocalBudgetExceeded ProposalReason = "local_budget_exceeded"
)

// LocalBudgetEvidence is an immutable proof emitted by the local scheduler.
// A model assertion or a local execution failure is not budget evidence.
type LocalBudgetEvidence struct {
	BudgetID string `json:"budget_id"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}

// ModelAuthorization binds a plan to an Agent-owned model profile and
// credential revision without making the long-lived credential representable.
// BindingDigest is also the audience binding used by short-lived Worker grants.
type ModelAuthorization struct {
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

// GitHubBinding is the optional, non-secret authorization snapshot for one
// Worker task. The PAT itself is resolved only at remote-task start and is
// never representable by a durable plan, task payload, or confirmation.
type GitHubBinding struct {
	OwnerID           string `json:"owner_id"`
	AccountGeneration uint64 `json:"account_generation"`
	ConfigRevision    uint64 `json:"config_revision"`
	CredentialVersion uint64 `json:"credential_version"`
	BindingDigest     string `json:"binding_digest"`
}

// InputManifest binds the immutable Agent-owned workspace sources that the SSH
// Worker receives after the owner confirms the quote.
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

type ExecutionState string

const (
	StateWaitingUser  ExecutionState = "waiting_user"
	StateQueued       ExecutionState = "queued"
	StateProvisioning ExecutionState = "provisioning"
	StateRunning      ExecutionState = "running"
	StateCleaning     ExecutionState = "cleaning"
	StateSucceeded    ExecutionState = "succeeded"
	StateFailed       ExecutionState = "failed"
	StateCanceled     ExecutionState = "canceled"
	StateRejected     ExecutionState = "rejected"
	StateExpired      ExecutionState = "expired"
)

type AWSBinding struct {
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
	CredentialID       string `json:"credential_id"`
	CredentialRevision uint64 `json:"credential_revision"`
}

type ComputeSpec struct {
	InstanceType         string `json:"instance_type"`
	Architecture         string `json:"architecture"`
	AcceleratorType      string `json:"accelerator_type,omitempty"`
	AcceleratorName      string `json:"accelerator_name,omitempty"`
	AcceleratorMemoryMiB uint64 `json:"accelerator_memory_mib,omitempty"`
	VCPU                 uint32 `json:"vcpu"`
	MemoryGiB            uint32 `json:"memory_gib"`
	RootDeviceName       string `json:"root_device_name"`
	VolumeGiB            uint64 `json:"volume_gib"`
	VolumeType           string `json:"volume_type"`
	VolumeIOPS           uint64 `json:"volume_iops"`
	VolumeThroughputMiB  uint64 `json:"volume_throughput_mib"`
}

type Limits struct {
	MaxRuntimeSeconds uint64 `json:"max_runtime_seconds"`
	MaxTokens         uint64 `json:"max_tokens"`
	MaxOutputBytes    uint64 `json:"max_output_bytes"`
}

// ComputeRequirements are model-estimated task needs. They deliberately do
// not expose provider-specific instance types to the model.
type ComputeRequirements struct {
	MinVCPU                 uint32 `json:"min_vcpu"`
	MinMemoryGiB            uint32 `json:"min_memory_gib"`
	MinAcceleratorMemoryGiB uint32 `json:"min_accelerator_memory_gib,omitempty"`
	DiskGiB                 uint64 `json:"disk_gib"`
	EstimatedRuntimeMinutes uint64 `json:"estimated_runtime_minutes"`
	AcceleratorType         string `json:"accelerator_type,omitempty"`
}

const (
	AcceleratorGPU    = "gpu"
	AcceleratorNeuron = "neuron"
	AcceleratorFPGA   = "fpga"
	AcceleratorMedia  = "media"
	AcceleratorAny    = "any"
)

func validAcceleratorRequirement(value string) bool {
	switch value {
	case "", AcceleratorGPU, AcceleratorNeuron, AcceleratorFPGA, AcceleratorMedia, AcceleratorAny:
		return true
	default:
		return false
	}
}

func validConcreteAccelerator(value string) bool {
	switch value {
	case "", AcceleratorGPU, AcceleratorNeuron, AcceleratorFPGA, AcceleratorMedia:
		return true
	default:
		return false
	}
}

func acceleratorSatisfies(required, actual string) bool {
	return required == "" || required == AcceleratorAny && actual != "" || required == actual
}

func acceleratorMemorySatisfies(requiredGiB uint32, actualMiB uint64) bool {
	return requiredGiB == 0 || actualMiB >= uint64(requiredGiB)*1024
}

// ValidatePublicCompute validates the secret-free compute projection exposed
// to clients and model-context projection code.
func ValidatePublicCompute(value ComputeSpec) error { return validateCompute(value) }

func (requirements ComputeRequirements) validate() error {
	if requirements.MinVCPU == 0 || requirements.MinVCPU > 128 || requirements.MinMemoryGiB == 0 || requirements.MinMemoryGiB > 1024 || !validAcceleratorRequirement(requirements.AcceleratorType) ||
		requirements.MinAcceleratorMemoryGiB > 1024 || (requirements.AcceleratorType == AcceleratorGPU && requirements.MinAcceleratorMemoryGiB == 0) ||
		(requirements.AcceleratorType != AcceleratorGPU && requirements.MinAcceleratorMemoryGiB != 0) || requirements.DiskGiB < 8 || requirements.DiskGiB > 16_384 ||
		requirements.EstimatedRuntimeMinutes == 0 || requirements.EstimatedRuntimeMinutes > 24*60 {
		return ErrInvalid
	}
	return nil
}

type WorkloadKind string

const (
	WorkloadJob     WorkloadKind = "job"
	WorkloadService WorkloadKind = "service"
)

type ServiceSpec struct {
	WorkloadID string `json:"workload_id"`
	Port       uint16 `json:"port"`
	HealthPath string `json:"health_path"`
	Hostname   string `json:"hostname,omitempty"`
}

func (spec ServiceSpec) validate() error {
	if strings.TrimSpace(spec.WorkloadID) == "" || len(spec.WorkloadID) > 128 || spec.Port == 0 || len(spec.HealthPath) > 2048 ||
		!strings.HasPrefix(spec.HealthPath, "/") || strings.HasPrefix(spec.HealthPath, "//") || strings.ContainsAny(spec.HealthPath, " \t\r\n#") ||
		(spec.Hostname != "" && (!remoteservice.ValidHostname(spec.Hostname) || spec.Port == 80 || spec.Port == 443)) {
		return ErrInvalid
	}
	for _, current := range spec.WorkloadID {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') && current != '-' {
			return ErrInvalid
		}
	}
	return nil
}

type Quote struct {
	AmountMicros                int64     `json:"amount_micros"`
	ComputeMicrosPerHour        uint64    `json:"compute_micros_per_hour"`
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
	ServerName               string               `json:"server_name,omitempty"`
	ObjectiveDigest          string               `json:"objective_digest"`
	WorkloadKind             WorkloadKind         `json:"workload_kind"`
	Service                  *ServiceSpec         `json:"service,omitempty"`
	UserPromptDigest         string               `json:"user_prompt_digest"`
	ProposalReason           ProposalReason       `json:"proposal_reason"`
	LocalBudgetEvidence      *LocalBudgetEvidence `json:"local_budget_evidence,omitempty"`
	InputManifest            InputManifest        `json:"-"`
	InputManifestDigest      string               `json:"input_manifest_digest"`
	InputManifestItemCount   uint64               `json:"input_manifest_item_count"`
	WorkspaceMode            WorkspaceMode        `json:"workspace_mode"`
	ModelAuthorization       ModelAuthorization   `json:"model_authorization"`
	GitHubBinding            *GitHubBinding       `json:"-"`
	AWS                      AWSBinding           `json:"aws"`
	Compute                  ComputeSpec          `json:"compute"`
	PersistentWorkerReuse    bool                 `json:"-"`
	ReuseWorkerID            string               `json:"-"`
	AuthorizationBasisDigest string               `json:"authorization_basis_digest"`
	Limits                   Limits               `json:"limits"`
	Quote                    Quote                `json:"quote"`
	ExecutionDigest          string               `json:"execution_digest"`
	CreatedAt                time.Time            `json:"created_at"`
	UpdatedAt                time.Time            `json:"updated_at"`
	// v185NilGitHubDigest marks the short-lived, unexported encoding emitted by
	// the deployed v1.0.185 build for an otherwise ordinary plan. New unbound
	// plans retain the pre-GitHub encoding; only persisted rows whose complete
	// immutable digests prove this historical form may set the bit while loading.
	v185NilGitHubDigest bool
}

func (p Plan) usesGitHubDigestFormat() bool {
	return p.GitHubBinding != nil || p.v185NilGitHubDigest
}

// githubBindingDigestValue preserves the two released JSON encodings: a nil
// interface omits the field (ordinary plans), while a typed nil pointer emits
// the v1.0.185 null field. A real pointer is the bound GitHub form.
func (p Plan) githubBindingDigestValue() any {
	if !p.usesGitHubDigestFormat() {
		return nil
	}
	return p.GitHubBinding
}

// IsV185NilGitHubEncoding reports the one historical, unbound persisted form.
// It is intentionally derived only by ValidatePersisted, never from callers.
func (p Plan) IsV185NilGitHubEncoding() bool {
	return p.GitHubBinding == nil && p.v185NilGitHubDigest
}

func (p Plan) RequiresWorkerCreationConfirmation() bool {
	return !p.PersistentWorkerReuse
}

type Execution struct {
	OwnerID            string         `json:"owner_id"`
	AccountGeneration  uint64         `json:"account_generation"`
	RunID              string         `json:"run_id"`
	ExecutionID        string         `json:"execution_id"`
	PlanID             string         `json:"plan_id"`
	PlanRevision       uint64         `json:"plan_revision"`
	PlanDigest         string         `json:"plan_digest"`
	TaskID             string         `json:"task_id"`
	ConfirmationID     string         `json:"confirmation_id"`
	ConversationID     string         `json:"conversation_id"`
	TurnID             string         `json:"turn_id"`
	Status             ExecutionState `json:"status"`
	State              ExecutionState `json:"state"`
	Revision           uint64         `json:"revision"`
	Digest             string         `json:"digest"`
	WorkspaceMode      WorkspaceMode  `json:"workspace_mode"`
	ModelBindingDigest string         `json:"model_binding_digest"`
	QuoteDigest        string         `json:"quote_digest"`
	ExecutionDigest    string         `json:"execution_digest"`
	WorkerID           string         `json:"worker_id,omitempty"`
	PersistentWorker   bool           `json:"persistent_worker,omitempty"`
	ArtifactIDs        []string       `json:"artifact_ids"`
	FailureCode        string         `json:"failure_code"`
	FailureSummary     string         `json:"failure_summary"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type Event struct {
	OwnerID           string         `json:"owner_id"`
	AccountGeneration uint64         `json:"account_generation"`
	RunID             string         `json:"run_id"`
	ExecutionID       string         `json:"execution_id"`
	Sequence          uint64         `json:"sequence"`
	EventID           string         `json:"event_id"`
	Type              string         `json:"type"`
	State             ExecutionState `json:"status,omitempty"`
	Revision          uint64         `json:"revision"`
	PayloadDigest     string         `json:"payload_digest"`
	CreatedAt         time.Time      `json:"at"`
}

const MaxRetainedRunEvents uint64 = 4096

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
	a.Model = strings.TrimSpace(a.Model)
	a.Interface = strings.TrimSpace(a.Interface)
	a.CredentialBindingDigest = strings.TrimSpace(a.CredentialBindingDigest)
	if !validUUID(a.ModelProfileID) || a.ModelProfileRevision == 0 || a.CredentialVersion == 0 ||
		a.Provider == "" || len(a.Provider) > 128 || strings.ContainsAny(a.Provider, "\r\n\x00") ||
		a.Model == "" || len(a.Model) > 256 || strings.ContainsAny(a.Model, "\r\n\x00") ||
		a.Interface == "" || len(a.Interface) > 128 || strings.ContainsAny(a.Interface, "\r\n\x00") ||
		a.MaximumOutputTokens > 10_000_000 ||
		!validDigest(a.CredentialBindingDigest) ||
		!((a.Provider == "openai" && a.Interface == "openai_responses") ||
			(a.Provider == "openai_compatible" && a.Interface == "openai_compatible") ||
			(a.Provider == "anthropic" && a.Interface == "anthropic-messages") ||
			(a.Provider == "gemini" && a.Interface == "google-generative-ai")) {
		return ErrInvalid
	}
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

func (b *GitHubBinding) Seal() error {
	if b == nil {
		return ErrInvalid
	}
	b.OwnerID = strings.TrimSpace(b.OwnerID)
	if b.OwnerID == "" || len(b.OwnerID) > 512 || b.AccountGeneration == 0 || b.ConfigRevision == 0 || b.CredentialVersion == 0 {
		return ErrInvalid
	}
	b.BindingDigest = digestValue(struct {
		OwnerID           string
		AccountGeneration uint64
		ConfigRevision    uint64
		CredentialVersion uint64
	}{b.OwnerID, b.AccountGeneration, b.ConfigRevision, b.CredentialVersion})
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
		ComputeMicrosPerHour                      uint64
		Currency                                  string
		SourceTime, ExpiresAt                     time.Time
		BasisDigest, CatalogRevisionDigest        string
	}{q.AmountMicros, q.MaximumAuthorizedCostMicros, q.ComputeMicrosPerHour, q.Currency, q.SourceTime, q.ExpiresAt, q.BasisDigest, q.CatalogRevisionDigest})
	return nil
}

func (p *Plan) Seal() error {
	if p == nil {
		return ErrInvalid
	}
	if p.v185NilGitHubDigest && p.GitHubBinding != nil {
		return ErrInvalid
	}
	p.OwnerID = strings.TrimSpace(p.OwnerID)
	p.Objective = strings.TrimSpace(p.Objective)
	p.ObjectiveSummary = strings.TrimSpace(p.ObjectiveSummary)
	p.ServerName = strings.TrimSpace(p.ServerName)
	p.RecipeID = strings.TrimSpace(p.RecipeID)
	p.Adapter = strings.TrimSpace(p.Adapter)
	p.Status = strings.TrimSpace(p.Status)
	if p.WorkloadKind == "" {
		p.WorkloadKind = WorkloadJob
	}
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	if p.OwnerID == "" || len(p.OwnerID) > 512 || p.AccountGeneration == 0 || !validUUID(p.PlanID) || !validUUID(p.ExecutionID) || !validUUID(p.TaskID) || !validUUID(p.ConfirmationID) || !validUUID(p.ConversationID) || !validUUID(p.TurnID) || p.Revision == 0 || p.Status != string(StateWaitingUser) || p.RecipeID != RecipeEphemeralPiTask || p.Adapter != AdapterPiJSONTaskV1 || p.Objective == "" || len(p.Objective) > coretask.MaxGoalBytes || !utf8.ValidString(p.Objective) || p.ObjectiveSummary == "" || len(p.ObjectiveSummary) > coretask.MaxSummaryBytes || !utf8.ValidString(p.ObjectiveSummary) || len([]rune(p.ServerName)) > 80 || !validDigest(p.UserPromptDigest) || !validateWorkspaceMode(p.WorkspaceMode) || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	if (p.WorkloadKind == WorkloadJob && p.Service != nil) || (p.WorkloadKind == WorkloadService && (p.Service == nil || p.Service.validate() != nil)) ||
		(p.WorkloadKind != WorkloadJob && p.WorkloadKind != WorkloadService) {
		return ErrInvalid
	}
	if (p.PersistentWorkerReuse && !validUUID(p.ReuseWorkerID)) || (!p.PersistentWorkerReuse && p.ReuseWorkerID != "") {
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
	executionBasis := struct {
		OwnerID, PlanID, ExecutionID, ConversationID, TurnID                 string
		AccountGeneration, Revision                                          uint64
		RecipeID, Adapter, ObjectiveDigest, UserPromptDigest, ManifestDigest string
		ProposalReason                                                       ProposalReason
		BudgetEvidence                                                       *LocalBudgetEvidence
		WorkspaceMode                                                        WorkspaceMode
		ModelAuthorization                                                   ModelAuthorization
		GitHubBinding                                                        any `json:",omitempty"`
		AWS                                                                  AWSBinding
		Compute                                                              ComputeSpec
		Limits                                                               Limits
		QuoteDigest                                                          string
	}{p.OwnerID, p.PlanID, p.ExecutionID, p.ConversationID, p.TurnID, p.AccountGeneration, p.Revision, p.RecipeID, p.Adapter, p.ObjectiveDigest, p.UserPromptDigest, p.InputManifestDigest, p.ProposalReason, p.LocalBudgetEvidence, p.WorkspaceMode, p.ModelAuthorization, p.githubBindingDigestValue(), p.AWS, p.Compute, p.Limits, p.Quote.Digest}
	var executionDigestBasis any = struct {
		Basis      any
		ServerName string
	}{executionBasis, p.ServerName}
	if p.WorkloadKind == WorkloadService {
		executionDigestBasis = struct {
			Basis        any
			WorkloadKind WorkloadKind
			Service      *ServiceSpec
		}{executionBasis, p.WorkloadKind, p.Service}
	}
	if p.PersistentWorkerReuse {
		p.ExecutionDigest = digestValue(struct {
			Basis                 any
			PersistentWorkerReuse bool
			ReuseWorkerID         string
		}{executionDigestBasis, true, p.ReuseWorkerID})
	} else {
		p.ExecutionDigest = digestValue(executionDigestBasis)
	}
	p.Digest = digestValue(struct {
		ExecutionDigest, TaskID, ConfirmationID string
	}{p.ExecutionDigest, p.TaskID, p.ConfirmationID})
	return nil
}

// ValidatePersisted verifies a complete immutable plan encoding without
// rewriting it. v1.0.185 briefly included a nil GitHub binding in otherwise
// ordinary digests. That deployed encoding is accepted only after every plan
// digest agrees; explicit bindings always use the GitHub-aware encoding.
func (p *Plan) ValidatePersisted() error {
	if p == nil {
		return ErrInvalid
	}
	storedDigest, storedExecution, storedAuthorization := p.Digest, p.ExecutionDigest, p.AuthorizationBasisDigest
	for _, historicalV185Nil := range []bool{false, true} {
		if historicalV185Nil && p.GitHubBinding != nil {
			continue
		}
		candidate := *p
		candidate.v185NilGitHubDigest = historicalV185Nil
		if err := candidate.Seal(); err != nil || candidate.Digest != storedDigest ||
			candidate.ExecutionDigest != storedExecution || candidate.AuthorizationBasisDigest != storedAuthorization {
			continue
		}
		*p = candidate
		return nil
	}
	return ErrConflict
}

func (p *Plan) sealAuthorizationBasis() error {
	if p.WorkloadKind == "" {
		p.WorkloadKind = WorkloadJob
	}
	if (p.WorkloadKind == WorkloadJob && p.Service != nil) || (p.WorkloadKind == WorkloadService && (p.Service == nil || p.Service.validate() != nil)) ||
		(p.WorkloadKind != WorkloadJob && p.WorkloadKind != WorkloadService) {
		return ErrInvalid
	}
	if (p.PersistentWorkerReuse && !validUUID(p.ReuseWorkerID)) || (!p.PersistentWorkerReuse && p.ReuseWorkerID != "") {
		return ErrInvalid
	}
	switch p.ProposalReason {
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
	if p.GitHubBinding != nil {
		if err := p.GitHubBinding.Seal(); err != nil || p.GitHubBinding.OwnerID != p.OwnerID || p.GitHubBinding.AccountGeneration != p.AccountGeneration {
			return ErrInvalid
		}
	}
	p.ObjectiveDigest = digestValue(p.Objective)
	if err := validateAWS(p.AWS); err != nil {
		return err
	}
	if err := validateCompute(p.Compute); err != nil {
		return err
	}
	if err := validateLimits(p.Limits); err != nil {
		return err
	}
	authorizationBasis := struct {
		OwnerID, ConversationID, TurnID, RecipeID, Adapter     string
		AccountGeneration                                      uint64
		ObjectiveDigest, UserPromptDigest, InputManifestDigest string
		ProposalReason                                         ProposalReason
		BudgetEvidence                                         *LocalBudgetEvidence
		WorkspaceMode                                          WorkspaceMode
		ModelAuthorization                                     ModelAuthorization
		GitHubBinding                                          any `json:",omitempty"`
		AWS                                                    AWSBinding
		Compute                                                ComputeSpec
		Limits                                                 Limits
	}{p.OwnerID, p.ConversationID, p.TurnID, p.RecipeID, p.Adapter, p.AccountGeneration, p.ObjectiveDigest, p.UserPromptDigest, p.InputManifestDigest, p.ProposalReason, p.LocalBudgetEvidence, p.WorkspaceMode, p.ModelAuthorization, p.githubBindingDigestValue(), p.AWS, p.Compute, p.Limits}
	var authorizationDigestBasis any = struct {
		Basis      any
		ServerName string
	}{authorizationBasis, p.ServerName}
	if p.WorkloadKind == WorkloadService {
		authorizationDigestBasis = struct {
			Basis        any
			WorkloadKind WorkloadKind
			Service      *ServiceSpec
		}{authorizationBasis, p.WorkloadKind, p.Service}
	}
	if p.PersistentWorkerReuse {
		authorizationDigestBasis = struct {
			Basis                 any
			PersistentWorkerReuse bool
			ReuseWorkerID         string
		}{authorizationDigestBasis, true, p.ReuseWorkerID}
	}
	p.AuthorizationBasisDigest = digestValue(authorizationDigestBasis)
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
	if strings.TrimSpace(value.InstanceType) == "" || (value.Architecture != "x86_64" && value.Architecture != "arm64") || !validConcreteAccelerator(value.AcceleratorType) || !strings.HasPrefix(value.RootDeviceName, "/dev/") || len(value.RootDeviceName) > 64 || strings.ContainsAny(value.RootDeviceName, "\r\n\x00") || value.VolumeGiB < 8 || value.VolumeGiB > 16384 || value.VolumeType != "gp3" || value.VolumeIOPS < 3000 || value.VolumeIOPS > 16000 || value.VolumeThroughputMiB < 125 || value.VolumeThroughputMiB > 1000 {
		return ErrInvalid
	}
	if value.AcceleratorType == "" && (value.AcceleratorName != "" || value.AcceleratorMemoryMiB != 0) ||
		strings.TrimSpace(value.AcceleratorName) != value.AcceleratorName || len(value.AcceleratorName) > 128 || strings.ContainsAny(value.AcceleratorName, "\r\n\x00") {
		return ErrInvalid
	}
	if (value.VCPU == 0) != (value.MemoryGiB == 0) {
		return ErrInvalid
	}
	return nil
}

func validateLimits(value Limits) error {
	if value.MaxRuntimeSeconds == 0 || value.MaxRuntimeSeconds > uint64((24*time.Hour)/time.Second) || value.MaxTokens == 0 || value.MaxTokens > 10_000_000 || value.MaxOutputBytes == 0 || value.MaxOutputBytes > MaxCloudWorkerOutputBytes {
		return ErrInvalid
	}
	return nil
}

func NewExecution(plan Plan) (Execution, error) {
	if err := plan.Seal(); err != nil {
		return Execution{}, err
	}
	execution := Execution{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		RunID: deterministicID("cloud-worker-run", plan.ExecutionID), ExecutionID: plan.ExecutionID,
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
	if e == nil || strings.TrimSpace(e.OwnerID) == "" || e.AccountGeneration == 0 || !validUUID(e.RunID) || !validUUID(e.ExecutionID) || !validUUID(e.PlanID) || !validUUID(e.TaskID) || !validUUID(e.ConfirmationID) || !validUUID(e.ConversationID) || !validUUID(e.TurnID) || e.PlanRevision == 0 || e.Revision == 0 || !validDigest(e.PlanDigest) || !validDigest(e.ModelBindingDigest) || !validDigest(e.QuoteDigest) || !validDigest(e.ExecutionDigest) || e.Status != e.State || !validExecutionState(e.State) || !validateWorkspaceMode(e.WorkspaceMode) || e.CreatedAt.IsZero() || e.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	e.CreatedAt, e.UpdatedAt = e.CreatedAt.UTC(), e.UpdatedAt.UTC()
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
	if e.PersistentWorker && strings.TrimSpace(e.WorkerID) == "" {
		return ErrInvalid
	}
	baseDigest := struct {
		ExecutionID, PlanDigest, ModelBindingDigest, QuoteDigest, ExecutionDigest string
		AccountGeneration                                                         uint64
		State                                                                     ExecutionState
		Revision                                                                  uint64
		Artifacts                                                                 []string
		FailureCode, FailureSummary                                               string
	}{e.ExecutionID, e.PlanDigest, e.ModelBindingDigest, e.QuoteDigest, e.ExecutionDigest, e.AccountGeneration, e.State, e.Revision, e.ArtifactIDs, e.FailureCode, e.FailureSummary}
	if e.PersistentWorker {
		e.Digest = digestValue(struct {
			Base     any
			WorkerID string
		}{baseDigest, e.WorkerID})
	} else {
		e.Digest = digestValue(baseDigest)
	}
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
	case StateWaitingUser, StateQueued, StateProvisioning, StateRunning, StateCleaning, StateSucceeded, StateFailed, StateCanceled, StateRejected, StateExpired:
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
		return to == StateRunning || to == StateCleaning || to == StateSucceeded || to == StateFailed || to == StateCanceled
	case StateRunning:
		return to == StateCleaning || to == StateSucceeded || to == StateFailed || to == StateCanceled
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
	permissionDigest := coreconfirmation.Digest(plan.ModelAuthorization.BindingDigest)
	if plan.usesGitHubDigestFormat() {
		permissionDigest = coreconfirmation.Digest(digestValue(struct {
			ModelBindingDigest string
			GitHubBinding      *GitHubBinding
		}{plan.ModelAuthorization.BindingDigest, plan.GitHubBinding}))
	}
	binding := coreconfirmation.Binding{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration, OperationDomain: OperationDomain,
		TargetID: plan.ExecutionID, TargetRevision: int64(plan.Revision),
		TargetKind: func() string {
			if plan.WorkloadKind == WorkloadService {
				return coreconfirmation.TargetKindPersistentService
			}
			if plan.PersistentWorkerReuse {
				return "persistent_worker_reuse"
			}
			return "persistent_ssh_worker"
		}(), SourceVersion: plan.RecipeID,
		SourceCommit:      "",
		ContentDigest:     coreconfirmation.Digest(plan.ObjectiveDigest),
		ManifestDigest:    coreconfirmation.Digest(plan.InputManifestDigest),
		ExecutionDigest:   coreconfirmation.Digest(plan.ExecutionDigest),
		PermissionDigest:  permissionDigest,
		ParameterDigest:   coreconfirmation.Digest(plan.Digest),
		NetworkDigest:     coreconfirmation.Digest(digestValue([]string{})),
		SecretGrantDigest: coreconfirmation.Digest(digestValue([]string{})),
		SelectedTool:      "cloud_worker_propose",
		SelectedCommand:   []string{},
		NetworkGrants:     []string{},
		SecretGrants:      []coreconfirmation.SecretGrant{},
		ExecutionID:       plan.ExecutionID, PlanID: plan.PlanID, PlanRevision: int64(plan.Revision), PlanDigest: coreconfirmation.Digest(plan.Digest),
		RunID: execution.RunID, RunRevision: int64(execution.Revision), RunDigest: coreconfirmation.Digest(execution.Digest), QuoteDigest: coreconfirmation.Digest(plan.Quote.Digest),
		Quote: &coreconfirmation.LiveQuote{AmountMicros: plan.Quote.AmountMicros, ComputeMicrosPerHour: plan.Quote.ComputeMicrosPerHour, Currency: plan.Quote.Currency,
			SourceTime: plan.Quote.SourceTime, ExpiresAt: plan.Quote.ExpiresAt,
			MaximumAuthorizedCostMicros: plan.Quote.MaximumAuthorizedCostMicros},
	}
	binding.Digest = coreconfirmation.Digest(digestValue(binding))
	return binding.Normalize()
}

// ValidateFrozenBinding verifies the immutable authority captured when the
// offer was created. TargetKind is presentation metadata and remains frozen;
// later code must not regenerate it from the current projection rules.
func ValidateFrozenBinding(plan Plan, execution Execution, binding coreconfirmation.Binding) error {
	if plan.Seal() != nil || execution.Seal() != nil || execution.ExecutionID != plan.ExecutionID ||
		execution.PlanID != plan.PlanID || execution.PlanRevision != plan.Revision || execution.PlanDigest != plan.Digest ||
		execution.TaskID != plan.TaskID || execution.ConfirmationID != plan.ConfirmationID ||
		execution.ExecutionDigest != plan.ExecutionDigest || execution.QuoteDigest != plan.Quote.Digest {
		return ErrStaleAuthorization
	}
	normalized, err := binding.Normalize()
	if err != nil || normalized.OwnerID != plan.OwnerID ||
		normalized.AccountGeneration != plan.AccountGeneration || normalized.OperationDomain != OperationDomain ||
		normalized.TargetID != plan.ExecutionID || normalized.TargetRevision != int64(plan.Revision) ||
		normalized.ExecutionDigest != coreconfirmation.Digest(plan.ExecutionDigest) ||
		normalized.ExecutionID != execution.ExecutionID || normalized.PlanID != plan.PlanID ||
		normalized.PlanRevision != int64(plan.Revision) || normalized.PlanDigest != coreconfirmation.Digest(plan.Digest) ||
		normalized.RunID != execution.RunID || normalized.RunRevision < 1 || uint64(normalized.RunRevision) > execution.Revision ||
		normalized.QuoteDigest != coreconfirmation.Digest(plan.Quote.Digest) || normalized.Quote == nil {
		return ErrStaleAuthorization
	}
	expectedQuote := coreconfirmation.LiveQuote{AmountMicros: plan.Quote.AmountMicros, ComputeMicrosPerHour: plan.Quote.ComputeMicrosPerHour,
		Currency: plan.Quote.Currency, SourceTime: plan.Quote.SourceTime, ExpiresAt: plan.Quote.ExpiresAt,
		MaximumAuthorizedCostMicros: plan.Quote.MaximumAuthorizedCostMicros}
	if *normalized.Quote != expectedQuote {
		return ErrStaleAuthorization
	}
	return nil
}

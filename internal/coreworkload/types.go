// Package coreworkload owns immutable workload plans and their confirmed,
// durable apply/destroy operations. Providers are deliberately typed and are
// never passed arbitrary shell or SDK arguments.
package coreworkload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type TargetKind string

const (
	TargetCoreRunner TargetKind = "CORE_RUNNER"
)

type OperationKind string

const (
	OperationApply   OperationKind = "apply"
	OperationDestroy OperationKind = "destroy"
)

type OperationStatus string

const (
	OperationWaitingUser OperationStatus = "waiting_user"
	OperationRunning     OperationStatus = "running"
	OperationSucceeded   OperationStatus = "succeeded"
	OperationFailed      OperationStatus = "failed"
	OperationUncertain   OperationStatus = "uncertain"
	OperationRejected    OperationStatus = "rejected"
	OperationExpired     OperationStatus = "expired"
	OperationCanceled    OperationStatus = "canceled"
)

type ResourceLimits struct {
	CPU       int64 `json:"cpu,omitempty"`
	MemoryMB  int64 `json:"memory_mb,omitempty"`
	Processes int64 `json:"processes,omitempty"`
	DiskMB    int64 `json:"disk_mb,omitempty"`
	TimeoutS  int64 `json:"timeout_seconds,omitempty"`
	OutputMB  int64 `json:"output_mb,omitempty"`
}

type TargetSettings struct {
	Identity            TargetIdentity    `json:"identity,omitempty" yaml:"identity,omitempty" mapstructure:"identity"`
	Ports               []int32           `json:"ports,omitempty"`
	PortDetails         []Port            `json:"port_details,omitempty"`
	NetworkGrantDetails []NetworkGrant    `json:"network_grant_details,omitempty"`
	Labels              map[string]string `json:"labels,omitempty"`
}

// TargetIdentity is the provider-safe, exact identity used for readback
// fencing. It contains no arbitrary provider payload or credentials.
type TargetIdentity struct {
	Kind              TargetKind `json:"kind" yaml:"kind" mapstructure:"kind"`
	CoreRunnerID      string     `json:"core_runner_id,omitempty"`
	CoreRunnerService string     `json:"core_runner_service,omitempty"`
	ImageDigest       string     `json:"image_digest,omitempty"`
}

func (i TargetIdentity) Validate(kind TargetKind) error {
	if i.Kind != "" && i.Kind != kind {
		return ErrInvalid
	}
	switch kind {
	case TargetCoreRunner:
		if strings.TrimSpace(i.CoreRunnerID) == "" || strings.TrimSpace(i.CoreRunnerService) == "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Port struct {
	Port uint32 `json:"port"`
}
type NetworkGrant struct {
	ReferenceID string `json:"reference_id"`
	Kind        string `json:"kind"`
}
type SecretGrantRef struct {
	ReferenceID   string                         `json:"reference_id"`
	Purpose       coreconfirmation.SecretPurpose `json:"purpose"`
	BindingDigest coreconfirmation.Digest        `json:"binding_digest"`
}
type ActualSnapshot struct {
	WorkloadID        string         `json:"workload_id"`
	Revision          uint64         `json:"revision"`
	State             string         `json:"state"`
	Identity          TargetIdentity `json:"identity"`
	AppliedPlanID     string         `json:"applied_plan_id,omitempty"`
	AppliedPlanDigest string         `json:"applied_plan_digest,omitempty"`
	ReadbackDigest    string         `json:"readback_digest,omitempty"`
	ProviderVersion   string         `json:"provider_version,omitempty"`
	ObservedAt        time.Time      `json:"observed_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}
type ProviderReadback = ActualSnapshot
type ProviderFailure struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

// Plan is immutable after creation. Revision and Digest are retained in every
// operation and task payload so a provider can reject drift before mutation.
type Plan struct {
	ID              string           `json:"plan_id"`
	Revision        uint64           `json:"revision"`
	Digest          string           `json:"digest"`
	Summary         string           `json:"summary"`
	Artifact        string           `json:"artifact,omitempty"`
	Source          string           `json:"source,omitempty"`
	CommandSteps    []string         `json:"command_steps,omitempty"`
	ImageDigest     string           `json:"image_digest,omitempty"`
	TargetKind      TargetKind       `json:"target_kind"`
	Target          TargetSettings   `json:"target"`
	NetworkGrants   []string         `json:"network_grants,omitempty"`
	SecretGrants    []string         `json:"secret_grants,omitempty"`
	SecretGrantRefs []SecretGrantRef `json:"secret_grant_refs,omitempty"`
	ResourceLimits  ResourceLimits   `json:"resource_limits,omitempty"`
	ExpiresAt       time.Time        `json:"expires_at"`
	CreatedAt       time.Time        `json:"created_at"`
}

type Workload struct {
	ID         string         `json:"workload_id"`
	Revision   uint64         `json:"revision"`
	PlanID     string         `json:"plan_id"`
	PlanDigest string         `json:"plan_digest"`
	TargetKind TargetKind     `json:"target_kind"`
	Identity   TargetIdentity `json:"identity,omitempty"`
	State      string         `json:"state"`
	UpdatedAt  time.Time      `json:"updated_at"`
	Actual     ActualSnapshot `json:"actual"`
}

type Operation struct {
	ID                    string          `json:"operation_id"`
	WorkloadID            string          `json:"workload_id"`
	PlanID                string          `json:"plan_id"`
	Kind                  OperationKind   `json:"kind"`
	PlanRevision          uint64          `json:"plan_revision"`
	PlanDigest            string          `json:"plan_digest"`
	TargetKind            TargetKind      `json:"target_kind"`
	TaskID                string          `json:"task_id"`
	ConfirmationID        string          `json:"confirmation_id"`
	Status                OperationStatus `json:"status"`
	Revision              uint64          `json:"revision"`
	FailureCode           string          `json:"failure_code,omitempty"`
	FailureSummary        string          `json:"failure_summary,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
	DispatchState         string          `json:"dispatch_state,omitempty"`
	DispatchAttempt       uint32          `json:"dispatch_attempt,omitempty"`
	DispatchEpoch         uint64          `json:"dispatch_epoch,omitempty"`
	DispatchClaim         string          `json:"dispatch_claim,omitempty"`
	DispatchLeaseUntil    time.Time       `json:"dispatch_lease_until,omitempty"`
	CompletionFingerprint string          `json:"completion_fingerprint,omitempty"`
}

// TaskFence is the exact generic WorkerPool lease presented to a workload
// handler. Workload execution must never mint or replace this lease.
type TaskFence struct {
	TaskID     string
	Holder     string
	Attempt    uint32
	LeaseEpoch uint64
	Revision   uint64
	ExpiresAt  time.Time
}

func (f TaskFence) Valid(now time.Time) bool {
	return ValidUUID(f.TaskID) && f.Holder != "" && f.Attempt > 0 && f.LeaseEpoch > 0 && f.Revision > 0 && !f.ExpiresAt.IsZero() && f.ExpiresAt.After(now.UTC())
}

type Event struct {
	OperationID string          `json:"operation_id"`
	Sequence    uint64          `json:"sequence"`
	Kind        string          `json:"kind"`
	Status      OperationStatus `json:"status"`
	Message     string          `json:"message,omitempty"`
	Readback    json.RawMessage `json:"readback,omitempty"`
	At          time.Time       `json:"at"`
}

type RequestResult struct {
	Operation    Operation
	Task         coretask.Task
	Confirmation coreconfirmation.Confirmation
}

type Readback struct {
	TargetKind      TargetKind      `json:"target_kind"`
	WorkloadID      string          `json:"workload_id"`
	State           string          `json:"state"`
	Identity        TargetIdentity  `json:"identity"`
	ProviderVersion string          `json:"provider_version,omitempty"`
	Details         json.RawMessage `json:"details,omitempty"`
	Digest          string          `json:"digest"`
	At              time.Time       `json:"at"`
}

var (
	ErrInvalid          = errors.New("coreworkload: invalid")
	ErrConflict         = errors.New("coreworkload: conflict")
	ErrNotFound         = errors.New("coreworkload: not found")
	ErrRevisionConflict = errors.New("coreworkload: revision conflict")
	ErrStale            = errors.New("coreworkload: stale plan")
	ErrProvider         = errors.New("coreworkload: provider unavailable")
)

func ValidUUID(v string) bool {
	id, err := uuid.Parse(strings.TrimSpace(v))
	return err == nil && id != uuid.Nil && id.String() == strings.TrimSpace(v)
}
func ValidDigest(v string) bool {
	if len(v) != 64 || strings.ToLower(v) != v {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func validTarget(v TargetKind) bool {
	return v == TargetCoreRunner
}

func canonicalDigest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func planInputDigest(p Plan) string {
	return canonicalDigest(struct {
		Summary, Artifact, Source string
		Commands                  []string
		Image                     string
		Target                    TargetKind
		Settings                  TargetSettings
		Network, Secrets          []string
		SecretRefs                []SecretGrantRef
		Limits                    ResourceLimits
		ExpiresAt                 time.Time
	}{p.Summary, p.Artifact, p.Source, p.CommandSteps, p.ImageDigest, p.TargetKind, p.Target, p.NetworkGrants, p.SecretGrants, p.SecretGrantRefs, p.ResourceLimits, p.ExpiresAt.UTC()})
}
func PlanInputDigest(p Plan) string { return planInputDigest(p) }

func RedactText(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return "provider operation failed"
}

// SafeFailure converts provider-controlled text into a small stable allowlist
// suitable for task, event, and operation persistence.
func SafeFailure(code, summary string) (string, string) {
	switch code {
	case "", "provider_uncertain", "provider_error", "canceled", "user_canceled":
	default:
		code = "provider_error"
	}
	if code == "" {
		return "", ""
	}
	switch code {
	case "canceled", "user_canceled":
		return code, "operation canceled"
	case "provider_uncertain":
		return code, "provider outcome requires reconciliation"
	default:
		return code, "provider operation failed"
	}
}
func SanitizeReadback(r Readback) Readback {
	out := Readback{TargetKind: r.TargetKind, WorkloadID: r.WorkloadID, State: r.State, Identity: r.Identity, ProviderVersion: r.ProviderVersion, At: r.At}
	out.Digest = ReadbackDigest(out)
	return out
}

func (p Plan) Normalize() (Plan, error) {
	p.ID = strings.TrimSpace(p.ID)
	p.Summary = strings.TrimSpace(p.Summary)
	p.Artifact = strings.TrimSpace(p.Artifact)
	p.Source = strings.TrimSpace(p.Source)
	p.ImageDigest = strings.TrimSpace(p.ImageDigest)
	if p.ID != "" && !ValidUUID(p.ID) || p.Summary == "" || len(p.Summary) > 4096 || !validTarget(p.TargetKind) || p.Revision == 0 || p.ExpiresAt.IsZero() || p.ExpiresAt.Location() != time.UTC {
		return Plan{}, ErrInvalid
	}
	if len(p.CommandSteps) == 0 && p.ImageDigest == "" {
		return Plan{}, ErrInvalid
	}
	if p.ImageDigest != "" && !ValidDigest(p.ImageDigest) {
		return Plan{}, ErrInvalid
	}
	if p.ExpiresAt.Before(time.Now().UTC()) { /* expiry is checked by service; retain historical plans */
	}
	p.NetworkGrants = normalizeStrings(p.NetworkGrants)
	p.SecretGrants = normalizeStrings(p.SecretGrants)
	p.CommandSteps = append([]string(nil), p.CommandSteps...)
	for _, s := range append(append([]string{}, p.CommandSteps...), append(p.NetworkGrants, p.SecretGrants...)...) {
		if strings.TrimSpace(s) == "" || len(s) > 4096 || strings.ContainsAny(s, "\r\n\x00") {
			return Plan{}, ErrInvalid
		}
	}
	for _, id := range p.SecretGrants {
		if !ValidUUID(id) {
			return Plan{}, ErrInvalid
		}
	}
	for _, ref := range p.SecretGrantRefs {
		if !ValidUUID(ref.ReferenceID) || !ref.BindingDigest.Valid() || !validSecretPurpose(ref.Purpose) {
			return Plan{}, ErrInvalid
		}
	}
	for _, port := range p.Target.Ports {
		if port < 1 || port > 65535 {
			return Plan{}, ErrInvalid
		}
	}
	if p.ResourceLimits.CPU < 0 || p.ResourceLimits.MemoryMB < 0 || p.ResourceLimits.Processes < 0 || p.ResourceLimits.DiskMB < 0 || p.ResourceLimits.TimeoutS < 0 || p.ResourceLimits.OutputMB < 0 {
		return Plan{}, ErrInvalid
	}
	if err := p.Target.Identity.Validate(p.TargetKind); err != nil {
		return Plan{}, err
	}
	if p.Digest == "" {
		p.Digest = canonicalDigest(struct {
			Summary, Artifact, Source string
			Commands                  []string
			Image                     string
			Target                    TargetKind
			Settings                  TargetSettings
			Network, Secrets          []string
			SecretRefs                []SecretGrantRef
			Limits                    ResourceLimits
			ExpiresAt                 time.Time
		}{p.Summary, p.Artifact, p.Source, p.CommandSteps, p.ImageDigest, p.TargetKind, p.Target, p.NetworkGrants, p.SecretGrants, p.SecretGrantRefs, p.ResourceLimits, p.ExpiresAt.UTC()})
	}
	if !ValidDigest(p.Digest) {
		return Plan{}, ErrInvalid
	}
	return p, nil
}

func validSecretPurpose(v coreconfirmation.SecretPurpose) bool {
	switch v {
	case coreconfirmation.SecretPurposeModelAPIKey, coreconfirmation.SecretPurposeMCPCredential, coreconfirmation.SecretPurposeSkillSecret, coreconfirmation.SecretPurposeAWSCredential, coreconfirmation.SecretPurposeOtherExtensionSecret:
		return true
	default:
		return false
	}
}
func normalizeStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
func (p Plan) Validate() error { _, e := p.Normalize(); return e }

func (o Operation) Validate() error {
	if !ValidUUID(o.ID) || !ValidUUID(o.WorkloadID) || !ValidUUID(o.PlanID) || !ValidUUID(o.TaskID) || !ValidUUID(o.ConfirmationID) || !validTarget(o.TargetKind) || !ValidDigest(o.PlanDigest) || o.PlanRevision == 0 || o.Revision == 0 || o.CreatedAt.IsZero() || o.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	if o.Kind != OperationApply && o.Kind != OperationDestroy {
		return ErrInvalid
	}
	return nil
}

func bindingForOperation(p Plan, workloadID string, kind OperationKind) coreconfirmation.Binding {
	param := canonicalDigest(struct {
		Kind     OperationKind
		Plan     Plan
		Workload string
	}{kind, p, workloadID})
	network := canonicalDigest(struct {
		Grants []string
		Limits ResourceLimits
	}{p.NetworkGrants, p.ResourceLimits})
	secret := canonicalDigest(struct {
		Legacy []string
		Typed  []SecretGrantRef
	}{p.SecretGrants, p.SecretGrantRefs})
	grants := make([]coreconfirmation.SecretGrant, 0, len(p.SecretGrants)+len(p.SecretGrantRefs))
	for _, ref := range p.SecretGrantRefs {
		if ValidUUID(ref.ReferenceID) && ref.BindingDigest.Valid() {
			grants = append(grants, coreconfirmation.SecretGrant{ReferenceID: ref.ReferenceID, Purpose: ref.Purpose, BindingDigest: ref.BindingDigest})
		}
	}
	for _, id := range p.SecretGrants {
		if ValidUUID(id) {
			grants = append(grants, coreconfirmation.SecretGrant{ReferenceID: id, Purpose: coreconfirmation.SecretPurposeOtherExtensionSecret, BindingDigest: coreconfirmation.Digest(secret)})
		}
	}
	return coreconfirmation.Binding{OperationDomain: "workload:" + string(kind), TargetID: workloadID, TargetRevision: int64(p.Revision), SourceVersion: "core-v1", ContentDigest: coreconfirmation.Digest(p.Digest), ParameterDigest: coreconfirmation.Digest(param), NetworkDigest: coreconfirmation.Digest(network), SecretGrantDigest: coreconfirmation.Digest(secret), NetworkGrants: append([]string(nil), p.NetworkGrants...), SecretGrants: grants}
}

// BindingForPlan returns the exact immutable confirmation snapshot used by
// both memory and PostgreSQL request paths.
func BindingForPlan(p Plan, workloadID string) coreconfirmation.Binding {
	return bindingForOperation(p, workloadID, OperationApply)
}

func BindingForOperation(p Plan, workloadID string, kind OperationKind) coreconfirmation.Binding {
	return bindingForOperation(p, workloadID, kind)
}

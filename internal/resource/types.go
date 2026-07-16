package resource

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

var (
	ErrInvalid                    = errors.New("invalid resource request")
	ErrNotFound                   = errors.New("resource not found")
	ErrAlreadyExists              = errors.New("resource already exists")
	ErrRevisionConflict           = errors.New("resource revision conflict")
	ErrDependency                 = errors.New("resource dependency is not ready")
	ErrReadBack                   = errors.New("provider read-back did not verify the resource")
	ErrDestroyBlocked             = errors.New("resource destruction is blocked")
	ErrManaged                    = errors.New("managed resource requires an explicit operation approval")
	ErrCreateAuthorizationExpired = errors.New("provider create authorization expired")
)

type Type string

const (
	TypeEC2      Type = "ec2"
	TypeEBS      Type = "ebs"
	TypeENI      Type = "eni"
	TypeEIP      Type = "eip"
	TypeSG       Type = "security_group"
	TypeEndpoint Type = "endpoint"
	TypeSnapshot Type = "snapshot"
)

type State string

const (
	StateProvisioning      State = "provisioning"
	StateActive            State = "active"
	StateDestroyScheduled  State = "destroy_scheduled"
	StateRetainedManaged   State = "retained_managed"
	StateDestroying        State = "destroying"
	StateVerifiedDestroyed State = "verified_destroyed"
	StateDestroyBlocked    State = "destroy_blocked"
	StateOrphaned          State = "orphaned"
)

type MutationOperation string

const (
	MutationCreate  MutationOperation = "create"
	MutationDestroy MutationOperation = "destroy"
)

const (
	TagAgentInstanceID = "agent_instance_id"
	TagOwnerID         = "owner_id"
	TagTaskID          = "task_id"
	TagDeploymentID    = "deployment_id"
	TagResourceID      = "resource_id"
	TagRetention       = "retention"
	TagDestroyDeadline = "destroy_deadline"
	// TagEmbeddedParentResourceID binds an AWS resource that is created as part
	// of another provider mutation (currently an EC2 root EBS volume) to its
	// parent while still giving it an independent ledger identity.
	TagEmbeddedParentResourceID = "embedded_parent_resource_id"
)

var sha256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type MutationIntent struct {
	Operation   MutationOperation
	ClientToken string
	RecordedAt  time.Time
}

type ReadBackEvidence struct {
	Exists     bool
	ProviderID string
	ObservedAt time.Time
	TagDigest  string
}

type ResourceV1 struct {
	ResourceID          string
	AgentInstanceID     string
	OwnerID             string
	TaskID              string
	DeploymentID        string
	Type                Type
	LogicalName         string
	Region              string
	SpecDigest          string
	ApprovedPlanHash    string
	ApprovalID          string
	ProviderID          string
	DependsOn           []string
	Retention           task.RetentionPolicy
	DestroyDeadline     time.Time
	AutoDestroyApproved bool
	Tags                map[string]string
	State               State
	Intent              MutationIntent
	ReadBack            ReadBackEvidence
	BlockedReason       string
	Revision            int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (resource ResourceV1) clone() ResourceV1 {
	resource.DependsOn = slices.Clone(resource.DependsOn)
	resource.Tags = cloneMap(resource.Tags)
	return resource
}

type ProvisionSpec struct {
	ResourceID          string
	AgentInstanceID     string
	OwnerID             string
	TaskID              string
	DeploymentID        string
	Type                Type
	LogicalName         string
	Region              string
	SpecDigest          string
	ApprovedPlanHash    string
	ApprovalID          string
	DependsOn           []string
	Retention           task.RetentionPolicy
	DestroyDeadline     time.Time
	AutoDestroyApproved bool
	AWS                 *AWSResourceSpecV1
}

// ProviderCreateAuthorization is the short-lived user authorization boundary
// for a new billable provider mutation. Reconciliation of a provider fact that
// already exists is intentionally allowed after these times so response loss
// or a controller restart cannot create a duplicate or strand the resource.
type ProviderCreateAuthorization struct {
	ApprovalExpiresAt time.Time
	QuoteValidUntil   time.Time
}

func (authorization ProviderCreateAuthorization) validate() error {
	if authorization.ApprovalExpiresAt.IsZero() || authorization.QuoteValidUntil.IsZero() {
		return fmt.Errorf("%w: provider create authorization requires approval and quote expiry", ErrInvalid)
	}
	return nil
}

func (authorization ProviderCreateAuthorization) authorize(now time.Time) error {
	if err := authorization.validate(); err != nil {
		return err
	}
	if !now.Before(authorization.ApprovalExpiresAt) || !now.Before(authorization.QuoteValidUntil) {
		return ErrCreateAuthorizationExpired
	}
	return nil
}

func (spec ProvisionSpec) Validate(now time.Time) error {
	for name, value := range map[string]string{
		"resource_id": spec.ResourceID, "agent_instance_id": spec.AgentInstanceID,
		"task_id": spec.TaskID, "deployment_id": spec.DeploymentID, "approval_id": spec.ApprovalID,
	} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return fmt.Errorf("%w: %s must be a non-zero UUID", ErrInvalid, name)
		}
	}
	owner := strings.TrimSpace(spec.OwnerID)
	if owner == "" || len(owner) > 255 || security.ContainsLikelySecret(owner) {
		return fmt.Errorf("%w: owner_id is invalid", ErrInvalid)
	}
	if !validType(spec.Type) {
		return fmt.Errorf("%w: unsupported resource type", ErrInvalid)
	}
	if name := strings.TrimSpace(spec.LogicalName); name == "" || len(name) > 128 || security.ContainsLikelySecret(name) {
		return fmt.Errorf("%w: logical_name is invalid", ErrInvalid)
	}
	if region := strings.TrimSpace(spec.Region); region == "" || len(region) > 64 || strings.ContainsAny(region, "/* ") {
		return fmt.Errorf("%w: region is invalid", ErrInvalid)
	}
	if !sha256Pattern.MatchString(spec.SpecDigest) || !sha256Pattern.MatchString(spec.ApprovedPlanHash) {
		return fmt.Errorf("%w: spec and approved plan digests must be sha256", ErrInvalid)
	}
	if spec.AWS != nil {
		digest, err := spec.AWS.Digest(spec.Type)
		if err != nil || digest != spec.SpecDigest {
			return fmt.Errorf("%w: AWS typed spec does not match spec_digest", ErrInvalid)
		}
	}
	if spec.Retention != task.RetentionEphemeralAutoDestroy && spec.Retention != task.RetentionManaged {
		return fmt.Errorf("%w: retention is invalid", ErrInvalid)
	}
	if spec.Retention == task.RetentionEphemeralAutoDestroy {
		if !spec.AutoDestroyApproved || !spec.DestroyDeadline.After(now) {
			return fmt.Errorf("%w: ephemeral resources require an approved future destroy deadline", ErrInvalid)
		}
	} else if !spec.DestroyDeadline.IsZero() || spec.AutoDestroyApproved {
		return fmt.Errorf("%w: managed retention cannot have auto-destroy approval or deadline", ErrInvalid)
	}
	if len(spec.DependsOn) > 64 {
		return fmt.Errorf("%w: too many resource dependencies", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(spec.DependsOn))
	for _, dependency := range spec.DependsOn {
		parsed, err := uuid.Parse(strings.TrimSpace(dependency))
		if err != nil || parsed == uuid.Nil || parsed.String() == spec.ResourceID {
			return fmt.Errorf("%w: invalid resource dependency", ErrInvalid)
		}
		if _, duplicate := seen[parsed.String()]; duplicate {
			return fmt.Errorf("%w: duplicate resource dependency", ErrInvalid)
		}
		seen[parsed.String()] = struct{}{}
	}
	return nil
}

func (spec ProvisionSpec) mandatoryTags() map[string]string {
	deadline := "managed"
	if !spec.DestroyDeadline.IsZero() {
		deadline = spec.DestroyDeadline.UTC().Format(time.RFC3339)
	}
	return map[string]string{
		TagAgentInstanceID: strings.TrimSpace(spec.AgentInstanceID), TagOwnerID: strings.TrimSpace(spec.OwnerID),
		TagTaskID: strings.TrimSpace(spec.TaskID), TagDeploymentID: strings.TrimSpace(spec.DeploymentID),
		TagResourceID: strings.TrimSpace(spec.ResourceID), TagRetention: string(spec.Retention), TagDestroyDeadline: deadline,
	}
}

type ProviderCreateRequest struct {
	ResourceID   string
	Type         Type
	LogicalName  string
	Region       string
	SpecDigest   string
	ClientToken  string
	Tags         map[string]string
	Dependencies []ProviderDependency
	AWS          *AWSResourceSpecV1
}

type ProviderObservation struct {
	ProviderID string
	Type       Type
	Exists     bool
	Tags       map[string]string
	ObservedAt time.Time
	// Embedded contains independently addressable resources created by the
	// same provider mutation. The control plane must persist and verify each
	// observation before exposing the parent as active.
	Embedded []ProviderObservation
}

type Provider interface {
	Create(context.Context, ProviderCreateRequest) (ProviderObservation, error)
	FindByClientToken(context.Context, Type, string, string) (ProviderObservation, bool, error)
	ReadBack(context.Context, Type, string, string) (ProviderObservation, error)
	Delete(context.Context, Type, string, string, map[string]string) error
	ListOwned(context.Context, string) ([]ProviderObservation, error)
}

type Manifest struct {
	ManifestID            string
	AgentInstanceID       string
	OwnerID               string
	TaskID                string
	DeploymentID          string
	Retention             task.RetentionPolicy
	DestroyDeadline       time.Time
	AutoDestroyApproved   bool
	AutoDestroyApprovalID string
	ApprovedPlanHash      string
	Managed               bool
	Resources             []ResourceV1
	Revision              int64
	UpdatedAt             time.Time
}

func (manifest Manifest) clone() Manifest {
	source := manifest.Resources
	manifest.Resources = make([]ResourceV1, len(source))
	for index, resource := range source {
		manifest.Resources[index] = resource.clone()
	}
	return manifest
}

type ManifestMirror interface {
	Put(context.Context, Manifest) error
	ListExpired(context.Context, time.Time) ([]Manifest, error)
}

// ManifestReadBack independently proves the exact durable cloud value after a
// write or a lost provider response.
type ManifestReadBack interface {
	Get(context.Context, string) (Manifest, error)
}

// ConditionalManifestMirror fences a Reaper against a concurrent manifest
// transition, most importantly an ephemeral-to-managed acceptance. Mirrors
// backed by a shared cloud store should implement it; the plain Put method is
// retained for local/fake mirrors and control-plane recovery writes.
type ConditionalManifestMirror interface {
	ManifestMirror
	PutIfRevision(context.Context, Manifest, int64) error
}

type ManagedContractV1 struct {
	DeploymentID         string
	OwnerID              string
	AcceptanceApprovalID string
	Currency             string
	CostAlertAmountMinor int64
	MonitorRef           string
	MaintenanceRef       string
	RestartRef           string
	BackupRef            string
	RestoreRef           string
	UpgradeRef           string
	RollbackRef          string
	DestroyRef           string
	AcceptedAt           time.Time
}

func (contract ManagedContractV1) Validate() error {
	for name, value := range map[string]string{"deployment_id": contract.DeploymentID, "acceptance_approval_id": contract.AcceptanceApprovalID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return fmt.Errorf("%w: %s must be a non-zero UUID", ErrInvalid, name)
		}
	}
	if owner := strings.TrimSpace(contract.OwnerID); owner == "" || len(owner) > 255 || security.ContainsLikelySecret(owner) {
		return fmt.Errorf("%w: managed owner is invalid", ErrInvalid)
	}
	if !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(contract.Currency) || contract.CostAlertAmountMinor <= 0 {
		return fmt.Errorf("%w: managed cost alert is invalid", ErrInvalid)
	}
	for name, ref := range map[string]string{
		"monitor": contract.MonitorRef, "maintenance": contract.MaintenanceRef, "restart": contract.RestartRef,
		"backup": contract.BackupRef, "restore": contract.RestoreRef, "upgrade": contract.UpgradeRef,
		"rollback": contract.RollbackRef, "destroy": contract.DestroyRef,
	} {
		if err := validateContractRef(name, ref); err != nil {
			return err
		}
	}
	if contract.AcceptedAt.IsZero() {
		return fmt.Errorf("%w: accepted_at is required", ErrInvalid)
	}
	return nil
}

type ManagedServiceV1 struct {
	ServiceID string
	Contract  ManagedContractV1
	State     string
	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type DestroyRequest struct {
	DeploymentID string
	OwnerID      string
	ApprovalID   string
}

type DestroyResult struct {
	Resources []ResourceV1
	Blocked   bool
}

type ProbeKind string

const (
	ProbeLiveness  ProbeKind = "liveness"
	ProbeReadiness ProbeKind = "readiness"
	ProbeSemantic  ProbeKind = "semantic"
)

type ProbeSpec struct {
	DeploymentID   string
	Kind           ProbeKind
	Endpoint       string
	ExpectedDigest string
	Timeout        time.Duration
}

type ProbeObservation struct {
	Healthy       bool
	StatusCode    int
	SummaryDigest string
	ObservedAt    time.Time
}

type ProbeEvidence struct {
	DeploymentID  string
	Kind          ProbeKind
	Endpoint      string
	Healthy       bool
	StatusCode    int
	SummaryDigest string
	Trust         string
	ObservedAt    time.Time
}

type ProbeRunner interface {
	Run(context.Context, ProbeSpec) (ProbeObservation, error)
}

func (spec ProbeSpec) Validate() error {
	parsedID, err := uuid.Parse(strings.TrimSpace(spec.DeploymentID))
	if err != nil || parsedID == uuid.Nil {
		return fmt.Errorf("%w: deployment_id must be a non-zero UUID", ErrInvalid)
	}
	if spec.Kind != ProbeLiveness && spec.Kind != ProbeReadiness && spec.Kind != ProbeSemantic {
		return fmt.Errorf("%w: probe kind is invalid", ErrInvalid)
	}
	parsed, err := url.Parse(strings.TrimSpace(spec.Endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || security.ContainsLikelySecret(spec.Endpoint) {
		return fmt.Errorf("%w: external probe endpoint must be credential-free HTTPS", ErrInvalid)
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("%w: loopback probe endpoint is forbidden", ErrInvalid)
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
		return fmt.Errorf("%w: private probe endpoint is forbidden", ErrInvalid)
	}
	if spec.Timeout < time.Second || spec.Timeout > time.Minute {
		return fmt.Errorf("%w: probe timeout must be 1..60 seconds", ErrInvalid)
	}
	if spec.Kind == ProbeSemantic && !sha256Pattern.MatchString(spec.ExpectedDigest) {
		return fmt.Errorf("%w: semantic probe expected digest is required", ErrInvalid)
	}
	return nil
}

func validType(kind Type) bool {
	switch kind {
	case TypeEC2, TypeEBS, TypeENI, TypeEIP, TypeSG, TypeEndpoint, TypeSnapshot:
		return true
	default:
		return false
	}
}

func validateContractRef(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 || security.ContainsLikelySecret(value) {
		return fmt.Errorf("%w: managed %s contract reference is invalid", ErrInvalid, name)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.User != nil {
		return fmt.Errorf("%w: managed %s contract reference must be an opaque URI", ErrInvalid, name)
	}
	return nil
}

func cloneMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

package resource

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
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
	ErrCreateAmbiguous            = errors.New("provider create result is ambiguous and requires reconciliation")
	ErrStaleProbeEvidence         = errors.New("stale external probe evidence")
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
	// TypeALB, TypeTargetGroup, TypeListener, and TypeSecurityGroupRule model
	// the closed public-entry graph. Target registration deliberately remains a
	// field of TypeTargetGroup because AWS does not give it an independently
	// taggable resource identity.
	TypeALB               Type = "alb"
	TypeTargetGroup       Type = "target_group"
	TypeListener          Type = "listener"
	TypeSecurityGroupRule Type = "security_group_rule"
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
	// TagApprovedPlanHash and TagApprovalID bind a provider object to the
	// exact device-approved operation that authorized it. They are deliberately
	// non-secret so an otherwise unknown provider object can be recovered only
	// after its durable approval origin is re-verified.
	TagApprovedPlanHash  = "approved_plan_hash"
	TagApprovalID        = "approval_id"
	TagIntentOrigin      = "intent_origin"
	TagOriginScopeDigest = "origin_scope_digest"
	// TagEmbeddedParentResourceID binds an AWS resource that is created as part
	// of another provider mutation (currently an EC2 root EBS volume) to its
	// parent while still giving it an independent ledger identity.
	TagEmbeddedParentResourceID = "embedded_parent_resource_id"
)

var sha256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type IntentOrigin string

const IntentOriginManagedPreparation IntentOrigin = "managed_preparation"

type MutationIntent struct {
	Operation               MutationOperation
	ClientToken             string
	RecordedAt              time.Time
	ProviderCreateStartedAt time.Time
}

type ReadBackEvidence struct {
	Exists     bool
	ProviderID string
	ObservedAt time.Time
	TagDigest  string
}

type ResourceV1 struct {
	ResourceID        string
	AgentInstanceID   string
	OwnerID           string
	TaskID            string
	DeploymentID      string
	Type              Type
	LogicalName       string
	Region            string
	SpecDigest        string
	ApprovedPlanHash  string
	ApprovalID        string
	IntentOrigin      IntentOrigin
	OriginScopeDigest string
	ProviderID        string
	// ProviderCandidateIDs records every provider object observed for this
	// mutation while the control plane cannot safely select one. Keeping these
	// IDs in the authoritative ledger lets both the Agent and the independent
	// Reaper clean up every billable object without guessing.
	ProviderCandidateIDs []string
	DependsOn            []string
	Retention            task.RetentionPolicy
	DestroyDeadline      time.Time
	AutoDestroyApproved  bool
	Tags                 map[string]string
	State                State
	Intent               MutationIntent
	ReadBack             ReadBackEvidence
	BlockedReason        string
	Revision             int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (resource ResourceV1) clone() ResourceV1 {
	resource.ProviderCandidateIDs = slices.Clone(resource.ProviderCandidateIDs)
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
	IntentOrigin        IntentOrigin
	OriginScopeDigest   string
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
	switch spec.IntentOrigin {
	case "":
		if spec.OriginScopeDigest != "" {
			return fmt.Errorf("%w: origin scope digest requires a typed origin", ErrInvalid)
		}
	case IntentOriginManagedPreparation:
		if !sha256Pattern.MatchString(spec.OriginScopeDigest) || (spec.Type != TypeSnapshot && spec.Type != TypeEBS) {
			return fmt.Errorf("%w: managed preparation origin is invalid", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported resource intent origin", ErrInvalid)
	}
	if spec.AWS != nil {
		digest, err := spec.AWS.Digest(spec.Type)
		if err != nil || digest != spec.SpecDigest {
			return fmt.Errorf("%w: AWS typed spec does not match spec_digest", ErrInvalid)
		}
		if spec.Type == TypeSnapshot {
			disposition := spec.AWS.Snapshot.Disposition
			if (spec.Retention == task.RetentionEphemeralAutoDestroy && disposition != AWSSnapshotDeleteWithDeployment) ||
				(spec.Retention == task.RetentionManaged && disposition != AWSSnapshotRetainWithManagedService) {
				return fmt.Errorf("%w: snapshot disposition does not match retention", ErrInvalid)
			}
		}
		if spec.Type == TypeEBS && spec.AWS.Volume != nil && spec.AWS.Volume.Disposition != "" {
			disposition := spec.AWS.Volume.Disposition
			if (spec.Retention == task.RetentionEphemeralAutoDestroy && disposition != AWSVolumeDeleteWithDeployment) ||
				(spec.Retention == task.RetentionManaged && disposition != AWSVolumeRetainWithManagedService) {
				return fmt.Errorf("%w: volume disposition does not match retention", ErrInvalid)
			}
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
	result := map[string]string{
		TagAgentInstanceID: strings.TrimSpace(spec.AgentInstanceID), TagOwnerID: strings.TrimSpace(spec.OwnerID),
		TagTaskID: strings.TrimSpace(spec.TaskID), TagDeploymentID: strings.TrimSpace(spec.DeploymentID),
		TagResourceID: strings.TrimSpace(spec.ResourceID), TagRetention: string(spec.Retention), TagDestroyDeadline: deadline,
		TagApprovedPlanHash: strings.TrimSpace(spec.ApprovedPlanHash), TagApprovalID: strings.TrimSpace(spec.ApprovalID),
	}
	if spec.IntentOrigin != "" {
		result[TagIntentOrigin] = string(spec.IntentOrigin)
		result[TagOriginScopeDigest] = spec.OriginScopeDigest
	}
	return result
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
	FindAllByClientToken(context.Context, Type, string, string) ([]ProviderObservation, error)
	ReadBack(context.Context, Type, string, string) (ProviderObservation, error)
	Delete(context.Context, Type, string, string, map[string]string) error
	// ListOwned is a read-only, owner-scoped discovery operation. Providers
	// must require both immutable Agent and owner tags; Agent identity alone is
	// not a tenancy boundary for orphan recovery.
	ListOwned(context.Context, string, string) ([]ProviderObservation, error)
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
	// ApprovalBindings is the exact, deterministic set of plan/approval pairs
	// that authorize resources in this deployment. A public entry can be added
	// after the Worker and therefore legitimately carries a distinct device
	// approval. The legacy top-level pair remains populated only for a single
	// binding; it must never authorize a multi-binding manifest.
	ApprovalBindings []ApprovalBinding `json:"ApprovalBindings,omitempty"`
	Managed          bool
	Resources        []ResourceV1
	Revision         int64
	UpdatedAt        time.Time
}

// ApprovalBinding binds one resource authorization source without exposing an
// approval signature or any secret material in the cloud manifest.
type ApprovalBinding struct {
	ApprovedPlanHash string
	ApprovalID       string
}

func (manifest Manifest) clone() Manifest {
	manifest.ApprovalBindings = slices.Clone(manifest.ApprovalBindings)
	source := manifest.Resources
	manifest.Resources = make([]ResourceV1, len(source))
	for index, resource := range source {
		manifest.Resources[index] = resource.clone()
	}
	return manifest
}

// ValidateApprovalBindings proves that every manifest resource is explicitly
// authorized by exactly one deterministic plan/approval pair. It deliberately
// rejects a missing, unordered, duplicate, or legacy-top-level-only binding so
// a Reaper cannot delete a resource by borrowing another resource's approval.
func (manifest Manifest) ValidateApprovalBindings() error {
	if len(manifest.ApprovalBindings) == 0 || len(manifest.ApprovalBindings) > 64 {
		return ErrInvalid
	}
	bindings := make(map[string]struct{}, len(manifest.ApprovalBindings))
	previous := ""
	for _, binding := range manifest.ApprovalBindings {
		if !sha256Pattern.MatchString(binding.ApprovedPlanHash) || !canonicalManifestUUID(binding.ApprovalID) {
			return ErrInvalid
		}
		key := manifestApprovalBindingKey(binding)
		if key <= previous {
			return ErrInvalid
		}
		bindings[key] = struct{}{}
		previous = key
	}
	for _, item := range manifest.Resources {
		if !sha256Pattern.MatchString(item.ApprovedPlanHash) || !canonicalManifestUUID(item.ApprovalID) {
			return ErrInvalid
		}
		if _, ok := bindings[manifestApprovalBindingKey(ApprovalBinding{ApprovedPlanHash: item.ApprovedPlanHash, ApprovalID: item.ApprovalID})]; !ok {
			return ErrInvalid
		}
	}
	if len(manifest.ApprovalBindings) == 1 {
		binding := manifest.ApprovalBindings[0]
		if manifest.ApprovedPlanHash != binding.ApprovedPlanHash {
			return ErrInvalid
		}
		if manifest.Retention == task.RetentionEphemeralAutoDestroy && manifest.AutoDestroyApprovalID != binding.ApprovalID {
			return ErrInvalid
		}
		if manifest.Retention == task.RetentionManaged && manifest.AutoDestroyApprovalID != "" {
			return ErrInvalid
		}
		return nil
	}
	if manifest.ApprovedPlanHash != "" || manifest.AutoDestroyApprovalID != "" {
		return ErrInvalid
	}
	return nil
}

// NormalizeLegacyApprovalBindings performs the one safe compatibility bridge
// for manifests written before ApprovalBindings existed. It can only derive a
// single binding when every resource already exactly matches the legacy
// top-level authorization. A mixed manifest has blank top-level fields and is
// therefore never silently collapsed into a weaker authorization scope.
func NormalizeLegacyApprovalBindings(manifest *Manifest) error {
	if manifest == nil || len(manifest.Resources) == 0 {
		return ErrInvalid
	}
	if len(manifest.ApprovalBindings) != 0 {
		return nil
	}
	if !sha256Pattern.MatchString(manifest.ApprovedPlanHash) {
		return ErrInvalid
	}
	approvalID := manifest.AutoDestroyApprovalID
	if manifest.Retention == task.RetentionEphemeralAutoDestroy {
		if !canonicalManifestUUID(approvalID) {
			return ErrInvalid
		}
	} else if manifest.Retention == task.RetentionManaged {
		if approvalID != "" || !canonicalManifestUUID(manifest.Resources[0].ApprovalID) {
			return ErrInvalid
		}
		approvalID = manifest.Resources[0].ApprovalID
	} else {
		return ErrInvalid
	}
	for _, item := range manifest.Resources {
		if item.ApprovedPlanHash != manifest.ApprovedPlanHash || item.ApprovalID != approvalID {
			return ErrInvalid
		}
	}
	manifest.ApprovalBindings = []ApprovalBinding{{ApprovedPlanHash: manifest.ApprovedPlanHash, ApprovalID: approvalID}}
	return nil
}

// ValidateResourceApprovalScope validates the per-resource authorization and
// retention facts that a durable manifest must preserve. Store adapters add
// their own persistence/read-back checks on top of this closed contract.
func (manifest Manifest) ValidateResourceApprovalScope() error {
	if err := manifest.ValidateApprovalBindings(); err != nil {
		return err
	}
	if manifest.Retention != task.RetentionEphemeralAutoDestroy && manifest.Retention != task.RetentionManaged {
		return ErrInvalid
	}
	if manifest.Retention == task.RetentionEphemeralAutoDestroy {
		if manifest.Managed || !manifest.AutoDestroyApproved || manifest.DestroyDeadline.IsZero() {
			return ErrInvalid
		}
	} else if !manifest.Managed || manifest.AutoDestroyApproved || !manifest.DestroyDeadline.IsZero() {
		return ErrInvalid
	}
	for _, item := range manifest.Resources {
		if !canonicalManifestUUID(item.ResourceID) || !sha256Pattern.MatchString(item.SpecDigest) ||
			item.AgentInstanceID != manifest.AgentInstanceID || item.OwnerID != manifest.OwnerID ||
			item.TaskID != manifest.TaskID || item.DeploymentID != manifest.DeploymentID || item.Retention != manifest.Retention {
			return ErrInvalid
		}
		expectedTags := map[string]string{
			TagAgentInstanceID:  manifest.AgentInstanceID,
			TagOwnerID:          manifest.OwnerID,
			TagTaskID:           manifest.TaskID,
			TagDeploymentID:     manifest.DeploymentID,
			TagResourceID:       item.ResourceID,
			TagRetention:        string(manifest.Retention),
			TagApprovedPlanHash: item.ApprovedPlanHash,
			TagApprovalID:       item.ApprovalID,
		}
		for key, expected := range expectedTags {
			if expected == "" || item.Tags[key] != expected {
				return ErrInvalid
			}
		}
		switch item.IntentOrigin {
		case "":
			if item.OriginScopeDigest != "" || item.Tags[TagIntentOrigin] != "" || item.Tags[TagOriginScopeDigest] != "" {
				return ErrInvalid
			}
		case IntentOriginManagedPreparation:
			if !sha256Pattern.MatchString(item.OriginScopeDigest) || (item.Type != TypeSnapshot && item.Type != TypeEBS) ||
				item.Tags[TagIntentOrigin] != string(item.IntentOrigin) || item.Tags[TagOriginScopeDigest] != item.OriginScopeDigest {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		if manifest.Retention == task.RetentionEphemeralAutoDestroy {
			if !item.AutoDestroyApproved || !item.DestroyDeadline.Equal(manifest.DestroyDeadline) ||
				item.Tags[TagDestroyDeadline] != manifest.DestroyDeadline.UTC().Truncate(time.Second).Format(time.RFC3339) {
				return ErrInvalid
			}
			continue
		}
		if item.AutoDestroyApproved || !item.DestroyDeadline.IsZero() || item.Tags[TagDestroyDeadline] != "managed" {
			return ErrInvalid
		}
	}
	return nil
}

func approvalBindingsFromResources(resources []ResourceV1) []ApprovalBinding {
	seen := make(map[string]ApprovalBinding, len(resources))
	for _, item := range resources {
		binding := ApprovalBinding{ApprovedPlanHash: item.ApprovedPlanHash, ApprovalID: item.ApprovalID}
		seen[manifestApprovalBindingKey(binding)] = binding
	}
	bindings := make([]ApprovalBinding, 0, len(seen))
	for _, binding := range seen {
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(left, right int) bool {
		return manifestApprovalBindingKey(bindings[left]) < manifestApprovalBindingKey(bindings[right])
	})
	return bindings
}

func manifestApprovalBindingKey(binding ApprovalBinding) string {
	return binding.ApprovedPlanHash + "\x00" + binding.ApprovalID
}

func canonicalManifestUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
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

func validType(kind Type) bool {
	switch kind {
	case TypeEC2, TypeEBS, TypeENI, TypeEIP, TypeSG, TypeEndpoint, TypeSnapshot,
		TypeALB, TypeTargetGroup, TypeListener, TypeSecurityGroupRule:
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

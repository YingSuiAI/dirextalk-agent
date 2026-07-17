// Package stackobservation assembles a de-sensitive, canonical observation of
// the current managed AWS stack. It is read-only: callers supply durable Agent
// facts and the package performs only typed attachment read-backs.
package stackobservation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

const SchemaV1 = "dirextalk.agent.cloud.stack-observation/v1"

var (
	ErrInvalid = errors.New("invalid stack observation")
	ErrDrift   = errors.New("stack observation drift")

	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	instancePattern = regexp.MustCompile(`^i-[a-f0-9]{8,17}$`)
	volumePattern   = regexp.MustCompile(`^vol-[a-f0-9]{8,17}$`)
	networkPattern  = regexp.MustCompile(`^eni-[a-f0-9]{8,17}$`)
	snapshotPattern = regexp.MustCompile(`^snap-[a-f0-9]{8,17}$`)
)

type AttachmentReader interface {
	ReadBackVolumeAttachment(context.Context, awsprovider.VolumeAttachmentSpecV1) (awsprovider.VolumeAttachmentObservationV1, error)
}

type Request struct {
	AgentInstanceID string
	OwnerID         string
	DeploymentID    string
	Plan            cloudapproval.PlanV1
	Approval        cloudapproval.ApprovalV1
	Resources       []resource.ResourceV1
	Health          cloudstatus.HealthSummary
	ObservedAt      time.Time
}

type ResourceFactV1 struct {
	ResourceID string        `json:"resource_id"`
	Type       resource.Type `json:"type"`
	ProviderID string        `json:"provider_id"`
	ApprovalID string        `json:"approval_id"`
	Revision   int64         `json:"revision"`
	TagDigest  string        `json:"tag_digest"`
}

type AttachmentFactV1 struct {
	ResourceID string    `json:"resource_id"`
	VolumeID   string    `json:"volume_id"`
	InstanceID string    `json:"instance_id"`
	DeviceName string    `json:"device_name"`
	ObservedAt time.Time `json:"observed_at"`
}

type ObservationV1 struct {
	SchemaVersion        string             `json:"schema_version"`
	AgentInstanceID      string             `json:"agent_instance_id"`
	OwnerID              string             `json:"owner_id"`
	DeploymentID         string             `json:"deployment_id"`
	PlanID               string             `json:"plan_id"`
	PlanRevision         uint64             `json:"plan_revision"`
	PlanHash             string             `json:"plan_hash"`
	ApprovalID           string             `json:"approval_id"`
	RecipeID             string             `json:"recipe_id"`
	RecipeDigest         string             `json:"recipe_digest"`
	HealthRevision       int64              `json:"health_revision"`
	HealthEvidenceDigest string             `json:"health_evidence_digest"`
	HealthObservedAt     time.Time          `json:"health_observed_at"`
	Resources            []ResourceFactV1   `json:"resources"`
	Attachments          []AttachmentFactV1 `json:"attachments"`
	ObservedAt           time.Time          `json:"observed_at"`
	Digest               string             `json:"digest"`
}

type Assembler struct {
	attachments  AttachmentReader
	maxHealthAge time.Duration
}

func New(attachments AttachmentReader) (*Assembler, error) {
	if attachments == nil {
		return nil, ErrInvalid
	}
	return &Assembler{attachments: attachments, maxHealthAge: 5 * time.Minute}, nil
}

func (assembler *Assembler) Observe(ctx context.Context, request Request) (ObservationV1, error) {
	if assembler == nil || assembler.attachments == nil {
		return ObservationV1{}, ErrInvalid
	}
	if err := validateRequest(request, assembler.maxHealthAge); err != nil {
		return ObservationV1{}, err
	}
	planHash, err := request.Plan.Hash()
	if err != nil || !sameApproval(request.Approval, request.Plan, planHash) {
		return ObservationV1{}, ErrDrift
	}

	resources, byLogicalName, instance, err := exactResources(request, planHash)
	if err != nil {
		return ObservationV1{}, err
	}
	attachments := make([]AttachmentFactV1, 0, len(request.Plan.ResourceScope.VolumeScopes))
	for _, slot := range request.Plan.ResourceScope.VolumeScopes {
		item, ok := byLogicalName["recipe-volume-"+slot.SlotID]
		if !ok || item.Type != resource.TypeEBS {
			return ObservationV1{}, fmt.Errorf("%w: volume slot %s has no exact ledger resource", ErrDrift, slot.SlotID)
		}
		spec := awsprovider.VolumeAttachmentSpecV1{
			IntentID: item.ResourceID, Region: item.Region, InstanceID: instance.ProviderID,
			VolumeID: item.ProviderID, DeviceName: slot.DeviceName,
		}
		observation, readErr := assembler.attachments.ReadBackVolumeAttachment(ctx, spec)
		if readErr != nil {
			return ObservationV1{}, fmt.Errorf("%w: attachment read-back: %v", ErrDrift, readErr)
		}
		if !observation.Exists || observation.State != awsprovider.VolumeAttachmentStateAttached ||
			observation.IntentID != spec.IntentID || observation.Region != spec.Region ||
			observation.InstanceID != spec.InstanceID || observation.VolumeID != spec.VolumeID ||
			observation.DeviceName != spec.DeviceName || observation.ObservedAt.IsZero() ||
			observation.ObservedAt.Location() != time.UTC || observation.ObservedAt.After(request.ObservedAt) {
			return ObservationV1{}, fmt.Errorf("%w: attachment read-back mismatch", ErrDrift)
		}
		if request.ObservedAt.Sub(observation.ObservedAt) > assembler.maxHealthAge {
			return ObservationV1{}, fmt.Errorf("%w: stale attachment read-back", ErrDrift)
		}
		attachments = append(attachments, AttachmentFactV1{
			ResourceID: item.ResourceID, VolumeID: item.ProviderID, InstanceID: instance.ProviderID,
			DeviceName: slot.DeviceName, ObservedAt: observation.ObservedAt,
		})
	}
	sort.Slice(attachments, func(i, j int) bool { return attachments[i].ResourceID < attachments[j].ResourceID })

	result := ObservationV1{
		SchemaVersion: SchemaV1, AgentInstanceID: request.AgentInstanceID, OwnerID: request.OwnerID,
		DeploymentID: request.DeploymentID, PlanID: request.Plan.PlanID, PlanRevision: request.Plan.Revision,
		PlanHash: planHash, ApprovalID: request.Approval.ApprovalID, RecipeID: request.Plan.Recipe.RecipeID,
		RecipeDigest: request.Plan.Recipe.Digest, HealthRevision: request.Health.Revision,
		HealthEvidenceDigest: request.Health.EvidenceDigest, HealthObservedAt: request.Health.ObservedAt,
		Resources: resources, Attachments: attachments, ObservedAt: request.ObservedAt,
	}
	result.Digest, err = canonical.Digest(observationDigestDocument(result))
	if err != nil {
		return ObservationV1{}, fmt.Errorf("%w: canonical digest", ErrInvalid)
	}
	return result, nil
}

func validateRequest(request Request, maxHealthAge time.Duration) error {
	if strings.TrimSpace(request.AgentInstanceID) == "" || strings.TrimSpace(request.OwnerID) == "" ||
		strings.TrimSpace(request.DeploymentID) == "" || request.ObservedAt.IsZero() ||
		request.ObservedAt.Location() != time.UTC || request.Plan.Status != cloudapproval.PlanApproved ||
		request.Plan.AgentInstanceID != request.AgentInstanceID || request.Plan.OwnerID != request.OwnerID ||
		request.Health.Status != cloudstatus.HealthHealthy || request.Health.EvidenceType != cloudstatus.HealthEvidenceIndependent ||
		request.Health.Revision < 1 || !digestPattern.MatchString(request.Health.EvidenceDigest) ||
		request.Health.ObservedAt.IsZero() || request.Health.ObservedAt.Location() != time.UTC ||
		request.Health.ObservedAt.After(request.ObservedAt) || request.ObservedAt.Sub(request.Health.ObservedAt) > maxHealthAge {
		return ErrInvalid
	}
	if err := request.Plan.Validate(); err != nil {
		return ErrInvalid
	}
	return nil
}

func sameApproval(approval cloudapproval.ApprovalV1, plan cloudapproval.PlanV1, planHash string) bool {
	return approval.AgentInstanceID == plan.AgentInstanceID && approval.OwnerID == plan.OwnerID &&
		approval.PlanID == plan.PlanID && approval.PlanRevision == plan.Revision && approval.PlanHash == planHash &&
		approval.ConnectionID == plan.ConnectionID && approval.RecipeDigest == plan.Recipe.Digest &&
		approval.QuoteID == plan.Quote.QuoteID && approval.QuoteDigest == plan.Quote.Digest &&
		approval.QuoteScopeDigest == plan.Quote.ScopeDigest && approval.QuoteCandidateID == plan.Quote.CandidateID &&
		reflect.DeepEqual(approval.ResourceScope, plan.ResourceScope) &&
		reflect.DeepEqual(approval.NetworkScope, plan.NetworkScope) &&
		reflect.DeepEqual(approval.SecretScope, plan.SecretScope) &&
		reflect.DeepEqual(approval.IntegrationScope, plan.IntegrationScope) &&
		reflect.DeepEqual(approval.RetentionScope, plan.RetentionScope)
}

func exactResources(request Request, planHash string) ([]ResourceFactV1, map[string]resource.ResourceV1, resource.ResourceV1, error) {
	allowed := map[resource.Type]bool{
		resource.TypeEC2: true, resource.TypeEBS: true, resource.TypeENI: true, resource.TypeSnapshot: true,
	}
	facts := make([]ResourceFactV1, 0, len(request.Resources))
	byLogicalName := make(map[string]resource.ResourceV1)
	seenIDs, seenProviders := make(map[string]struct{}), make(map[string]struct{})
	resourceTypes := make(map[string]resource.Type)
	counts := make(map[resource.Type]int)
	var instance resource.ResourceV1
	for _, item := range request.Resources {
		if !allowed[item.Type] {
			continue
		}
		if item.AgentInstanceID != request.AgentInstanceID || item.OwnerID != request.OwnerID ||
			item.DeploymentID != request.DeploymentID || item.ApprovedPlanHash != planHash ||
			strings.TrimSpace(item.ApprovalID) == "" ||
			item.State != resource.StateActive && item.State != resource.StateRetainedManaged ||
			item.ResourceID == "" || item.ProviderID == "" || item.Revision < 1 ||
			!item.ReadBack.Exists || item.ReadBack.ProviderID != item.ProviderID ||
			!digestPattern.MatchString(item.ReadBack.TagDigest) {
			return nil, nil, resource.ResourceV1{}, ErrDrift
		}
		if !validProviderID(item.Type, item.ProviderID) ||
			item.Type == resource.TypeEC2 && item.ApprovalID != request.Approval.ApprovalID {
			return nil, nil, resource.ResourceV1{}, ErrDrift
		}
		if _, exists := seenIDs[item.ResourceID]; exists {
			return nil, nil, resource.ResourceV1{}, ErrDrift
		}
		if _, exists := seenProviders[item.ProviderID]; exists {
			return nil, nil, resource.ResourceV1{}, ErrDrift
		}
		if _, exists := byLogicalName[item.LogicalName]; exists {
			return nil, nil, resource.ResourceV1{}, ErrDrift
		}
		seenIDs[item.ResourceID], seenProviders[item.ProviderID] = struct{}{}, struct{}{}
		resourceTypes[item.ResourceID] = item.Type
		byLogicalName[item.LogicalName] = item
		counts[item.Type]++
		if item.Type == resource.TypeEC2 {
			instance = item
		}
		if item.Type == resource.TypeSnapshot && len(item.DependsOn) != 1 {
			return nil, nil, resource.ResourceV1{}, ErrDrift
		}
		facts = append(facts, ResourceFactV1{
			ResourceID: item.ResourceID, Type: item.Type, ProviderID: item.ProviderID,
			ApprovalID: item.ApprovalID, Revision: item.Revision, TagDigest: item.ReadBack.TagDigest,
		})
	}
	if counts[resource.TypeEC2] != 1 || counts[resource.TypeENI] != 1 ||
		counts[resource.TypeEBS] < 1 || counts[resource.TypeSnapshot] < 1 {
		return nil, nil, resource.ResourceV1{}, ErrDrift
	}
	for _, item := range request.Resources {
		if item.Type != resource.TypeSnapshot {
			continue
		}
		if resourceTypes[item.DependsOn[0]] != resource.TypeEBS {
			return nil, nil, resource.ResourceV1{}, ErrDrift
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ResourceID < facts[j].ResourceID })
	return facts, byLogicalName, instance, nil
}

func validProviderID(kind resource.Type, providerID string) bool {
	switch kind {
	case resource.TypeEC2:
		return instancePattern.MatchString(providerID)
	case resource.TypeEBS:
		return volumePattern.MatchString(providerID)
	case resource.TypeENI:
		return networkPattern.MatchString(providerID)
	case resource.TypeSnapshot:
		return snapshotPattern.MatchString(providerID)
	default:
		return false
	}
}

func observationDigestDocument(value ObservationV1) any {
	value.Digest = ""
	return value
}

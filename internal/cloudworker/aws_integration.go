package cloudworker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
)

func expectedEphemeralAWSResourceCount() uint64 {
	return uint64(len(cloudaws.AllResourceKinds()))
}

// ErrCleanupPending means that at least one independently durable cleanup
// authority has not yet proved absence. It is always reclaimable and must
// never be converted into a terminal execution state.
var ErrCleanupPending = errors.New("cloudworker: cleanup evidence is pending")

var (
	cloudWorkerEC2InstanceIDPattern = regexp.MustCompile(`^i-[0-9a-f]{8,32}$`)
)

// ProjectAWSResourceGraph is the sole AWS ledger -> Execution V2 resource
// projection. ResourceID is stable for the execution/kind pair; ProviderID is
// bound once the physical AWS identity is observed and can never be replaced.
// A provisioning or never-created tombstone may therefore have an empty
// ProviderID. The owning Store must allow that empty planned/delete-requested
// identity and only permit the one-way empty -> exact ProviderID transition.
//
// The private AWS ledger may verify resources independently, but the public
// projection deliberately exposes cleanup atomically. While the graph is
// destroying every resource remains delete_requested; only a centrally
// validated, fully absent graph publishes all resources as verified_destroyed.
func ProjectAWSResourceGraph(
	plan Plan,
	execution Execution,
	awsPlan cloudaws.Plan,
	intent cloudaws.DispatchIntent,
	graph cloudaws.ObservedGraph,
	previous []Resource,
) ([]Resource, error) {
	sealedPlan := plan
	if sealedPlan.Seal() != nil || execution.Seal() != nil ||
		awsPlan.Validate() != nil || intent.Validate(awsPlan) != nil ||
		graph.Validate(awsPlan, intent) != nil ||
		sealedPlan.ExecutionID != execution.ExecutionID ||
		sealedPlan.TaskID != execution.TaskID ||
		sealedPlan.Digest != execution.PlanDigest ||
		sealedPlan.ExecutionDigest != execution.ExecutionDigest ||
		awsPlan.Digest != sealedPlan.Digest ||
		awsPlan.ExecutionSHA256 != sealedPlan.ExecutionDigest ||
		awsPlan.Identity.OwnerID != sealedPlan.OwnerID ||
		awsPlan.Identity.AccountGeneration != sealedPlan.AccountGeneration ||
		awsPlan.Identity.AccountID != sealedPlan.AWS.AccountID ||
		awsPlan.Identity.Region != sealedPlan.AWS.Region ||
		awsPlan.Identity.ExecutionID != sealedPlan.ExecutionID ||
		awsPlan.Identity.TaskID != sealedPlan.TaskID {
		return nil, ErrStaleAuthorization
	}

	prior, err := indexProjectedResources(sealedPlan, awsPlan.Identity, previous)
	if err != nil {
		return nil, err
	}
	observed := make(map[cloudaws.ResourceKind]cloudaws.ResourceObservation, len(graph.Resources))
	for _, value := range graph.Resources {
		observed[value.Kind] = value
	}
	result := make([]Resource, 0, len(cloudaws.AllResourceKinds()))
	for _, kind := range cloudaws.AllResourceKinds() {
		observation := observed[kind]
		old, hadOld := prior[kind]
		providerID := strings.TrimSpace(observation.ProviderID)
		if hadOld && old.ProviderID != "" {
			if providerID != "" && providerID != old.ProviderID {
				return nil, ErrConflict
			}
			providerID = old.ProviderID
		}
		state := projectedResourceState(graph.State, observation.Exists)
		if state == "" || (observation.Exists && providerID == "") {
			return nil, ErrInvalid
		}
		createdAt := intent.RecordedAt.UTC()
		revision := uint64(1)
		if hadOld {
			createdAt, revision = old.CreatedAt.UTC(), old.Revision
			if !validProjectedResourceTransition(old.State, state) {
				return nil, ErrConflict
			}
		}
		updatedAt := graph.ObservedAt.UTC()
		if updatedAt.Before(createdAt) {
			return nil, ErrInvalid
		}
		var verifiedAt *time.Time
		if state == ResourceVerifiedDestroyed {
			at := updatedAt
			if hadOld && old.VerifiedAt != nil {
				at = old.VerifiedAt.UTC()
			}
			verifiedAt = &at
		}
		next := Resource{
			ResourceID:  deterministicID("cloud-worker-aws-resource", sealedPlan.ExecutionID+":"+string(kind)),
			ExecutionID: sealedPlan.ExecutionID, AccountGeneration: sealedPlan.AccountGeneration,
			Provider: "aws", Kind: string(kind), ProviderID: providerID,
			AccountID: sealedPlan.AWS.AccountID, Region: sealedPlan.AWS.Region,
			LaunchIdentity: awsPlan.Identity.LaunchIdentity, State: state,
			Revision: revision, CreatedAt: createdAt, UpdatedAt: updatedAt,
			VerifiedAt: verifiedAt,
		}
		if hadOld && !sameProjectedResource(old, next) {
			next.Revision++
		}
		result = append(result, next)
	}
	return result, nil
}

func indexProjectedResources(plan Plan, identity cloudaws.ExecutionIdentity, values []Resource) (map[cloudaws.ResourceKind]Resource, error) {
	if len(values) > len(cloudaws.AllResourceKinds()) {
		return nil, ErrInvalid
	}
	result := make(map[cloudaws.ResourceKind]Resource, len(values))
	for _, value := range values {
		kind := cloudaws.ResourceKind(value.Kind)
		expectedID := deterministicID("cloud-worker-aws-resource", plan.ExecutionID+":"+string(kind))
		if !slices.Contains(cloudaws.AllResourceKinds(), kind) || value.ResourceID != expectedID ||
			value.ExecutionID != plan.ExecutionID || value.AccountGeneration != plan.AccountGeneration ||
			value.Provider != "aws" || value.AccountID != plan.AWS.AccountID || value.Region != plan.AWS.Region ||
			value.LaunchIdentity != identity.LaunchIdentity || value.Revision == 0 || value.CreatedAt.IsZero() ||
			value.UpdatedAt.Before(value.CreatedAt) || (value.State == ResourceVerifiedDestroyed) != (value.VerifiedAt != nil) {
			return nil, ErrConflict
		}
		if _, duplicate := result[kind]; duplicate {
			return nil, ErrConflict
		}
		result[kind] = value
	}
	return result, nil
}

func projectedResourceState(graphState cloudaws.GraphState, exists bool) ResourceState {
	switch graphState {
	case cloudaws.GraphProvisioning:
		if exists {
			return ResourceCreated
		}
		return ResourcePlanned
	case cloudaws.GraphActive:
		return ResourceCreated
	case cloudaws.GraphDestroying:
		return ResourceDeleteRequested
	case cloudaws.GraphVerifiedDestroyed:
		return ResourceVerifiedDestroyed
	default:
		return ""
	}
}

func validProjectedResourceTransition(current, next ResourceState) bool {
	switch current {
	case ResourcePlanned:
		return next == ResourcePlanned || next == ResourceCreated || next == ResourceDeleteRequested || next == ResourceVerifiedDestroyed
	case ResourceCreated:
		return next == ResourceCreated || next == ResourceDeleteRequested || next == ResourceVerifiedDestroyed
	case ResourceDeleteRequested:
		return next == ResourceDeleteRequested || next == ResourceVerifiedDestroyed
	case ResourceVerifiedDestroyed:
		return next == ResourceVerifiedDestroyed
	default:
		return false
	}
}

func sameProjectedResource(left, right Resource) bool {
	return left.ResourceID == right.ResourceID && left.ExecutionID == right.ExecutionID &&
		left.AccountGeneration == right.AccountGeneration && left.Provider == right.Provider &&
		left.Kind == right.Kind && left.ProviderID == right.ProviderID && left.AccountID == right.AccountID &&
		left.Region == right.Region && left.LaunchIdentity == right.LaunchIdentity && left.State == right.State &&
		left.CreatedAt.Equal(right.CreatedAt) && left.UpdatedAt.Equal(right.UpdatedAt) && equalOptionalTime(left.VerifiedAt, right.VerifiedAt)
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

// BuildWorkerIdentityExpectation converts a fully validated one-instance AWS
// graph into the immutable challenge expectation used by WorkerControl. It is
// intentionally unavailable while provisioning is partial.
func BuildWorkerIdentityExpectation(awsPlan cloudaws.Plan, intent cloudaws.DispatchIntent, graph cloudaws.ObservedGraph) (control.IdentityExpectation, error) {
	if awsPlan.Validate() != nil || intent.Validate(awsPlan) != nil || graph.Validate(awsPlan, intent) != nil || graph.State != cloudaws.GraphActive {
		return control.IdentityExpectation{}, ErrInvalid
	}
	var instance, role, instanceProfile cloudaws.ResourceObservation
	for _, value := range graph.Resources {
		switch value.Kind {
		case cloudaws.ResourceEC2:
			instance = value
		case cloudaws.ResourceIAMRole:
			role = value
		case cloudaws.ResourceInstanceProfile:
			instanceProfile = value
		}
	}
	if !instance.Exists || !cloudWorkerEC2InstanceIDPattern.MatchString(instance.ProviderID) ||
		instance.LaunchIdentity != awsPlan.Identity.LaunchIdentity || !role.Exists ||
		!cloudaws.ValidIAMImmutableID(role.ProviderID) || !instanceProfile.Exists ||
		!cloudaws.ValidIAMImmutableID(instanceProfile.ProviderID) {
		return control.IdentityExpectation{}, ErrInvalid
	}
	partition := "aws"
	if strings.HasPrefix(awsPlan.Identity.Region, "cn-") {
		partition = "aws-cn"
	} else if strings.HasPrefix(awsPlan.Identity.Region, "us-gov-") {
		partition = "aws-us-gov"
	}
	return control.IdentityExpectation{
		OwnerID: awsPlan.Identity.OwnerID, AccountGeneration: awsPlan.Identity.AccountGeneration,
		AccountID: awsPlan.Identity.AccountID, Region: awsPlan.Identity.Region,
		InstanceID: instance.ProviderID, LaunchIdentity: awsPlan.Identity.LaunchIdentity,
		RoleARN: fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, awsPlan.Identity.AccountID, awsPlan.IAMRoleName),
		RoleID:  role.ProviderID, InstanceProfileID: instanceProfile.ProviderID,
		RequiredTags: cloudaws.RequiredTags(awsPlan.Identity, awsPlan.Digest, awsPlan.InfrastructureDigest, intent.IntentDigest),
	}, nil
}

type AWSGraphLifecycle interface {
	Observe(context.Context, cloudaws.ExecutionIdentity) (cloudaws.ObservedGraph, error)
	Destroy(context.Context, cloudaws.ExecutionIdentity, cloudaws.ObservedGraph) (cloudaws.ObservedGraph, error)
}

type StagedInputCleaner interface {
	Cleanup(context.Context, Plan) error
}

type CleanupEvidence struct {
	AWSGraph                cloudaws.ObservedGraph `json:"aws_graph"`
	AWSVerifiedDestroyed    bool                   `json:"aws_verified_destroyed"`
	InputsVerifiedDestroyed bool                   `json:"inputs_verified_destroyed"`
}

func (evidence CleanupEvidence) Verified() bool {
	return evidence.AWSVerifiedDestroyed && evidence.InputsVerifiedDestroyed && evidence.AWSGraph.State == cloudaws.GraphVerifiedDestroyed
}

// CleanupCoordinator always advances both independent cleanup authorities.
// An AWS readback failure must not prevent exact-version input cleanup, and an
// S3 uncertainty must not prevent the resource Reaper path from progressing.
type CleanupCoordinator struct {
	aws     AWSGraphLifecycle
	staging StagedInputCleaner
}

func NewCleanupCoordinator(aws AWSGraphLifecycle, staging StagedInputCleaner) (*CleanupCoordinator, error) {
	if aws == nil || staging == nil {
		return nil, ErrInvalid
	}
	return &CleanupCoordinator{aws: aws, staging: staging}, nil
}

func (coordinator *CleanupCoordinator) Reconcile(
	ctx context.Context,
	plan Plan,
	awsPlan cloudaws.Plan,
	intent cloudaws.DispatchIntent,
) (CleanupEvidence, error) {
	sealedPlan := plan
	if coordinator == nil || ctx == nil || sealedPlan.Seal() != nil || awsPlan.Validate() != nil || intent.Validate(awsPlan) != nil ||
		awsPlan.Digest != sealedPlan.Digest || awsPlan.Identity.ExecutionID != sealedPlan.ExecutionID ||
		awsPlan.Identity.OwnerID != sealedPlan.OwnerID || awsPlan.Identity.AccountGeneration != sealedPlan.AccountGeneration {
		return CleanupEvidence{}, ErrInvalid
	}
	evidence := CleanupEvidence{}
	graph, awsErr := coordinator.aws.Observe(ctx, awsPlan.Identity)
	if awsErr == nil {
		if graph.Validate(awsPlan, intent) != nil {
			awsErr = ErrConflict
		} else if graph.State != cloudaws.GraphVerifiedDestroyed {
			graph, awsErr = coordinator.aws.Destroy(ctx, awsPlan.Identity, graph)
			if graph.Identity.ExecutionID != "" && graph.Validate(awsPlan, intent) != nil {
				awsErr = errors.Join(awsErr, ErrConflict)
			}
		}
	}
	evidence.AWSGraph = graph
	evidence.AWSVerifiedDestroyed = awsErr == nil && graph.State == cloudaws.GraphVerifiedDestroyed
	stagingErr := coordinator.staging.Cleanup(ctx, sealedPlan)
	evidence.InputsVerifiedDestroyed = stagingErr == nil
	if !evidence.Verified() {
		return evidence, errors.Join(ErrCleanupPending, awsErr, stagingErr)
	}
	return evidence, nil
}

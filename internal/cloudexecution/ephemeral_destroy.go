package cloudexecution

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

var ErrLifecycleFactsMismatch = errors.New("cloud execution lifecycle facts do not match")

// AgentResourceReader returns the durable resource ledger for exactly one
// Agent instance. Implementations must scope this lookup server-side.
type AgentResourceReader interface {
	ListByAgent(context.Context, string) ([]resource.ResourceV1, error)
}

// DeploymentLaunchReader deliberately does not accept an owner supplied by a
// caller. The controller starts from an Agent-scoped resource and validates
// every recovered owner binding before a destructive operation.
type DeploymentLaunchReader interface {
	GetByDeployment(context.Context, string) (Operation, error)
}

type TaskFactReader interface {
	Get(context.Context, string) (task.Task, error)
}

// ResourceLifecycle is the typed destructive boundary. Destroy implementations
// must re-check managed retention when committing the destructive transition;
// the controller also checks both the scanned and scheduled snapshots.
type ResourceLifecycle interface {
	ScheduleDestroy(context.Context, string, string) ([]resource.ResourceV1, error)
	Destroy(context.Context, resource.DestroyRequest) (resource.DestroyResult, error)
}

type LifecycleFactory interface {
	ForConnection(context.Context, cloudapp.Connection) (ResourceLifecycle, error)
}

type EphemeralDestroyConfig struct {
	AgentInstanceID string
	PollInterval    time.Duration
	Resources       AgentResourceReader
	Launches        DeploymentLaunchReader
	Facts           FactReader
	Connections     ConnectionReader
	Tasks           TaskFactReader
	Lifecycles      LifecycleFactory
	Now             func() time.Time
}

// EphemeralDestroyController reconstructs authorization from durable facts on
// every poll. It keeps no local completion marker: the resource ledger and
// provider read-back make restart and repeated polling idempotent.
type EphemeralDestroyController struct {
	agentInstanceID string
	interval        time.Duration
	resources       AgentResourceReader
	launches        DeploymentLaunchReader
	facts           FactReader
	connections     ConnectionReader
	tasks           TaskFactReader
	lifecycles      LifecycleFactory
	now             func() time.Time
}

func NewEphemeralDestroyController(config EphemeralDestroyConfig) (*EphemeralDestroyController, error) {
	agentID, err := uuid.Parse(strings.TrimSpace(config.AgentInstanceID))
	if err != nil || agentID == uuid.Nil || config.PollInterval < time.Second || config.PollInterval > 5*time.Minute ||
		config.Resources == nil || config.Launches == nil || config.Facts == nil || config.Connections == nil ||
		config.Tasks == nil || config.Lifecycles == nil || config.Now == nil {
		return nil, ErrInvalid
	}
	return &EphemeralDestroyController{
		agentInstanceID: agentID.String(), interval: config.PollInterval, resources: config.Resources,
		launches: config.Launches, facts: config.Facts, connections: config.Connections,
		tasks: config.Tasks, lifecycles: config.Lifecycles, now: config.Now,
	}, nil
}

func (controller *EphemeralDestroyController) Run(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return ErrInvalid
	}
	ticker := time.NewTicker(controller.interval)
	defer ticker.Stop()
	for {
		if err := controller.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			// Facts and provider failures remain durable and are retried on the
			// next poll. One bad deployment must not stop lifecycle monitoring.
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (controller *EphemeralDestroyController) RunOnce(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return ErrInvalid
	}
	items, err := controller.resources.ListByAgent(ctx, controller.agentInstanceID)
	if err != nil {
		return err
	}
	groups, invalid := groupDestroyCandidates(controller.agentInstanceID, items)
	var batchErr error
	if invalid {
		batchErr = ErrLifecycleFactsMismatch
	}
	deployments := make([]string, 0, len(groups))
	for deploymentID := range groups {
		deployments = append(deployments, deploymentID)
	}
	sort.Strings(deployments)
	for _, deploymentID := range deployments {
		resources := groups[deploymentID]
		if deploymentIsDestroyed(resources) || deploymentIsManaged(resources) {
			continue
		}
		if reconcileErr := controller.reconcile(ctx, deploymentID, resources); reconcileErr != nil {
			batchErr = errors.Join(batchErr, fmt.Errorf("deployment %s: %w", deploymentID, reconcileErr))
		}
	}
	return batchErr
}

func (controller *EphemeralDestroyController) reconcile(ctx context.Context, deploymentID string, resources []resource.ResourceV1) error {
	operation, err := controller.launches.GetByDeployment(ctx, deploymentID)
	if err != nil {
		return err
	}
	plan, err := controller.facts.LoadPlan(ctx, operation.Launch.OwnerID, operation.Launch.PlanID)
	if err != nil {
		return err
	}
	approval, err := controller.facts.LoadApproval(ctx, operation.Launch.OwnerID, operation.Launch.ApprovalID)
	if err != nil {
		return err
	}
	connection, err := controller.connections.LoadConnection(ctx, operation.Launch.OwnerID, operation.ConnectionID)
	if err != nil {
		return err
	}
	taskValue, err := controller.tasks.Get(ctx, operation.TaskID)
	if err != nil {
		return err
	}
	managed, due, err := controller.lifecycleDecision(operation, plan, approval, connection, taskValue, resources)
	if err != nil || managed || !due {
		return err
	}
	lifecycle, err := controller.lifecycles.ForConnection(ctx, connection)
	if err != nil {
		return err
	}
	if lifecycle == nil {
		return ErrUnavailable
	}
	scheduled, err := lifecycle.ScheduleDestroy(ctx, deploymentID, operation.Launch.OwnerID)
	if errors.Is(err, resource.ErrManaged) {
		return nil
	}
	if err != nil {
		return err
	}
	if !scheduledSnapshotMatches(controller.agentInstanceID, operation, resources, scheduled) {
		return ErrLifecycleFactsMismatch
	}
	result, err := lifecycle.Destroy(ctx, resource.DestroyRequest{
		DeploymentID: deploymentID,
		OwnerID:      operation.Launch.OwnerID,
		ApprovalID:   operation.Launch.ApprovalID,
	})
	if errors.Is(err, resource.ErrManaged) || errors.Is(err, resource.ErrDestroyBlocked) {
		return nil
	}
	if err != nil {
		return err
	}
	if result.Blocked {
		// The next poll reconstructs the same approved facts and retries. The
		// resource service preserves dependency ordering and read-back state.
		return nil
	}
	return nil
}

func (controller *EphemeralDestroyController) lifecycleDecision(
	operation Operation,
	plan cloudapproval.PlanV1,
	approval cloudapproval.ApprovalV1,
	connection cloudapp.Connection,
	taskValue task.Task,
	resources []resource.ResourceV1,
) (managed bool, due bool, err error) {
	if plan.RetentionScope.Class == cloudapproval.RetentionManaged || taskValue.RetentionPolicy == task.RetentionManaged {
		return true, false, nil
	}
	if plan.AgentInstanceID != controller.agentInstanceID || approval.AgentInstanceID != controller.agentInstanceID ||
		operation.DeploymentID == "" || operation.DeploymentID != resources[0].DeploymentID || operation.TaskID == "" ||
		operation.Launch.OwnerID != plan.OwnerID || plan.OwnerID != approval.OwnerID || plan.OwnerID != connection.OwnerID || plan.OwnerID != taskValue.OwnerID ||
		operation.Launch.PlanID != plan.PlanID || operation.Launch.ApprovalID != approval.ApprovalID || approval.PlanID != plan.PlanID ||
		operation.ConnectionID != plan.ConnectionID || operation.ConnectionID != approval.ConnectionID || operation.ConnectionID != connection.ConnectionID ||
		operation.ApprovedPlanHash != approval.PlanHash || operation.TaskID != taskValue.TaskID ||
		(taskValue.ApprovedPlanID != "" && taskValue.ApprovedPlanID != plan.PlanID) || plan.ResourceScope.Region != connection.Region ||
		!matchesDurableApproval(plan, approval) || plan.RetentionScope.Class != cloudapproval.RetentionEphemeral || !plan.RetentionScope.AutoDestroy ||
		plan.RetentionScope.GracePeriodSeconds == 0 || plan.RetentionScope.MaxLifetimeSeconds == 0 || operation.CreatedAt.IsZero() || taskValue.UpdatedAt.IsZero() {
		return false, false, ErrLifecycleFactsMismatch
	}
	maximumDeadline := operation.CreatedAt.UTC().Add(time.Duration(plan.RetentionScope.MaxLifetimeSeconds) * time.Second)
	for _, item := range resources {
		if item.AgentInstanceID != controller.agentInstanceID || item.DeploymentID != operation.DeploymentID || item.OwnerID != plan.OwnerID ||
			item.TaskID != operation.TaskID || item.ApprovalID != approval.ApprovalID || item.ApprovedPlanHash != approval.PlanHash ||
			item.Retention != task.RetentionEphemeralAutoDestroy || !item.AutoDestroyApproved || !item.DestroyDeadline.UTC().Equal(maximumDeadline) {
			return false, false, ErrLifecycleFactsMismatch
		}
	}
	now := controller.now().UTC()
	if !now.Before(maximumDeadline) {
		return false, true, nil
	}
	if taskValue.ExecutionStatus != task.ExecutionFinished || !terminalOutcome(taskValue.OutcomeStatus) {
		return false, false, nil
	}
	graceDeadline := taskValue.UpdatedAt.UTC().Add(time.Duration(plan.RetentionScope.GracePeriodSeconds) * time.Second)
	return false, !now.Before(graceDeadline), nil
}

func groupDestroyCandidates(agentInstanceID string, items []resource.ResourceV1) (map[string][]resource.ResourceV1, bool) {
	groups := make(map[string][]resource.ResourceV1)
	invalid := false
	for _, item := range items {
		if item.AgentInstanceID != agentInstanceID || strings.TrimSpace(item.DeploymentID) == "" {
			invalid = true
			continue
		}
		groups[item.DeploymentID] = append(groups[item.DeploymentID], item)
	}
	return groups, invalid
}

func deploymentIsDestroyed(items []resource.ResourceV1) bool {
	if len(items) == 0 {
		return true
	}
	for _, item := range items {
		if item.State != resource.StateVerifiedDestroyed {
			return false
		}
	}
	return true
}

func deploymentIsManaged(items []resource.ResourceV1) bool {
	for _, item := range items {
		if item.Retention == task.RetentionManaged || item.State == resource.StateRetainedManaged {
			return true
		}
	}
	return false
}

func scheduledSnapshotMatches(agentInstanceID string, operation Operation, before, after []resource.ResourceV1) bool {
	if len(before) == 0 || len(before) != len(after) {
		return false
	}
	expected := make(map[string]struct{}, len(before))
	for _, item := range before {
		expected[item.ResourceID] = struct{}{}
	}
	for _, item := range after {
		if _, ok := expected[item.ResourceID]; !ok {
			return false
		}
		delete(expected, item.ResourceID)
		if item.AgentInstanceID != agentInstanceID || item.DeploymentID != operation.DeploymentID || item.OwnerID != operation.Launch.OwnerID || item.TaskID != operation.TaskID ||
			item.ApprovalID != operation.Launch.ApprovalID || item.ApprovedPlanHash != operation.ApprovedPlanHash ||
			item.Retention != task.RetentionEphemeralAutoDestroy || !item.AutoDestroyApproved || item.State == resource.StateRetainedManaged {
			return false
		}
	}
	return len(expected) == 0
}

func terminalOutcome(value task.OutcomeStatus) bool {
	switch value {
	case task.OutcomeSucceeded, task.OutcomeFailed, task.OutcomeCanceled, task.OutcomeTimedOut, task.OutcomeInterrupted:
		return true
	default:
		return false
	}
}

package workerrunner

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

type InstallerExecuteAction struct {
	client installer.ExecuteClient
	now    func() time.Time
}

func NewInstallerExecuteAction(client installer.ExecuteClient, now func() time.Time) (*InstallerExecuteAction, error) {
	if client == nil || now == nil {
		return nil, ErrInstallerAction
	}
	return &InstallerExecuteAction{client: client, now: now}, nil
}

func (*InstallerExecuteAction) Kind() string { return installer.ActionExecute }

func (handler *InstallerExecuteAction) Validate(action ActionV1) error {
	if handler == nil || handler.client == nil || handler.now == nil || action.Kind != installer.ActionExecute || action.Noop != nil || action.Installer == nil || action.Installer.LeaseGrant == nil {
		return ErrInvalidBundle
	}
	if err := installer.ValidateLeaseGrantAt(action.Installer.Delivery, *action.Installer.LeaseGrant, action.Installer.CommandID, handler.now().UTC()); err != nil {
		return ErrInvalidBundle
	}
	command, found := installerCommand(action.Installer.Delivery, action.Installer.CommandID)
	if !found || command.TimeoutSeconds != action.TimeoutSeconds {
		return ErrInvalidBundle
	}
	return nil
}

func (handler *InstallerExecuteAction) Execute(ctx context.Context, action ActionV1) (ActionResult, error) {
	if err := handler.Validate(action); err != nil {
		return ActionResult{}, err
	}
	response, err := handler.client.Execute(ctx, action.Installer.Delivery, *action.Installer.LeaseGrant, action.Installer.CommandID)
	if err != nil {
		return ActionResult{}, errors.Join(ErrInstallerAction, err)
	}
	if response.Action != installer.ActionExecute || response.CommandID != action.Installer.CommandID || response.Status != installer.StatusExecuted || response.ErrorCode != "" {
		return ActionResult{}, ErrInstallerAction
	}
	return ActionResult{Status: installer.StatusExecuted}, nil
}

func bindInstallerAssignment(bundle ExecutionBundleV1, assignment *agentv1.WorkerAssignment, now time.Time) (ExecutionBundleV1, error) {
	if assignment == nil || assignment.GetLeaseExpiresAt() == nil {
		return ExecutionBundleV1{}, ErrInvalidBundle
	}
	grants, err := installerGrantSetFromProto(assignment.GetInstallerLeaseGrants())
	if err != nil {
		return ExecutionBundleV1{}, err
	}
	return bindInstallerGrantSet(
		bundle, assignment.GetDeploymentId(), assignment.GetTaskId(), assignment.GetRecipeBundle().GetSha256(),
		assignment.GetLeaseEpoch(), assignment.GetLeaseExpiresAt().AsTime(), grants, now,
	)
}

func bindInstallerGrantSet(
	bundle ExecutionBundleV1,
	deploymentID string,
	taskID string,
	recipeSHA256 []byte,
	leaseEpoch int64,
	leaseExpiresAt time.Time,
	grants map[string]installer.SignedLeaseGrantV1,
	now time.Time,
) (ExecutionBundleV1, error) {
	bound := bundle
	bound.Actions = append([]ActionV1(nil), bundle.Actions...)
	used := make(map[string]struct{}, len(grants))
	for index, action := range bound.Actions {
		if action.Kind != installer.ActionExecute {
			continue
		}
		if action.Installer == nil || action.Installer.LeaseGrant != nil {
			return ExecutionBundleV1{}, ErrInvalidBundle
		}
		grant, found := grants[action.Installer.CommandID]
		if !found || installer.ValidateLeaseGrantAt(action.Installer.Delivery, grant, action.Installer.CommandID, now.UTC()) != nil {
			return ExecutionBundleV1{}, ErrInvalidBundle
		}
		if _, duplicate := used[action.Installer.CommandID]; duplicate {
			return ExecutionBundleV1{}, ErrInvalidBundle
		}
		used[action.Installer.CommandID] = struct{}{}
		binding := action.Installer.Delivery.Config.Binding
		if binding.DeploymentID != deploymentID || binding.TaskID != taskID ||
			binding.RecipeDigest != "sha256:"+hex.EncodeToString(recipeSHA256) {
			return ExecutionBundleV1{}, ErrInvalidBundle
		}
		grantValue := grant.Grant
		assignmentExpiry := leaseExpiresAt.UTC().Format(time.RFC3339Nano)
		if grantValue.LeaseEpoch != leaseEpoch || grantValue.ExpiresAt != assignmentExpiry {
			return ExecutionBundleV1{}, ErrInvalidBundle
		}
		input := *action.Installer
		grant = cloneInstallerLeaseGrant(grant)
		input.LeaseGrant = &grant
		bound.Actions[index].Installer = &input
	}
	if len(used) != len(grants) {
		return ExecutionBundleV1{}, ErrInvalidBundle
	}
	return bound, nil
}

func installerGrantSetFromProto(values []*agentv1.WorkerInstallerLeaseGrant) (map[string]installer.SignedLeaseGrantV1, error) {
	grants := make(map[string]installer.SignedLeaseGrantV1, len(values))
	for _, encoded := range values {
		grant, err := installerGrantFromProto(encoded)
		if err != nil {
			return nil, ErrInvalidBundle
		}
		if _, duplicate := grants[grant.Grant.CommandID]; duplicate {
			return nil, ErrInvalidBundle
		}
		grants[grant.Grant.CommandID] = grant
	}
	return grants, nil
}

func cloneInstallerLeaseGrant(value installer.SignedLeaseGrantV1) installer.SignedLeaseGrantV1 {
	value.Signature = append([]byte(nil), value.Signature...)
	return value
}

func (state *leaseState) initializeInstallerGrants(assignment *agentv1.WorkerAssignment) error {
	if state == nil || assignment == nil || assignment.GetLeaseEpoch() != state.epoch || assignment.GetLeaseExpiresAt() == nil ||
		assignment.GetLeaseExpiresAt().CheckValid() != nil {
		return ErrInvalidBundle
	}
	leaseExpiresAt := assignment.GetLeaseExpiresAt().AsTime().UTC()
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.replaceInstallerGrantsLocked(assignment.GetInstallerLeaseGrants(), state.epoch, leaseExpiresAt, true); err != nil {
		return err
	}
	state.leaseExpiresAt = leaseExpiresAt
	return nil
}

func (state *leaseState) replaceInstallerGrantsLocked(
	values []*agentv1.WorkerInstallerLeaseGrant,
	leaseEpoch int64,
	leaseExpiresAt time.Time,
	initialize bool,
) error {
	if state == nil || leaseEpoch < 1 || leaseExpiresAt.IsZero() {
		return ErrInvalidBundle
	}
	grants, err := installerGrantSetFromProto(values)
	if err != nil {
		return err
	}
	expiresAt := leaseExpiresAt.UTC().Format(time.RFC3339Nano)
	for _, grant := range grants {
		issuedAt, issuedErr := time.Parse(time.RFC3339Nano, grant.Grant.IssuedAt)
		grantExpiresAt, expiresErr := time.Parse(time.RFC3339Nano, grant.Grant.ExpiresAt)
		if issuedErr != nil || expiresErr != nil || !issuedAt.Before(grantExpiresAt) ||
			grant.Grant.LeaseEpoch != leaseEpoch || grant.Grant.ExpiresAt != expiresAt {
			return ErrInvalidBundle
		}
	}
	if initialize {
		state.installerCommands = make(map[string]struct{}, len(grants))
		for commandID := range grants {
			state.installerCommands[commandID] = struct{}{}
		}
	} else {
		if state.installerCommands == nil || len(grants) != len(state.installerCommands) {
			return ErrInvalidBundle
		}
		for commandID := range state.installerCommands {
			if _, found := grants[commandID]; !found {
				return ErrInvalidBundle
			}
		}
	}
	state.installerGrants = make(map[string]installer.SignedLeaseGrantV1, len(grants))
	for commandID, grant := range grants {
		state.installerGrants[commandID] = cloneInstallerLeaseGrant(grant)
	}
	return nil
}

func (state *leaseState) bindInstallerBundle(bundle ExecutionBundleV1, assignment *agentv1.WorkerAssignment, now func() time.Time) (ExecutionBundleV1, error) {
	if state == nil || assignment == nil || now == nil {
		return ExecutionBundleV1{}, ErrInvalidBundle
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return bindInstallerGrantSet(
		bundle, assignment.GetDeploymentId(), assignment.GetTaskId(), assignment.GetRecipeBundle().GetSha256(),
		state.epoch, state.leaseExpiresAt, state.installerGrants, now().UTC(),
	)
}

// bindCurrentInstallerAction reads and validates the current grant while the
// heartbeat state is locked. The returned action owns a copy, so a concurrent
// heartbeat can rotate the durable lease without mutating an in-flight request.
func (state *leaseState) bindCurrentInstallerAction(action ActionV1, now func() time.Time) (ActionV1, error) {
	if action.Kind != installer.ActionExecute {
		return action, nil
	}
	if state == nil || action.Installer == nil || action.Installer.LeaseGrant == nil || now == nil {
		return ActionV1{}, ErrInvalidBundle
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	validationTime := now().UTC()
	if !validationTime.Before(state.leaseExpiresAt) {
		return ActionV1{}, ErrInvalidBundle
	}
	grant, found := state.installerGrants[action.Installer.CommandID]
	if !found || grant.Grant.LeaseEpoch != state.epoch ||
		grant.Grant.ExpiresAt != state.leaseExpiresAt.UTC().Format(time.RFC3339Nano) ||
		installer.ValidateLeaseGrantAt(action.Installer.Delivery, grant, action.Installer.CommandID, validationTime) != nil {
		return ActionV1{}, ErrInvalidBundle
	}
	grant = cloneInstallerLeaseGrant(grant)
	input := *action.Installer
	input.LeaseGrant = &grant
	action.Installer = &input
	return action, nil
}

func installerGrantFromProto(value *agentv1.WorkerInstallerLeaseGrant) (installer.SignedLeaseGrantV1, error) {
	if value == nil || value.GetBinding() == nil || value.GetIssuedAt() == nil || value.GetExpiresAt() == nil ||
		value.GetIssuedAt().CheckValid() != nil || value.GetExpiresAt().CheckValid() != nil || len(value.GetSignature()) != ed25519.SignatureSize {
		return installer.SignedLeaseGrantV1{}, ErrInvalidBundle
	}
	binding := value.GetBinding()
	return installer.SignedLeaseGrantV1{
		Grant: installer.LeaseGrantV1{
			SchemaVersion: value.GetSchemaVersion(), TrustID: value.GetTrustId(),
			Binding: installer.BindingV1{
				AgentInstanceID: binding.GetAgentInstanceId(), DeploymentID: binding.GetDeploymentId(), TaskID: binding.GetTaskId(),
				PlanHash: binding.GetPlanHash(), ApprovalID: binding.GetApprovalId(), RecipeDigest: binding.GetRecipeDigest(),
			},
			PlanDigest: value.GetPlanDigest(), OperationID: value.GetOperationId(), CommandID: value.GetCommandId(),
			LeaseEpoch: value.GetLeaseEpoch(), IssuedAt: value.GetIssuedAt().AsTime().UTC().Format(time.RFC3339Nano),
			ExpiresAt: value.GetExpiresAt().AsTime().UTC().Format(time.RFC3339Nano),
		},
		SignerKeyID: value.GetSignerKeyId(), Signature: append([]byte(nil), value.GetSignature()...),
	}, nil
}

func installerCommand(delivery installer.DeliveryV1, commandID string) (installer.CommandV1, bool) {
	for _, command := range delivery.SignedPlan.Plan.Commands {
		if command.CommandID == commandID {
			return command, true
		}
	}
	return installer.CommandV1{}, false
}

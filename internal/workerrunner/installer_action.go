package workerrunner

import (
	"context"
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
	if handler == nil || handler.client == nil || handler.now == nil || action.Kind != installer.ActionExecute || action.Noop != nil || action.Installer == nil {
		return ErrInvalidBundle
	}
	if err := installer.ValidateLeaseGrantAt(action.Installer.Delivery, action.Installer.LeaseGrant, action.Installer.CommandID, handler.now().UTC()); err != nil {
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
	response, err := handler.client.Execute(ctx, action.Installer.Delivery, action.Installer.LeaseGrant, action.Installer.CommandID)
	if err != nil {
		return ActionResult{}, errors.Join(ErrInstallerAction, err)
	}
	if response.Action != installer.ActionExecute || response.CommandID != action.Installer.CommandID || response.Status != installer.StatusExecuted || response.ErrorCode != "" {
		return ActionResult{}, ErrInstallerAction
	}
	return ActionResult{Status: installer.StatusExecuted}, nil
}

func validateInstallerAssignment(bundle ExecutionBundleV1, assignment *agentv1.WorkerAssignment, now time.Time) error {
	for _, action := range bundle.Actions {
		if action.Kind != installer.ActionExecute {
			continue
		}
		if action.Installer == nil || assignment == nil || assignment.GetLeaseExpiresAt() == nil ||
			installer.ValidateLeaseGrantAt(action.Installer.Delivery, action.Installer.LeaseGrant, action.Installer.CommandID, now.UTC()) != nil {
			return ErrInvalidBundle
		}
		binding := action.Installer.Delivery.Config.Binding
		if binding.DeploymentID != assignment.GetDeploymentId() || binding.TaskID != assignment.GetTaskId() ||
			binding.RecipeDigest != "sha256:"+hex.EncodeToString(assignment.GetRecipeBundle().GetSha256()) {
			return ErrInvalidBundle
		}
		grant := action.Installer.LeaseGrant.Grant
		assignmentExpiry := assignment.GetLeaseExpiresAt().AsTime().UTC().Format(time.RFC3339Nano)
		if grant.LeaseEpoch != assignment.GetLeaseEpoch() || grant.ExpiresAt != assignmentExpiry {
			return ErrInvalidBundle
		}
	}
	return nil
}

func installerCommand(delivery installer.DeliveryV1, commandID string) (installer.CommandV1, bool) {
	for _, command := range delivery.SignedPlan.Plan.Commands {
		if command.CommandID == commandID {
			return command, true
		}
	}
	return installer.CommandV1{}, false
}

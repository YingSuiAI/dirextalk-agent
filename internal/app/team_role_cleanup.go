package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
)

type awsTeamRoleCleanup struct {
	lifecycles cloudexecution.LifecycleFactory
	secrets    *awsartifact.DeploymentSecretLifecycle
}

func newAWSTeamRoleCleanup(
	lifecycles cloudexecution.LifecycleFactory,
	secrets *awsartifact.DeploymentSecretLifecycle,
) (*awsTeamRoleCleanup, error) {
	if lifecycles == nil || secrets == nil {
		return nil, cloudapp.ErrInvalid
	}
	return &awsTeamRoleCleanup{
		lifecycles: lifecycles,
		secrets:    secrets,
	}, nil
}

func (cleanup *awsTeamRoleCleanup) DestroyRole(
	ctx context.Context,
	connection cloudapp.Connection,
	dispatch teamdispatch.Fact,
) (bool, error) {
	if cleanup == nil ||
		cleanup.lifecycles == nil ||
		cleanup.secrets == nil ||
		ctx == nil ||
		dispatch.Validate() != nil ||
		dispatch.Phase != teamdispatch.PhaseDestroying ||
		dispatch.Intent.OwnerID != connection.OwnerID {
		return false, cloudapp.ErrInvalid
	}
	lifecycle, err := cleanup.lifecycles.ForConnection(
		ctx,
		connection,
	)
	if err != nil {
		return false, err
	}
	_, scheduleErr := lifecycle.ScheduleDestroy(
		ctx,
		dispatch.Intent.DeploymentID,
		dispatch.Intent.OwnerID,
	)
	if errors.Is(scheduleErr, resource.ErrNotFound) {
		scheduleErr = nil
	}
	if scheduleErr != nil {
		scheduleErr = fmt.Errorf(
			"schedule Team role resource destruction: %w",
			scheduleErr,
		)
	}
	result, destroyErr := lifecycle.Destroy(
		ctx,
		resource.DestroyRequest{
			DeploymentID: dispatch.Intent.DeploymentID,
			OwnerID:      dispatch.Intent.OwnerID,
			ApprovalID:   dispatch.Intent.ApprovalID,
		},
	)
	if errors.Is(destroyErr, resource.ErrNotFound) {
		destroyErr = nil
	}
	if destroyErr != nil {
		destroyErr = fmt.Errorf(
			"execute Team role resource destruction: %w",
			destroyErr,
		)
	}
	var secretErr error
	if dispatch.PublishedEvidence != nil {
		secretErr = cleanup.secrets.DestroyPublished(
			ctx,
			connection,
			dispatch.Intent.OwnerID,
			dispatch.Intent.DeploymentID,
			dispatch.PublishedEvidence.InstallerSecrets,
		)
		if secretErr != nil {
			secretErr = fmt.Errorf(
				"destroy Team role published secrets: %w",
				secretErr,
			)
		}
	}
	joined := errors.Join(scheduleErr, destroyErr, secretErr)
	if joined != nil {
		return false, joined
	}
	if result.Blocked {
		return false, resource.ErrDestroyBlocked
	}
	for _, item := range result.Resources {
		if item.DeploymentID != dispatch.Intent.DeploymentID ||
			item.OwnerID != dispatch.Intent.OwnerID ||
			item.ApprovalID != dispatch.Intent.ApprovalID ||
			item.State != resource.StateVerifiedDestroyed {
			return false, resource.ErrDestroyBlocked
		}
	}
	return true, nil
}

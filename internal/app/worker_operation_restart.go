package app

import (
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

type currentReadyRootHelperReader interface {
	CurrentReadyRootHelper(context.Context, string, string) (helperkey.Record, error)
}

// workerOperationRestartPort is the production managed-preparation intent
// producer. It refuses to expose or create a privileged restart assignment
// unless the deployment currently has a ready root-helper signing key.
type workerOperationRestartPort struct {
	operations *workeroperation.Service
	helpers    currentReadyRootHelperReader
}

func newWorkerOperationRestartPort(operations *workeroperation.Service, helpers currentReadyRootHelperReader) (*workerOperationRestartPort, error) {
	if operations == nil || helpers == nil {
		return nil, workeroperation.ErrInvalid
	}
	return &workerOperationRestartPort{operations: operations, helpers: helpers}, nil
}

func (port *workerOperationRestartPort) EnsureRestart(ctx context.Context, operation serviceoperation.OperationV1,
	reference serviceoperation.RestartReferenceV1) (workeroperation.Operation, error) {
	if ctx == nil || operation.Challenge.Scope.Validate() != nil ||
		operation.Challenge.Scope.Restart != reference || reference.ExpectedInitialRevision != 1 {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	if err := port.requireReady(ctx, operation.Challenge.Scope.DeploymentID); err != nil {
		return workeroperation.Operation{}, err
	}
	current, err := port.operations.Get(ctx, reference.OperationID)
	if err == nil {
		if !sameRestartIntent(current, operation, reference) {
			return workeroperation.Operation{}, workeroperation.ErrIdempotencyConflict
		}
		return current, nil
	}
	if !errors.Is(err, workeroperation.ErrNotFound) {
		return workeroperation.Operation{}, err
	}
	namespace, err := uuid.Parse(reference.OperationID)
	if err != nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	created, err := port.operations.CreateRestart(ctx, workeroperation.CreateRestartRequest{
		OperationID: reference.OperationID, DeploymentID: operation.Challenge.Scope.DeploymentID,
		OwnerID: operation.Challenge.Scope.OwnerID, LifecycleRestartRef: reference.LifecycleRestartRef,
		ExecutionBundleDigest:           reference.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest: operation.Challenge.Scope.ExpectedInstalledManifestDigest,
		IdempotencyKey:                  uuid.NewSHA1(namespace, []byte("managed-preparation-restart-intent/v1")).String(),
	})
	if err != nil {
		// A lost create response or a competing exact producer is recovered by
		// authoritative readback; mismatched content remains a hard conflict.
		current, readErr := port.operations.Get(ctx, reference.OperationID)
		if readErr != nil {
			return workeroperation.Operation{}, err
		}
		if !sameRestartIntent(current, operation, reference) {
			return workeroperation.Operation{}, workeroperation.ErrIdempotencyConflict
		}
		return current, nil
	}
	return created, nil
}

func (port *workerOperationRestartPort) Get(ctx context.Context, operationID string) (workeroperation.Operation, error) {
	value, err := port.operations.Get(ctx, operationID)
	if err != nil {
		return workeroperation.Operation{}, err
	}
	if err := port.requireReady(ctx, value.DeploymentID); err != nil {
		return workeroperation.Operation{}, err
	}
	return value, nil
}

func (port *workerOperationRestartPort) requireReady(ctx context.Context, deploymentID string) error {
	value, err := port.helpers.CurrentReadyRootHelper(ctx, deploymentID, helperkey.DefaultHelperID)
	if err != nil {
		if errors.Is(err, helperkey.ErrNotFound) {
			return helperkey.ErrNotReady
		}
		return err
	}
	if value.State != helperkey.StateReady ||
		value.Binding.DeploymentID != deploymentID || value.Binding.HelperID != helperkey.DefaultHelperID {
		return helperkey.ErrNotReady
	}
	return nil
}

func sameRestartIntent(value workeroperation.Operation, operation serviceoperation.OperationV1,
	reference serviceoperation.RestartReferenceV1) bool {
	scope := operation.Challenge.Scope
	return value.OperationID == reference.OperationID && value.DeploymentID == scope.DeploymentID &&
		value.OwnerID == scope.OwnerID && value.Action == workeroperation.ActionRestart &&
		value.LifecycleRestartRef == reference.LifecycleRestartRef &&
		value.ExecutionBundleDigest == reference.ExecutionBundleDigest &&
		value.ExpectedInstalledManifestDigest == scope.ExpectedInstalledManifestDigest
}

var _ serviceoperation.RestartPort = (*workerOperationRestartPort)(nil)

package workeroperation

import (
	"context"

	"github.com/google/uuid"
)

// RootHelper exposes exactly one reviewed privileged capability. It receives
// no argv, environment, filesystem path, shell fragment, or provider control.
type RootHelper interface {
	Restart(context.Context, RestartCapability) (RootHelperReceipt, error)
}

type RestartCapability struct {
	OperationID                     string
	DeploymentID                    string
	OwnerID                         string
	LifecycleRestartRef             string
	ExecutionBundleDigest           string
	ExpectedInstalledManifestDigest string
	LeaseEpoch                      int64
}

type RunnerControl interface {
	Get(context.Context, string) (Operation, error)
	Claim(context.Context, ClaimRequest) (Assignment, error)
	Complete(context.Context, CompleteRequest) (Operation, error)
}

type Runner struct {
	Control RunnerControl
	Helper  RootHelper
}

func (runner Runner) RunRestart(ctx context.Context, request ClaimRequest) (Operation, error) {
	current, err := runner.Control.Get(ctx, request.OperationID)
	if err != nil {
		return Operation{}, err
	}
	if current.State == StateSucceeded || current.State == StateFailed {
		return current, nil
	}
	assignment, err := runner.Control.Claim(ctx, request)
	if err != nil {
		return Operation{}, err
	}
	receipt, err := runner.Helper.Restart(ctx, RestartCapability{
		OperationID: assignment.OperationID, DeploymentID: assignment.DeploymentID, OwnerID: assignment.OwnerID,
		LifecycleRestartRef: assignment.LifecycleRestartRef, ExecutionBundleDigest: assignment.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest: assignment.ExpectedInstalledManifestDigest,
		LeaseEpoch:                      assignment.LeaseEpoch,
	})
	if err != nil {
		return runner.Control.Complete(ctx, CompleteRequest{
			OperationID: assignment.OperationID, DeploymentID: assignment.DeploymentID, WorkerID: assignment.WorkerID,
			LeaseEpoch: assignment.LeaseEpoch, IdempotencyKey: uuid.NewSHA1(uuid.NameSpaceOID, []byte(assignment.OperationID+":failed")).String(),
			ExpectedRevision: assignment.Revision, FailureCode: "root_helper_failed",
		})
	}
	return runner.Control.Complete(ctx, CompleteRequest{
		OperationID: assignment.OperationID, DeploymentID: assignment.DeploymentID, WorkerID: assignment.WorkerID,
		LeaseEpoch: assignment.LeaseEpoch, IdempotencyKey: uuid.NewSHA1(uuid.NameSpaceOID, []byte(assignment.OperationID+":succeeded")).String(),
		ExpectedRevision: assignment.Revision, Receipt: receipt,
	})
}

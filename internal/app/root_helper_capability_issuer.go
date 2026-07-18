package app

import (
	"context"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
)

const rootHelperCapabilityLifetime = 5 * time.Minute
const rootHelperLifecycleTimeoutGrace = 30 * time.Second

type rootHelperWorkerDeploymentReader interface {
	Get(context.Context, string) (worker.Deployment, error)
}

type rootHelperCapabilityKeyReader interface {
	Get(context.Context, string) (helperkey.Record, error)
	CurrentReadyRootHelper(context.Context, string, string) (helperkey.Record, error)
}

type managedKnowledgeLifecycleExecutionFencer interface {
	FenceManagedKnowledgeLifecycleExecution(context.Context, workeroperation.Assignment, time.Time) error
}

// productionRootHelperCapabilityIssuer derives every short-lived privileged
// grant from the original immutable InstallerDelivery and live Agent-owned
// deployment/helper records. Neither a Worker nor a public caller can supply
// installer trust, helper trust, or installed-manifest expectations.
type productionRootHelperCapabilityIssuer struct {
	workers   rootHelperWorkerDeploymentReader
	helpers   rootHelperCapabilityKeyReader
	issuer    *installer.TrustIssuer
	lifecycle managedKnowledgeLifecycleExecutionFencer
	now       func() time.Time
}

func newProductionRootHelperCapabilityIssuer(workers rootHelperWorkerDeploymentReader,
	helpers rootHelperCapabilityKeyReader, issuer *installer.TrustIssuer,
	now func() time.Time, lifecycle ...managedKnowledgeLifecycleExecutionFencer) (*productionRootHelperCapabilityIssuer, error) {
	if workers == nil || helpers == nil || issuer == nil || now == nil {
		return nil, workeroperation.ErrInvalid
	}
	result := &productionRootHelperCapabilityIssuer{workers: workers, helpers: helpers, issuer: issuer, now: now}
	if len(lifecycle) > 0 {
		result.lifecycle = lifecycle[0]
	}
	return result, nil
}

func (value *productionRootHelperCapabilityIssuer) IssueBootstrapCapability(ctx context.Context,
	assignment worker.Assignment, returned helperkey.Record,
) (installer.DeliveryV1, installer.SignedRootHelperBootstrapCapabilityV1, error) {
	if value == nil || ctx == nil || returned.Validate() != nil ||
		returned.State == helperkey.StateReady || returned.State == helperkey.StateRevoked ||
		assignment.DeploymentID != returned.Binding.DeploymentID ||
		assignment.OwnerID != returned.Binding.OwnerID || assignment.WorkerID == "" {
		return installer.DeliveryV1{}, installer.SignedRootHelperBootstrapCapabilityV1{}, helperkey.ErrConflict
	}
	current, err := value.helpers.Get(ctx, returned.Binding.DeliveryID)
	if err != nil || !sameRootHelperRecord(current, returned) {
		return installer.DeliveryV1{}, installer.SignedRootHelperBootstrapCapabilityV1{}, helperkey.ErrConflict
	}
	deployment, delivery, err := value.authoritativeDelivery(ctx, assignment, current)
	if err != nil || deployment.WorkerID != assignment.WorkerID {
		return installer.DeliveryV1{}, installer.SignedRootHelperBootstrapCapabilityV1{}, helperkey.ErrConflict
	}
	now := value.now().UTC().Truncate(time.Microsecond)
	signed, err := value.issuer.IssueRootHelperBootstrapCapability(
		delivery, current.Binding, current.PublicKey, current.Nonce, current.Revision,
		now.Add(rootHelperCapabilityLifetime), now,
	)
	if err != nil {
		return installer.DeliveryV1{}, installer.SignedRootHelperBootstrapCapabilityV1{}, helperkey.ErrConflict
	}
	return delivery, signed, nil
}

func (value *productionRootHelperCapabilityIssuer) IssueRestartCapability(ctx context.Context,
	assignment worker.Assignment, operation workeroperation.Assignment,
) (installer.DeliveryV1, installer.SignedRootHelperRestartCapabilityV1, error) {
	if value == nil || ctx == nil || assignment.DeploymentID != operation.DeploymentID ||
		assignment.OwnerID != operation.OwnerID || assignment.WorkerID != operation.WorkerID ||
		!operation.Action.Valid() || operation.LeaseEpoch < 1 ||
		operation.LeaseExpiresAt.IsZero() {
		return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, workeroperation.ErrInvalid
	}
	helper, err := value.helpers.CurrentReadyRootHelper(ctx, operation.DeploymentID, helperkey.DefaultHelperID)
	if err != nil || helper.Validate() != nil || helper.State != helperkey.StateReady {
		return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, workeroperation.ErrInvalid
	}
	deployment, delivery, err := value.authoritativeDelivery(ctx, assignment, helper)
	if err != nil || deployment.WorkerID != operation.WorkerID ||
		"sha256:"+hex.EncodeToString(deployment.ExecutionBundle.SHA256[:]) != operation.ExecutionBundleDigest {
		return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, workeroperation.ErrInvalid
	}
	manifestDigest, err := canonical.Digest(delivery.ArtifactManifest.Manifest)
	if err != nil || manifestDigest != operation.ExpectedInstalledManifestDigest {
		return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, workeroperation.ErrInvalid
	}
	now := value.now().UTC().Truncate(time.Microsecond)
	if operation.Action != workeroperation.ActionRestart {
		if value.lifecycle == nil || deployment.Revision != operation.ExpectedDeploymentRevision ||
			value.lifecycle.FenceManagedKnowledgeLifecycleExecution(ctx, operation, now) != nil {
			return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, workeroperation.ErrRevisionConflict
		}
	}
	commandTimeout, found := declaredRootHelperCommandTimeout(delivery, operation.LifecycleRestartRef)
	if !found {
		return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, workeroperation.ErrInvalid
	}
	expiresAt := now.Add(commandTimeout + rootHelperLifecycleTimeoutGrace)
	if !expiresAt.Before(operation.LeaseExpiresAt) && !expiresAt.Equal(operation.LeaseExpiresAt) {
		return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, workeroperation.ErrLeaseExpired
	}
	signed, err := value.issuer.IssueRootHelperRestartCapability(delivery, helper.Binding, installer.RootHelperRestartGrantV1{
		OperationID: operation.OperationID, DeploymentID: operation.DeploymentID, OwnerID: operation.OwnerID,
		Action:              string(operation.Action),
		LifecycleRestartRef: operation.LifecycleRestartRef, ExecutionBundleDigest: operation.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest:  operation.ExpectedInstalledManifestDigest,
		ExpectedDeploymentRevision:       operation.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   operation.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: operation.ExpectedKnowledgeBindingRevision,
		WorkerLeaseEpoch:                 operation.LeaseEpoch, LeaseExpiresAt: expiresAt,
	}, now)
	if err != nil {
		return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, workeroperation.ErrInvalid
	}
	return delivery, signed, nil
}

func declaredRootHelperCommandTimeout(delivery installer.DeliveryV1, commandID string) (time.Duration, bool) {
	for _, command := range delivery.SignedPlan.Plan.Commands {
		if command.CommandID == commandID && command.TimeoutSeconds > 0 {
			return time.Duration(command.TimeoutSeconds) * time.Second, true
		}
	}
	return 0, false
}

func (value *productionRootHelperCapabilityIssuer) authoritativeDelivery(ctx context.Context,
	assignment worker.Assignment, helper helperkey.Record,
) (worker.Deployment, installer.DeliveryV1, error) {
	deployment, err := value.workers.Get(ctx, assignment.DeploymentID)
	if err != nil || deployment.DeploymentID != assignment.DeploymentID ||
		deployment.OwnerID != assignment.OwnerID || deployment.WorkerID != assignment.WorkerID ||
		deployment.InstallerDelivery == nil || installer.ValidateDeliveryTrust(*deployment.InstallerDelivery) != nil {
		return worker.Deployment{}, installer.DeliveryV1{}, workeroperation.ErrInvalid
	}
	delivery := *deployment.InstallerDelivery
	if delivery.Config.Binding.DeploymentID != deployment.DeploymentID ||
		helper.Binding.DeploymentID != deployment.DeploymentID || helper.Binding.OwnerID != deployment.OwnerID ||
		helper.Binding.AgentInstanceID != delivery.Config.Binding.AgentInstanceID ||
		helper.Binding.InstanceID != deployment.ProviderInstanceID {
		return worker.Deployment{}, installer.DeliveryV1{}, workeroperation.ErrInvalid
	}
	return deployment, delivery, nil
}

func sameRootHelperRecord(left, right helperkey.Record) bool {
	return reflect.DeepEqual(left, right)
}

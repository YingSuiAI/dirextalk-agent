package app

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairingworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
)

func (value *productionRootHelperCapabilityIssuer) IssuePairingCapability(ctx context.Context,
	assignment worker.Assignment, operation pairingworker.Operation,
) (installer.DeliveryV1, installer.SignedRootHelperPairingCapabilityV1, []byte, error) {
	if value == nil || ctx == nil || operation.Validate() != nil || operation.State != pairingworker.StateLeased ||
		assignment.DeploymentID != operation.DeploymentID || assignment.OwnerID != operation.OwnerID ||
		assignment.TaskID != operation.TaskID || assignment.StepID != operation.StepID ||
		assignment.WorkerID != operation.WorkerID || operation.LeaseEpoch < 1 || operation.LeaseExpiresAt.IsZero() {
		return installer.DeliveryV1{}, installer.SignedRootHelperPairingCapabilityV1{}, nil, pairingworker.ErrInvalid
	}
	helper, err := value.helpers.CurrentReadyRootHelper(ctx, operation.DeploymentID, helperkey.DefaultHelperID)
	if err != nil || helper.Validate() != nil || helper.State != helperkey.StateReady {
		return installer.DeliveryV1{}, installer.SignedRootHelperPairingCapabilityV1{}, nil, pairingworker.ErrInvalid
	}
	deployment, delivery, err := value.authoritativeDelivery(ctx, assignment, helper)
	if err != nil || deployment.WorkerID != operation.WorkerID || deployment.TaskID != operation.TaskID ||
		deployment.StepID != operation.StepID || deployment.OwnerID != operation.OwnerID || deployment.Revision != operation.DeploymentRevision {
		return installer.DeliveryV1{}, installer.SignedRootHelperPairingCapabilityV1{}, nil, pairingworker.ErrInvalid
	}
	manifestDigest, err := canonical.Digest(delivery.ArtifactManifest.Manifest)
	if err != nil || manifestDigest != operation.ExecutionManifestDigest {
		return installer.DeliveryV1{}, installer.SignedRootHelperPairingCapabilityV1{}, nil, pairingworker.ErrInvalid
	}
	executionDigest := "sha256:" + hex.EncodeToString(deployment.ExecutionBundle.SHA256[:])
	now := value.now().UTC().Truncate(time.Microsecond)
	if operation.ExecutionEpoch < 1 || operation.PairingExpiresAt.IsZero() || !now.Before(operation.PairingExpiresAt) {
		return installer.DeliveryV1{}, installer.SignedRootHelperPairingCapabilityV1{}, nil, pairingworker.ErrInvalid
	}
	expiresAt := now.Add(rootHelperCapabilityLifetime)
	if operation.LeaseExpiresAt.Before(expiresAt) {
		expiresAt = operation.LeaseExpiresAt
	}
	if operation.PairingExpiresAt.Before(expiresAt) {
		expiresAt = operation.PairingExpiresAt
	}
	if !now.Before(expiresAt) {
		return installer.DeliveryV1{}, installer.SignedRootHelperPairingCapabilityV1{}, nil, pairingworker.ErrInvalid
	}
	kind := installer.RootHelperOperationPairingBegin
	if operation.Action == pairingworker.ActionResume {
		kind = installer.RootHelperOperationPairingResume
	}
	signed, err := value.issuer.IssueRootHelperPairingCapability(delivery, helper.Binding, kind, installer.RootHelperPairingGrantV1{
		OperationID: operation.OperationID, SessionID: operation.SessionID, TaskID: operation.TaskID, StepID: operation.StepID,
		DeploymentID: operation.DeploymentID, OwnerID: operation.OwnerID, RecipeID: operation.RecipeID,
		RecipeDigest: operation.RecipeDigest, RecipeRevision: operation.RecipeRevision,
		PayloadScopeRevision: operation.PayloadScopeRevision, RecipientPublicKeyDigest: operation.RecipientPublicKeyDigest,
		ExecutionEpoch: operation.ExecutionEpoch, PairingExpiresAt: operation.PairingExpiresAt,
		CommandID:             operation.CommandID,
		ExecutionBundleDigest: executionDigest, ExpectedInstalledManifestDigest: manifestDigest,
		WorkerLeaseEpoch: operation.LeaseEpoch, LeaseExpiresAt: expiresAt,
	}, now)
	if err != nil {
		return installer.DeliveryV1{}, installer.SignedRootHelperPairingCapabilityV1{}, nil, pairingworker.ErrInvalid
	}
	return delivery, signed, append([]byte(nil), helper.PublicKey...), nil
}

type pairingWorkerReceiptVerifier struct {
	keys workeroperation.CurrentReadyPublicKeyStore
}

func (verifier pairingWorkerReceiptVerifier) VerifyPairingBegin(ctx context.Context, value roothelper.PairingBeginReceiptV1) error {
	if verifier.keys == nil {
		return pairingworker.ErrInvalid
	}
	key, err := verifier.keys.CurrentReadyPublicKey(ctx, value.DeploymentID, helperkey.DefaultHelperID, value.SignerKeyID)
	if err != nil || roothelper.VerifyPairingBeginReceiptSignature(value, key) != nil {
		return pairingworker.ErrInvalid
	}
	return nil
}

func (verifier pairingWorkerReceiptVerifier) VerifyPairingResume(ctx context.Context, value roothelper.PairingResumeReceiptV1) error {
	if verifier.keys == nil {
		return pairingworker.ErrInvalid
	}
	key, err := verifier.keys.CurrentReadyPublicKey(ctx, value.DeploymentID, helperkey.DefaultHelperID, value.SignerKeyID)
	if err != nil || roothelper.VerifyPairingResumeReceiptSignature(value, key) != nil {
		return pairingworker.ErrInvalid
	}
	return nil
}

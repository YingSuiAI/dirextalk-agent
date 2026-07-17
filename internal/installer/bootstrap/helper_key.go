package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

func ValidateRootHelperKeySource(source RootHelperKeySourceV1, deploymentID string, identity InstanceIdentityV1) error {
	binding := helperKeyBinding(source)
	if source.SchemaVersion != helperkey.SchemaV1 || source.DeploymentID != deploymentID ||
		source.InstanceID != identity.InstanceID || source.TargetPath != helperkey.SecretTarget ||
		source.FileMode != helperkey.SecretMode || source.OwnerUID != 0 || source.OwnerGID != 0 ||
		len(source.PublicKey) != ed25519.PublicKeySize || len(source.Nonce) != 32 ||
		helperkey.ValidateBinding(binding, source.PublicKey) != nil {
		return ErrTrustMismatch
	}
	return nil
}

type HelperKeySecretAccess interface {
	ReadRootHelperKey(context.Context, RootHelperKeySourceV1) ([]byte, error)
	CanaryRootHelperKey(context.Context, RootHelperKeySourceV1) error
}

type HelperKeyControl interface {
	SubmitRootHelperProof(context.Context, helperkey.ProofRequest, []byte) (helperkey.Record, error)
	ReconcileRootHelperRevocation(context.Context, string, string) (helperkey.Record, error)
	ConfirmRootHelperCanary(context.Context, helperkey.CanaryRequest) (helperkey.Record, error)
}

type PrincipalIdentity interface {
	CurrentPrincipal(context.Context) (string, error)
}

type RootHelperKeyBootstrap struct {
	secrets  HelperKeySecretAccess
	files    SecretMaterializer
	control  HelperKeyControl
	identity PrincipalIdentity
	now      func() time.Time
	wait     func(context.Context, time.Duration) error
}

func NewRootHelperKeyBootstrap(secrets HelperKeySecretAccess, files SecretMaterializer, control HelperKeyControl, identity PrincipalIdentity, now func() time.Time) (*RootHelperKeyBootstrap, error) {
	if secrets == nil || files == nil || control == nil || identity == nil || now == nil {
		return nil, ErrInvalidInput
	}
	return &RootHelperKeyBootstrap{secrets: secrets, files: files, control: control, identity: identity, now: now,
		wait: func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}}, nil
}

func (b *RootHelperKeyBootstrap) Bootstrap(ctx context.Context, source RootHelperKeySourceV1) error {
	principal, err := b.identity.CurrentPrincipal(ctx)
	if err != nil || principal != source.WorkerPrincipalID {
		return ErrMaterialize
	}
	privateKey, err := b.secrets.ReadRootHelperKey(ctx, source)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey[32:], source.PublicKey) {
		clear(privateKey)
		return ErrMaterialize
	}
	defer clear(privateKey)
	if _, err := b.files.ReplaceSecret(ctx, SecretFileSpec{
		Path: helperkey.SecretTarget, Mode: 0o400, UID: 0, GID: 0, VersionID: source.VersionID,
	}, privateKey); err != nil {
		return ErrMaterialize
	}
	binding := helperKeyBinding(source)
	proofPayload, err := helperkey.PossessionPayload(binding, source.Nonce)
	if err != nil {
		return ErrMaterialize
	}
	proof, err := b.control.SubmitRootHelperProof(ctx, helperkey.ProofRequest{
		DeliveryID: source.DeliveryID, InstanceID: source.InstanceID, PrincipalID: principal,
		IdempotencyKey: deterministicKey(source.DeliveryID, "proof"), Signature: ed25519.Sign(privateKey, proofPayload),
	}, source.Nonce)
	if err != nil || (proof.State != helperkey.StateProof && proof.State != helperkey.StateRevoking &&
		proof.State != helperkey.StateVerifiedRevoked && proof.State != helperkey.StateReady) {
		return ErrMaterialize
	}
	var revoked helperkey.Record
	for attempt := 0; attempt < 8; attempt++ {
		revoked, err = b.control.ReconcileRootHelperRevocation(ctx, source.DeliveryID, deterministicKey(source.DeliveryID, "revoke"))
		if err == nil && (revoked.State == helperkey.StateVerifiedRevoked || revoked.State == helperkey.StateReady) {
			break
		}
		if attempt == 7 || b.wait(ctx, 250*time.Millisecond) != nil {
			return ErrMaterialize
		}
	}
	if revoked.State != helperkey.StateVerifiedRevoked && revoked.State != helperkey.StateReady {
		return ErrMaterialize
	}
	if err := b.secrets.CanaryRootHelperKey(ctx, source); !accessDenied(err) {
		return ErrMaterialize
	}
	observedAt := b.now().UTC()
	canaryPayload, err := helperkey.CanaryPayload(binding, observedAt)
	if err != nil {
		return ErrMaterialize
	}
	ready, err := b.control.ConfirmRootHelperCanary(ctx, helperkey.CanaryRequest{
		DeliveryID: source.DeliveryID, InstanceID: source.InstanceID, PrincipalID: principal,
		ErrorCode: "AccessDeniedException", ObservedAt: observedAt,
		IdempotencyKey: deterministicKey(source.DeliveryID, "canary"), Signature: ed25519.Sign(privateKey, canaryPayload),
	})
	if err != nil || ready.State != helperkey.StateReady {
		return ErrMaterialize
	}
	return nil
}

func helperKeyBinding(source RootHelperKeySourceV1) helperkey.DeviceBinding {
	return helperkey.DeviceBinding{
		SchemaVersion: source.SchemaVersion, AgentInstanceID: source.AgentInstanceID, OwnerID: source.OwnerID,
		DeliveryID: source.DeliveryID, DeploymentID: source.DeploymentID, BindingRevision: source.BindingRevision,
		InstanceID: source.InstanceID, WorkerRoleARN: source.WorkerRoleARN, WorkerPrincipalID: source.WorkerPrincipalID,
		HelperID: source.HelperID, SignerKeyID: source.SignerKeyID, PublicKeyDigest: source.PublicKeyDigest,
		SecretPlan: helperkey.SecretPlan{
			Partition: source.SecretPartition, AccountID: source.SecretAccountID, Region: source.SecretRegion,
			Name: source.SecretName, VersionID: source.VersionID, KMSKeyARN: source.KMSKeyARN,
			TargetPath: source.TargetPath, FileMode: source.FileMode,
		},
		Secret:      helperkey.SecretCoordinate{ARN: source.SecretARN, Name: source.SecretName, VersionID: source.VersionID, KMSKeyARN: source.KMSKeyARN},
		NonceDigest: source.NonceDigest,
	}
}

func accessDenied(err error) bool {
	var apiErr smithy.APIError
	return err != nil && errors.As(err, &apiErr) &&
		(apiErr.ErrorCode() == "AccessDeniedException" || apiErr.ErrorCode() == "AccessDenied")
}

func deterministicKey(deliveryID, operation string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(deliveryID+"\x00"+operation)).String()
}

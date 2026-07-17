// Package roothelper implements the typed privileged boundary hosted by the
// root-owned local installer daemon. It deliberately contains no public RPC
// or Worker-controlled process fields.
package roothelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
)

var (
	ErrInvalid      = errors.New("root helper request is invalid")
	ErrUnauthorized = errors.New("root helper capability is unauthorized")
	ErrUnavailable  = errors.New("root helper dependency is unavailable")
	ErrNotReady     = errors.New("root helper signing key is not ready")
)

const accessDeniedCode = "AccessDeniedException"

// SecretAccess must read and canary the exact coordinate in DeviceBinding.
// Implementations must not accept a separate ARN, name, region, or version.
type SecretAccess interface {
	ReadRootHelperKey(context.Context, helperkey.DeviceBinding) ([]byte, error)
	CanaryRootHelperKey(context.Context, helperkey.DeviceBinding) error
}

// SigningKeyStore owns the fixed
// /etc/dirextalk-root-helper/signing.key, mode 0400, uid/gid 0 boundary.
// It accepts no path or file metadata from callers.
type SigningKeyStore interface {
	ReplaceRootHelperSigningKey(context.Context, []byte) error
	ReadRootHelperSigningKey(context.Context) ([]byte, error)
}

// Observer independently calculates local state. Neither digest can be
// supplied by the Worker or by the command runner.
type Observer interface {
	InstalledManifestDigest(context.Context, installer.DeliveryV1) (string, error)
	RestartObservationDigest(context.Context, installer.DeliveryV1, installer.CommandV1) (string, error)
}

type PossessionProof struct {
	CapabilityID string `json:"capability_id"`
	DeliveryID   string `json:"delivery_id"`
	DeploymentID string `json:"deployment_id"`
	InstanceID   string `json:"instance_id"`
	PrincipalID  string `json:"principal_id"`
	Signature    []byte `json:"signature"`
}

type CanaryProof struct {
	CapabilityID string    `json:"capability_id"`
	DeliveryID   string    `json:"delivery_id"`
	DeploymentID string    `json:"deployment_id"`
	InstanceID   string    `json:"instance_id"`
	PrincipalID  string    `json:"principal_id"`
	ErrorCode    string    `json:"error_code"`
	ObservedAt   time.Time `json:"observed_at"`
	Signature    []byte    `json:"signature"`
}

type Handler struct {
	delivery       installer.DeliveryV1
	secrets        SecretAccess
	keys           SigningKeyStore
	runner         installer.CommandRunner
	observer       Observer
	journal        RestartJournal
	pairingJournal PairingJournal
	pairingRunner  PairingCommandRunner
	fence          DeliveryFence
	now            func() time.Time

	mu          sync.Mutex
	possessions map[string]cachedPossession
	canaries    map[string]cachedCanary
	restarts    map[string]cachedRestart
}

type cachedPossession struct {
	digest string
	value  PossessionProof
}

type cachedCanary struct {
	digest string
	value  CanaryProof
}

type cachedRestart struct {
	digest string
	value  workeroperation.RootHelperReceipt
}

func New(
	delivery installer.DeliveryV1,
	secrets SecretAccess,
	keys SigningKeyStore,
	runner installer.CommandRunner,
	observer Observer,
	journal RestartJournal,
	fence DeliveryFence,
	now func() time.Time,
) (*Handler, error) {
	if secrets == nil || keys == nil || runner == nil || observer == nil || journal == nil || fence == nil || now == nil ||
		installer.ValidateDeliveryTrust(delivery) != nil {
		return nil, ErrInvalid
	}
	var pairingJournal PairingJournal = newMemoryPairingJournal()
	if fileJournal, ok := journal.(*FileRestartJournal); ok {
		var err error
		pairingJournal, err = openPairingJournal(
			fileJournal.path+".pairing", fileJournal.requireRootOwnership, fileJournal.parentSync,
		)
		if err != nil {
			return nil, err
		}
	}
	return &Handler{
		delivery: delivery, secrets: secrets, keys: keys, runner: runner, observer: observer,
		journal: journal, pairingJournal: pairingJournal, pairingRunner: OSPairingCommandRunner{},
		fence: fence, now: now,
		possessions: make(map[string]cachedPossession), canaries: make(map[string]cachedCanary),
		restarts: make(map[string]cachedRestart),
	}, nil
}

func (handler *Handler) Bootstrap(ctx context.Context, signed installer.SignedRootHelperBootstrapCapabilityV1) (PossessionProof, error) {
	if handler == nil || ctx == nil || installer.ValidateRootHelperBootstrapCapabilityAt(handler.delivery, signed, handler.now().UTC()) != nil {
		return PossessionProof{}, ErrUnauthorized
	}
	digest, err := canonical.Digest(signed)
	if err != nil {
		return PossessionProof{}, ErrInvalid
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	fence := deliveryFenceValue(signed)
	if err := handler.fence.Accept(ctx, fence); err != nil {
		return PossessionProof{}, err
	}
	if cached, found := handler.possessions[signed.Capability.CapabilityID]; found {
		if cached.digest != digest {
			return PossessionProof{}, ErrUnauthorized
		}
		return clonePossession(cached.value), nil
	}
	privateKey, err := handler.secrets.ReadRootHelperKey(ctx, signed.Capability.HelperBinding)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey[ed25519.PublicKeySize:], signed.Capability.HelperPublicKey) {
		clear(privateKey)
		return PossessionProof{}, ErrUnavailable
	}
	defer clear(privateKey)
	if err := handler.keys.ReplaceRootHelperSigningKey(ctx, privateKey); err != nil {
		return PossessionProof{}, ErrUnavailable
	}
	payload, err := helperkey.PossessionPayload(signed.Capability.HelperBinding, signed.Capability.Nonce)
	if err != nil {
		return PossessionProof{}, ErrInvalid
	}
	defer clear(payload)
	binding := signed.Capability.HelperBinding
	proof := PossessionProof{
		CapabilityID: signed.Capability.CapabilityID, DeliveryID: binding.DeliveryID,
		DeploymentID: binding.DeploymentID, InstanceID: binding.InstanceID,
		PrincipalID: binding.WorkerPrincipalID, Signature: ed25519.Sign(privateKey, payload),
	}
	handler.possessions[signed.Capability.CapabilityID] = cachedPossession{digest: digest, value: clonePossession(proof)}
	return proof, nil
}

func (handler *Handler) Canary(ctx context.Context, signed installer.SignedRootHelperBootstrapCapabilityV1) (CanaryProof, error) {
	if handler == nil || ctx == nil || installer.ValidateRootHelperBootstrapCapabilityAt(handler.delivery, signed, handler.now().UTC()) != nil {
		return CanaryProof{}, ErrUnauthorized
	}
	digest, err := canonical.Digest(signed)
	if err != nil {
		return CanaryProof{}, ErrInvalid
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if err := handler.fence.Match(ctx, deliveryFenceValue(signed)); err != nil {
		return CanaryProof{}, err
	}
	if cached, found := handler.canaries[signed.Capability.CapabilityID]; found {
		if cached.digest != digest {
			return CanaryProof{}, ErrUnauthorized
		}
		return cloneCanary(cached.value), nil
	}
	binding := signed.Capability.HelperBinding
	if err := handler.secrets.CanaryRootHelperKey(ctx, binding); !isAccessDenied(err) {
		return CanaryProof{}, ErrUnavailable
	}
	privateKey, err := handler.keys.ReadRootHelperSigningKey(ctx)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey[ed25519.PublicKeySize:], signed.Capability.HelperPublicKey) {
		clear(privateKey)
		return CanaryProof{}, ErrNotReady
	}
	defer clear(privateKey)
	observedAt := handler.now().UTC()
	payload, err := helperkey.CanaryPayload(binding, observedAt)
	if err != nil {
		return CanaryProof{}, ErrInvalid
	}
	defer clear(payload)
	proof := CanaryProof{
		CapabilityID: signed.Capability.CapabilityID, DeliveryID: binding.DeliveryID,
		DeploymentID: binding.DeploymentID, InstanceID: binding.InstanceID,
		PrincipalID: binding.WorkerPrincipalID, ErrorCode: accessDeniedCode, ObservedAt: observedAt,
		Signature: ed25519.Sign(privateKey, payload),
	}
	handler.canaries[signed.Capability.CapabilityID] = cachedCanary{digest: digest, value: cloneCanary(proof)}
	return proof, nil
}

func (handler *Handler) Restart(ctx context.Context, signed installer.SignedRootHelperRestartCapabilityV1) (workeroperation.RootHelperReceipt, error) {
	if handler == nil || ctx == nil || installer.ValidateRootHelperRestartCapabilityAt(handler.delivery, signed, handler.now().UTC()) != nil {
		return workeroperation.RootHelperReceipt{}, ErrUnauthorized
	}
	digest, err := restartJournalDigest(signed.Capability)
	if err != nil {
		return workeroperation.RootHelperReceipt{}, ErrInvalid
	}
	journalID := signed.Capability.OperationID
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if cached, found := handler.restarts[journalID]; found {
		if cached.digest != digest {
			return workeroperation.RootHelperReceipt{}, ErrUnauthorized
		}
		return cloneReceipt(cached.value), nil
	}
	capability := signed.Capability
	privateKey, err := handler.keys.ReadRootHelperSigningKey(ctx)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize ||
		publicKeyDigest(privateKey[ed25519.PublicKeySize:]) != capability.HelperPublicKeyDigest {
		clear(privateKey)
		return workeroperation.RootHelperReceipt{}, ErrNotReady
	}
	defer clear(privateKey)
	command, found := declaredCommand(handler.delivery, capability.LifecycleRestartRef)
	if !found {
		return workeroperation.RootHelperReceipt{}, ErrUnauthorized
	}
	installedDigest, err := handler.observer.InstalledManifestDigest(ctx, handler.delivery)
	if err != nil || installedDigest != capability.ExpectedInstalledManifestDigest {
		return workeroperation.RootHelperReceipt{}, ErrUnavailable
	}
	if replayed, found, err := handler.journal.Begin(journalID, digest); err != nil {
		return workeroperation.RootHelperReceipt{}, err
	} else if found {
		if validateRestartReceipt(replayed, capability, ed25519.PublicKey(privateKey[ed25519.PublicKeySize:])) != nil {
			return workeroperation.RootHelperReceipt{}, ErrUnauthorized
		}
		handler.restarts[journalID] = cachedRestart{digest: digest, value: cloneReceipt(replayed)}
		return replayed, nil
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, capability.ExpiresAt)
	if err != nil {
		return workeroperation.RootHelperReceipt{}, ErrInvalid
	}
	remaining := expiresAt.Sub(handler.now().UTC())
	timeout := time.Duration(command.TimeoutSeconds) * time.Second
	if remaining <= 0 {
		return workeroperation.RootHelperReceipt{}, ErrUnauthorized
	}
	if timeout > remaining {
		timeout = remaining
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	runErr := handler.runner.Run(runCtx, installer.CommandExecution{
		Argv: append([]string(nil), command.Argv...), WorkingDirectory: command.WorkingDirectory,
		Environment: []string{installer.SafePathEnvironment}, Timeout: timeout,
	})
	cancel()
	if runErr != nil {
		return workeroperation.RootHelperReceipt{}, ErrUnavailable
	}
	observationDigest, err := handler.observer.RestartObservationDigest(ctx, handler.delivery, command)
	if err != nil {
		return workeroperation.RootHelperReceipt{}, ErrUnavailable
	}
	receipt, err := workeroperation.SignReceipt(workeroperation.RootHelperReceipt{
		SchemaVersion: workeroperation.SchemaV1, OperationID: capability.OperationID,
		DeploymentID: capability.DeploymentID, OwnerID: capability.OwnerID,
		Action: workeroperation.ActionRestart, LifecycleRestartRef: capability.LifecycleRestartRef,
		ExecutionBundleDigest: capability.ExecutionBundleDigest, LeaseEpoch: capability.WorkerLeaseEpoch,
		InstallManifestDigest: installedDigest, RestartObservationDigest: observationDigest,
		ObservedAt: handler.now().UTC(), HelperID: capability.HelperID, SignerKeyID: capability.HelperSignerKeyID,
	}, privateKey)
	if err != nil {
		return workeroperation.RootHelperReceipt{}, ErrInvalid
	}
	if validateRestartReceipt(receipt, capability, ed25519.PublicKey(privateKey[ed25519.PublicKeySize:])) != nil {
		return workeroperation.RootHelperReceipt{}, fmt.Errorf("%w: invalid root receipt", ErrUnavailable)
	}
	if err := handler.journal.Complete(journalID, digest, receipt); err != nil {
		return workeroperation.RootHelperReceipt{}, err
	}
	handler.restarts[journalID] = cachedRestart{digest: digest, value: cloneReceipt(receipt)}
	return receipt, nil
}

// restartJournalDigest intentionally excludes capability freshness fields.
// A response-lost AcquireNext may reissue a fresh signed capability for the
// same still-leased operation; that must replay the terminal receipt rather
// than execute the command again. Lease epoch and every execution binding
// remain included, so a newly leased attempt fails closed.
func restartJournalDigest(value installer.RootHelperRestartCapabilityV1) (string, error) {
	value.CapabilityID = ""
	value.IssuedAt = ""
	value.ExpiresAt = ""
	return canonical.Digest(value)
}

func declaredCommand(delivery installer.DeliveryV1, commandID string) (installer.CommandV1, bool) {
	for _, command := range delivery.SignedPlan.Plan.Commands {
		if command.CommandID == commandID {
			command.Argv = append([]string(nil), command.Argv...)
			command.ArtifactRefs = append([]string(nil), command.ArtifactRefs...)
			command.VolumeRefs = append([]string(nil), command.VolumeRefs...)
			command.SecretRefs = append([]string(nil), command.SecretRefs...)
			return command, true
		}
	}
	return installer.CommandV1{}, false
}

type codedError interface{ ErrorCode() string }

func isAccessDenied(err error) bool {
	var coded codedError
	return err != nil && errors.As(err, &coded) &&
		(coded.ErrorCode() == "AccessDeniedException" || coded.ErrorCode() == "AccessDenied")
}

func clonePossession(value PossessionProof) PossessionProof {
	value.Signature = bytes.Clone(value.Signature)
	return value
}

func cloneCanary(value CanaryProof) CanaryProof {
	value.Signature = bytes.Clone(value.Signature)
	return value
}

func cloneReceipt(value workeroperation.RootHelperReceipt) workeroperation.RootHelperReceipt {
	value.Signature = bytes.Clone(value.Signature)
	return value
}

func publicKeyDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func deliveryFenceValue(signed installer.SignedRootHelperBootstrapCapabilityV1) DeliveryFenceValue {
	return DeliveryFenceValue{
		SchemaVersion:   DeliveryFenceSchemaV1,
		DeploymentID:    signed.Capability.HelperBinding.DeploymentID,
		DeliveryID:      signed.Capability.HelperBinding.DeliveryID,
		BindingRevision: signed.Capability.HelperBinding.BindingRevision,
		PublicKeyDigest: signed.Capability.HelperBinding.PublicKeyDigest,
	}
}

func validateRestartReceipt(receipt workeroperation.RootHelperReceipt, capability installer.RootHelperRestartCapabilityV1, publicKey ed25519.PublicKey) error {
	if err := receipt.ValidateFor(workeroperation.Operation{
		OperationID: capability.OperationID, DeploymentID: capability.DeploymentID, OwnerID: capability.OwnerID,
		Action: workeroperation.ActionRestart, LifecycleRestartRef: capability.LifecycleRestartRef,
		ExecutionBundleDigest:           capability.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest: capability.ExpectedInstalledManifestDigest,
		LeaseEpoch:                      capability.WorkerLeaseEpoch,
	}); err != nil {
		return err
	}
	return (workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{
		capability.HelperSignerKeyID: publicKey,
	}}).Verify(context.Background(), receipt)
}

func (proof PossessionProof) String() string {
	return fmt.Sprintf("root-helper possession proof %s", proof.CapabilityID)
}

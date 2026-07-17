package roothelper

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os/exec"
	"path"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
)

const (
	PairingBeginReceiptSchemaV1  = "dirextalk.agent.root-helper-pairing-begin-receipt/v1"
	PairingResumeReceiptSchemaV1 = "dirextalk.agent.root-helper-pairing-resume-receipt/v1"
	pairingAADSchemaV1           = "dirextalk.agent.root-helper-pairing-payload-aad/v1"
	maxPairingPayloadBytes       = 64 << 10
)

// PairingBeginReceiptV1 carries only an encrypted payload and its exact
// binding. Plaintext never crosses the root-helper boundary.
type PairingBeginReceiptV1 struct {
	SchemaVersion            string                              `json:"schema_version"`
	OperationID              string                              `json:"operation_id"`
	DeploymentID             string                              `json:"deployment_id"`
	OwnerID                  string                              `json:"owner_id"`
	CommandID                string                              `json:"command_id"`
	ExecutionEpoch           int64                               `json:"execution_epoch"`
	PairingExpiresAt         string                              `json:"pairing_expires_at"`
	WorkerLeaseEpoch         int64                               `json:"worker_lease_epoch"`
	RecipientPublicKeyDigest string                              `json:"recipient_public_key_digest"`
	AssociatedData           []byte                              `json:"associated_data"`
	Envelope                 secretbootstrap.RecipientEnvelopeV1 `json:"envelope"`
	ObservedAt               time.Time                           `json:"observed_at"`
	SignerKeyID              string                              `json:"signer_key_id"`
	Signature                []byte                              `json:"signature"`
}

type PairingResumeReceiptV1 struct {
	SchemaVersion            string    `json:"schema_version"`
	OperationID              string    `json:"operation_id"`
	DeploymentID             string    `json:"deployment_id"`
	OwnerID                  string    `json:"owner_id"`
	CommandID                string    `json:"command_id"`
	RecipientPublicKeyDigest string    `json:"recipient_public_key_digest"`
	ExecutionEpoch           int64     `json:"execution_epoch"`
	PairingExpiresAt         string    `json:"pairing_expires_at"`
	WorkerLeaseEpoch         int64     `json:"worker_lease_epoch"`
	ObservedAt               time.Time `json:"observed_at"`
	SignerKeyID              string    `json:"signer_key_id"`
	Signature                []byte    `json:"signature"`
}

type pairingPayloadAADV1 struct {
	SchemaVersion            string                            `json:"schema_version"`
	TrustID                  string                            `json:"trust_id"`
	InstallerBinding         installer.BindingV1               `json:"installer_binding"`
	PlanDigest               string                            `json:"plan_digest"`
	OperationID              string                            `json:"operation_id"`
	OperationKind            installer.RootHelperOperationKind `json:"operation_kind"`
	SessionID                string                            `json:"session_id"`
	TaskID                   string                            `json:"task_id"`
	StepID                   string                            `json:"step_id"`
	DeploymentID             string                            `json:"deployment_id"`
	OwnerID                  string                            `json:"owner_id"`
	RecipeID                 string                            `json:"recipe_id"`
	RecipeDigest             string                            `json:"recipe_digest"`
	RecipeRevision           int64                             `json:"recipe_revision"`
	PayloadScopeRevision     int64                             `json:"payload_scope_revision"`
	RecipientPublicKeyDigest string                            `json:"recipient_public_key_digest"`
	ExecutionEpoch           int64                             `json:"execution_epoch"`
	PairingExpiresAt         string                            `json:"pairing_expires_at"`
	CommandID                string                            `json:"command_id"`
	ExecutionBundleDigest    string                            `json:"execution_bundle_digest"`
	InstalledManifestDigest  string                            `json:"installed_manifest_digest"`
	HelperDeliveryID         string                            `json:"helper_delivery_id"`
	HelperID                 string                            `json:"helper_id"`
	HelperSignerKeyID        string                            `json:"helper_signer_key_id"`
	HelperPublicKeyDigest    string                            `json:"helper_public_key_digest"`
	InstanceID               string                            `json:"instance_id"`
	WorkerPrincipalID        string                            `json:"worker_principal_id"`
	RecipientPublicKey       string                            `json:"recipient_public_key"`
}

type PairingCommandRunner interface {
	RunPairingBegin(context.Context, installer.CommandExecution) ([]byte, error)
}

type OSPairingCommandRunner struct{}

func (OSPairingCommandRunner) RunPairingBegin(ctx context.Context, execution installer.CommandExecution) ([]byte, error) {
	if ctx == nil || len(execution.Argv) == 0 || len(execution.Environment) != 1 ||
		execution.Environment[0] != installer.SafePathEnvironment || execution.Timeout <= 0 ||
		!path.IsAbs(execution.Argv[0]) || !path.IsAbs(execution.WorkingDirectory) ||
		path.Clean(execution.WorkingDirectory) != execution.WorkingDirectory {
		return nil, ErrInvalid
	}
	command := exec.CommandContext(ctx, execution.Argv[0], execution.Argv[1:]...)
	configurePairingCommandCancellation(command)
	command.Dir = execution.WorkingDirectory
	command.Env = append([]string(nil), execution.Environment...)
	command.Stdin = nil
	output := &boundedPairingOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || output.overflow || output.buffer.Len() == 0 {
		output.clear()
		return nil, ErrUnavailable
	}
	value := bytes.Clone(output.buffer.Bytes())
	output.clear()
	return value, nil
}

type boundedPairingOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (output *boundedPairingOutput) Write(value []byte) (int, error) {
	if output == nil {
		return 0, ErrInvalid
	}
	remaining := maxPairingPayloadBytes - output.buffer.Len()
	if remaining > 0 {
		written := len(value)
		if written > remaining {
			written = remaining
		}
		_, _ = output.buffer.Write(value[:written])
	}
	if len(value) > remaining {
		output.overflow = true
	}
	return len(value), nil
}

func (output *boundedPairingOutput) clear() {
	if output == nil {
		return
	}
	clear(output.buffer.Bytes())
	output.buffer.Reset()
}

func (handler *Handler) PairingBegin(ctx context.Context, signed installer.SignedRootHelperPairingCapabilityV1, recipientPublicKey string) (PairingBeginReceiptV1, error) {
	if handler == nil || ctx == nil || installer.ValidateRootHelperPairingCapabilityAt(
		handler.delivery, signed, installer.RootHelperOperationPairingBegin, handler.now().UTC(),
	) != nil {
		return PairingBeginReceiptV1{}, ErrUnauthorized
	}
	// The raw recipient arrives over the unprivileged local socket. Its exact
	// digest is signed into the capability and must match before the helper can
	// journal or execute the Recipe command.
	if digestText(recipientPublicKey) != signed.Capability.RecipientPublicKeyDigest {
		return PairingBeginReceiptV1{}, ErrUnauthorized
	}
	aad, err := pairingAssociatedData(signed.Capability, recipientPublicKey)
	if err != nil {
		return PairingBeginReceiptV1{}, ErrInvalid
	}
	defer clear(aad)
	digest, err := pairingJournalDigest("begin", signed.Capability, recipientPublicKey)
	if err != nil {
		return PairingBeginReceiptV1{}, ErrInvalid
	}
	journalID := "pairing.begin/" + signed.Capability.OperationID
	handler.mu.Lock()
	defer handler.mu.Unlock()
	privateKey, err := handlerPrivateKey(handler, ctx, signed.Capability)
	if err != nil {
		return PairingBeginReceiptV1{}, err
	}
	defer clear(privateKey)
	command, found := declaredCommand(handler.delivery, signed.Capability.CommandID)
	if !found {
		return PairingBeginReceiptV1{}, ErrUnauthorized
	}
	installedDigest, err := handler.observer.InstalledManifestDigest(ctx, handler.delivery)
	if err != nil || installedDigest != signed.Capability.ExpectedInstalledManifestDigest {
		return PairingBeginReceiptV1{}, ErrUnavailable
	}
	execution, err := pairingExecution(command, signed.Capability.ExpiresAt, signed.Capability.PairingExpiresAt, handler.now().UTC())
	if err != nil {
		return PairingBeginReceiptV1{}, err
	}
	if replay, found, err := handler.pairingJournal.Begin(journalID, digest); err != nil {
		return PairingBeginReceiptV1{}, err
	} else if found {
		if replay.Begin == nil || validatePairingBeginReceipt(*replay.Begin, signed.Capability, recipientPublicKey,
			ed25519.PublicKey(privateKey[ed25519.PublicKeySize:])) != nil {
			return PairingBeginReceiptV1{}, ErrUnauthorized
		}
		return clonePairingBeginReceipt(*replay.Begin), nil
	}
	runCtx, cancel := context.WithTimeout(ctx, execution.Timeout)
	plaintext, runErr := handler.pairingRunner.RunPairingBegin(runCtx, execution)
	cancel()
	if runErr != nil || len(plaintext) == 0 || len(plaintext) > maxPairingPayloadBytes {
		clear(plaintext)
		return PairingBeginReceiptV1{}, ErrUnavailable
	}
	envelope, sealErr := secretbootstrap.SealToRecipient(recipientPublicKey, plaintext, aad)
	clear(plaintext)
	if sealErr != nil {
		return PairingBeginReceiptV1{}, ErrInvalid
	}
	capability := signed.Capability
	receipt := PairingBeginReceiptV1{
		SchemaVersion: PairingBeginReceiptSchemaV1, OperationID: capability.OperationID,
		DeploymentID: capability.DeploymentID, OwnerID: capability.OwnerID,
		CommandID: capability.CommandID, ExecutionEpoch: capability.ExecutionEpoch,
		PairingExpiresAt: capability.PairingExpiresAt, WorkerLeaseEpoch: capability.WorkerLeaseEpoch,
		RecipientPublicKeyDigest: digestText(recipientPublicKey),
		AssociatedData:           bytes.Clone(aad), Envelope: envelope, ObservedAt: handler.now().UTC(),
		SignerKeyID: capability.HelperSignerKeyID,
	}
	if err := signPairingBeginReceipt(&receipt, privateKey); err != nil {
		return PairingBeginReceiptV1{}, ErrInvalid
	}
	if err := handler.pairingJournal.Complete(journalID, digest, pairingJournalReceipt{Begin: &receipt}); err != nil {
		return PairingBeginReceiptV1{}, err
	}
	return clonePairingBeginReceipt(receipt), nil
}

func (handler *Handler) PairingResume(ctx context.Context, signed installer.SignedRootHelperPairingCapabilityV1) (PairingResumeReceiptV1, error) {
	if handler == nil || ctx == nil || installer.ValidateRootHelperPairingCapabilityAt(
		handler.delivery, signed, installer.RootHelperOperationPairingResume, handler.now().UTC(),
	) != nil {
		return PairingResumeReceiptV1{}, ErrUnauthorized
	}
	digest, err := pairingJournalDigest("resume", signed.Capability, "")
	if err != nil {
		return PairingResumeReceiptV1{}, ErrInvalid
	}
	journalID := "pairing.resume/" + signed.Capability.OperationID
	handler.mu.Lock()
	defer handler.mu.Unlock()
	privateKey, err := handlerPrivateKey(handler, ctx, signed.Capability)
	if err != nil {
		return PairingResumeReceiptV1{}, err
	}
	defer clear(privateKey)
	command, found := declaredCommand(handler.delivery, signed.Capability.CommandID)
	if !found {
		return PairingResumeReceiptV1{}, ErrUnauthorized
	}
	installedDigest, err := handler.observer.InstalledManifestDigest(ctx, handler.delivery)
	if err != nil || installedDigest != signed.Capability.ExpectedInstalledManifestDigest {
		return PairingResumeReceiptV1{}, ErrUnavailable
	}
	execution, err := pairingExecution(command, signed.Capability.ExpiresAt, signed.Capability.PairingExpiresAt, handler.now().UTC())
	if err != nil {
		return PairingResumeReceiptV1{}, err
	}
	if replay, found, err := handler.pairingJournal.Begin(journalID, digest); err != nil {
		return PairingResumeReceiptV1{}, err
	} else if found {
		if replay.Resume == nil || validatePairingResumeReceipt(*replay.Resume, signed.Capability,
			ed25519.PublicKey(privateKey[ed25519.PublicKeySize:])) != nil {
			return PairingResumeReceiptV1{}, ErrUnauthorized
		}
		return clonePairingResumeReceipt(*replay.Resume), nil
	}
	runCtx, cancel := context.WithTimeout(ctx, execution.Timeout)
	runErr := handler.runner.Run(runCtx, execution)
	cancel()
	if runErr != nil {
		return PairingResumeReceiptV1{}, ErrUnavailable
	}
	capability := signed.Capability
	receipt := PairingResumeReceiptV1{
		SchemaVersion: PairingResumeReceiptSchemaV1, OperationID: capability.OperationID,
		DeploymentID: capability.DeploymentID, OwnerID: capability.OwnerID,
		CommandID: capability.CommandID, RecipientPublicKeyDigest: capability.RecipientPublicKeyDigest,
		ExecutionEpoch: capability.ExecutionEpoch, PairingExpiresAt: capability.PairingExpiresAt,
		WorkerLeaseEpoch: capability.WorkerLeaseEpoch,
		ObservedAt:       handler.now().UTC(), SignerKeyID: capability.HelperSignerKeyID,
	}
	if err := signPairingResumeReceipt(&receipt, privateKey); err != nil {
		return PairingResumeReceiptV1{}, ErrInvalid
	}
	if err := handler.pairingJournal.Complete(journalID, digest, pairingJournalReceipt{Resume: &receipt}); err != nil {
		return PairingResumeReceiptV1{}, err
	}
	return clonePairingResumeReceipt(receipt), nil
}

func pairingExecution(command installer.CommandV1, capabilityExpiresAt, pairingExpiresAt string, now time.Time) (installer.CommandExecution, error) {
	expiry, err := time.Parse(time.RFC3339Nano, capabilityExpiresAt)
	pairingExpiry, pairingErr := time.Parse(time.RFC3339Nano, pairingExpiresAt)
	if err != nil || pairingErr != nil || !now.Before(expiry) || !now.Before(pairingExpiry) || expiry.After(pairingExpiry) {
		return installer.CommandExecution{}, ErrUnauthorized
	}
	timeout := time.Duration(command.TimeoutSeconds) * time.Second
	if remaining := expiry.Sub(now); timeout > remaining {
		timeout = remaining
	}
	return installer.CommandExecution{
		Argv: append([]string(nil), command.Argv...), WorkingDirectory: command.WorkingDirectory,
		Environment: []string{installer.SafePathEnvironment}, Timeout: timeout,
	}, nil
}

func pairingAssociatedData(capability installer.RootHelperPairingCapabilityV1, recipientPublicKey string) ([]byte, error) {
	publicBytes, err := base64.RawURLEncoding.DecodeString(recipientPublicKey)
	if err != nil || len(publicBytes) != 32 {
		return nil, ErrInvalid
	}
	defer clear(publicBytes)
	if _, err := ecdh.X25519().NewPublicKey(publicBytes); err != nil {
		return nil, ErrInvalid
	}
	if capability.OperationKind != installer.RootHelperOperationPairingBegin ||
		capability.RecipientPublicKeyDigest != digestText(recipientPublicKey) {
		return nil, ErrUnauthorized
	}
	// Transport lease/capability expiry intentionally do not enter the AAD.
	// A response-lost operation may be re-leased with a fresh short capability;
	// its already-signed encrypted payload must remain exactly decryptable and
	// verifiable against the immutable pairing scope.
	return canonical.Marshal(pairingPayloadAADV1{
		SchemaVersion: pairingAADSchemaV1,
		TrustID:       capability.TrustID, InstallerBinding: capability.InstallerBinding, PlanDigest: capability.PlanDigest,
		OperationID: capability.OperationID, OperationKind: capability.OperationKind, SessionID: capability.SessionID,
		TaskID: capability.TaskID, StepID: capability.StepID, DeploymentID: capability.DeploymentID,
		OwnerID: capability.OwnerID, RecipeID: capability.RecipeID, RecipeDigest: capability.RecipeDigest,
		RecipeRevision: capability.RecipeRevision, PayloadScopeRevision: capability.PayloadScopeRevision,
		RecipientPublicKeyDigest: capability.RecipientPublicKeyDigest, ExecutionEpoch: capability.ExecutionEpoch,
		PairingExpiresAt: capability.PairingExpiresAt, CommandID: capability.CommandID,
		ExecutionBundleDigest: capability.ExecutionBundleDigest, InstalledManifestDigest: capability.ExpectedInstalledManifestDigest,
		HelperDeliveryID: capability.HelperDeliveryID, HelperID: capability.HelperID,
		HelperSignerKeyID: capability.HelperSignerKeyID, HelperPublicKeyDigest: capability.HelperPublicKeyDigest,
		InstanceID: capability.InstanceID, WorkerPrincipalID: capability.WorkerPrincipalID,
		RecipientPublicKey: recipientPublicKey,
	})
}

func pairingJournalDigest(phase string, capability installer.RootHelperPairingCapabilityV1, recipientPublicKey string) (string, error) {
	if phase == "begin" && capability.RecipientPublicKeyDigest != digestText(recipientPublicKey) ||
		phase == "resume" && (recipientPublicKey != "" || capability.RecipientPublicKeyDigest != "") {
		return "", ErrUnauthorized
	}
	// A fresh signed capability may differ only in its transport delivery
	// fields. The journal identity remains the immutable operation scope,
	// recipient binding, execution epoch and pairing deadline.
	capability.CapabilityID, capability.IssuedAt, capability.ExpiresAt = "", "", ""
	capability.WorkerLeaseEpoch = 0
	return canonical.Digest(struct {
		Phase      string                                  `json:"phase"`
		Capability installer.RootHelperPairingCapabilityV1 `json:"capability"`
	}{phase, capability})
}

func handlerPrivateKey(handler *Handler, ctx context.Context, capability installer.RootHelperPairingCapabilityV1) ([]byte, error) {
	privateKey, err := handler.keys.ReadRootHelperSigningKey(ctx)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize ||
		publicKeyDigest(privateKey[ed25519.PublicKeySize:]) != capability.HelperPublicKeyDigest {
		clear(privateKey)
		return nil, ErrNotReady
	}
	return privateKey, nil
}

func signPairingBeginReceipt(receipt *PairingBeginReceiptV1, privateKey ed25519.PrivateKey) error {
	if receipt == nil || len(privateKey) != ed25519.PrivateKeySize {
		return ErrInvalid
	}
	unsigned := clonePairingBeginReceipt(*receipt)
	unsigned.Signature = nil
	payload, err := canonical.Marshal(unsigned)
	if err != nil {
		return err
	}
	defer clear(payload)
	receipt.Signature = ed25519.Sign(privateKey, payload)
	return nil
}

func signPairingResumeReceipt(receipt *PairingResumeReceiptV1, privateKey ed25519.PrivateKey) error {
	if receipt == nil || len(privateKey) != ed25519.PrivateKeySize {
		return ErrInvalid
	}
	unsigned := clonePairingResumeReceipt(*receipt)
	unsigned.Signature = nil
	payload, err := canonical.Marshal(unsigned)
	if err != nil {
		return err
	}
	defer clear(payload)
	receipt.Signature = ed25519.Sign(privateKey, payload)
	return nil
}

func validatePairingBeginReceipt(receipt PairingBeginReceiptV1, capability installer.RootHelperPairingCapabilityV1, recipientPublicKey string, publicKey ed25519.PublicKey) error {
	aad, err := pairingAssociatedData(capability, recipientPublicKey)
	if err != nil {
		return err
	}
	defer clear(aad)
	if receipt.SchemaVersion != PairingBeginReceiptSchemaV1 || receipt.OperationID != capability.OperationID ||
		receipt.DeploymentID != capability.DeploymentID || receipt.OwnerID != capability.OwnerID ||
		receipt.CommandID != capability.CommandID || receipt.WorkerLeaseEpoch < 1 ||
		receipt.ExecutionEpoch != capability.ExecutionEpoch || receipt.PairingExpiresAt != capability.PairingExpiresAt ||
		receipt.RecipientPublicKeyDigest != capability.RecipientPublicKeyDigest ||
		receipt.RecipientPublicKeyDigest != digestText(recipientPublicKey) || !bytes.Equal(receipt.AssociatedData, aad) ||
		receipt.ObservedAt.IsZero() || receipt.SignerKeyID != capability.HelperSignerKeyID ||
		receipt.Envelope.SchemaVersion != secretbootstrap.RecipientEnvelopeSchemaV1 || len(publicKey) != ed25519.PublicKeySize {
		return ErrUnauthorized
	}
	unsigned := clonePairingBeginReceipt(receipt)
	signature := bytes.Clone(unsigned.Signature)
	unsigned.Signature = nil
	payload, err := canonical.Marshal(unsigned)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		clear(payload)
		return ErrUnauthorized
	}
	clear(payload)
	return nil
}

func validatePairingResumeReceipt(receipt PairingResumeReceiptV1, capability installer.RootHelperPairingCapabilityV1, publicKey ed25519.PublicKey) error {
	if receipt.SchemaVersion != PairingResumeReceiptSchemaV1 || receipt.OperationID != capability.OperationID ||
		receipt.DeploymentID != capability.DeploymentID || receipt.OwnerID != capability.OwnerID ||
		receipt.CommandID != capability.CommandID || receipt.RecipientPublicKeyDigest != "" ||
		receipt.ExecutionEpoch != capability.ExecutionEpoch || receipt.PairingExpiresAt != capability.PairingExpiresAt ||
		receipt.WorkerLeaseEpoch < 1 ||
		receipt.ObservedAt.IsZero() || receipt.SignerKeyID != capability.HelperSignerKeyID || len(publicKey) != ed25519.PublicKeySize {
		return ErrUnauthorized
	}
	unsigned := clonePairingResumeReceipt(receipt)
	signature := bytes.Clone(unsigned.Signature)
	unsigned.Signature = nil
	payload, err := canonical.Marshal(unsigned)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		clear(payload)
		return ErrUnauthorized
	}
	clear(payload)
	return nil
}

func VerifyPairingBeginReceiptSignature(receipt PairingBeginReceiptV1, publicKey ed25519.PublicKey) error {
	if receipt.SchemaVersion != PairingBeginReceiptSchemaV1 || receipt.OperationID == "" || receipt.DeploymentID == "" ||
		receipt.OwnerID == "" || receipt.CommandID == "" || receipt.ExecutionEpoch < 1 || receipt.PairingExpiresAt == "" || receipt.WorkerLeaseEpoch < 1 ||
		receipt.RecipientPublicKeyDigest == "" || len(receipt.AssociatedData) == 0 || receipt.ObservedAt.IsZero() ||
		receipt.SignerKeyID == "" || receipt.Envelope.SchemaVersion != secretbootstrap.RecipientEnvelopeSchemaV1 ||
		len(publicKey) != ed25519.PublicKeySize {
		return ErrUnauthorized
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.PairingExpiresAt); err != nil {
		return ErrUnauthorized
	}
	unsigned := clonePairingBeginReceipt(receipt)
	signature := bytes.Clone(unsigned.Signature)
	unsigned.Signature = nil
	payload, err := canonical.Marshal(unsigned)
	defer clear(payload)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrUnauthorized
	}
	return nil
}

func VerifyPairingResumeReceiptSignature(receipt PairingResumeReceiptV1, publicKey ed25519.PublicKey) error {
	if receipt.SchemaVersion != PairingResumeReceiptSchemaV1 || receipt.OperationID == "" || receipt.DeploymentID == "" ||
		receipt.OwnerID == "" || receipt.CommandID == "" || receipt.RecipientPublicKeyDigest != "" ||
		receipt.ExecutionEpoch < 1 || receipt.PairingExpiresAt == "" || receipt.WorkerLeaseEpoch < 1 || receipt.ObservedAt.IsZero() ||
		receipt.SignerKeyID == "" || len(publicKey) != ed25519.PublicKeySize {
		return ErrUnauthorized
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.PairingExpiresAt); err != nil {
		return ErrUnauthorized
	}
	unsigned := clonePairingResumeReceipt(receipt)
	signature := bytes.Clone(unsigned.Signature)
	unsigned.Signature = nil
	payload, err := canonical.Marshal(unsigned)
	defer clear(payload)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrUnauthorized
	}
	return nil
}

func clonePairingBeginReceipt(value PairingBeginReceiptV1) PairingBeginReceiptV1 {
	value.AssociatedData = bytes.Clone(value.AssociatedData)
	value.Signature = bytes.Clone(value.Signature)
	return value
}

func clonePairingResumeReceipt(value PairingResumeReceiptV1) PairingResumeReceiptV1 {
	value.Signature = bytes.Clone(value.Signature)
	return value
}

func digestText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var _ PairingCommandRunner = OSPairingCommandRunner{}

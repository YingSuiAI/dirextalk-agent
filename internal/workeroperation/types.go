// Package workeroperation owns deployment-bound Worker lifecycle assignments.
// It is deliberately separate from the Deployment Task/Step execution lease:
// a service operation never carries or mutates TaskID or StepID.
package workeroperation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	SchemaV1 = "dirextalk.agent.worker-service-operation/v1"

	ActionRestart  Action = "restart"
	ActionStop     Action = "stop"
	ActionBackup   Action = "backup"
	ActionRestore  Action = "restore"
	ActionUpgrade  Action = "upgrade"
	ActionRollback Action = "rollback"
	ActionDestroy  Action = "destroy"

	StatePending   State = "pending"
	StateLeased    State = "leased"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
)

var (
	ErrInvalid                   = errors.New("worker service operation is invalid")
	ErrNotFound                  = errors.New("worker service operation was not found")
	ErrRevisionConflict          = errors.New("worker service operation revision conflict")
	ErrIdempotencyConflict       = errors.New("worker service operation idempotency conflict")
	ErrLeaseActive               = errors.New("worker service operation lease is active")
	ErrStaleLease                = errors.New("worker service operation lease is stale")
	ErrLeaseExpired              = errors.New("worker service operation lease expired")
	ErrTerminal                  = errors.New("worker service operation is terminal")
	ErrSignedObservationRequired = errors.New("worker service operation requires a signed root observation")

	digestPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type Action string
type State string

func (value Action) Valid() bool {
	switch value {
	case ActionRestart, ActionStop, ActionBackup, ActionRestore, ActionUpgrade, ActionRollback, ActionDestroy:
		return true
	default:
		return false
	}
}

type Operation struct {
	SchemaVersion                    string
	OperationID                      string
	DeploymentID                     string
	OwnerID                          string
	Action                           Action
	LifecycleRestartRef              string
	ExecutionBundleDigest            string
	ExpectedInstalledManifestDigest  string
	ExpectedDeploymentRevision       int64
	ExpectedManagedServiceRevision   int64
	ExpectedKnowledgeBindingRevision int64
	State                            State
	WorkerID                         string
	LeaseEpoch                       int64
	LeaseExpiresAt                   time.Time
	Receipt                          *RootHelperReceipt
	FailureCode                      string
	Revision                         int64
	CreatedAt                        time.Time
	UpdatedAt                        time.Time
}

type Assignment struct {
	OperationID                      string
	DeploymentID                     string
	OwnerID                          string
	Action                           Action
	LifecycleRestartRef              string
	ExecutionBundleDigest            string
	ExpectedInstalledManifestDigest  string
	ExpectedDeploymentRevision       int64
	ExpectedManagedServiceRevision   int64
	ExpectedKnowledgeBindingRevision int64
	WorkerID                         string
	LeaseEpoch                       int64
	LeaseExpiresAt                   time.Time
	Revision                         int64
}

// RootHelperReceipt is a signed, terminal receipt from the authenticated
// privileged helper. It is not Worker Evidence and must never be projected as
// an untrusted_worker_claim.
type RootHelperReceipt struct {
	SchemaVersion                    string
	OperationID                      string
	DeploymentID                     string
	OwnerID                          string
	Action                           Action
	LifecycleRestartRef              string
	ExecutionBundleDigest            string
	LeaseEpoch                       int64
	InstallManifestDigest            string
	RestartObservationDigest         string
	ExpectedDeploymentRevision       int64
	ExpectedManagedServiceRevision   int64
	ExpectedKnowledgeBindingRevision int64
	ObservedAt                       time.Time
	HelperID                         string
	SignerKeyID                      string
	Signature                        []byte
}

func (value Operation) Clone() Operation {
	cloned := value
	if value.Receipt != nil {
		receipt := *value.Receipt
		receipt.Signature = bytes.Clone(value.Receipt.Signature)
		cloned.Receipt = &receipt
	}
	return cloned
}

func (value Operation) Validate() error {
	if value.SchemaVersion != SchemaV1 || !validUUID(value.OperationID) || !validUUID(value.DeploymentID) ||
		!validOwner(value.OwnerID) || !value.Action.Valid() ||
		!identifierPattern.MatchString(value.LifecycleRestartRef) || !digestPattern.MatchString(value.ExecutionBundleDigest) ||
		!digestPattern.MatchString(value.ExpectedInstalledManifestDigest) || !validExpectedRevisions(value.Action,
		value.ExpectedDeploymentRevision, value.ExpectedManagedServiceRevision, value.ExpectedKnowledgeBindingRevision) ||
		value.Revision < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return ErrInvalid
	}
	switch value.State {
	case StatePending:
		if value.WorkerID != "" || value.LeaseEpoch != 0 || !value.LeaseExpiresAt.IsZero() || value.Receipt != nil || value.FailureCode != "" {
			return ErrInvalid
		}
	case StateLeased:
		if !validUUID(value.WorkerID) || value.LeaseEpoch < 1 || value.LeaseExpiresAt.IsZero() ||
			!value.UpdatedAt.Before(value.LeaseExpiresAt) || value.Receipt != nil || value.FailureCode != "" {
			return ErrInvalid
		}
	case StateSucceeded:
		if !validUUID(value.WorkerID) || value.LeaseEpoch < 1 || !value.LeaseExpiresAt.IsZero() || value.Receipt == nil ||
			value.FailureCode != "" || value.Receipt.ValidateFor(value) != nil ||
			value.Receipt.ObservedAt.Before(value.CreatedAt) || value.Receipt.ObservedAt.After(value.UpdatedAt) {
			return ErrInvalid
		}
	case StateFailed:
		if !validUUID(value.WorkerID) || value.LeaseEpoch < 1 || !value.LeaseExpiresAt.IsZero() || value.Receipt != nil ||
			!identifierPattern.MatchString(value.FailureCode) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (value RootHelperReceipt) ValidateFor(operation Operation) error {
	if value.SchemaVersion != SchemaV1 || value.OperationID != operation.OperationID ||
		value.DeploymentID != operation.DeploymentID || value.OwnerID != operation.OwnerID ||
		value.Action != operation.Action || !value.Action.Valid() || value.LifecycleRestartRef != operation.LifecycleRestartRef ||
		value.ExecutionBundleDigest != operation.ExecutionBundleDigest || value.LeaseEpoch != operation.LeaseEpoch ||
		value.InstallManifestDigest != operation.ExpectedInstalledManifestDigest ||
		value.ExpectedDeploymentRevision != operation.ExpectedDeploymentRevision ||
		value.ExpectedManagedServiceRevision != operation.ExpectedManagedServiceRevision ||
		value.ExpectedKnowledgeBindingRevision != operation.ExpectedKnowledgeBindingRevision ||
		!digestPattern.MatchString(value.RestartObservationDigest) ||
		value.ObservedAt.IsZero() || !identifierPattern.MatchString(value.HelperID) ||
		!identifierPattern.MatchString(value.SignerKeyID) || len(value.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return nil
}

func (value RootHelperReceipt) signingPayload() ([]byte, error) {
	if value.SchemaVersion != SchemaV1 || !value.Action.Valid() || value.ObservedAt.IsZero() {
		return nil, ErrInvalid
	}
	fields := []string{
		value.SchemaVersion, value.OperationID, value.DeploymentID, value.OwnerID, string(value.Action),
		value.LifecycleRestartRef, value.ExecutionBundleDigest, fmt.Sprint(value.LeaseEpoch),
		value.InstallManifestDigest, value.RestartObservationDigest,
		fmt.Sprint(value.ExpectedDeploymentRevision), fmt.Sprint(value.ExpectedManagedServiceRevision),
		fmt.Sprint(value.ExpectedKnowledgeBindingRevision),
		value.ObservedAt.UTC().Format(time.RFC3339Nano), value.HelperID, value.SignerKeyID,
	}
	var payload bytes.Buffer
	for _, field := range fields {
		if len(field) > 1<<20 {
			return nil, ErrInvalid
		}
		_ = binary.Write(&payload, binary.BigEndian, uint32(len(field)))
		_, _ = payload.WriteString(field)
	}
	return payload.Bytes(), nil
}

func validExpectedRevisions(action Action, deployment, service, binding int64) bool {
	if action == ActionRestart {
		return deployment == 0 && service == 0 && binding == 0
	}
	return deployment > 0 && service > 0 && binding > 0
}

func SignReceipt(value RootHelperReceipt, privateKey ed25519.PrivateKey) (RootHelperReceipt, error) {
	payload, err := value.signingPayload()
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return RootHelperReceipt{}, ErrInvalid
	}
	value.Signature = ed25519.Sign(privateKey, payload)
	return value, nil
}

type ReceiptVerifier interface {
	Verify(context.Context, RootHelperReceipt) error
}

type Ed25519ReceiptVerifier struct {
	Keys map[string]ed25519.PublicKey
}

func (verifier Ed25519ReceiptVerifier) Verify(_ context.Context, value RootHelperReceipt) error {
	key := verifier.Keys[value.SignerKeyID]
	return verifyReceipt(value, key)
}

type CurrentReadyPublicKeyStore interface {
	CurrentReadyPublicKey(context.Context, string, string, string) (ed25519.PublicKey, error)
}

// CurrentReadyReceiptVerifier resolves trust for every receipt so revocation
// and rotation take effect without relying on an in-process key cache.
type CurrentReadyReceiptVerifier struct {
	Keys CurrentReadyPublicKeyStore
}

func (verifier CurrentReadyReceiptVerifier) Verify(ctx context.Context, value RootHelperReceipt) error {
	if verifier.Keys == nil {
		return ErrInvalid
	}
	key, err := verifier.Keys.CurrentReadyPublicKey(ctx, value.DeploymentID, value.HelperID, value.SignerKeyID)
	if err != nil {
		return ErrInvalid
	}
	return verifyReceipt(value, key)
}

func verifyReceipt(value RootHelperReceipt, key ed25519.PublicKey) error {
	payload, err := value.signingPayload()
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, payload, value.Signature) {
		return ErrInvalid
	}
	return nil
}

type Mutation struct {
	IdempotencyKey   string
	ExpectedRevision int64
	RequestHash      [32]byte
}

func NewMutation(idempotencyKey string, expectedRevision int64, payload string) (Mutation, error) {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if !validUUID(idempotencyKey) || expectedRevision < 0 || payload == "" {
		return Mutation{}, ErrInvalid
	}
	return Mutation{IdempotencyKey: idempotencyKey, ExpectedRevision: expectedRevision, RequestHash: sha256.Sum256([]byte(payload))}, nil
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == strings.ToLower(strings.TrimSpace(value))
}

func validOwner(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == value && len(value) >= 1 && len(value) <= 255 && !strings.ContainsAny(value, "\r\n\x00")
}

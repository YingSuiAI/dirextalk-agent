// Package pairingworker defines the narrow, deployment-bound bridge between
// the Agent pairing state machine and an exclusive Worker/root-helper.
package pairingworker

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/google/uuid"
)

var ErrInvalid = errors.New("pairing Worker operation is invalid")

type Action string

const (
	ActionBegin  Action = "pairing_begin"
	ActionResume Action = "pairing_resume"
)

// Command contains only public, signed-scope inputs. In particular, it never
// contains the pairing plaintext. Dispatch implementations must durably replay
// an exact command by OperationID and reject a different command with that ID.
type Command struct {
	OperationID, SessionID, TaskID, StepID, DeploymentID, OwnerID string
	DeploymentRevision                                            int64
	RecipeID, RecipeDigest, CommandID, ExecutionManifestDigest    string
	RecipeRevision, PayloadScopeRevision                          int64
	// ExecutionEpoch is zero until the durable operation is first acquired.
	// It is then initialized once and remains stable across re-leases.
	ExecutionEpoch           int64
	PairingExpiresAt         time.Time
	Action                   Action
	RecipientPublicKey       string
	RecipientPublicKeyDigest string
}

type Result struct {
	Begin  *roothelper.PairingBeginReceiptV1
	Resume *roothelper.PairingResumeReceiptV1
}

// Dispatcher is the durable Worker transport. Dispatch returns only after the
// exact root-helper receipt has been persisted and independently verified.
type Dispatcher interface {
	Dispatch(context.Context, Command) (Result, error)
}

type Executor struct{ Dispatch Dispatcher }

func (executor Executor) Begin(ctx context.Context, session pairing.SessionV1, recipientPublicKey string, payloadScopeRevision int64) (pairing.PayloadResult, error) {
	command, err := commandFor(session, ActionBegin, recipientPublicKey, payloadScopeRevision)
	if err != nil || executor.Dispatch == nil {
		return pairing.PayloadResult{}, ErrInvalid
	}
	result, err := executor.Dispatch.Dispatch(ctx, command)
	if err != nil {
		return pairing.PayloadResult{}, err
	}
	if result.Begin == nil || result.Resume != nil || !sameBegin(*result.Begin, command) {
		return pairing.PayloadResult{}, ErrInvalid
	}
	digest, err := canonical.Digest(struct {
		Envelope       any    `json:"envelope"`
		AssociatedData []byte `json:"associated_data"`
	}{result.Begin.Envelope, result.Begin.AssociatedData})
	if err != nil {
		return pairing.PayloadResult{}, ErrInvalid
	}
	return pairing.PayloadResult{
		Envelope: result.Begin.Envelope, AssociatedDataCBOR: append([]byte(nil), result.Begin.AssociatedData...),
		PayloadDigest: digest,
	}, nil
}

func (executor Executor) Resume(ctx context.Context, session pairing.SessionV1) error {
	command, err := commandFor(session, ActionResume, "", 0)
	if err != nil || executor.Dispatch == nil {
		return ErrInvalid
	}
	result, err := executor.Dispatch.Dispatch(ctx, command)
	if err != nil {
		return err
	}
	if result.Resume == nil || result.Begin != nil || !sameResume(*result.Resume, command) {
		return ErrInvalid
	}
	return nil
}

func commandFor(session pairing.SessionV1, action Action, recipient string, requestedScopeRevision int64) (Command, error) {
	if session.Validate() != nil || (action != ActionBegin && action != ActionResume) ||
		(action == ActionBegin && !validRecipient(recipient)) ||
		(action == ActionResume && recipient != "") {
		return Command{}, ErrInvalid
	}
	scopeRevision := requestedScopeRevision
	commandID := session.BeginCommand
	if action == ActionResume {
		commandID = session.ResumeCommand
		// BeginResume advances the session revision; the payload binding remains
		// the immutable revision recorded with the encrypted envelope.
		scopeRevision = session.PayloadScopeRevision
	}
	if scopeRevision < 1 {
		return Command{}, ErrInvalid
	}
	recipientKeyDigest := ""
	if recipient != "" {
		recipientKeyDigest = recipientDigest(recipient)
	}
	operationID := ""
	if action == ActionBegin {
		var err error
		operationID, err = pairing.PayloadOperationID(session.SessionID, scopeRevision, recipientKeyDigest)
		if err != nil {
			return Command{}, ErrInvalid
		}
	} else {
		operationID = uuid.NewSHA1(uuid.MustParse(session.SessionID),
			[]byte(string(action)+":"+recipientKeyDigest+":"+strconv.FormatInt(scopeRevision, 10))).String()
	}
	return Command{
		OperationID: operationID, SessionID: session.SessionID, TaskID: session.TaskID, StepID: session.StepID,
		DeploymentID: session.DeploymentID, DeploymentRevision: session.DeploymentRevision, OwnerID: session.OwnerID, RecipeID: session.RecipeID,
		RecipeDigest: session.RecipeDigest, RecipeRevision: session.RecipeRevision,
		PayloadScopeRevision: scopeRevision, CommandID: commandID,
		PairingExpiresAt:        session.ExpiresAt.UTC().Truncate(time.Microsecond),
		ExecutionManifestDigest: session.ExecutionManifestDigest, Action: action,
		RecipientPublicKey: recipient, RecipientPublicKeyDigest: recipientKeyDigest,
	}, nil
}

func validRecipient(value string) bool {
	if strings.TrimSpace(value) != value {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		clear(raw)
		return false
	}
	_, err = ecdh.X25519().NewPublicKey(raw)
	clear(raw)
	return err == nil
}

// CapabilityIssuer derives a fresh short-lived capability from authoritative
// Worker assignment, installer delivery and current helper trust.
type CapabilityIssuer interface {
	IssuePairingCapability(context.Context, Command) (installer.DeliveryV1, installer.SignedRootHelperPairingCapabilityV1, ed25519.PublicKey, error)
}

type RootControl interface {
	PairingBegin(context.Context, installer.DeliveryV1, installer.SignedRootHelperPairingCapabilityV1, string, ed25519.PublicKey) (roothelper.PairingBeginReceiptV1, error)
	PairingResume(context.Context, installer.DeliveryV1, installer.SignedRootHelperPairingCapabilityV1, ed25519.PublicKey) (roothelper.PairingResumeReceiptV1, error)
}

// Runner is used by the authenticated exclusive Worker after acquiring a
// durable command. SocketClient satisfies RootControl.
type Runner struct {
	Issuer CapabilityIssuer
	Root   RootControl
}

func (runner Runner) Run(ctx context.Context, command Command) (Result, error) {
	if runner.Issuer == nil || runner.Root == nil {
		return Result{}, ErrInvalid
	}
	delivery, signed, publicKey, err := runner.Issuer.IssuePairingCapability(ctx, command)
	if err != nil {
		return Result{}, err
	}
	switch command.Action {
	case ActionBegin:
		value, err := runner.Root.PairingBegin(ctx, delivery, signed, command.RecipientPublicKey, publicKey)
		if err != nil {
			return Result{}, err
		}
		if !sameBegin(value, command) {
			return Result{}, ErrInvalid
		}
		return Result{Begin: &value}, nil
	case ActionResume:
		value, err := runner.Root.PairingResume(ctx, delivery, signed, publicKey)
		if err != nil {
			return Result{}, err
		}
		if !sameResume(value, command) {
			return Result{}, ErrInvalid
		}
		return Result{Resume: &value}, nil
	default:
		return Result{}, ErrInvalid
	}
}

func sameBegin(value roothelper.PairingBeginReceiptV1, command Command) bool {
	return value.OperationID == command.OperationID && value.DeploymentID == command.DeploymentID &&
		value.OwnerID == command.OwnerID && value.CommandID == command.CommandID &&
		value.RecipientPublicKeyDigest == command.RecipientPublicKeyDigest && value.ExecutionEpoch == command.ExecutionEpoch &&
		value.PairingExpiresAt == pairingExpiryText(command.PairingExpiresAt) && value.WorkerLeaseEpoch >= 1 &&
		len(value.AssociatedData) > 0 && len(value.Signature) == ed25519.SignatureSize
}

func sameResume(value roothelper.PairingResumeReceiptV1, command Command) bool {
	return value.OperationID == command.OperationID && value.DeploymentID == command.DeploymentID &&
		value.OwnerID == command.OwnerID && value.CommandID == command.CommandID &&
		value.RecipientPublicKeyDigest == "" && value.ExecutionEpoch == command.ExecutionEpoch &&
		value.PairingExpiresAt == pairingExpiryText(command.PairingExpiresAt) && value.WorkerLeaseEpoch >= 1 &&
		len(value.Signature) == ed25519.SignatureSize
}

func pairingExpiryText(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

var _ pairing.Executor = Executor{}

package pairing

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
)

type PayloadResult struct {
	Envelope           secretbootstrap.RecipientEnvelopeV1
	AssociatedDataCBOR []byte
	PayloadDigest      string
}

// Executor is the only bridge to the exclusive Worker/root-helper chain. A
// begin result is already encrypted; plaintext must never cross this API.
type Executor interface {
	Begin(context.Context, SessionV1, string, int64) (PayloadResult, error)
	Resume(context.Context, SessionV1) error
}

type Service struct {
	repository Repository
	executor   Executor
	now        func() time.Time
}

func NewService(repository Repository, executor Executor, now func() time.Time) (*Service, error) {
	if repository == nil || executor == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, executor: executor, now: now}, nil
}

type CreateCommand struct {
	OwnerID, IdempotencyKey, SessionID, DeploymentID, PlanID, ConnectionID string
	DeploymentRevision                                                     int64
	TaskID, StepID, RecipeID, RecipeDigest, ExecutionManifestDigest        string
	RecipeRevision                                                         int64
	BeginCommand, ResumeCommand                                            string
	Timeout                                                                time.Duration
}

func (service *Service) Create(ctx context.Context, command CreateCommand) (SessionV1, error) {
	if service == nil || ctx == nil || command.Timeout <= 0 || command.Timeout > 30*24*time.Hour {
		return SessionV1{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	value := SessionV1{
		SchemaVersion: SchemaV1, SessionID: strings.TrimSpace(command.SessionID), OwnerID: strings.TrimSpace(command.OwnerID),
		DeploymentID: strings.TrimSpace(command.DeploymentID), DeploymentRevision: command.DeploymentRevision,
		PlanID: strings.TrimSpace(command.PlanID), ConnectionID: strings.TrimSpace(command.ConnectionID),
		TaskID: strings.TrimSpace(command.TaskID), StepID: strings.TrimSpace(command.StepID), RecipeID: strings.TrimSpace(command.RecipeID),
		RecipeDigest: strings.TrimSpace(command.RecipeDigest), RecipeRevision: command.RecipeRevision,
		ExecutionManifestDigest: strings.TrimSpace(command.ExecutionManifestDigest),
		BeginCommand:            strings.TrimSpace(command.BeginCommand), ResumeCommand: strings.TrimSpace(command.ResumeCommand),
		Status: StatusWaitingPayload, ExpiresAt: now.Add(command.Timeout), Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if value.Validate() != nil {
		return SessionV1{}, ErrInvalid
	}
	digest, err := canonical.Digest(struct {
		Operation string    `json:"operation"`
		Session   SessionV1 `json:"session"`
	}{"pairing.create", value})
	if err != nil {
		return SessionV1{}, ErrInvalid
	}
	return service.repository.Create(ctx, Mutation{OwnerID: value.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest}, 0, value)
}

// Get is the public-facing read fence for pairing sessions.  Once a pairing
// deadline has passed, no caller may observe or use its encrypted envelope:
// non-terminal sessions are durably converted to timed_out.  That scrubbed
// terminal state may be projected to callers, but its prior envelope never is.
func (service *Service) Get(ctx context.Context, ownerID, sessionID string) (SessionV1, error) {
	if service == nil || ctx == nil {
		return SessionV1{}, ErrInvalid
	}
	current, err := service.repository.Get(ctx, strings.TrimSpace(ownerID), strings.TrimSpace(sessionID))
	if err != nil {
		return SessionV1{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	if now.Before(current.ExpiresAt) {
		return current, nil
	}
	if current.Status == StatusTimedOut && current.Envelope == nil {
		return current, nil
	}
	if !IsTerminal(current.Status) {
		expired, expireErr := service.repository.Expire(ctx, current.OwnerID, current.SessionID, now)
		if expireErr == nil && expired.Status == StatusTimedOut && expired.Envelope == nil {
			return expired, nil
		}
		if expireErr != nil && !errors.Is(expireErr, ErrRevisionConflict) {
			return SessionV1{}, expireErr
		}
		// A second observer may have won the expiry race.  It is still safe to
		// project a scrubbed timed_out state, but never the prior envelope.
		latest, latestErr := service.repository.Get(ctx, current.OwnerID, current.SessionID)
		if latestErr == nil && latest.Status == StatusTimedOut && latest.Envelope == nil {
			return latest, nil
		}
	}
	return SessionV1{}, ErrRevisionConflict
}

type RetrieveCommand struct {
	OwnerID, IdempotencyKey, SessionID, DeploymentID, RecipientPublicKey string
	ExpectedRevision                                                     int64
}

func (service *Service) Retrieve(ctx context.Context, command RetrieveCommand) (SessionV1, PayloadResult, error) {
	if service == nil || ctx == nil || command.ExpectedRevision < 1 || !validRecipientKey(command.RecipientPublicKey) {
		return SessionV1{}, PayloadResult{}, ErrInvalid
	}
	ownerID, sessionID, deploymentID := strings.TrimSpace(command.OwnerID), strings.TrimSpace(command.SessionID), strings.TrimSpace(command.DeploymentID)
	current, err := service.Get(ctx, ownerID, sessionID)
	if err != nil {
		return SessionV1{}, PayloadResult{}, err
	}
	if current.OwnerID != ownerID || current.DeploymentID != deploymentID {
		return SessionV1{}, PayloadResult{}, ErrRevisionConflict
	}
	recipientDigest := digestText(command.RecipientPublicKey)
	if current.Envelope != nil {
		if current.RecipientKeyDigest != recipientDigest || current.PayloadScopeRevision != command.ExpectedRevision {
			return SessionV1{}, PayloadResult{}, ErrRevisionConflict
		}
		payload, payloadErr := service.payloadResultIfLive(ctx, current)
		if payloadErr != nil {
			return SessionV1{}, PayloadResult{}, payloadErr
		}
		return current, payload, nil
	}
	if current.Status != StatusWaitingPayload || current.Revision != command.ExpectedRevision {
		return SessionV1{}, PayloadResult{}, ErrRevisionConflict
	}
	operationID, err := PayloadOperationID(current.SessionID, command.ExpectedRevision, recipientDigest)
	if err != nil {
		return SessionV1{}, PayloadResult{}, ErrInvalid
	}
	digest, err := canonical.Digest(struct {
		Operation          string `json:"operation"`
		SessionID          string `json:"session_id"`
		DeploymentID       string `json:"deployment_id"`
		ExpectedRevision   int64  `json:"expected_revision"`
		RecipientKeyDigest string `json:"recipient_key_digest"`
		OperationID        string `json:"operation_id"`
	}{"pairing.retrieve", current.SessionID, current.DeploymentID, command.ExpectedRevision, recipientDigest, operationID})
	if err != nil {
		return SessionV1{}, PayloadResult{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	reserved, reservation, _, err := service.repository.ReservePayload(ctx,
		Mutation{OwnerID: current.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest},
		current.SessionID, command.ExpectedRevision, recipientDigest, operationID, now)
	if err != nil {
		if expiredAt := service.now().UTC().Truncate(time.Microsecond); !expiredAt.Before(current.ExpiresAt) {
			return service.expiredRetrieve(ctx, current, expiredAt)
		}
		return SessionV1{}, PayloadResult{}, err
	}
	if reserved.Envelope != nil {
		if reserved.RecipientKeyDigest != recipientDigest || reserved.PayloadScopeRevision != command.ExpectedRevision {
			return SessionV1{}, PayloadResult{}, ErrRevisionConflict
		}
		payload, payloadErr := service.payloadResultIfLive(ctx, reserved)
		if payloadErr != nil {
			return SessionV1{}, PayloadResult{}, payloadErr
		}
		return reserved, payload, nil
	}
	if reservation.SessionID != current.SessionID || reservation.OwnerID != current.OwnerID ||
		reservation.PayloadScopeRevision != command.ExpectedRevision || reservation.RecipientKeyDigest != recipientDigest ||
		reservation.OperationID != operationID {
		return SessionV1{}, PayloadResult{}, ErrRevisionConflict
	}
	dispatchCtx, cancel := context.WithDeadline(ctx, reserved.ExpiresAt)
	result, executionErr := service.executor.Begin(dispatchCtx, reserved, command.RecipientPublicKey, command.ExpectedRevision)
	cancel()
	completedAt := service.now().UTC().Truncate(time.Microsecond)
	if !completedAt.Before(reserved.ExpiresAt) {
		return service.expiredRetrieve(ctx, reserved, completedAt)
	}
	if executionErr != nil || result.PayloadDigest == "" || len(result.AssociatedDataCBOR) == 0 {
		return SessionV1{}, PayloadResult{}, errors.Join(ErrRevisionConflict, executionErr)
	}
	updated, err := service.repository.RecordEnvelope(ctx,
		Mutation{OwnerID: current.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest},
		current.SessionID, command.ExpectedRevision, recipientDigest, operationID, result.Envelope,
		result.AssociatedDataCBOR, result.PayloadDigest, completedAt)
	if err != nil {
		// A concurrent retry for the same recipient may have won the final CAS.
		// It is safe to replay that one exact ciphertext; a different recipient
		// is still rejected by the persisted digest/scope fence.
		latest, latestErr := service.Get(ctx, current.OwnerID, current.SessionID)
		if latestErr == nil && latest.Envelope != nil && latest.RecipientKeyDigest == recipientDigest &&
			latest.PayloadScopeRevision == command.ExpectedRevision {
			payload, payloadErr := service.payloadResultIfLive(ctx, latest)
			if payloadErr == nil {
				return latest, payload, nil
			}
			return SessionV1{}, PayloadResult{}, payloadErr
		}
		return SessionV1{}, PayloadResult{}, err
	}
	returnedAt := service.now().UTC().Truncate(time.Microsecond)
	if !returnedAt.Before(updated.ExpiresAt) {
		return service.expiredRetrieve(ctx, updated, returnedAt)
	}
	return updated, payloadResultFor(updated), nil
}

func payloadResultFor(session SessionV1) PayloadResult {
	return PayloadResult{Envelope: *session.Envelope, AssociatedDataCBOR: append([]byte(nil), session.AssociatedDataCBOR...), PayloadDigest: session.PayloadDigest}
}

func (service *Service) payloadResultIfLive(ctx context.Context, current SessionV1) (PayloadResult, error) {
	if current.Envelope == nil {
		return PayloadResult{}, ErrRevisionConflict
	}
	at := service.now().UTC().Truncate(time.Microsecond)
	if !at.Before(current.ExpiresAt) {
		_, _, err := service.expiredRetrieve(ctx, current, at)
		return PayloadResult{}, err
	}
	return payloadResultFor(current), nil
}

func (service *Service) expiredRetrieve(ctx context.Context, current SessionV1, at time.Time) (SessionV1, PayloadResult, error) {
	if !IsTerminal(current.Status) {
		if _, err := service.repository.Expire(ctx, current.OwnerID, current.SessionID, at); err != nil && !errors.Is(err, ErrRevisionConflict) {
			return SessionV1{}, PayloadResult{}, err
		}
	}
	return SessionV1{}, PayloadResult{}, ErrRevisionConflict
}

type ResumeCommand struct {
	OwnerID, IdempotencyKey, SessionID, DeploymentID string
	ExpectedRevision                                 int64
}

func (service *Service) Resume(ctx context.Context, command ResumeCommand) (SessionV1, error) {
	if service == nil || ctx == nil || command.ExpectedRevision < 1 {
		return SessionV1{}, ErrInvalid
	}
	ownerID, sessionID, deploymentID := strings.TrimSpace(command.OwnerID), strings.TrimSpace(command.SessionID), strings.TrimSpace(command.DeploymentID)
	current, err := service.Get(ctx, ownerID, sessionID)
	if err != nil {
		return SessionV1{}, err
	}
	if current.OwnerID != ownerID || current.DeploymentID != deploymentID {
		return SessionV1{}, ErrRevisionConflict
	}
	if current.Status == StatusSucceeded && current.Revision > command.ExpectedRevision {
		return current, nil
	}
	digest, err := canonical.Digest(struct {
		Operation        string `json:"operation"`
		SessionID        string `json:"session_id"`
		DeploymentID     string `json:"deployment_id"`
		ExpectedRevision int64  `json:"expected_revision"`
	}{"pairing.resume", current.SessionID, current.DeploymentID, command.ExpectedRevision})
	if err != nil {
		return SessionV1{}, ErrInvalid
	}
	resuming := current
	if current.Status == StatusResuming && current.Revision == command.ExpectedRevision+1 {
		// The approval response was lost after the durable transition. Re-enter
		// only the root-journaled exact command and then finish the same revision.
	} else {
		if current.Revision != command.ExpectedRevision || !CanBeginResume(current.Status) {
			return SessionV1{}, ErrRevisionConflict
		}
		startedAt := service.now().UTC().Truncate(time.Microsecond)
		resuming, err = service.repository.BeginResume(ctx, Mutation{OwnerID: current.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest}, current.SessionID, command.ExpectedRevision, startedAt)
		if err != nil {
			if expiredAt := service.now().UTC().Truncate(time.Microsecond); !expiredAt.Before(current.ExpiresAt) {
				if !IsTerminal(current.Status) {
					if _, expireErr := service.repository.Expire(ctx, current.OwnerID, current.SessionID, expiredAt); expireErr != nil && !errors.Is(expireErr, ErrRevisionConflict) {
						return SessionV1{}, expireErr
					}
				}
				return SessionV1{}, ErrRevisionConflict
			}
			return SessionV1{}, err
		}
	}
	dispatchCtx, cancel := context.WithDeadline(ctx, resuming.ExpiresAt)
	resumeErr := service.executor.Resume(dispatchCtx, resuming)
	cancel()
	completedAt := service.now().UTC().Truncate(time.Microsecond)
	if !completedAt.Before(resuming.ExpiresAt) {
		if !IsTerminal(resuming.Status) {
			if _, expireErr := service.repository.Expire(ctx, resuming.OwnerID, resuming.SessionID, completedAt); expireErr != nil && !errors.Is(expireErr, ErrRevisionConflict) {
				return SessionV1{}, expireErr
			}
		}
		return SessionV1{}, ErrRevisionConflict
	}
	// A Worker/root-helper dispatch error is ambiguous at this boundary: the
	// root command may already have completed and journaled its receipt while
	// the transport response was lost.  Leave the durable session resuming so a
	// later call with the original expected revision can replay that exact
	// journaled command.  The immutable session deadline is the only terminal
	// outcome for an unresolved dispatch here.
	if resumeErr != nil {
		return SessionV1{}, resumeErr
	}
	status, failure := StatusSucceeded, ""
	completeKey := uuid.NewSHA1(uuid.MustParse(resuming.SessionID), []byte(command.IdempotencyKey+":"+string(status))).String()
	completeDigest, err := canonical.Digest(struct {
		Operation string `json:"operation"`
		SessionID string `json:"session_id"`
		Revision  int64  `json:"revision"`
		Status    Status `json:"status"`
	}{"pairing.complete_resume", resuming.SessionID, resuming.Revision, status})
	if err != nil {
		return SessionV1{}, ErrInvalid
	}
	completed, err := service.repository.CompleteResume(ctx, Mutation{OwnerID: resuming.OwnerID, IdempotencyKey: completeKey, RequestDigest: completeDigest},
		resuming.SessionID, resuming.Revision, status, failure, completedAt)
	if err != nil {
		if expiredAt := service.now().UTC().Truncate(time.Microsecond); !expiredAt.Before(resuming.ExpiresAt) {
			if !IsTerminal(resuming.Status) {
				if _, expireErr := service.repository.Expire(ctx, resuming.OwnerID, resuming.SessionID, expiredAt); expireErr != nil && !errors.Is(expireErr, ErrRevisionConflict) {
					return SessionV1{}, expireErr
				}
			}
			return SessionV1{}, ErrRevisionConflict
		}
		return SessionV1{}, err
	}
	returnedAt := service.now().UTC().Truncate(time.Microsecond)
	if !returnedAt.Before(completed.ExpiresAt) {
		if !IsTerminal(completed.Status) {
			if _, expireErr := service.repository.Expire(ctx, completed.OwnerID, completed.SessionID, returnedAt); expireErr != nil && !errors.Is(expireErr, ErrRevisionConflict) {
				return SessionV1{}, expireErr
			}
		}
		return SessionV1{}, ErrRevisionConflict
	}
	return completed, nil
}

func validRecipientKey(value string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		clear(raw)
		return false
	}
	_, err = ecdh.X25519().NewPublicKey(raw)
	clear(raw)
	return err == nil
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

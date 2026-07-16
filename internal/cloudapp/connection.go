package cloudapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

type FoundationBootstrapper interface {
	Establish(context.Context, []byte, awsfoundation.EstablishRequest) (awsfoundation.EstablishResult, error)
}

var errFoundationRecoveryPersistence = errors.New("Foundation recovery state could not be persisted")

type SecretBootstrapLifecycle interface {
	Get(context.Context, string, string) (secretbootstrap.SessionV1, error)
	Inspect(context.Context, string, string, uint64, secretbootstrap.SecretConsumer) (secretbootstrap.SessionV1, error)
}

// AWSConnectionService executes only a previously device-approved Foundation
// operation. Its durable operation row is written before any IAM or
// CloudFormation mutation and is the recovery key after response loss.
type AWSConnectionService struct {
	agentInstanceID string
	facts           CloudFactRepository
	identities      AWSIdentityRepository
	operations      ConnectionRepository
	secrets         SecretBootstrapLifecycle
	foundation      FoundationBootstrapper
	reaperImageURI  string
	now             func() time.Time
}

func NewAWSConnectionService(agentInstanceID, reaperImageURI string, facts CloudFactRepository, identities AWSIdentityRepository, operations ConnectionRepository, secrets SecretBootstrapLifecycle, foundation FoundationBootstrapper, now func() time.Time) (*AWSConnectionService, error) {
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed == uuid.Nil || facts == nil || identities == nil || operations == nil || secrets == nil || foundation == nil || now == nil || reaperImageURI == "" {
		return nil, ErrInvalid
	}
	return &AWSConnectionService{
		agentInstanceID: agentInstanceID, facts: facts, identities: identities, operations: operations,
		secrets: secrets, foundation: foundation, reaperImageURI: reaperImageURI, now: now,
	}, nil
}

func (service *AWSConnectionService) EstablishAWSConnection(ctx context.Context, scope MutationScope, command EstablishConnectionCommand) (Connection, error) {
	if service == nil || ctx == nil || scope.Validate() != nil || command.Validate() != nil {
		return Connection{}, ErrInvalid
	}
	now := service.now().UTC()
	plan, err := service.facts.LoadPlan(ctx, command.OwnerID, command.PlanID)
	if err != nil {
		return Connection{}, err
	}
	if plan.Status != cloudapproval.PlanApproved || plan.Revision != command.ExpectedPlanRevision {
		return Connection{}, ErrRevisionConflict
	}
	storedApproval, err := service.facts.LoadApproval(ctx, command.OwnerID, command.Approval.ApprovalID)
	if err != nil {
		return Connection{}, err
	}
	if err := validateStoredApprovalAuthorization(storedApproval, plan, command.Approval, now, false); err != nil {
		return Connection{}, err
	}
	descriptor, err := service.secrets.Get(ctx, scope.ClientID, command.BootstrapSessionID)
	if err != nil {
		return Connection{}, mapBootstrapError(err)
	}
	consumedReplay := descriptor.Status == secretbootstrap.StatusConsumed && descriptor.Revision == command.ExpectedSessionRevision+1
	if descriptor.AgentInstanceID != service.agentInstanceID || descriptor.OwnerID != command.OwnerID ||
		descriptor.TargetID != plan.ConnectionID || descriptor.Purpose != "aws_connection" ||
		!((descriptor.Status == secretbootstrap.StatusUploaded && descriptor.Revision == command.ExpectedSessionRevision) || consumedReplay) {
		return Connection{}, ErrRevisionConflict
	}
	evidence, err := service.identities.GetAWSIdentityEvidence(ctx, command.BootstrapSessionID, command.ExpectedSessionRevision)
	if err != nil {
		return Connection{}, err
	}
	if evidence.AgentInstanceID != service.agentInstanceID || evidence.OwnerID != command.OwnerID ||
		evidence.TargetID != plan.ConnectionID || evidence.Identity.Region != plan.ResourceScope.Region ||
		evidence.Identity.AccountID == "" {
		return Connection{}, ErrApprovalRequired
	}
	connectionID, err := uuid.Parse(plan.ConnectionID)
	if err != nil || connectionID == uuid.Nil {
		return Connection{}, ErrInvalid
	}
	requestHash, err := command.Digest()
	if err != nil {
		return Connection{}, ErrInvalid
	}
	operationID := deterministicFoundationOperationID(service.agentInstanceID, scope, command.IdempotencyKey)
	operation, created, err := service.operations.BeginFoundationOperation(ctx, scope, FoundationOperationIntent{
		Caller: scope, OperationID: operationID, IdempotencyKey: command.IdempotencyKey, RequestHash: requestHash,
		OwnerID: command.OwnerID, BootstrapSessionID: command.BootstrapSessionID, PlanID: command.PlanID,
		ConnectionID: connectionID.String(), AccountID: evidence.Identity.AccountID, Region: evidence.Identity.Region,
		ExpectedCredentialGeneration: 0, ExpectedSessionRevision: command.ExpectedSessionRevision, ReaperImageURI: service.reaperImageURI,
	})
	if err != nil {
		return Connection{}, err
	}
	if operation.Status == FoundationOperationSucceeded && operation.Connection != nil {
		return *operation.Connection, nil
	}
	if consumedReplay || !now.Before(descriptor.ExpiresAt) || !now.Before(evidence.ExpiresAt) {
		return Connection{}, ErrRevisionConflict
	}
	if err := validateStoredApprovalAuthorization(storedApproval, plan, command.Approval, now, true); err != nil {
		return Connection{}, err
	}
	if operation.Status == FoundationOperationDestroyBlocked {
		return Connection{}, ErrUnavailable
	}
	resume := !created && (operation.Status == FoundationOperationRunning || operation.Status == FoundationOperationFailedRetriable)
	if operation.Status != FoundationOperationRunning {
		operation, err = service.operations.MarkFoundationOperationRunning(ctx, operation.OperationID, operation.Revision)
		if err != nil {
			return Connection{}, err
		}
	}
	connection, err := service.executeFoundationOperation(ctx, operation, evidence, resume)
	return connection, err
}

// RecoverPendingFoundationOperations resumes only durable intents that were
// created after plan/device approval succeeded. It deliberately revalidates
// the original caller-bound bootstrap session and identity evidence expiry;
// the operation row is authorization to resume the exact recorded mutation,
// never authorization to broaden or replace it.
func (service *AWSConnectionService) RecoverPendingFoundationOperations(ctx context.Context, limit int) error {
	if service == nil || ctx == nil || limit < 1 || limit > 256 {
		return ErrInvalid
	}
	operations, err := service.operations.ListRecoverableFoundationOperations(ctx, limit)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		if err := service.recoverFoundationOperation(ctx, operation); err != nil {
			return err
		}
	}
	return nil
}

func (service *AWSConnectionService) recoverFoundationOperation(ctx context.Context, operation FoundationOperation) error {
	if operation.Caller.Validate() != nil || operation.ExpectedSessionRevision == 0 || operation.OperationID == "" ||
		operation.BootstrapSessionID == "" || operation.OwnerID == "" || operation.ConnectionID == "" ||
		operation.AccountID == "" || operation.Region == "" || operation.ReaperImageURI == "" ||
		(operation.Status != FoundationOperationIntentStatus && operation.Status != FoundationOperationRunning && operation.Status != FoundationOperationFailedRetriable) {
		return service.blockUnsafeRecovery(ctx, operation, "persisted Foundation recovery binding is invalid")
	}
	descriptor, err := service.secrets.Get(ctx, operation.Caller.ClientID, operation.BootstrapSessionID)
	if err != nil {
		return service.blockUnsafeRecovery(ctx, operation, "bootstrap authorization is unavailable for safe Foundation recovery")
	}
	now := service.now().UTC()
	if descriptor.AgentInstanceID != service.agentInstanceID || descriptor.OwnerID != operation.OwnerID ||
		descriptor.TargetID != operation.ConnectionID || descriptor.Purpose != "aws_connection" ||
		descriptor.Status != secretbootstrap.StatusUploaded || descriptor.Revision != operation.ExpectedSessionRevision ||
		!now.Before(descriptor.ExpiresAt) {
		return service.blockUnsafeRecovery(ctx, operation, "bootstrap authorization expired or no longer matches the Foundation intent")
	}
	evidence, err := service.identities.GetAWSIdentityEvidence(ctx, operation.BootstrapSessionID, operation.ExpectedSessionRevision)
	if err != nil || evidence.AgentInstanceID != service.agentInstanceID || evidence.BootstrapSessionID != operation.BootstrapSessionID ||
		evidence.SessionRevision != operation.ExpectedSessionRevision || evidence.OwnerID != operation.OwnerID ||
		evidence.TargetID != operation.ConnectionID || evidence.Identity.AccountID != operation.AccountID ||
		evidence.Identity.Region != operation.Region || !now.Before(evidence.ExpiresAt) {
		return service.blockUnsafeRecovery(ctx, operation, "AWS identity evidence expired or no longer matches the Foundation intent")
	}
	resume := operation.Status == FoundationOperationRunning || operation.Status == FoundationOperationFailedRetriable
	if operation.Status != FoundationOperationRunning {
		operation, err = service.operations.MarkFoundationOperationRunning(ctx, operation.OperationID, operation.Revision)
		if err != nil {
			return err
		}
	}
	_, executeErr := service.executeFoundationOperation(ctx, operation, evidence, resume)
	if errors.Is(executeErr, errFoundationRecoveryPersistence) {
		return executeErr
	}
	if executeErr != nil {
		// Provider and authorization failures have already been durably reduced
		// to failed_retriable or destroy_blocked by executeFoundationOperation.
		return nil
	}
	return nil
}

func (service *AWSConnectionService) blockUnsafeRecovery(ctx context.Context, operation FoundationOperation, reason string) error {
	var err error
	if operation.Status != FoundationOperationRunning {
		operation, err = service.operations.MarkFoundationOperationRunning(ctx, operation.OperationID, operation.Revision)
		if err != nil {
			return err
		}
	}
	_, err = service.operations.FailFoundationOperation(ctx, operation.OperationID, operation.Revision, true, safeFoundationFailure(errors.New(reason)))
	return err
}

func (service *AWSConnectionService) executeFoundationOperation(ctx context.Context, operation FoundationOperation, evidence AWSIdentityEvidence, resume bool) (Connection, error) {
	var established awsfoundation.EstablishResult
	_, err := service.secrets.Inspect(ctx, operation.Caller.ClientID, operation.BootstrapSessionID, operation.ExpectedSessionRevision, func(payload []byte) error {
		request := awsfoundation.EstablishRequest{
			AgentInstanceID: service.agentInstanceID, Region: evidence.Identity.Region,
			ConfirmedAccountID: evidence.Identity.AccountID, ExpectedCredentialGeneration: operation.ExpectedCredentialGeneration,
			ResumeExistingGeneration: resume,
			AdminAuthorization: awsfoundation.AdminAuthorization{
				SessionID: operation.OperationID, AccountID: evidence.Identity.AccountID, Region: evidence.Identity.Region,
				VerifiedAt: evidence.ObservedAt, ExpiresAt: evidence.ExpiresAt,
			},
			ReaperImageURI: operation.ReaperImageURI,
		}
		var establishErr error
		if request.ResumeExistingGeneration {
			resumePayload := append([]byte(nil), payload...)
			established, establishErr = service.foundation.Establish(ctx, resumePayload, request)
			clear(resumePayload)
			if errors.Is(establishErr, awsfoundation.ErrCredentialRevisionConflict) {
				// A prior attempt can fail before source-key persistence. Retrying
				// the initial CAS path is safe: a key from this or any other
				// operation makes CheckGeneration fail closed.
				request.ResumeExistingGeneration = false
				established, establishErr = service.foundation.Establish(ctx, payload, request)
			}
		} else {
			established, establishErr = service.foundation.Establish(ctx, payload, request)
		}
		return establishErr
	})
	if err != nil {
		blocked := errors.Is(err, awsfoundation.ErrIdentityConfirmationMismatch) || errors.Is(err, awsfoundation.ErrAdminAuthorizationRequired) ||
			errors.Is(err, awsprovider.ErrInvalidCredentials) || errors.Is(err, awsfoundation.ErrFoundationPermissionDenied)
		if _, failErr := service.operations.FailFoundationOperation(ctx, operation.OperationID, operation.Revision, blocked, safeFoundationFailure(err)); failErr != nil {
			return Connection{}, fmt.Errorf("%w: failed operation", errFoundationRecoveryPersistence)
		}
		return Connection{}, mapFoundationError(err)
	}
	if established.SourceCredentialGeneration != operation.ExpectedCredentialGeneration+1 || established.Identity.AccountID != evidence.Identity.AccountID || established.Identity.Region != evidence.Identity.Region {
		if _, failErr := service.operations.FailFoundationOperation(ctx, operation.OperationID, operation.Revision, true, "foundation read-back did not match approved identity"); failErr != nil {
			return Connection{}, fmt.Errorf("%w: read-back mismatch", errFoundationRecoveryPersistence)
		}
		return Connection{}, ErrUnavailable
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: service.agentInstanceID, Partition: established.Identity.Partition,
		AccountID: established.Identity.AccountID, Region: established.Identity.Region,
	})
	if err != nil {
		if _, failErr := service.operations.FailFoundationOperation(ctx, operation.OperationID, operation.Revision, true, "foundation role specification could not be reconstructed"); failErr != nil {
			return Connection{}, fmt.Errorf("%w: specification mismatch", errFoundationRecoveryPersistence)
		}
		return Connection{}, ErrUnavailable
	}
	controlRoleARN := fmt.Sprintf("arn:%s:iam::%s:role/%s", established.Identity.Partition, established.Identity.AccountID, spec.ControlRoleName)
	connection := Connection{
		ConnectionID: operation.ConnectionID, OwnerID: operation.OwnerID, AccountID: operation.AccountID,
		Region: operation.Region, ControlRoleARN: controlRoleARN, FoundationStack: established.Stack.StackID,
		Status: "active", Revision: 1,
	}
	completed, err := service.operations.FinalizeFoundationOperation(
		ctx, operation.OperationID, operation.Revision,
		operation.BootstrapSessionID, operation.ExpectedSessionRevision, connection,
	)
	if err != nil {
		return Connection{}, fmt.Errorf("%w: finalization", errFoundationRecoveryPersistence)
	}
	if completed.Connection == nil {
		return Connection{}, ErrUnavailable
	}
	return *completed.Connection, nil
}

func safeFoundationFailure(err error) string {
	if err == nil {
		return "Foundation operation failed"
	}
	message := strings.TrimSpace(security.RedactText(err.Error()))
	if message == "" {
		message = "Foundation operation failed"
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func validateStoredApprovalAuthorization(stored cloudapproval.ApprovalV1, approvedPlan cloudapproval.PlanV1, supplied ApprovalSignature, now time.Time, requireFresh bool) error {
	if now.IsZero() || stored.ApprovalID != supplied.ApprovalID || stored.ChallengeID != supplied.ChallengeID ||
		stored.SignerKeyID != supplied.SignerKeyID || !stored.ExpiresAt.Equal(supplied.ExpiresAt) ||
		stored.OwnerID != approvedPlan.OwnerID || stored.PlanID != approvedPlan.PlanID ||
		stored.PlanRevision+1 != approvedPlan.Revision || (requireFresh && !now.Before(stored.ExpiresAt)) {
		return ErrApprovalRequired
	}
	storedSignature, err := base64.RawURLEncoding.DecodeString(stored.Signature)
	if err != nil || !bytes.Equal(storedSignature, supplied.Signature) {
		return ErrApprovalRequired
	}
	signedPlan := approvedPlan
	signedPlan.Status = cloudapproval.PlanReadyForConfirmation
	signedPlan.Revision = stored.PlanRevision
	validationTime := now
	if !requireFresh {
		validUntil := stored.ExpiresAt
		if stored.QuoteValidUntil.Before(validUntil) {
			validUntil = stored.QuoteValidUntil
		}
		validationTime = validUntil.Add(-time.Nanosecond)
	}
	if err := stored.ValidateAgainstPlan(signedPlan, validationTime); err != nil {
		return ErrApprovalRequired
	}
	return nil
}

func deterministicFoundationOperationID(agentInstanceID string, scope MutationScope, idempotencyKey string) string {
	return uuid.NewSHA1(uuid.MustParse(agentInstanceID), []byte("aws-foundation\x00"+scope.ClientID+"\x00"+scope.CredentialID+"\x00"+idempotencyKey)).String()
}

func mapFoundationError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ErrUnavailable
	case errors.Is(err, awsfoundation.ErrIdentityConfirmationMismatch), errors.Is(err, awsfoundation.ErrAdminAuthorizationRequired),
		errors.Is(err, awsprovider.ErrInvalidCredentials), errors.Is(err, awsfoundation.ErrFoundationPermissionDenied):
		return ErrApprovalRequired
	case errors.Is(err, awsfoundation.ErrCredentialRevisionConflict):
		return ErrRevisionConflict
	default:
		return ErrUnavailable
	}
}

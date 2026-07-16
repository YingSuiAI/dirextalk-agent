package cloudapp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
)

const identityEvidenceValidity = 10 * time.Minute

var cloudRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)

type SecretBootstrapInspector interface {
	Get(context.Context, string, string) (secretbootstrap.SessionV1, error)
	Inspect(context.Context, string, string, uint64, secretbootstrap.SecretConsumer) (secretbootstrap.SessionV1, error)
}

type AWSController struct {
	agentInstanceID string
	secrets         SecretBootstrapInspector
	factory         awsprovider.BootstrapProviderFactory
	repository      AWSIdentityRepository
	now             func() time.Time
}

func NewAWSController(agentInstanceID string, secrets SecretBootstrapInspector, factory awsprovider.BootstrapProviderFactory, repository AWSIdentityRepository, now func() time.Time) (*AWSController, error) {
	if agentInstanceID == "" || secrets == nil || factory == nil || repository == nil || now == nil {
		return nil, ErrInvalid
	}
	return &AWSController{agentInstanceID: agentInstanceID, secrets: secrets, factory: factory, repository: repository, now: now}, nil
}

func (controller *AWSController) PreviewIdentity(ctx context.Context, callerClientID, sessionID string, expectedRevision uint64, region string) (AWSIdentity, error) {
	if controller == nil || secretbootstrap.ValidateClientID(callerClientID) != nil || expectedRevision == 0 || !cloudRegionPattern.MatchString(region) {
		return AWSIdentity{}, ErrInvalid
	}
	descriptor, err := controller.secrets.Get(ctx, callerClientID, sessionID)
	if err != nil {
		return AWSIdentity{}, mapBootstrapError(err)
	}
	if descriptor.AgentInstanceID != controller.agentInstanceID || descriptor.Purpose != "aws_connection" || descriptor.Status != secretbootstrap.StatusUploaded || descriptor.Revision != expectedRevision {
		return AWSIdentity{}, ErrRevisionConflict
	}
	var identity awsprovider.CallerIdentity
	_, err = controller.secrets.Inspect(ctx, callerClientID, sessionID, expectedRevision, func(payload []byte) error {
		return awsprovider.ConsumeBootstrapCredentials(payload, func(credentials *awsprovider.Credentials) error {
			provider, providerErr := controller.factory.NewBootstrapProvider(ctx, region, credentials)
			if providerErr != nil {
				return providerErr
			}
			observed, providerErr := provider.GetCallerIdentity(ctx)
			if providerErr != nil {
				return providerErr
			}
			identity = observed
			return nil
		})
	})
	if err != nil {
		return AWSIdentity{}, mapBootstrapError(err)
	}
	if identity.AccountID == "" || identity.ARN == "" || identity.UserID == "" || identity.Region != region {
		return AWSIdentity{}, ErrUnavailable
	}
	now := controller.now().UTC()
	if now.IsZero() || !now.Before(descriptor.ExpiresAt) {
		return AWSIdentity{}, ErrQuoteExpired
	}
	expiresAt := now.Add(identityEvidenceValidity)
	if descriptor.ExpiresAt.Before(expiresAt) {
		expiresAt = descriptor.ExpiresAt
	}
	result := AWSIdentity{
		AccountID: identity.AccountID, PrincipalARN: identity.ARN, PrincipalID: identity.UserID,
		Region: identity.Region, RootIdentity: identity.ARN == fmt.Sprintf("arn:%s:iam::%s:root", identity.Partition, identity.AccountID),
	}
	evidence := AWSIdentityEvidence{
		BootstrapSessionID: sessionID, SessionRevision: expectedRevision, AgentInstanceID: controller.agentInstanceID,
		OwnerID: descriptor.OwnerID, TargetID: descriptor.TargetID, Identity: result, ObservedAt: now, ExpiresAt: expiresAt,
	}
	if err := controller.repository.PutAWSIdentityEvidence(ctx, evidence); err != nil {
		return AWSIdentity{}, err
	}
	return result, nil
}

func mapBootstrapError(err error) error {
	switch {
	case errors.Is(err, secretbootstrap.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, secretbootstrap.ErrCallerMismatch):
		return ErrForbidden
	case errors.Is(err, secretbootstrap.ErrRevisionConflict):
		return ErrRevisionConflict
	case errors.Is(err, secretbootstrap.ErrInvalidContext), errors.Is(err, secretbootstrap.ErrInvalidEnvelope),
		errors.Is(err, awsprovider.ErrInvalidCredentials), errors.Is(err, awsprovider.ErrCredentialRejected),
		errors.Is(err, awsprovider.ErrPermissionDenied):
		return ErrInvalid
	default:
		return ErrUnavailable
	}
}

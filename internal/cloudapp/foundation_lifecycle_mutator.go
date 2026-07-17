package cloudapp

import (
	"context"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
)

type foundationLifecycleBootstrapper interface {
	Mutate(context.Context, []byte, awsfoundation.LifecycleRequest) (awsfoundation.LifecycleResult, error)
}

type AWSFoundationLifecycleMutator struct {
	bootstrapper foundationLifecycleBootstrapper
}

func NewAWSFoundationLifecycleMutator(bootstrapper foundationLifecycleBootstrapper) (*AWSFoundationLifecycleMutator, error) {
	if bootstrapper == nil {
		return nil, cloudfoundation.ErrInvalid
	}
	return &AWSFoundationLifecycleMutator{bootstrapper: bootstrapper}, nil
}

func (mutator *AWSFoundationLifecycleMutator) MutateFoundation(ctx context.Context, payload []byte, operation cloudfoundation.OperationV1) (cloudfoundation.ExecutionResult, error) {
	if mutator == nil || ctx == nil || operation.Challenge.Validate() != nil {
		return cloudfoundation.ExecutionResult{}, cloudfoundation.ErrInvalid
	}
	scope := operation.Challenge.Scope
	action := awsfoundation.LifecycleAction(scope.Action)
	result, err := mutator.bootstrapper.Mutate(ctx, payload, awsfoundation.LifecycleRequest{Action: action, OperationID: operation.Challenge.OperationID,
		AgentInstanceID: scope.AgentInstanceID, Region: scope.Region, ConfirmedAccountID: scope.AccountID,
		ExpectedCredentialGeneration: scope.ExpectedCredentialGeneration, Recovery: operation.Recovery,
		AdoptExistingGeneration: operation.AdoptExisting,
		AdminAuthorization: awsfoundation.AdminAuthorization{SessionID: operation.Challenge.OperationID, AccountID: scope.AccountID, Region: scope.Region,
			VerifiedAt: scope.IdentityObservedAt, ExpiresAt: scope.IdentityExpiresAt}, TemplateDigest: scope.FoundationTemplateDigest, ReaperImageURI: scope.ReaperImageURI})
	if err != nil {
		if errors.Is(err, awsfoundation.ErrFoundationDestroyBlocked) {
			return cloudfoundation.ExecutionResult{}, fmt.Errorf("%w: %v", cloudfoundation.ErrProviderDestroyBlocked, err)
		}
		if errors.Is(err, awsfoundation.ErrAdminAuthorizationRequired) || errors.Is(err, awsfoundation.ErrIdentityConfirmationMismatch) ||
			errors.Is(err, awsfoundation.ErrCredentialRevisionConflict) || errors.Is(err, awsfoundation.ErrCredentialEnvelope) {
			if scope.Action == cloudfoundation.ActionTeardown || scope.Action == cloudfoundation.ActionRemediate {
				return cloudfoundation.ExecutionResult{}, cloudfoundation.ErrProviderDestroyBlocked
			}
			return cloudfoundation.ExecutionResult{}, cloudfoundation.ErrProviderAuthorizationExpired
		}
		return cloudfoundation.ExecutionResult{}, err
	}
	if result.Destroyed {
		return cloudfoundation.ExecutionResult{ConnectionStatus: "destroyed", CredentialGeneration: result.CredentialGeneration}, nil
	}
	spec, specErr := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: scope.AgentInstanceID, Partition: result.Identity.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if specErr != nil {
		return cloudfoundation.ExecutionResult{}, errors.New("Foundation role read-back could not be reconstructed")
	}
	return cloudfoundation.ExecutionResult{ConnectionStatus: "active", FoundationStackID: result.Stack.StackID,
		ControlRoleARN: fmt.Sprintf("arn:%s:iam::%s:role/%s", result.Identity.Partition, scope.AccountID, spec.ControlRoleName), CredentialGeneration: result.CredentialGeneration}, nil
}

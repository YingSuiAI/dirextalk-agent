package cloudapp

import (
	"context"
	"errors"
	"strings"

	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

// FoundationLifecycleMutator is the only provider-capability surface exposed
// to the lifecycle executor. The immutable signed scope is the provider
// request; implementations cannot accept an operator credential chain or
// caller-selected AWS arguments.
type FoundationLifecycleMutator interface {
	MutateFoundation(context.Context, []byte, cloudfoundation.OperationV1) (cloudfoundation.ExecutionResult, error)
}

type FoundationLifecycleProvider struct {
	secrets SecretBootstrapLifecycle
	mutator FoundationLifecycleMutator
}

func NewFoundationLifecycleProvider(secrets SecretBootstrapLifecycle, mutator FoundationLifecycleMutator) (*FoundationLifecycleProvider, error) {
	if secrets == nil || mutator == nil {
		return nil, cloudfoundation.ErrInvalid
	}
	return &FoundationLifecycleProvider{secrets: secrets, mutator: mutator}, nil
}

func (provider *FoundationLifecycleProvider) ExecuteFoundation(ctx context.Context, operation cloudfoundation.OperationV1) (cloudfoundation.ExecutionResult, error) {
	if provider == nil || ctx == nil || operation.Caller.Validate() != nil || operation.Challenge.Validate() != nil ||
		(operation.Status != cloudfoundation.StatusRunning && operation.Status != cloudfoundation.StatusFailedRetriable) {
		return cloudfoundation.ExecutionResult{}, cloudfoundation.ErrInvalid
	}
	var result cloudfoundation.ExecutionResult
	var providerErr error
	_, err := provider.secrets.Inspect(ctx, operation.Caller.ClientID, operation.Challenge.Scope.BootstrapSessionID,
		operation.Challenge.Scope.ExpectedBootstrapRevision, func(payload []byte) error {
			result, providerErr = provider.mutator.MutateFoundation(ctx, payload, operation)
			return providerErr
		})
	if err != nil {
		if errors.Is(providerErr, cloudfoundation.ErrProviderDestroyBlocked) {
			return cloudfoundation.ExecutionResult{}, cloudfoundation.ErrProviderDestroyBlocked
		}
		if errors.Is(providerErr, cloudfoundation.ErrProviderAuthorizationExpired) {
			return cloudfoundation.ExecutionResult{}, cloudfoundation.ErrProviderAuthorizationExpired
		}
		if errors.Is(err, secretbootstrap.ErrExpired) || errors.Is(err, secretbootstrap.ErrStateConflict) || errors.Is(err, secretbootstrap.ErrKeyUnavailable) {
			if operation.Challenge.Scope.Action == cloudfoundation.ActionTeardown || operation.Challenge.Scope.Action == cloudfoundation.ActionRemediate {
				return cloudfoundation.ExecutionResult{}, cloudfoundation.ErrProviderDestroyBlocked
			}
			return cloudfoundation.ExecutionResult{}, cloudfoundation.ErrProviderAuthorizationExpired
		}
		if providerErr != nil {
			err = providerErr
		}
		message := strings.TrimSpace(security.RedactText(err.Error()))
		if message == "" {
			message = "Foundation provider failed"
		}
		return cloudfoundation.ExecutionResult{}, errors.New(message)
	}
	if !validFoundationExecutionResult(operation.Challenge.Scope, result) {
		return cloudfoundation.ExecutionResult{}, errors.New("Foundation provider read-back did not match approved scope")
	}
	return result, nil
}

func validFoundationExecutionResult(scope cloudfoundation.ScopeV1, result cloudfoundation.ExecutionResult) bool {
	switch scope.Action {
	case cloudfoundation.ActionEstablish:
		return result.ConnectionStatus == "active" && result.FoundationStackID != "" && result.ControlRoleARN != "" && result.CredentialGeneration == 1
	case cloudfoundation.ActionUpgrade:
		return result.ConnectionStatus == "active" && result.FoundationStackID != "" && result.ControlRoleARN != "" && result.CredentialGeneration == scope.ExpectedCredentialGeneration
	case cloudfoundation.ActionTeardown, cloudfoundation.ActionRemediate:
		return result.ConnectionStatus == "destroyed" && result.FoundationStackID == "" && result.ControlRoleARN == "" && result.CredentialGeneration == scope.ExpectedCredentialGeneration
	default:
		return false
	}
}

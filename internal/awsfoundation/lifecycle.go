package awsfoundation

import (
	"context"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
)

type LifecycleAction string

const (
	LifecycleEstablish LifecycleAction = "establish"
	LifecycleUpgrade   LifecycleAction = "upgrade"
	LifecycleTeardown  LifecycleAction = "teardown"
	LifecycleRemediate LifecycleAction = "remediate_destroy_blocked"
)

type LifecycleRequest struct {
	Action                       LifecycleAction
	OperationID                  string
	AgentInstanceID              string
	Region                       string
	ConfirmedAccountID           string
	ExpectedCredentialGeneration uint64
	Recovery                     bool
	AdoptExistingGeneration      bool
	AdminAuthorization           AdminAuthorization
	TemplateDigest               string
	ReaperImageURI               string
}

type LifecycleResult struct {
	Identity             awsprovider.CallerIdentity
	CredentialGeneration uint64
	Stack                awsprovider.FoundationStackReceipt
	Destroyed            bool
}

func (bootstrapper *Bootstrapper) Mutate(ctx context.Context, payload []byte, request LifecycleRequest) (LifecycleResult, error) {
	if bootstrapper == nil || request.TemplateDigest != bootstrapper.templateHash {
		zeroBytes(payload)
		return LifecycleResult{}, ErrFoundationBootstrap
	}
	if request.Action == LifecycleEstablish {
		result, err := bootstrapper.Establish(ctx, payload, EstablishRequest{AgentInstanceID: request.AgentInstanceID, Region: request.Region,
			ConfirmedAccountID: request.ConfirmedAccountID, ExpectedCredentialGeneration: request.ExpectedCredentialGeneration,
			ResumeExistingGeneration: request.Recovery, AdoptExistingGeneration: request.AdoptExistingGeneration,
			AdminAuthorization: request.AdminAuthorization, ReaperImageURI: request.ReaperImageURI})
		return LifecycleResult{Identity: result.Identity, CredentialGeneration: result.SourceCredentialGeneration, Stack: result.Stack}, err
	}
	bootstrapper.mu.Lock()
	defer bootstrapper.mu.Unlock()
	if !idPattern.MatchString(request.OperationID) || !idPattern.MatchString(request.AgentInstanceID) || !accountPattern.MatchString(request.ConfirmedAccountID) ||
		!regionPattern.MatchString(request.Region) || !validImmutableImage(request.ReaperImageURI) {
		zeroBytes(payload)
		return LifecycleResult{}, ErrFoundationBootstrap
	}
	var result LifecycleResult
	var lifecycleErr error
	err := awsprovider.ConsumeBootstrapCredentials(payload, func(credentials *awsprovider.Credentials) error {
		provider, err := bootstrapper.factory.NewBootstrapProvider(ctx, request.Region, credentials)
		if err != nil {
			lifecycleErr = ErrFoundationPermissionDenied
			return err
		}
		lifecycle, ok := provider.(awsprovider.FoundationLifecycleProvider)
		if !ok {
			lifecycleErr = ErrFoundationBootstrap
			return lifecycleErr
		}
		identity, err := provider.GetCallerIdentity(ctx)
		if err != nil {
			lifecycleErr = ErrFoundationPermissionDenied
			return err
		}
		if identity.AccountID != request.ConfirmedAccountID || identity.Region != request.Region || !validIdentity(identity) {
			lifecycleErr = ErrIdentityConfirmationMismatch
			return lifecycleErr
		}
		binding := SourceCredentialBinding{AgentInstanceID: request.AgentInstanceID, AccountID: identity.AccountID, Region: identity.Region}
		if !validAuthorization(binding, request.AdminAuthorization, bootstrapper.now()) {
			lifecycleErr = ErrAdminAuthorizationRequired
			return lifecycleErr
		}
		spec, err := BuildSpec(SpecInput{AgentInstanceID: request.AgentInstanceID, Partition: identity.Partition, AccountID: identity.AccountID, Region: identity.Region})
		if err != nil {
			lifecycleErr = ErrFoundationBootstrap
			return err
		}
		stackRequest := foundationStackRequest(spec, request.ReaperImageURI, bootstrapper.templateBody, bootstrapper.templateHash, string(request.Action), request.OperationID)
		switch request.Action {
		case LifecycleUpgrade:
			if err := bootstrapper.vault.CheckGeneration(ctx, binding, request.ExpectedCredentialGeneration); err != nil {
				lifecycleErr = err
				return err
			}
			if err := lifecycle.UpdateBootstrapPolicies(ctx, spec); err != nil {
				lifecycleErr = ErrFoundationPermissionDenied
				return err
			}
			receipt, err := lifecycle.UpdateFoundationStack(ctx, stackRequest)
			if err != nil {
				lifecycleErr = ErrFoundationBootstrap
				return err
			}
			result = LifecycleResult{Identity: identity, CredentialGeneration: request.ExpectedCredentialGeneration, Stack: receipt}
		case LifecycleTeardown, LifecycleRemediate:
			if err := bootstrapper.vault.CheckGeneration(ctx, binding, request.ExpectedCredentialGeneration); err != nil && !(request.Recovery && errors.Is(err, ErrCredentialEnvelope)) {
				lifecycleErr = err
				return err
			}
			// A fresh admin bootstrap must be able to repair an older or
			// partially removed Foundation execution role before CloudFormation
			// performs the destructive transition. This updates policies only;
			// it never creates or rotates the locally persisted source key.
			if err := lifecycle.UpdateBootstrapPolicies(ctx, spec); err != nil {
				lifecycleErr = ErrFoundationPermissionDenied
				return err
			}
			receipt, err := lifecycle.DeleteFoundationStack(ctx, stackRequest)
			if err != nil {
				if errors.Is(err, awsprovider.ErrFoundationStackFailed) {
					lifecycleErr = fmt.Errorf("%w: stack deletion failed", ErrFoundationDestroyBlocked)
				} else {
					lifecycleErr = ErrFoundationBootstrap
				}
				return lifecycleErr
			}
			if err := lifecycle.DeleteBootstrapIdentity(ctx, spec); err != nil {
				lifecycleErr = fmt.Errorf("%w: bootstrap identity removal incomplete", ErrFoundationDestroyBlocked)
				return lifecycleErr
			}
			if err := bootstrapper.vault.Delete(ctx, binding, request.ExpectedCredentialGeneration, request.AdminAuthorization); err != nil && !errors.Is(err, ErrCredentialNotFound) {
				lifecycleErr = fmt.Errorf("%w: credential removal incomplete", ErrFoundationDestroyBlocked)
				return lifecycleErr
			}
			result = LifecycleResult{Identity: identity, CredentialGeneration: request.ExpectedCredentialGeneration, Stack: receipt, Destroyed: true}
		default:
			lifecycleErr = ErrFoundationBootstrap
			return lifecycleErr
		}
		return nil
	})
	if err != nil {
		if lifecycleErr != nil {
			return LifecycleResult{}, lifecycleErr
		}
		return LifecycleResult{}, ErrFoundationPermissionDenied
	}
	return result, nil
}

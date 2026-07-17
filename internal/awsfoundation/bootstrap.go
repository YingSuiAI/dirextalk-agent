package awsfoundation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

var (
	ErrFoundationBootstrap          = errors.New("AWS foundation bootstrap failed")
	ErrFoundationPermissionDenied   = errors.New("AWS foundation bootstrap permission denied")
	ErrIdentityConfirmationMismatch = errors.New("AWS account or Region did not match confirmation")
	ErrFoundationDestroyBlocked     = errors.New("AWS Foundation teardown is incomplete")
	immutableImagePattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*:[vV]?[0-9]+\.[0-9]+\.[0-9]+-(?:alpha|beta|rc)(?:[.-][A-Za-z0-9][A-Za-z0-9.-]*)?@sha256:[a-f0-9]{64}$`)
)

type EstablishRequest struct {
	AgentInstanceID              string
	Region                       string
	ConfirmedAccountID           string
	ExpectedCredentialGeneration uint64
	ResumeExistingGeneration     bool
	AdoptExistingGeneration      bool
	AdminAuthorization           AdminAuthorization
	ReaperImageURI               string
}

type EstablishResult struct {
	Identity                   awsprovider.CallerIdentity
	SourceCredentialGeneration uint64
	Stack                      awsprovider.FoundationStackReceipt
}

type Bootstrapper struct {
	factory      awsprovider.BootstrapProviderFactory
	vault        *CredentialVault
	templateBody string
	templateHash string
	now          func() time.Time
	mu           sync.Mutex
}

func NewBootstrapper(factory awsprovider.BootstrapProviderFactory, vault *CredentialVault, template []byte, now func() time.Time) (*Bootstrapper, error) {
	if factory == nil || vault == nil || now == nil || ValidateTemplate(template) != nil {
		return nil, ErrFoundationBootstrap
	}
	hash := sha256.Sum256(template)
	return &Bootstrapper{factory: factory, vault: vault, templateBody: string(template), templateHash: "sha256:" + hex.EncodeToString(hash[:]), now: now}, nil
}

func (bootstrapper *Bootstrapper) Establish(ctx context.Context, payload []byte, request EstablishRequest) (EstablishResult, error) {
	if bootstrapper == nil {
		zeroBytes(payload)
		return EstablishResult{}, ErrFoundationBootstrap
	}
	bootstrapper.mu.Lock()
	defer bootstrapper.mu.Unlock()
	if !idPattern.MatchString(request.AgentInstanceID) || !accountPattern.MatchString(request.ConfirmedAccountID) || !regionPattern.MatchString(request.Region) ||
		!validImmutableImage(request.ReaperImageURI) || (request.AdoptExistingGeneration && !request.ResumeExistingGeneration) {
		zeroBytes(payload)
		return EstablishResult{}, ErrFoundationBootstrap
	}
	var result EstablishResult
	var establishErr error
	err := awsprovider.ConsumeBootstrapCredentials(payload, func(credentials *awsprovider.Credentials) error {
		provider, err := bootstrapper.factory.NewBootstrapProvider(ctx, request.Region, credentials)
		if err != nil {
			establishErr = ErrFoundationPermissionDenied
			return err
		}
		identity, err := provider.GetCallerIdentity(ctx)
		if err != nil {
			establishErr = ErrFoundationPermissionDenied
			return err
		}
		if identity.AccountID != request.ConfirmedAccountID || identity.Region != request.Region || !validIdentity(identity) {
			establishErr = ErrIdentityConfirmationMismatch
			return establishErr
		}
		binding := SourceCredentialBinding{AgentInstanceID: request.AgentInstanceID, AccountID: identity.AccountID, Region: identity.Region}
		if !validAuthorization(binding, request.AdminAuthorization, bootstrapper.now()) {
			establishErr = ErrAdminAuthorizationRequired
			return establishErr
		}
		spec, err := BuildSpec(SpecInput{AgentInstanceID: request.AgentInstanceID, Partition: identity.Partition, AccountID: identity.AccountID, Region: identity.Region})
		if err != nil {
			establishErr = ErrFoundationBootstrap
			return err
		}
		var generation uint64
		resumeExisting := request.ResumeExistingGeneration
		if resumeExisting {
			var record EncryptedSourceCredential
			if request.AdoptExistingGeneration {
				record, err = bootstrapper.vault.AdoptExistingGeneration(ctx, binding, request.ExpectedCredentialGeneration)
			} else {
				record, err = bootstrapper.vault.ResumeExistingGeneration(ctx, binding, request.ExpectedCredentialGeneration, request.AdminAuthorization.SessionID)
			}
			if request.AdoptExistingGeneration && errors.Is(err, ErrCredentialNotFound) {
				resumeExisting = false
			} else if err != nil {
				establishErr = err
				return err
			} else {
				generation = record.Generation
			}
		}
		if !resumeExisting {
			if err := bootstrapper.vault.CheckGeneration(ctx, binding, request.ExpectedCredentialGeneration); err != nil {
				establishErr = err
				return err
			}
			source, err := provider.EnsureBootstrapIdentity(ctx, spec)
			if err != nil {
				if errors.Is(err, awsprovider.ErrSourceCredentialRemediationRequired) {
					establishErr = ErrAdminAuthorizationRequired
				} else {
					establishErr = ErrFoundationPermissionDenied
				}
				return err
			}
			defer source.Wipe()
			record, err := bootstrapper.vault.SealAndStore(ctx, binding, request.ExpectedCredentialGeneration, request.AdminAuthorization, source)
			if err != nil {
				establishErr = err
				return err
			}
			generation = record.Generation
		}
		stackRequest := foundationStackRequest(spec, request.ReaperImageURI, bootstrapper.templateBody, bootstrapper.templateHash, string(LifecycleEstablish), request.AdminAuthorization.SessionID)
		receipt, err := provider.CreateFoundationStack(ctx, stackRequest)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				establishErr = err
				return err
			}
			establishErr = ErrFoundationBootstrap
			return err
		}
		if receipt.StackID == "" || receipt.Status != awsprovider.FoundationStackReadyStatus || receipt.ObservedAt.IsZero() {
			establishErr = ErrFoundationBootstrap
			return establishErr
		}
		result = EstablishResult{Identity: identity, SourceCredentialGeneration: generation, Stack: receipt}
		return nil
	})
	if err != nil {
		if establishErr != nil {
			return EstablishResult{}, establishErr
		}
		if errors.Is(err, awsprovider.ErrInvalidCredentials) {
			return EstablishResult{}, awsprovider.ErrInvalidCredentials
		}
		return EstablishResult{}, ErrFoundationPermissionDenied
	}
	return result, nil
}

func validIdentity(identity awsprovider.CallerIdentity) bool {
	if !accountPattern.MatchString(identity.AccountID) || !regionPattern.MatchString(identity.Region) || identity.UserID == "" {
		return false
	}
	parsed, err := arn.Parse(identity.ARN)
	if err != nil || parsed.Partition != identity.Partition || parsed.AccountID != identity.AccountID || (parsed.Service != "iam" && parsed.Service != "sts") || parsed.Resource == "" {
		return false
	}
	switch identity.Partition {
	case "aws", "aws-cn", "aws-us-gov":
		return true
	default:
		return false
	}
}

func validImmutableImage(value string) bool {
	if !immutableImagePattern.MatchString(value) {
		return false
	}
	lower := strings.ToLower(value)
	return !strings.Contains(lower, ":latest@") && !strings.Contains(lower, ":v1.0.3@")
}

func foundationStackRequest(spec awsprovider.BootstrapIdentitySpec, reaperImageURI, templateBody, templateHash, action, operationID string) awsprovider.FoundationStackRequest {
	roleARN := "arn:" + spec.Partition + ":iam::" + spec.AccountID + ":role/" + spec.FoundationRoleName
	tokenHash := sha256.Sum256([]byte(strings.Join([]string{spec.AgentInstanceID, spec.AccountID, spec.Region, templateHash, reaperImageURI, action, operationID}, "\x00")))
	return awsprovider.FoundationStackRequest{
		StackName: spec.StackName, Region: spec.Region, AccountID: spec.AccountID, FoundationRoleARN: roleARN,
		ClientToken: "dtx-" + hex.EncodeToString(tokenHash[:16]), TemplateBody: templateBody, TemplateSHA256: templateHash,
		Parameters: map[string]string{
			"AgentInstanceId": spec.AgentInstanceID, "ControlRoleName": spec.ControlRoleName,
			"WorkerRoleName": spec.WorkerRoleName, "WorkerProfileName": spec.WorkerProfileName,
			"ReaperRoleName": spec.ReaperRoleName, "ArtifactBucketName": spec.ArtifactBucketName,
			"ManifestTableName": spec.ManifestTableName, "WorkerLogGroupName": spec.WorkerLogGroupName,
			"ReaperLogGroupName": spec.ReaperLogGroupName, "ReaperFunctionName": spec.ReaperFunctionName,
			"ReaperScheduleName": spec.ReaperScheduleName, "SecretNamespace": spec.SecretNamespace,
			"ReaperImageUri": reaperImageURI,
		},
		Tags: spec.Tags, TerminationProtect: true,
	}
}

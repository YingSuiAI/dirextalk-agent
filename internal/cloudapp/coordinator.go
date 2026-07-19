package cloudapp

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/google/uuid"
)

type QuoteEngine interface {
	Quote(context.Context, QuoteExecutionRequest, recipe.RecipeV1) (cloudquote.QuoteV1, error)
}

type QuoteExecutionRequest struct {
	Pricing                 cloudquote.RequestV1
	CallerClientID          string
	BootstrapSessionID      string
	ExpectedSessionRevision uint64
}

type ApprovalEngine interface {
	DraftChallenge(context.Context, cloudapproval.PlanV1, cloudquote.QuoteV1, string) (cloudapproval.ChallengeV1, error)
	Verify(context.Context, cloudapproval.ApprovalV1, cloudapproval.PlanV1, cloudquote.QuoteV1) error
}

type IdentityPreviewer interface {
	PreviewIdentity(context.Context, string, string, uint64, string) (AWSIdentityEvidence, error)
}

type ConnectionEstablisher interface {
	EstablishAWSConnection(context.Context, MutationScope, EstablishConnectionCommand) (Connection, error)
}

// Service is the application coordinator shared by gRPC and trusted native
// Skills. It creates facts and delegates typed provider mutations; it never
// receives an approval signing key or an AWS SDK client.
type Service struct {
	agentInstanceID    string
	facts              CloudFactRepository
	recipes            RecipeResolver
	quotes             QuoteEngine
	approvals          ApprovalEngine
	identity           IdentityPreviewer
	connections        ConnectionEstablisher
	launcher           DeploymentLauncher
	capabilities       Capabilities
	workerControlReady bool
	now                func() time.Time
}

type ServiceOption func(*Service) error

func WithDeploymentLauncher(launcher DeploymentLauncher) ServiceOption {
	return func(service *Service) error {
		if launcher == nil {
			return ErrInvalid
		}
		service.launcher = launcher
		return nil
	}
}

func NewService(agentInstanceID string, facts CloudFactRepository, recipes RecipeResolver, quotes QuoteEngine, approvals ApprovalEngine, identity IdentityPreviewer, connections ConnectionEstablisher, capabilities Capabilities, now func() time.Time, options ...ServiceOption) (*Service, error) {
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed == uuid.Nil || facts == nil || recipes == nil || quotes == nil || approvals == nil || now == nil {
		return nil, ErrInvalid
	}
	service := &Service{
		agentInstanceID: agentInstanceID, facts: facts, recipes: recipes, quotes: quotes, approvals: approvals,
		identity: identity, connections: connections, capabilities: capabilities, workerControlReady: true, now: now,
	}
	for _, option := range options {
		if option == nil || option(service) != nil {
			return nil, ErrInvalid
		}
	}
	return service, nil
}

// NewStagedAWSService exposes only the read-only identity preview required to
// prepare a Foundation. Quote, approval, Foundation, launch, and provider
// mutation paths stay closed until the immutable Worker Control PrivateLink
// endpoint/service pair is present and the full cloud composition is rebuilt.
func NewStagedAWSService(agentInstanceID string, identity IdentityPreviewer) (*Service, error) {
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed == uuid.Nil || identity == nil {
		return nil, ErrInvalid
	}
	return &Service{
		agentInstanceID: agentInstanceID,
		identity:        identity,
		capabilities:    Capabilities{AWS: true, DirectSTS: true},
	}, nil
}

func (service *Service) Capabilities(context.Context) Capabilities { return service.capabilities }

func (service *Service) WorkerControlPrivateLinkReady() bool {
	return service != nil && service.workerControlReady
}

func (service *Service) PreviewAWSIdentity(ctx context.Context, scope MutationScope, sessionID string, expectedRevision uint64, region string) (AWSIdentityEvidence, error) {
	if service == nil || service.identity == nil || scope.Validate() != nil {
		return AWSIdentityEvidence{}, ErrUnavailable
	}
	return service.identity.PreviewIdentity(ctx, scope.ClientID, sessionID, expectedRevision, region)
}

func (service *Service) CreateQuote(ctx context.Context, scope MutationScope, command CreateQuoteCommand) (cloudquote.QuoteV1, error) {
	if err := service.workerControlCapabilityError(); err != nil {
		return cloudquote.QuoteV1{}, err
	}
	if service == nil || ctx == nil || scope.Validate() != nil || command.Validate() != nil {
		return cloudquote.QuoteV1{}, ErrInvalid
	}
	first := command.Scopes[0]
	for _, candidate := range command.Scopes {
		if candidate.AgentInstanceID != service.agentInstanceID || candidate.OwnerID != first.OwnerID || candidate.Recipe != first.Recipe {
			return cloudquote.QuoteV1{}, ErrInvalid
		}
	}
	boundRecipe, err := service.recipes.ResolveRecipe(ctx, first.OwnerID, first.Recipe.RecipeID, first.Recipe.Digest)
	if err != nil {
		return cloudquote.QuoteV1{}, mapRecipeError(err)
	}
	quoteID, err := uuid.NewV7()
	if err != nil {
		return cloudquote.QuoteV1{}, ErrUnavailable
	}
	created, err := service.quotes.Quote(ctx, QuoteExecutionRequest{
		Pricing: cloudquote.RequestV1{
			QuoteID: quoteID.String(), Scopes: command.Scopes, Usage: command.Usage, SpotQualification: command.SpotQualification,
		},
		CallerClientID: scope.ClientID, BootstrapSessionID: command.BootstrapSessionID, ExpectedSessionRevision: command.ExpectedSessionRevision,
	}, boundRecipe)
	if err != nil {
		if errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) ||
			errors.Is(err, ErrRevisionConflict) || errors.Is(err, ErrApprovalRequired) || errors.Is(err, ErrQuoteExpired) {
			return cloudquote.QuoteV1{}, err
		}
		return cloudquote.QuoteV1{}, ErrUnavailable
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return cloudquote.QuoteV1{}, ErrInvalid
	}
	return service.facts.PersistQuote(ctx, scope, command.IdempotencyKey, requestDigest, created)
}

func (service *Service) GetQuote(ctx context.Context, ownerID, quoteID string) (cloudquote.QuoteV1, error) {
	if err := service.workerControlCapabilityError(); err != nil {
		return cloudquote.QuoteV1{}, err
	}
	if service == nil || ctx == nil {
		return cloudquote.QuoteV1{}, ErrInvalid
	}
	return service.facts.LoadQuote(ctx, ownerID, quoteID)
}

func (service *Service) CreatePlan(ctx context.Context, scope MutationScope, command CreatePlanCommand) (cloudapproval.PlanV1, error) {
	if err := service.workerControlCapabilityError(); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if service == nil || ctx == nil || scope.Validate() != nil || command.Validate() != nil {
		return cloudapproval.PlanV1{}, ErrInvalid
	}
	priced, err := service.facts.LoadQuote(ctx, command.CurrentScope.OwnerID, command.QuoteID)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	planID, err := uuid.NewV7()
	if err != nil {
		return cloudapproval.PlanV1{}, ErrUnavailable
	}
	plan, err := BuildPlan(service.agentInstanceID, planID.String(), priced, command.CandidateID, command.CurrentScope, service.now().UTC())
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	return service.facts.PersistPlan(ctx, scope, command.IdempotencyKey, plan)
}

func (service *Service) GetPlan(ctx context.Context, ownerID, planID string) (cloudapproval.PlanV1, error) {
	if err := service.workerControlCapabilityError(); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if service == nil || ctx == nil {
		return cloudapproval.PlanV1{}, ErrInvalid
	}
	return service.facts.LoadPlan(ctx, ownerID, planID)
}

func (service *Service) CreateApprovalChallenge(ctx context.Context, scope MutationScope, command CreateChallengeCommand) (Challenge, error) {
	if err := service.workerControlCapabilityError(); err != nil {
		return Challenge{}, err
	}
	if service == nil || ctx == nil || scope.Validate() != nil || command.Validate() != nil {
		return Challenge{}, ErrInvalid
	}
	plan, err := service.facts.LoadPlan(ctx, command.OwnerID, command.PlanID)
	if err != nil {
		return Challenge{}, err
	}
	if plan.Revision != command.ExpectedRevision {
		return Challenge{}, ErrRevisionConflict
	}
	priced, err := service.facts.LoadQuote(ctx, command.OwnerID, plan.Quote.QuoteID)
	if err != nil {
		return Challenge{}, err
	}
	draft, err := service.approvals.DraftChallenge(ctx, plan, priced, command.SignerKeyID)
	if err != nil {
		return Challenge{}, mapApprovalError(err)
	}
	stored, err := service.facts.PersistChallenge(ctx, scope, command.IdempotencyKey, draft)
	if err != nil {
		return Challenge{}, err
	}
	approvalID := deterministicApprovalID(service.agentInstanceID, scope, command.IdempotencyKey)
	unsigned, err := cloudapproval.NewApprovalV1(plan, approvalID, stored.ChallengeID, stored.SignerKeyID, stored.ExpiresAt)
	if err != nil {
		return Challenge{}, ErrInvalid
	}
	payload, err := unsigned.SigningPayload()
	if err != nil {
		return Challenge{}, ErrInvalid
	}
	return Challenge{ApprovalID: approvalID, Challenge: stored, ExpiresAt: stored.ExpiresAt, SigningCBOR: payload}, nil
}

func (service *Service) ApprovePlan(ctx context.Context, scope MutationScope, command ApprovePlanCommand) (cloudapproval.PlanV1, error) {
	if err := service.workerControlCapabilityError(); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if service == nil || ctx == nil || scope.Validate() != nil || command.Validate() != nil {
		return cloudapproval.PlanV1{}, ErrInvalid
	}
	plan, err := service.facts.LoadPlan(ctx, command.OwnerID, command.PlanID)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	challenge, err := service.facts.LoadChallenge(ctx, command.Approval.ChallengeID)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if plan.Status == cloudapproval.PlanApproved && plan.Revision == command.ExpectedRevision+1 {
		stored, loadErr := service.facts.LoadApproval(ctx, command.OwnerID, command.Approval.ApprovalID)
		if loadErr != nil {
			return cloudapproval.PlanV1{}, loadErr
		}
		now := service.now().UTC()
		if challenge.ConsumedAt == nil || challenge.Revision < 2 || validateStoredApprovalAuthorization(stored, plan, command.Approval, now, false) != nil {
			return cloudapproval.PlanV1{}, ErrApprovalRequired
		}
		approved, persistErr := service.facts.PersistApproval(
			ctx, scope, command.IdempotencyKey, challenge.Revision-1, command.ExpectedRevision, stored,
		)
		if persistErr != nil {
			return cloudapproval.PlanV1{}, persistErr
		}
		approvalIsFresh := now.Before(stored.ExpiresAt) && now.Before(stored.QuoteValidUntil)
		if service.launcher != nil && approvalIsFresh {
			if launchErr := service.launcher.SubmitApprovedPlan(ctx, scope, SubmitApprovedPlanCommand{OwnerID: command.OwnerID, PlanID: command.PlanID, ApprovalID: stored.ApprovalID}); launchErr != nil {
				return approved, launchErr
			}
		}
		return approved, nil
	}
	if plan.Status != cloudapproval.PlanReadyForConfirmation || plan.Revision != command.ExpectedRevision {
		return cloudapproval.PlanV1{}, ErrRevisionConflict
	}
	priced, err := service.facts.LoadQuote(ctx, command.OwnerID, plan.Quote.QuoteID)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	signed, err := cloudapproval.NewApprovalV1(plan, command.Approval.ApprovalID, command.Approval.ChallengeID, command.Approval.SignerKeyID, command.Approval.ExpiresAt)
	if err != nil {
		return cloudapproval.PlanV1{}, ErrApprovalRequired
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(command.Approval.Signature)
	if err := service.approvals.Verify(ctx, signed, plan, priced); err != nil {
		return cloudapproval.PlanV1{}, mapApprovalError(err)
	}
	approved, err := service.facts.PersistApproval(ctx, scope, command.IdempotencyKey, challenge.Revision, command.ExpectedRevision, signed)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if service.launcher != nil {
		if err := service.launcher.SubmitApprovedPlan(ctx, scope, SubmitApprovedPlanCommand{OwnerID: command.OwnerID, PlanID: command.PlanID, ApprovalID: signed.ApprovalID}); err != nil {
			return approved, err
		}
	}
	return approved, nil
}

func (service *Service) EstablishAWSConnection(ctx context.Context, scope MutationScope, command EstablishConnectionCommand) (Connection, error) {
	if err := service.workerControlCapabilityError(); err != nil {
		return Connection{}, err
	}
	if service == nil || service.connections == nil {
		return Connection{}, ErrUnavailable
	}
	connection, err := service.connections.EstablishAWSConnection(ctx, scope, command)
	if err != nil {
		return Connection{}, err
	}
	if service.launcher != nil {
		if err := service.launcher.SubmitApprovedPlan(ctx, scope, SubmitApprovedPlanCommand{OwnerID: command.OwnerID, PlanID: command.PlanID, ApprovalID: command.Approval.ApprovalID}); err != nil {
			return connection, err
		}
	}
	return connection, nil
}

func (service *Service) workerControlCapabilityError() error {
	if service != nil && !service.workerControlReady {
		return ErrCapabilityNotReady
	}
	return nil
}

func deterministicApprovalID(agentInstanceID string, scope MutationScope, idempotencyKey string) string {
	namespace := uuid.MustParse(agentInstanceID)
	return uuid.NewSHA1(namespace, []byte("cloud-approval\x00"+scope.ClientID+"\x00"+scope.CredentialID+"\x00"+idempotencyKey)).String()
}

func mapRecipeError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return ErrInvalid
}

func mapApprovalError(err error) error {
	switch {
	case errors.Is(err, cloudapproval.ErrDeviceNotFound), errors.Is(err, cloudapproval.ErrChallengeNotFound):
		return ErrNotFound
	case errors.Is(err, cloudapproval.ErrChallengeConsumed), errors.Is(err, cloudapproval.ErrRevisionConflict):
		return ErrRevisionConflict
	default:
		return ErrApprovalRequired
	}
}

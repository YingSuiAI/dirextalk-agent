package cloudworker

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

const (
	RequoteReasonExpired = "quote_expired"
	RequoteReasonDrift   = "quote_drift"
)

// compileRequoteOffer constructs the complete replacement before the Store
// transaction starts. In particular, the Quoter sees the replacement's real
// authorization basis (including its execution-scoped artifact grant); the
// Store is never allowed to rewrite a quote basis or digest.
func compileRequoteOffer(
	ctx context.Context,
	quoter Quoter,
	baseLimits Limits,
	old Plan,
	reason string,
	now time.Time,
	awsBinding AWSBinding,
	modelAuthorization ModelAuthorization,
) (RequoteOfferCommand, error) {
	modelDigest := modelAuthorization.BindingDigest
	if ctx == nil || quoter == nil || validateLimits(baseLimits) != nil || old.Seal() != nil || validateAWS(awsBinding) != nil ||
		modelAuthorization.Seal() != nil || modelAuthorization.BindingDigest != modelDigest ||
		modelAuthorization.ModelProfileID != old.ModelAuthorization.ModelProfileID {
		return RequoteOfferCommand{}, ErrInvalid
	}
	reason = strings.TrimSpace(reason)
	if reason != RequoteReasonExpired && reason != RequoteReasonDrift {
		return RequoteOfferCommand{}, ErrInvalid
	}
	now = now.UTC()
	if now.IsZero() {
		return RequoteOfferCommand{}, ErrInvalid
	}
	seed := old.ExecutionID + ":" + old.Quote.Digest + ":" + reason
	plan := old
	plan.AWS = awsBinding
	plan.ModelAuthorization = modelAuthorization
	limits, err := effectivePlanLimits(baseLimits, modelAuthorization)
	if err != nil {
		return RequoteOfferCommand{}, err
	}
	plan.Limits = limits
	plan.PlanID = deterministicID("cloud-worker-requote-plan", seed)
	plan.ExecutionID = deterministicID("cloud-worker-requote-execution", seed)
	plan.TaskID = deterministicID("cloud-worker-requote-task", seed)
	plan.ConfirmationID = deterministicID("cloud-worker-requote-confirmation", seed)
	plan.Revision = 1
	plan.Status = string(StateWaitingUser)
	plan.CreatedAt, plan.UpdatedAt = now, now

	if strings.Count(plan.ArtifactGrant.KeyPrefix, old.ExecutionID) != 1 {
		return RequoteOfferCommand{}, ErrInvalid
	}
	plan.ArtifactGrant.KeyPrefix = strings.Replace(
		plan.ArtifactGrant.KeyPrefix, old.ExecutionID, plan.ExecutionID, 1,
	)
	// All derived values are recomputed from the replacement's exact IDs and
	// grants before requesting a price sample.
	plan.Digest = ""
	plan.ExecutionDigest = ""
	plan.AuthorizationBasisDigest = ""
	plan.AWSInfrastructureDigest = ""
	plan.Placement.IAMPolicyDigest = ""
	plan.ArtifactGrant.Digest = ""
	plan.ModelRelay.BindingDigest = ""
	plan.Quote = Quote{}
	if err := plan.sealAuthorizationBasis(); err != nil {
		return RequoteOfferCommand{}, err
	}
	quote, err := quoter.Quote(ctx, QuoteRequest{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		ObjectiveDigest: plan.ObjectiveDigest, UserPromptDigest: plan.UserPromptDigest,
		InputManifestDigest: plan.InputManifestDigest, WorkspaceMode: plan.WorkspaceMode,
		ProposalReason:           plan.ProposalReason,
		ModelBindingDigest:       plan.ModelAuthorization.BindingDigest,
		AuthorizationBasisDigest: plan.AuthorizationBasisDigest,
		AWS:                      plan.AWS, Compute: plan.Compute, Limits: plan.Limits,
	})
	if err != nil {
		return RequoteOfferCommand{}, err
	}
	plan.Quote = quote
	if err := plan.Seal(); err != nil {
		return RequoteOfferCommand{}, err
	}
	execution, err := NewExecution(plan)
	if err != nil {
		return RequoteOfferCommand{}, err
	}
	binding, err := BindingForPlan(plan)
	if err != nil {
		return RequoteOfferCommand{}, err
	}
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		return RequoteOfferCommand{}, ErrInvalid
	}
	payload := coretask.CloudWorkerTaskPayload{
		ExecutionID: plan.ExecutionID, AccountGeneration: plan.AccountGeneration,
		PlanID: plan.PlanID, PlanRevision: plan.Revision, PlanDigest: plan.Digest,
		ConfirmationID: plan.ConfirmationID, TurnID: plan.TurnID,
		ConversationID: plan.ConversationID, QuoteDigest: plan.Quote.Digest,
		ExecutionDigest: plan.ExecutionDigest,
	}
	idempotencyKey := deterministicID("cloud-worker-requote-idempotency", seed)
	requestDigest := digestValue(struct {
		OldExecutionID string `json:"old_execution_id"`
		Reason         string `json:"reason"`
		PlanDigest     string `json:"plan_digest"`
	}{old.ExecutionID, reason, plan.Digest})
	return RequoteOfferCommand{
		IdempotencyKey: idempotencyKey, RequestDigest: requestDigest,
		OldExecutionID: old.ExecutionID, Reason: reason,
		Plan: plan, Execution: execution, BindingJSON: bindingRaw,
		TaskPayload: payload,
	}, nil
}

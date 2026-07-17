// Package costalert owns the durable, Agent-local managed-service cost alert.
// It derives projected accrued cost only from the immutable selected Quote and
// the durable time at which the launch operation became active.
package costalert

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
)

const SchemaV1 = "dirextalk.agent.cloud.cost-alert-policy/v1"

type Status string

const (
	StatusActive  Status = "active"
	StatusAlerted Status = "alerted"
)

var (
	ErrInvalid          = errors.New("invalid cost alert")
	ErrNotReady         = errors.New("cost alert facts are not ready")
	ErrRevisionConflict = errors.New("cost alert revision conflict")
	ErrUnavailable      = errors.New("cost alert dependency unavailable")

	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
)

type PolicyV1 struct {
	SchemaVersion          string    `json:"schema_version"`
	PolicyID               string    `json:"policy_id"`
	AgentInstanceID        string    `json:"agent_instance_id"`
	OwnerID                string    `json:"owner_id"`
	DeploymentID           string    `json:"deployment_id"`
	PlanID                 string    `json:"plan_id"`
	PlanRevision           uint64    `json:"plan_revision"`
	QuoteID                string    `json:"quote_id"`
	Currency               string    `json:"currency"`
	ThresholdAmountMinor   int64     `json:"threshold_amount_minor"`
	HourlyEstimateMicros   uint64    `json:"hourly_estimate_micros"`
	RunningSince           time.Time `json:"running_since"`
	Status                 Status    `json:"status"`
	ProjectedAccruedMicros uint64    `json:"projected_accrued_micros"`
	LastObservedAt         time.Time `json:"last_observed_at"`
	AlertedAt              time.Time `json:"alerted_at,omitempty"`
	Revision               int64     `json:"revision"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

func (policy PolicyV1) Validate() error {
	if policy.SchemaVersion != SchemaV1 || strings.TrimSpace(policy.PolicyID) == "" ||
		strings.TrimSpace(policy.AgentInstanceID) == "" || strings.TrimSpace(policy.OwnerID) == "" ||
		strings.TrimSpace(policy.DeploymentID) == "" || strings.TrimSpace(policy.PlanID) == "" ||
		strings.TrimSpace(policy.QuoteID) == "" || policy.PlanRevision < 1 ||
		!currencyPattern.MatchString(policy.Currency) || policy.ThresholdAmountMinor < 1 ||
		policy.HourlyEstimateMicros < 1 || policy.RunningSince.IsZero() ||
		policy.RunningSince.Location() != time.UTC || policy.Revision < 1 {
		return ErrInvalid
	}
	if policy.Status != StatusActive && policy.Status != StatusAlerted {
		return ErrInvalid
	}
	if policy.Status == StatusActive && !policy.AlertedAt.IsZero() ||
		policy.Status == StatusAlerted && (policy.AlertedAt.IsZero() || policy.AlertedAt.Location() != time.UTC) {
		return ErrInvalid
	}
	return nil
}

type FactReader interface {
	// LoadQuote must return the authoritative durable Quote. The PostgreSQL
	// adapter verifies its stored digest and canonical bytes before returning.
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error)
	GetByDeployment(context.Context, string) (cloudexecution.Operation, error)
}

type Repository interface {
	Activate(context.Context, PolicyV1) (PolicyV1, error)
	Get(context.Context, string, string) (PolicyV1, error)
	Evaluate(context.Context, string, int64, uint64, time.Time) (PolicyV1, bool, error)
}

type Controller struct {
	agentInstanceID string
	facts           FactReader
	policies        Repository
}

func NewController(agentInstanceID string, facts FactReader, policies Repository) (*Controller, error) {
	if strings.TrimSpace(agentInstanceID) == "" || facts == nil || policies == nil {
		return nil, ErrInvalid
	}
	return &Controller{agentInstanceID: agentInstanceID, facts: facts, policies: policies}, nil
}

type EvaluateRequest struct {
	OwnerID              string
	DeploymentID         string
	ThresholdAmountMinor int64
	ObservedAt           time.Time
}

func (controller *Controller) Evaluate(ctx context.Context, request EvaluateRequest) (PolicyV1, bool, error) {
	if controller == nil || strings.TrimSpace(request.OwnerID) == "" || strings.TrimSpace(request.DeploymentID) == "" ||
		request.ThresholdAmountMinor < 1 || request.ObservedAt.IsZero() || request.ObservedAt.Location() != time.UTC {
		return PolicyV1{}, false, ErrInvalid
	}
	launch, err := controller.facts.GetByDeployment(ctx, request.DeploymentID)
	if err != nil {
		return PolicyV1{}, false, fmt.Errorf("%w: load launch", ErrUnavailable)
	}
	if launch.State != cloudexecution.StateActive || launch.DeploymentID != request.DeploymentID ||
		launch.Launch.OwnerID != request.OwnerID || launch.UpdatedAt.IsZero() ||
		launch.UpdatedAt.Location() != time.UTC || launch.UpdatedAt.After(request.ObservedAt) {
		return PolicyV1{}, false, ErrNotReady
	}
	plan, err := controller.facts.LoadPlan(ctx, request.OwnerID, launch.Launch.PlanID)
	if err != nil {
		return PolicyV1{}, false, fmt.Errorf("%w: load plan", ErrUnavailable)
	}
	quote, err := controller.facts.LoadQuote(ctx, request.OwnerID, plan.Quote.QuoteID)
	if err != nil {
		return PolicyV1{}, false, fmt.Errorf("%w: load quote", ErrUnavailable)
	}
	if plan.Status != cloudapproval.PlanApproved || plan.AgentInstanceID != controller.agentInstanceID ||
		plan.OwnerID != request.OwnerID || plan.PlanID != launch.Launch.PlanID ||
		quote.QuoteID != plan.Quote.QuoteID ||
		!quote.ValidUntil.Equal(plan.Quote.ValidUntil) {
		return PolicyV1{}, false, ErrNotReady
	}
	candidate, ok := selectedCandidate(quote, plan.Quote.CandidateID)
	if !ok || candidate.ScopeDigest != plan.Quote.ScopeDigest || quote.Currency != "USD" {
		// AmountMinor currently has a closed, unambiguous conversion only for
		// USD cents. Supporting other currencies requires a versioned exponent
		// registry rather than guessing from a three-letter code.
		return PolicyV1{}, false, ErrNotReady
	}
	policy := PolicyV1{
		SchemaVersion: SchemaV1, PolicyID: request.DeploymentID, AgentInstanceID: controller.agentInstanceID,
		OwnerID: request.OwnerID, DeploymentID: request.DeploymentID, PlanID: plan.PlanID, PlanRevision: plan.Revision,
		QuoteID: quote.QuoteID, Currency: quote.Currency, ThresholdAmountMinor: request.ThresholdAmountMinor,
		HourlyEstimateMicros: candidate.HourlyEstimateMicros, RunningSince: launch.UpdatedAt,
		Status: StatusActive, Revision: 1,
	}
	current, err := controller.policies.Activate(ctx, policy)
	if err != nil {
		return PolicyV1{}, false, err
	}
	accrued, err := projectedAccruedMicros(current.HourlyEstimateMicros, current.RunningSince, request.ObservedAt)
	if err != nil {
		return PolicyV1{}, false, err
	}
	return controller.policies.Evaluate(ctx, current.PolicyID, current.Revision, accrued, request.ObservedAt)
}

func selectedCandidate(quote cloudquote.QuoteV1, candidateID string) (cloudquote.CandidateV1, bool) {
	for _, candidate := range quote.Candidates {
		if string(candidate.CandidateID) == candidateID {
			return candidate, candidate.HourlyEstimateMicros > 0
		}
	}
	return cloudquote.CandidateV1{}, false
}

func projectedAccruedMicros(hourly uint64, runningSince, observedAt time.Time) (uint64, error) {
	if hourly < 1 || runningSince.IsZero() || observedAt.Before(runningSince) {
		return 0, ErrInvalid
	}
	elapsedNanos := new(big.Int).SetInt64(observedAt.Sub(runningSince).Nanoseconds())
	value := new(big.Int).Mul(new(big.Int).SetUint64(hourly), elapsedNanos)
	denominator := big.NewInt(int64(time.Hour))
	value.Add(value, new(big.Int).Sub(denominator, big.NewInt(1)))
	value.Div(value, denominator)
	if !value.IsUint64() {
		return 0, ErrInvalid
	}
	return value.Uint64(), nil
}

func ThresholdMicros(amountMinor int64, currency string) (uint64, error) {
	if amountMinor < 1 || currency != "USD" {
		return 0, ErrInvalid
	}
	value := new(big.Int).Mul(big.NewInt(amountMinor), big.NewInt(10_000))
	if !value.IsUint64() {
		return 0, ErrInvalid
	}
	return value.Uint64(), nil
}

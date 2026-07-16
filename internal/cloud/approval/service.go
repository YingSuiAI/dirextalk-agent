package approval

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"reflect"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

const ChallengeValidity = 5 * time.Minute

type Service struct {
	devices    DeviceKeyRepository
	challenges ChallengeRepository
	now        func() time.Time
	random     io.Reader
}

func NewService(devices DeviceKeyRepository, challenges ChallengeRepository, now func() time.Time) (*Service, error) {
	if devices == nil || challenges == nil {
		return nil, fmt.Errorf("device and challenge repositories are required")
	}
	if now == nil {
		return nil, fmt.Errorf("clock is required")
	}
	return &Service{devices: devices, challenges: challenges, now: now, random: rand.Reader}, nil
}

// DraftChallenge validates the current Plan, Quote, and approval device and
// returns a short-lived challenge without persisting it. Coordinators that
// need caller-scoped idempotency persist the returned value in their own
// transaction before exposing it to the caller.
func (s *Service) DraftChallenge(ctx context.Context, plan PlanV1, pricedQuote cloudquote.QuoteV1, signerKeyID string) (ChallengeV1, error) {
	if ctx == nil {
		return ChallengeV1{}, fmt.Errorf("context is required")
	}
	if err := plan.Validate(); err != nil {
		return ChallengeV1{}, err
	}
	if plan.Status != PlanReadyForConfirmation {
		return ChallengeV1{}, fmt.Errorf("plan must be ready_for_confirmation")
	}
	// Approval timestamps cross PostgreSQL, protobuf, and Dart. Truncating the
	// authority clock before drafting avoids a sub-microsecond value being
	// signed by the client but rounded by PostgreSQL during challenge read-back.
	now := s.now().UTC().Truncate(time.Microsecond)
	if err := plan.ValidateQuote(pricedQuote, now); err != nil {
		return ChallengeV1{}, err
	}
	device, err := s.devices.GetDeviceKey(ctx, signerKeyID)
	if err != nil {
		return ChallengeV1{}, err
	}
	if err := device.ValidateAt(now); err != nil {
		return ChallengeV1{}, err
	}
	if device.AgentInstanceID != plan.AgentInstanceID || device.OwnerID != plan.OwnerID {
		return ChallengeV1{}, fmt.Errorf("device key does not belong to plan owner")
	}
	challengeID, err := randomChallengeID(s.random)
	if err != nil {
		return ChallengeV1{}, err
	}
	planHash, err := plan.Hash()
	if err != nil {
		return ChallengeV1{}, err
	}
	expiresAt := now.Add(ChallengeValidity)
	if plan.Quote.ValidUntil.Before(expiresAt) {
		expiresAt = plan.Quote.ValidUntil.UTC()
	}
	if !now.Before(expiresAt) {
		return ChallengeV1{}, fmt.Errorf("quote is already expired")
	}
	challenge := ChallengeV1{
		ChallengeID:      challengeID,
		Revision:         1,
		AgentInstanceID:  plan.AgentInstanceID,
		OwnerID:          plan.OwnerID,
		PlanID:           plan.PlanID,
		PlanRevision:     plan.Revision,
		PlanHash:         planHash,
		ConnectionID:     plan.ConnectionID,
		RecipeDigest:     plan.Recipe.Digest,
		QuoteID:          plan.Quote.QuoteID,
		QuoteDigest:      plan.Quote.Digest,
		QuoteScopeDigest: plan.Quote.ScopeDigest,
		QuoteCandidateID: plan.Quote.CandidateID,
		SignerKeyID:      signerKeyID,
		IssuedAt:         now,
		ExpiresAt:        expiresAt,
	}
	if err := validateChallenge(challenge, now); err != nil {
		return ChallengeV1{}, err
	}
	return challenge, nil
}

// CreateChallenge preserves the repository-backed convenience boundary. New
// durable coordinators should call DraftChallenge and atomically persist the
// result together with their idempotency response.
func (s *Service) CreateChallenge(ctx context.Context, plan PlanV1, pricedQuote cloudquote.QuoteV1, signerKeyID string) (ChallengeV1, error) {
	challenge, err := s.DraftChallenge(ctx, plan, pricedQuote, signerKeyID)
	if err != nil {
		return ChallengeV1{}, err
	}
	if err := s.challenges.CreateChallenge(ctx, challenge); err != nil {
		return ChallengeV1{}, err
	}
	return challenge, nil
}

// Verify checks the complete approval binding without consuming the
// challenge. Durable coordinators use this before an atomic transaction that
// consumes the challenge, saves the approval, and advances the Plan revision.
func (s *Service) Verify(ctx context.Context, signed ApprovalV1, plan PlanV1, pricedQuote cloudquote.QuoteV1) error {
	_, err := s.verify(ctx, signed, plan, pricedQuote)
	return err
}

// VerifyAndConsume preserves the repository-backed convenience boundary.
// Verification completes before an atomic compare-and-consume.
func (s *Service) VerifyAndConsume(ctx context.Context, signed ApprovalV1, plan PlanV1, pricedQuote cloudquote.QuoteV1) error {
	challenge, err := s.verify(ctx, signed, plan, pricedQuote)
	if err != nil {
		return err
	}
	return s.challenges.ConsumeChallenge(ctx, challenge.ChallengeID, challenge.Revision, s.now().UTC())
}

func (s *Service) verify(ctx context.Context, signed ApprovalV1, plan PlanV1, pricedQuote cloudquote.QuoteV1) (ChallengeV1, error) {
	if ctx == nil {
		return ChallengeV1{}, fmt.Errorf("context is required")
	}
	now := s.now().UTC()
	if err := plan.ValidateQuote(pricedQuote, now); err != nil {
		return ChallengeV1{}, err
	}
	device, err := s.devices.GetDeviceKey(ctx, signed.SignerKeyID)
	if err != nil {
		return ChallengeV1{}, err
	}
	if err := device.ValidateAt(now); err != nil {
		return ChallengeV1{}, err
	}
	if device.AgentInstanceID != signed.AgentInstanceID || device.OwnerID != signed.OwnerID {
		return ChallengeV1{}, fmt.Errorf("device key does not belong to approval owner")
	}
	challenge, err := s.challenges.GetChallenge(ctx, signed.ChallengeID)
	if err != nil {
		return ChallengeV1{}, err
	}
	if err := validateChallenge(challenge, now); err != nil {
		return ChallengeV1{}, err
	}
	if challenge.ConsumedAt != nil {
		return ChallengeV1{}, ErrChallengeConsumed
	}
	if err := signed.VerifyForPlan(device.PublicKey, plan, now); err != nil {
		return ChallengeV1{}, err
	}
	if err := challengeMatchesApproval(challenge, signed); err != nil {
		return ChallengeV1{}, err
	}
	if signed.ExpiresAt.After(challenge.ExpiresAt) {
		return ChallengeV1{}, fmt.Errorf("approval expiry exceeds challenge expiry")
	}
	return challenge, nil
}

func randomChallengeID(source io.Reader) (string, error) {
	var entropy [32]byte
	if _, err := io.ReadFull(source, entropy[:]); err != nil {
		return "", fmt.Errorf("generate challenge entropy: %w", err)
	}
	return "challenge_" + base64.RawURLEncoding.EncodeToString(entropy[:]), nil
}

func validateChallenge(value ChallengeV1, now time.Time) error {
	for name, field := range map[string]string{
		"challenge_id":       value.ChallengeID,
		"agent_instance_id":  value.AgentInstanceID,
		"owner_id":           value.OwnerID,
		"plan_id":            value.PlanID,
		"connection_id":      value.ConnectionID,
		"quote_id":           value.QuoteID,
		"quote_candidate_id": value.QuoteCandidateID,
		"signer_key_id":      value.SignerKeyID,
	} {
		if err := validateIdentifier(name, field); err != nil {
			return err
		}
	}
	if value.Revision == 0 || value.PlanRevision == 0 {
		return fmt.Errorf("challenge revisions must be positive")
	}
	for name, digest := range map[string]string{
		"plan_hash":          value.PlanHash,
		"recipe_digest":      value.RecipeDigest,
		"quote_digest":       value.QuoteDigest,
		"quote_scope_digest": value.QuoteScopeDigest,
	} {
		if err := validateDigest(name, digest); err != nil {
			return err
		}
	}
	if now.IsZero() || value.IssuedAt.IsZero() || value.ExpiresAt.IsZero() || !value.IssuedAt.Before(value.ExpiresAt) || value.ExpiresAt.Sub(value.IssuedAt) > ChallengeValidity {
		return fmt.Errorf("challenge validity window is invalid")
	}
	if now.Before(value.IssuedAt.Add(-30*time.Second)) || !now.Before(value.ExpiresAt) {
		return fmt.Errorf("challenge is not currently valid")
	}
	if value.ConsumedAt != nil && (value.ConsumedAt.Before(value.IssuedAt) || value.ConsumedAt.After(value.ExpiresAt)) {
		return fmt.Errorf("challenge consumed_at is invalid")
	}
	return nil
}

func challengeMatchesApproval(challenge ChallengeV1, signed ApprovalV1) error {
	left := []any{
		challenge.ChallengeID, challenge.AgentInstanceID, challenge.OwnerID, challenge.PlanID,
		challenge.PlanRevision, challenge.PlanHash, challenge.ConnectionID, challenge.RecipeDigest,
		challenge.QuoteID, challenge.QuoteDigest, challenge.QuoteScopeDigest,
		challenge.QuoteCandidateID, challenge.SignerKeyID,
	}
	right := []any{
		signed.ChallengeID, signed.AgentInstanceID, signed.OwnerID, signed.PlanID,
		signed.PlanRevision, signed.PlanHash, signed.ConnectionID, signed.RecipeDigest,
		signed.QuoteID, signed.QuoteDigest, signed.QuoteScopeDigest,
		signed.QuoteCandidateID, signed.SignerKeyID,
	}
	if !reflect.DeepEqual(left, right) {
		return fmt.Errorf("challenge does not bind this approval")
	}
	return nil
}

func validateDigest(name, value string) error {
	if err := recipe.ValidateDigest(value); err != nil {
		return fmt.Errorf("%s %w", name, err)
	}
	return nil
}

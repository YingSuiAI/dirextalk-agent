package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"reflect"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
)

type planHashDocumentV1 struct {
	SchemaVersion    string               `json:"schema_version"`
	HashAlgorithm    string               `json:"hash_algorithm"`
	AgentInstanceID  string               `json:"agent_instance_id"`
	OwnerID          string               `json:"owner_id"`
	PlanID           string               `json:"plan_id"`
	Revision         uint64               `json:"revision"`
	ConnectionID     string               `json:"connection_id"`
	Recipe           RecipeBindingV1      `json:"recipe"`
	Quote            QuoteBindingV1       `json:"quote"`
	ResourceScope    ResourceScopeV1      `json:"resource_scope"`
	NetworkScope     NetworkScopeV1       `json:"network_scope"`
	SecretScope      []SecretReferenceV1  `json:"secret_scope,omitempty"`
	IntegrationScope []IntegrationScopeV1 `json:"integration_scope,omitempty"`
	RetentionScope   RetentionScopeV1     `json:"retention_scope"`
}

func (p PlanV1) CanonicalCBOR() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(p.hashDocument())
}

func (p PlanV1) Hash() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	return canonical.Digest(p.hashDocument())
}

func (p PlanV1) hashDocument() planHashDocumentV1 {
	normalized := normalizePlan(p)
	return planHashDocumentV1{
		SchemaVersion:    normalized.SchemaVersion,
		HashAlgorithm:    canonical.Algorithm,
		AgentInstanceID:  normalized.AgentInstanceID,
		OwnerID:          normalized.OwnerID,
		PlanID:           normalized.PlanID,
		Revision:         normalized.Revision,
		ConnectionID:     normalized.ConnectionID,
		Recipe:           normalized.Recipe,
		Quote:            normalized.Quote,
		ResourceScope:    normalized.ResourceScope,
		NetworkScope:     normalized.NetworkScope,
		SecretScope:      normalized.SecretScope,
		IntegrationScope: normalized.IntegrationScope,
		RetentionScope:   normalized.RetentionScope,
	}
}

func normalizePlan(value PlanV1) PlanV1 {
	value.Quote.ValidUntil = value.Quote.ValidUntil.UTC()
	value.ResourceScope = normalizeResource(value.ResourceScope)
	value.NetworkScope = normalizeNetwork(value.NetworkScope)
	value.SecretScope = normalizeSecrets(value.SecretScope)
	value.IntegrationScope = normalizeIntegrations(value.IntegrationScope)
	return value
}

// NewApprovalV1 creates the exact unsigned payload that a registered user
// device must sign. It deliberately has no signing-key parameter.
func NewApprovalV1(plan PlanV1, approvalID, challengeID, signerKeyID string, expiresAt time.Time) (ApprovalV1, error) {
	if err := plan.Validate(); err != nil {
		return ApprovalV1{}, err
	}
	if plan.Status != PlanReadyForConfirmation {
		return ApprovalV1{}, fmt.Errorf("plan must be ready_for_confirmation")
	}
	normalized := normalizePlan(plan)
	planHash, err := normalized.Hash()
	if err != nil {
		return ApprovalV1{}, err
	}
	approval := ApprovalV1{
		SchemaVersion:    ApprovalSchemaV1,
		HashAlgorithm:    canonical.Algorithm,
		ApprovalID:       approvalID,
		AgentInstanceID:  normalized.AgentInstanceID,
		OwnerID:          normalized.OwnerID,
		PlanID:           normalized.PlanID,
		PlanRevision:     normalized.Revision,
		PlanHash:         planHash,
		ConnectionID:     normalized.ConnectionID,
		RecipeDigest:     normalized.Recipe.Digest,
		QuoteID:          normalized.Quote.QuoteID,
		QuoteDigest:      normalized.Quote.Digest,
		QuoteScopeDigest: normalized.Quote.ScopeDigest,
		QuoteCandidateID: normalized.Quote.CandidateID,
		QuoteValidUntil:  normalized.Quote.ValidUntil,
		ResourceScope:    normalized.ResourceScope,
		NetworkScope:     normalized.NetworkScope,
		SecretScope:      normalized.SecretScope,
		IntegrationScope: normalized.IntegrationScope,
		RetentionScope:   normalized.RetentionScope,
		ChallengeID:      challengeID,
		SignerKeyID:      signerKeyID,
		ExpiresAt:        expiresAt.UTC(),
	}
	if err := approval.validate(false); err != nil {
		return ApprovalV1{}, err
	}
	return approval, nil
}

type approvalSigningDocumentV1 struct {
	PayloadSchema    string               `json:"payload_schema"`
	HashAlgorithm    string               `json:"hash_algorithm"`
	ApprovalID       string               `json:"approval_id"`
	AgentInstanceID  string               `json:"agent_instance_id"`
	OwnerID          string               `json:"owner_id"`
	PlanID           string               `json:"plan_id"`
	PlanRevision     uint64               `json:"plan_revision"`
	PlanHash         string               `json:"plan_hash"`
	ConnectionID     string               `json:"connection_id"`
	RecipeDigest     string               `json:"recipe_digest"`
	QuoteID          string               `json:"quote_id"`
	QuoteDigest      string               `json:"quote_digest"`
	QuoteScopeDigest string               `json:"quote_scope_digest"`
	QuoteCandidateID string               `json:"quote_candidate_id"`
	QuoteValidUntil  time.Time            `json:"quote_valid_until"`
	ResourceScope    ResourceScopeV1      `json:"resource_scope"`
	NetworkScope     NetworkScopeV1       `json:"network_scope"`
	SecretScope      []SecretReferenceV1  `json:"secret_scope,omitempty"`
	IntegrationScope []IntegrationScopeV1 `json:"integration_scope,omitempty"`
	RetentionScope   RetentionScopeV1     `json:"retention_scope"`
	ChallengeID      string               `json:"challenge_id"`
	SignerKeyID      string               `json:"signer_key_id"`
	ExpiresAt        time.Time            `json:"expires_at"`
}

// SigningPayload returns deterministic bytes for Ed25519 signing. Signature is
// intentionally excluded from the projection.
func (a ApprovalV1) SigningPayload() ([]byte, error) {
	if err := a.validate(false); err != nil {
		return nil, err
	}
	normalized := normalizeApproval(a)
	return canonical.Marshal(approvalSigningDocumentV1{
		PayloadSchema:    ApprovalSigningPayloadV1,
		HashAlgorithm:    normalized.HashAlgorithm,
		ApprovalID:       normalized.ApprovalID,
		AgentInstanceID:  normalized.AgentInstanceID,
		OwnerID:          normalized.OwnerID,
		PlanID:           normalized.PlanID,
		PlanRevision:     normalized.PlanRevision,
		PlanHash:         normalized.PlanHash,
		ConnectionID:     normalized.ConnectionID,
		RecipeDigest:     normalized.RecipeDigest,
		QuoteID:          normalized.QuoteID,
		QuoteDigest:      normalized.QuoteDigest,
		QuoteScopeDigest: normalized.QuoteScopeDigest,
		QuoteCandidateID: normalized.QuoteCandidateID,
		QuoteValidUntil:  normalized.QuoteValidUntil,
		ResourceScope:    normalized.ResourceScope,
		NetworkScope:     normalized.NetworkScope,
		SecretScope:      normalized.SecretScope,
		IntegrationScope: normalized.IntegrationScope,
		RetentionScope:   normalized.RetentionScope,
		ChallengeID:      normalized.ChallengeID,
		SignerKeyID:      normalized.SignerKeyID,
		ExpiresAt:        normalized.ExpiresAt,
	})
}

func (a ApprovalV1) Validate() error {
	return a.validate(false)
}

func (a ApprovalV1) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be Ed25519")
	}
	if now.IsZero() {
		return fmt.Errorf("current time is required")
	}
	if err := a.validate(true); err != nil {
		return err
	}
	if !now.Before(a.ExpiresAt) || !now.Before(a.QuoteValidUntil) {
		return fmt.Errorf("approval is expired")
	}
	payload, err := a.SigningPayload()
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil {
		return fmt.Errorf("decode approval signature: %w", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("approval signature is invalid")
	}
	return nil
}

func (a ApprovalV1) ValidateAgainstPlan(plan PlanV1, now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("current time is required")
	}
	if err := a.validate(false); err != nil {
		return err
	}
	if !now.Before(a.ExpiresAt) || !now.Before(a.QuoteValidUntil) {
		return fmt.Errorf("approval is expired")
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.Status != PlanReadyForConfirmation && plan.Status != PlanApproved {
		return fmt.Errorf("plan is not approvable")
	}
	normalizedPlan := normalizePlan(plan)
	planHash, err := normalizedPlan.Hash()
	if err != nil {
		return err
	}
	normalizedApproval := normalizeApproval(a)
	if normalizedApproval.AgentInstanceID != normalizedPlan.AgentInstanceID ||
		normalizedApproval.OwnerID != normalizedPlan.OwnerID ||
		normalizedApproval.PlanID != normalizedPlan.PlanID ||
		normalizedApproval.PlanRevision != normalizedPlan.Revision ||
		normalizedApproval.PlanHash != planHash ||
		normalizedApproval.ConnectionID != normalizedPlan.ConnectionID ||
		normalizedApproval.RecipeDigest != normalizedPlan.Recipe.Digest ||
		normalizedApproval.QuoteID != normalizedPlan.Quote.QuoteID ||
		normalizedApproval.QuoteDigest != normalizedPlan.Quote.Digest ||
		normalizedApproval.QuoteScopeDigest != normalizedPlan.Quote.ScopeDigest ||
		normalizedApproval.QuoteCandidateID != normalizedPlan.Quote.CandidateID ||
		!normalizedApproval.QuoteValidUntil.Equal(normalizedPlan.Quote.ValidUntil) ||
		!reflect.DeepEqual(normalizedApproval.ResourceScope, normalizedPlan.ResourceScope) ||
		!reflect.DeepEqual(normalizedApproval.NetworkScope, normalizedPlan.NetworkScope) ||
		!reflect.DeepEqual(normalizedApproval.SecretScope, normalizedPlan.SecretScope) ||
		!reflect.DeepEqual(normalizedApproval.IntegrationScope, normalizedPlan.IntegrationScope) ||
		!reflect.DeepEqual(normalizedApproval.RetentionScope, normalizedPlan.RetentionScope) {
		return fmt.Errorf("approval does not match the current plan revision and scopes")
	}
	return nil
}

// VerifyForPlan verifies the cryptographic Plan binding. High-risk callers use
// Service.Verify plus an atomic persistence transaction so Quote freshness,
// device registration, and one-time challenge consumption are also enforced.
func (a ApprovalV1) VerifyForPlan(publicKey ed25519.PublicKey, plan PlanV1, now time.Time) error {
	if err := a.Verify(publicKey, now); err != nil {
		return err
	}
	return a.ValidateAgainstPlan(plan, now)
}

// ValidateQuote proves that the Plan references a real, current Quote and the
// exact selected candidate scope. It must run before a challenge is issued and
// again immediately before the approved mutation.
func (p PlanV1) ValidateQuote(value cloudquote.QuoteV1, now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("current time is required")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := value.Validate(); err != nil {
		return fmt.Errorf("validate quote: %w", err)
	}
	digest, err := value.Digest()
	if err != nil {
		return err
	}
	if value.QuoteID != p.Quote.QuoteID || digest != p.Quote.Digest || !value.ValidUntil.Equal(p.Quote.ValidUntil) {
		return fmt.Errorf("quote identity, digest, or validity does not match plan")
	}
	candidateID := cloudquote.CandidateProfile(p.Quote.CandidateID)
	candidate, exists := value.Candidate(candidateID)
	if !exists || candidate.ScopeDigest != p.Quote.ScopeDigest {
		return fmt.Errorf("quote does not contain the selected plan scope")
	}
	if err := value.ValidateSelection(now, candidateID, p.PricingScope()); err != nil {
		return err
	}
	return nil
}

func normalizeApproval(value ApprovalV1) ApprovalV1 {
	value.QuoteValidUntil = value.QuoteValidUntil.UTC()
	value.ExpiresAt = value.ExpiresAt.UTC()
	value.ResourceScope = normalizeResource(value.ResourceScope)
	value.NetworkScope = normalizeNetwork(value.NetworkScope)
	value.SecretScope = normalizeSecrets(value.SecretScope)
	value.IntegrationScope = normalizeIntegrations(value.IntegrationScope)
	return value
}

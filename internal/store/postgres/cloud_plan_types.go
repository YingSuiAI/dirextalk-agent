package postgres

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/google/uuid"
)

var (
	ErrCloudFactNotFound      = errors.New("cloud fact not found")
	ErrCloudFactRevision      = errors.New("cloud fact expected revision does not match")
	ErrCloudFactScope         = errors.New("cloud fact owner or agent scope does not match")
	ErrCloudFactInvalid       = errors.New("invalid cloud fact mutation")
	ErrCloudFactCorrupt       = errors.New("stored cloud fact failed integrity validation")
	ErrCloudChallengeConsumed = errors.New("cloud approval challenge already consumed")
)

const cloudFactSnapshotSchemaV1 = 1

type CloudQuoteRecord struct {
	Quote     quote.QuoteV1 `json:"quote"`
	Digest    string        `json:"digest"`
	Revision  uint64        `json:"revision"`
	CreatedAt time.Time     `json:"created_at"`
}

type CloudPlanRecord struct {
	Plan      approval.PlanV1 `json:"plan"`
	PlanHash  string          `json:"plan_hash"`
	Revision  uint64          `json:"revision"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type ApprovalDeviceRecord struct {
	Device    approval.DeviceKeyV1 `json:"device"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
}

type ApprovalChallengeRecord struct {
	Challenge approval.ChallengeV1 `json:"challenge"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
}

type CloudApprovalRecord struct {
	Approval   approval.ApprovalV1 `json:"approval"`
	Revision   uint64              `json:"revision"`
	ApprovedAt time.Time           `json:"approved_at"`
}

type CreateQuoteCommand struct {
	IdempotencyKey   string
	ExpectedRevision uint64
	RequestDigest    [sha256.Size]byte
	Quote            quote.QuoteV1
}

func (command CreateQuoteCommand) validate() error {
	if err := validateCloudMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if command.ExpectedRevision != 0 {
		return fmt.Errorf("%w: immutable quote expected_revision must be zero", ErrCloudFactInvalid)
	}
	if err := command.Quote.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrCloudFactInvalid, err)
	}
	if _, err := uuid.Parse(command.Quote.QuoteID); err != nil {
		return fmt.Errorf("%w: quote_id must be a UUID", ErrCloudFactInvalid)
	}
	return nil
}

func (command CreateQuoteCommand) digest() ([sha256.Size]byte, error) {
	if command.RequestDigest != ([sha256.Size]byte{}) {
		return command.RequestDigest, nil
	}
	scopes := make([]quote.ScopeV1, 0, len(command.Quote.Candidates))
	for _, candidate := range command.Quote.Candidates {
		scopes = append(scopes, candidate.Scope)
	}
	sort.Slice(scopes, func(i, j int) bool {
		return scopes[i].Resource.CandidateID < scopes[j].Resource.CandidateID
	})
	return cloudMutationDigest(struct {
		ExpectedRevision uint64                     `json:"expected_revision"`
		Scopes           []quote.ScopeV1            `json:"scopes"`
		Usage            quote.UsageV1              `json:"usage"`
		Spot             *quote.SpotQualificationV1 `json:"spot,omitempty"`
	}{command.ExpectedRevision, scopes, command.Quote.Usage, command.Quote.SpotEvidence})
}

type CreatePlanCommand struct {
	IdempotencyKey   string
	ExpectedRevision uint64
	Plan             approval.PlanV1
}

func (command CreatePlanCommand) validate() error {
	if err := validateCloudMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if err := command.Plan.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrCloudFactInvalid, err)
	}
	if _, err := uuid.Parse(command.Plan.PlanID); err != nil {
		return fmt.Errorf("%w: plan_id must be a UUID", ErrCloudFactInvalid)
	}
	if _, err := uuid.Parse(command.Plan.Quote.QuoteID); err != nil {
		return fmt.Errorf("%w: quote_id must be a UUID", ErrCloudFactInvalid)
	}
	if command.ExpectedRevision != 0 || command.Plan.Revision != 1 || command.Plan.Status != approval.PlanReadyForConfirmation {
		return fmt.Errorf("%w: new Plan must be ready_for_confirmation with expected/revision 0/1", ErrCloudFactInvalid)
	}
	return nil
}

func (command CreatePlanCommand) digest() ([sha256.Size]byte, error) {
	return cloudMutationDigest(struct {
		ExpectedRevision uint64    `json:"expected_revision"`
		AgentInstanceID  string    `json:"agent_instance_id"`
		OwnerID          string    `json:"owner_id"`
		ConnectionID     string    `json:"connection_id"`
		RecipeDigest     string    `json:"recipe_digest"`
		QuoteID          string    `json:"quote_id"`
		QuoteDigest      string    `json:"quote_digest"`
		QuoteScopeDigest string    `json:"quote_scope_digest"`
		QuoteCandidateID string    `json:"quote_candidate_id"`
		QuoteValidUntil  time.Time `json:"quote_valid_until"`
	}{
		command.ExpectedRevision, command.Plan.AgentInstanceID, command.Plan.OwnerID,
		command.Plan.ConnectionID, command.Plan.Recipe.Digest, command.Plan.Quote.QuoteID,
		command.Plan.Quote.Digest, command.Plan.Quote.ScopeDigest, command.Plan.Quote.CandidateID,
		command.Plan.Quote.ValidUntil.UTC(),
	})
}

type RegisterApprovalDeviceCommand struct {
	IdempotencyKey   string
	ExpectedRevision uint64
	Device           approval.DeviceKeyV1
}

func (command RegisterApprovalDeviceCommand) validate() error {
	if err := validateCloudMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if command.ExpectedRevision != 0 || command.Device.Revision != 1 {
		return fmt.Errorf("%w: new device expected/revision must be 0/1", ErrCloudFactInvalid)
	}
	return validateDeviceForStorage(command.Device, false)
}

func (command RegisterApprovalDeviceCommand) digest() ([sha256.Size]byte, error) {
	return cloudMutationDigest(struct {
		ExpectedRevision uint64               `json:"expected_revision"`
		Device           approval.DeviceKeyV1 `json:"device"`
	}{command.ExpectedRevision, command.Device})
}

type RevokeApprovalDeviceCommand struct {
	IdempotencyKey   string
	ExpectedRevision uint64
	KeyID            string
}

func (command RevokeApprovalDeviceCommand) validate() error {
	if err := validateCloudMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if command.ExpectedRevision == 0 || command.KeyID == "" || len(command.KeyID) > 128 {
		return fmt.Errorf("%w: key_id and positive expected_revision are required", ErrCloudFactInvalid)
	}
	return nil
}

func (command RevokeApprovalDeviceCommand) digest() ([sha256.Size]byte, error) {
	return cloudMutationDigest(struct {
		ExpectedRevision uint64 `json:"expected_revision"`
		KeyID            string `json:"key_id"`
	}{command.ExpectedRevision, command.KeyID})
}

type CreateApprovalChallengeCommand struct {
	IdempotencyKey   string
	ExpectedRevision uint64
	Challenge        approval.ChallengeV1
}

func (command CreateApprovalChallengeCommand) validate() error {
	if err := validateCloudMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if command.ExpectedRevision != 0 || command.Challenge.Revision != 1 {
		return fmt.Errorf("%w: new challenge expected/revision must be 0/1", ErrCloudFactInvalid)
	}
	return validateChallengeForStorage(command.Challenge)
}

func (command CreateApprovalChallengeCommand) digest() ([sha256.Size]byte, error) {
	return cloudMutationDigest(struct {
		ExpectedRevision uint64 `json:"expected_revision"`
		AgentInstanceID  string `json:"agent_instance_id"`
		OwnerID          string `json:"owner_id"`
		PlanID           string `json:"plan_id"`
		PlanRevision     uint64 `json:"plan_revision"`
		PlanHash         string `json:"plan_hash"`
		ConnectionID     string `json:"connection_id"`
		RecipeDigest     string `json:"recipe_digest"`
		QuoteID          string `json:"quote_id"`
		QuoteDigest      string `json:"quote_digest"`
		QuoteScopeDigest string `json:"quote_scope_digest"`
		QuoteCandidateID string `json:"quote_candidate_id"`
		SignerKeyID      string `json:"signer_key_id"`
	}{
		command.ExpectedRevision, command.Challenge.AgentInstanceID, command.Challenge.OwnerID,
		command.Challenge.PlanID, command.Challenge.PlanRevision, command.Challenge.PlanHash,
		command.Challenge.ConnectionID, command.Challenge.RecipeDigest, command.Challenge.QuoteID,
		command.Challenge.QuoteDigest, command.Challenge.QuoteScopeDigest,
		command.Challenge.QuoteCandidateID, command.Challenge.SignerKeyID,
	})
}

type ApprovePlanCommand struct {
	IdempotencyKey            string
	ExpectedChallengeRevision uint64
	ExpectedPlanRevision      uint64
	Approval                  approval.ApprovalV1
}

func (command ApprovePlanCommand) validate() error {
	if err := validateCloudMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if command.ExpectedChallengeRevision == 0 || command.ExpectedPlanRevision == 0 || command.Approval.PlanRevision != command.ExpectedPlanRevision {
		return fmt.Errorf("%w: expected challenge/Plan revisions are required and must bind Approval", ErrCloudFactInvalid)
	}
	if err := command.Approval.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrCloudFactInvalid, err)
	}
	if command.Approval.Signature == "" {
		return fmt.Errorf("%w: signed approval is required", ErrCloudFactInvalid)
	}
	for name, value := range map[string]string{
		"approval_id": command.Approval.ApprovalID,
		"plan_id":     command.Approval.PlanID,
		"quote_id":    command.Approval.QuoteID,
	} {
		if _, err := uuid.Parse(value); err != nil {
			return fmt.Errorf("%w: %s must be a UUID", ErrCloudFactInvalid, name)
		}
	}
	return nil
}

func (command ApprovePlanCommand) digest() ([sha256.Size]byte, error) {
	return cloudMutationDigest(struct {
		ExpectedChallengeRevision uint64              `json:"expected_challenge_revision"`
		ExpectedPlanRevision      uint64              `json:"expected_plan_revision"`
		Approval                  approval.ApprovalV1 `json:"approval"`
	}{command.ExpectedChallengeRevision, command.ExpectedPlanRevision, command.Approval})
}

type ConsumeApprovalChallengeCommand struct {
	IdempotencyKey   string
	ChallengeID      string
	ExpectedRevision uint64
	ConsumedAt       time.Time
}

func (command ConsumeApprovalChallengeCommand) validate() error {
	if err := validateCloudMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if command.ChallengeID == "" || command.ExpectedRevision == 0 || command.ConsumedAt.IsZero() {
		return fmt.Errorf("%w: challenge, expected revision, and consumed_at are required", ErrCloudFactInvalid)
	}
	return nil
}

func (command ConsumeApprovalChallengeCommand) digest() ([sha256.Size]byte, error) {
	return cloudMutationDigest(struct {
		ChallengeID      string `json:"challenge_id"`
		ExpectedRevision uint64 `json:"expected_revision"`
	}{command.ChallengeID, command.ExpectedRevision})
}

func validateCloudMutationKey(value string) error {
	if _, err := uuid.Parse(value); err != nil {
		return fmt.Errorf("%w: idempotency_key must be a UUID", ErrCloudFactInvalid)
	}
	return nil
}

func cloudMutationDigest(value any) ([sha256.Size]byte, error) {
	encoded, err := canonical.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: canonicalize mutation: %v", ErrCloudFactInvalid, err)
	}
	return sha256.Sum256(encoded), nil
}

package cloudapp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const validationQuoteID = "00000000-0000-4000-8000-000000000001"

const (
	validationWorkerImageID     = "ami-00000000000000000"
	validationWorkerImageDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

func (scope MutationScope) Validate() error {
	clientID := strings.TrimSpace(scope.ClientID)
	if utf8.RuneCountInString(clientID) < 1 || utf8.RuneCountInString(clientID) > 255 || security.ContainsLikelySecret(clientID) {
		return ErrInvalid
	}
	for _, character := range clientID {
		if unicode.IsControl(character) {
			return ErrInvalid
		}
	}
	credentialID, err := uuid.Parse(scope.CredentialID)
	if err != nil || credentialID == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

func (command CreateQuoteCommand) Validate() error {
	if err := validateMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if (command.BootstrapSessionID == "") != (command.ExpectedSessionRevision == 0) {
		return ErrInvalid
	}
	if command.BootstrapSessionID != "" {
		if parsed, err := uuid.Parse(command.BootstrapSessionID); err != nil || parsed == uuid.Nil {
			return ErrInvalid
		}
	}
	validationScopes := append([]cloudquote.ScopeV1(nil), command.Scopes...)
	for index := range validationScopes {
		resource := &validationScopes[index].Resource
		if (resource.WorkerImageID == "") != (resource.WorkerImageDigest == "") {
			return ErrInvalid
		}
		if resource.WorkerImageID == "" {
			// AWS quote execution replaces this validation-only pair with the
			// active server-owned Worker release before provider pricing. This
			// lets clients omit AMI coordinates without weakening validation of
			// the remaining price- and approval-sensitive scope.
			resource.WorkerImageID = validationWorkerImageID
			resource.WorkerImageDigest = validationWorkerImageDigest
		}
	}
	request := cloudquote.RequestV1{
		QuoteID: validationQuoteID, Scopes: validationScopes, Usage: command.Usage, SpotQualification: command.SpotQualification,
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

func (command CreateQuoteCommand) Digest() ([sha256.Size]byte, error) {
	return digestCommand(struct {
		SchemaVersion           string                          `json:"schema_version"`
		BootstrapSessionID      string                          `json:"bootstrap_session_id,omitempty"`
		ExpectedSessionRevision uint64                          `json:"expected_session_revision,omitempty"`
		Scopes                  []cloudquote.ScopeV1            `json:"scopes"`
		Usage                   cloudquote.UsageV1              `json:"usage"`
		SpotQualification       *cloudquote.SpotQualificationV1 `json:"spot_qualification,omitempty"`
	}{
		"dirextalk.agent.cloud.create-quote-request/v1", command.BootstrapSessionID,
		command.ExpectedSessionRevision, command.Scopes, command.Usage, command.SpotQualification,
	})
}

func (command CreatePlanCommand) Validate() error {
	if err := validateMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if parsed, err := uuid.Parse(command.QuoteID); err != nil || parsed == uuid.Nil {
		return ErrInvalid
	}
	if command.CandidateID != cloudquote.CandidateEconomic && command.CandidateID != cloudquote.CandidateRecommended && command.CandidateID != cloudquote.CandidatePerformance {
		return ErrInvalid
	}
	if err := command.CurrentScope.Validate(); err != nil || command.CurrentScope.Resource.CandidateID != command.CandidateID {
		return fmt.Errorf("%w: current quote scope is invalid", ErrInvalid)
	}
	return nil
}

func (command CreatePlanCommand) Digest() ([sha256.Size]byte, error) {
	return digestCommand(struct {
		SchemaVersion string                      `json:"schema_version"`
		QuoteID       string                      `json:"quote_id"`
		CandidateID   cloudquote.CandidateProfile `json:"candidate_id"`
		CurrentScope  cloudquote.ScopeV1          `json:"current_scope"`
	}{"dirextalk.agent.cloud.create-plan-request/v1", command.QuoteID, command.CandidateID, command.CurrentScope})
}

func (command CreateChallengeCommand) Validate() error {
	if err := validateMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if strings.TrimSpace(command.OwnerID) == "" || strings.TrimSpace(command.SignerKeyID) == "" || command.ExpectedRevision == 0 {
		return ErrInvalid
	}
	if parsed, err := uuid.Parse(command.PlanID); err != nil || parsed == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

func (command CreateChallengeCommand) Digest() ([sha256.Size]byte, error) {
	return digestCommand(struct {
		SchemaVersion    string `json:"schema_version"`
		OwnerID          string `json:"owner_id"`
		PlanID           string `json:"plan_id"`
		ExpectedRevision uint64 `json:"expected_revision"`
		SignerKeyID      string `json:"signer_key_id"`
	}{"dirextalk.agent.cloud.create-challenge-request/v1", command.OwnerID, command.PlanID, command.ExpectedRevision, command.SignerKeyID})
}

func (approval ApprovalSignature) Validate() error {
	for _, identifier := range []string{approval.ApprovalID, approval.ChallengeID, approval.SignerKeyID} {
		if strings.TrimSpace(identifier) == "" || security.ContainsLikelySecret(identifier) {
			return ErrInvalid
		}
	}
	if parsed, err := uuid.Parse(approval.ApprovalID); err != nil || parsed == uuid.Nil {
		return ErrInvalid
	}
	if approval.ExpiresAt.IsZero() || len(approval.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return nil
}

func (command ApprovePlanCommand) Validate() error {
	if err := validateMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if strings.TrimSpace(command.OwnerID) == "" || command.ExpectedRevision == 0 || command.Approval.Validate() != nil {
		return ErrInvalid
	}
	if parsed, err := uuid.Parse(command.PlanID); err != nil || parsed == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

func (command ApprovePlanCommand) Digest() ([sha256.Size]byte, error) {
	return digestCommand(struct {
		SchemaVersion    string            `json:"schema_version"`
		OwnerID          string            `json:"owner_id"`
		PlanID           string            `json:"plan_id"`
		ExpectedRevision uint64            `json:"expected_revision"`
		Approval         ApprovalSignature `json:"approval"`
	}{"dirextalk.agent.cloud.approve-plan-request/v1", command.OwnerID, command.PlanID, command.ExpectedRevision, command.Approval})
}

func (command EstablishConnectionCommand) Validate() error {
	if err := validateMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if strings.TrimSpace(command.OwnerID) == "" || command.ExpectedSessionRevision == 0 || command.ExpectedPlanRevision == 0 || command.Approval.Validate() != nil {
		return ErrInvalid
	}
	for _, identifier := range []string{command.BootstrapSessionID, command.PlanID} {
		if parsed, err := uuid.Parse(identifier); err != nil || parsed == uuid.Nil {
			return ErrInvalid
		}
	}
	return nil
}

func (command EstablishConnectionCommand) Digest() ([sha256.Size]byte, error) {
	return digestCommand(struct {
		SchemaVersion           string            `json:"schema_version"`
		OwnerID                 string            `json:"owner_id"`
		BootstrapSessionID      string            `json:"bootstrap_session_id"`
		ExpectedSessionRevision uint64            `json:"expected_session_revision"`
		PlanID                  string            `json:"plan_id"`
		ExpectedPlanRevision    uint64            `json:"expected_plan_revision"`
		Approval                ApprovalSignature `json:"approval"`
	}{
		"dirextalk.agent.cloud.establish-connection-request/v1", command.OwnerID, command.BootstrapSessionID,
		command.ExpectedSessionRevision, command.PlanID, command.ExpectedPlanRevision, command.Approval,
	})
}

func validateMutationKey(value string) error {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil || parsed == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

func digestCommand(value any) ([sha256.Size]byte, error) {
	encoded, err := canonical.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: deterministic request encoding failed", ErrInvalid)
	}
	return sha256.Sum256(encoded), nil
}

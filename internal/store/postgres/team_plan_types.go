package postgres

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

var (
	ErrTeamFactNotFound      = errors.New("Team Plan fact not found")
	ErrTeamFactRevision      = errors.New("Team Plan fact revision does not match")
	ErrTeamFactScope         = errors.New("Team Plan fact scope does not match")
	ErrTeamFactInvalid       = errors.New("invalid Team Plan fact mutation")
	ErrTeamFactCorrupt       = errors.New("stored Team Plan fact failed integrity validation")
	ErrTeamChallengeConsumed = errors.New("Team Plan approval challenge already consumed")
)

const teamFactSnapshotSchemaV1 = 1

var teamSignerKeyPattern = regexp.MustCompile(
	`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
)
var teamDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type TeamPlanStatus string

const (
	TeamPlanReadyForConfirmation TeamPlanStatus = "ready_for_confirmation"
	TeamPlanApproved             TeamPlanStatus = "approved"
	TeamPlanExpired              TeamPlanStatus = "expired"
	TeamPlanSuperseded           TeamPlanStatus = "superseded"
	TeamPlanExecuting            TeamPlanStatus = "executing"
	TeamPlanCompleted            TeamPlanStatus = "completed"
	TeamPlanFailed               TeamPlanStatus = "failed"
	TeamPlanCanceled             TeamPlanStatus = "canceled"
)

type TeamOfferSnapshotRecord struct {
	OwnerID   string                         `json:"owner_id"`
	Document  teamplan.OfferSnapshotDocument `json:"document"`
	Digest    string                         `json:"digest"`
	CreatedAt time.Time                      `json:"created_at"`
}

func (record TeamOfferSnapshotRecord) Snapshot() (*teamplan.OfferSnapshot, error) {
	snapshot, err := teamplan.NewOfferSnapshot(record.Document)
	if err != nil || snapshot.Digest() != record.Digest {
		return nil, ErrTeamFactCorrupt
	}
	return snapshot, nil
}

type TeamPlanRecord struct {
	TaskID         string         `json:"task_id,omitempty"`
	Plan           teamplan.Plan  `json:"plan"`
	PlanDigest     string         `json:"plan_digest"`
	Status         TeamPlanStatus `json:"status"`
	RecordRevision uint64         `json:"record_revision"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type TeamApprovalChallengeRecord struct {
	Challenge      teamapproval.ChallengeV1 `json:"challenge"`
	ConsumedAt     *time.Time               `json:"consumed_at,omitempty"`
	RecordRevision uint64                   `json:"record_revision"`
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
}

type TeamApprovalRecord struct {
	Signature  teamapproval.SignatureV1 `json:"signature"`
	ApprovedAt time.Time                `json:"approved_at"`
	CreatedAt  time.Time                `json:"created_at"`
}

type CreateTeamOfferSnapshotCommand struct {
	IdempotencyKey string
	OwnerID        string
	Snapshot       *teamplan.OfferSnapshot
}

func (command CreateTeamOfferSnapshotCommand) validate() error {
	if err := validateTeamMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if command.OwnerID != strings.TrimSpace(command.OwnerID) ||
		command.OwnerID == "" ||
		len(command.OwnerID) > 255 ||
		command.Snapshot == nil {
		return ErrTeamFactInvalid
	}
	if _, err := command.Snapshot.CanonicalCBOR(); err != nil {
		return ErrTeamFactInvalid
	}
	return nil
}

func (command CreateTeamOfferSnapshotCommand) digest() ([sha256.Size]byte, error) {
	return teamMutationDigest(struct {
		OwnerID  string                         `json:"owner_id"`
		Document teamplan.OfferSnapshotDocument `json:"document"`
	}{
		OwnerID:  command.OwnerID,
		Document: command.Snapshot.Document(),
	})
}

type CreateTeamPlanCommand struct {
	IdempotencyKey           string
	TaskID                   string
	ExpectedPreviousRevision uint64
	Plan                     teamplan.Plan
}

func (command CreateTeamPlanCommand) validate() error {
	if err := validateTeamMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if err := command.Plan.Validate(); err != nil ||
		command.Plan.Revision > uint64(math.MaxInt64) {
		return ErrTeamFactInvalid
	}
	if command.Plan.Revision == 1 {
		if command.ExpectedPreviousRevision != 0 {
			return ErrTeamFactInvalid
		}
	} else if command.ExpectedPreviousRevision != command.Plan.Revision-1 {
		return ErrTeamFactInvalid
	}
	if command.TaskID != "" && !canonicalTeamUUID(command.TaskID) {
		return ErrTeamFactInvalid
	}
	return nil
}

func (command CreateTeamPlanCommand) digest() ([sha256.Size]byte, error) {
	return teamMutationDigest(struct {
		TaskID                   string        `json:"task_id,omitempty"`
		ExpectedPreviousRevision uint64        `json:"expected_previous_revision"`
		Plan                     teamplan.Plan `json:"plan"`
	}{
		TaskID:                   command.TaskID,
		ExpectedPreviousRevision: command.ExpectedPreviousRevision,
		Plan:                     command.Plan,
	})
}

type CreateTeamApprovalChallengeCommand struct {
	IdempotencyKey             string
	OwnerID                    string
	PlanID                     string
	PlanRevision               uint64
	ExpectedPlanRecordRevision uint64
	ApprovalID                 string
	ChallengeID                string
	SignerKeyID                string
}

func (command CreateTeamApprovalChallengeCommand) validate() error {
	if err := validateTeamMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if !validTeamOwnerID(command.OwnerID) ||
		!canonicalTeamUUID(command.PlanID) ||
		command.PlanRevision == 0 ||
		command.PlanRevision > uint64(math.MaxInt64) ||
		command.ExpectedPlanRecordRevision == 0 ||
		!canonicalTeamUUID(command.ApprovalID) ||
		!canonicalTeamUUID(command.ChallengeID) ||
		!teamSignerKeyPattern.MatchString(command.SignerKeyID) {
		return ErrTeamFactInvalid
	}
	return nil
}

func (command CreateTeamApprovalChallengeCommand) digest() ([sha256.Size]byte, error) {
	return teamMutationDigest(struct {
		OwnerID                    string `json:"owner_id"`
		PlanID                     string `json:"plan_id"`
		PlanRevision               uint64 `json:"plan_revision"`
		ExpectedPlanRecordRevision uint64 `json:"expected_plan_record_revision"`
		ApprovalID                 string `json:"approval_id"`
		ChallengeID                string `json:"challenge_id"`
		SignerKeyID                string `json:"signer_key_id"`
	}{
		OwnerID:                    command.OwnerID,
		PlanID:                     command.PlanID,
		PlanRevision:               command.PlanRevision,
		ExpectedPlanRecordRevision: command.ExpectedPlanRecordRevision,
		ApprovalID:                 command.ApprovalID,
		ChallengeID:                command.ChallengeID,
		SignerKeyID:                command.SignerKeyID,
	})
}

type ExpireTeamPlanCommand struct {
	IdempotencyKey         string
	OwnerID                string
	PlanID                 string
	PlanRevision           uint64
	ExpectedRecordRevision uint64
}

func (command ExpireTeamPlanCommand) validate() error {
	if err := validateTeamMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if !validTeamOwnerID(command.OwnerID) ||
		!canonicalTeamUUID(command.PlanID) ||
		command.PlanRevision == 0 ||
		command.PlanRevision > uint64(math.MaxInt64) ||
		command.ExpectedRecordRevision == 0 ||
		command.ExpectedRecordRevision > uint64(math.MaxInt64) {
		return ErrTeamFactInvalid
	}
	return nil
}

func (command ExpireTeamPlanCommand) digest() ([sha256.Size]byte, error) {
	return teamMutationDigest(struct {
		OwnerID                string `json:"owner_id"`
		PlanID                 string `json:"plan_id"`
		PlanRevision           uint64 `json:"plan_revision"`
		ExpectedRecordRevision uint64 `json:"expected_record_revision"`
	}{
		OwnerID:                command.OwnerID,
		PlanID:                 command.PlanID,
		PlanRevision:           command.PlanRevision,
		ExpectedRecordRevision: command.ExpectedRecordRevision,
	})
}

type ApproveTeamPlanCommand struct {
	IdempotencyKey                  string
	OwnerID                         string
	ExpectedPlanRecordRevision      uint64
	ExpectedChallengeRecordRevision uint64
	Signature                       teamapproval.SignatureV1
}

func (command ApproveTeamPlanCommand) validate() error {
	if err := validateTeamMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	signature := command.Signature
	decoded, err := base64.RawURLEncoding.DecodeString(
		signature.SignatureBase64URL,
	)
	if !validTeamOwnerID(command.OwnerID) ||
		command.ExpectedPlanRecordRevision == 0 ||
		command.ExpectedChallengeRecordRevision == 0 ||
		signature.SchemaVersion != teamapproval.SignatureSchemaV1 ||
		!canonicalTeamUUID(signature.ApprovalID) ||
		!canonicalTeamUUID(signature.ChallengeID) ||
		!canonicalTeamUUID(signature.PlanID) ||
		signature.PlanRevision == 0 ||
		signature.PlanRevision > uint64(math.MaxInt64) ||
		!teamDigestPattern.MatchString(signature.PlanDigest) ||
		!teamSignerKeyPattern.MatchString(signature.SignerKeyID) ||
		err != nil ||
		len(decoded) != 64 ||
		base64.RawURLEncoding.EncodeToString(decoded) !=
			signature.SignatureBase64URL {
		return ErrTeamFactInvalid
	}
	return nil
}

func (command ApproveTeamPlanCommand) digest() ([sha256.Size]byte, error) {
	return teamMutationDigest(struct {
		OwnerID                         string                   `json:"owner_id"`
		ExpectedPlanRecordRevision      uint64                   `json:"expected_plan_record_revision"`
		ExpectedChallengeRecordRevision uint64                   `json:"expected_challenge_record_revision"`
		Signature                       teamapproval.SignatureV1 `json:"signature"`
	}{
		OwnerID:                         command.OwnerID,
		ExpectedPlanRecordRevision:      command.ExpectedPlanRecordRevision,
		ExpectedChallengeRecordRevision: command.ExpectedChallengeRecordRevision,
		Signature:                       command.Signature,
	})
}

func validateTeamMutationKey(value string) error {
	if !canonicalTeamUUID(value) {
		return fmt.Errorf("%w: idempotency_key must be a canonical UUID", ErrTeamFactInvalid)
	}
	return nil
}

func teamMutationDigest(value any) ([sha256.Size]byte, error) {
	encoded, err := canonical.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf(
			"%w: canonicalize Team Plan mutation",
			ErrTeamFactInvalid,
		)
	}
	return sha256.Sum256(encoded), nil
}

func canonicalTeamUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validTeamOwnerID(value string) bool {
	return value == strings.TrimSpace(value) &&
		value != "" &&
		len(value) <= 255
}

func validTeamPlanStatus(status TeamPlanStatus) bool {
	switch status {
	case TeamPlanReadyForConfirmation,
		TeamPlanApproved,
		TeamPlanExpired,
		TeamPlanSuperseded,
		TeamPlanExecuting,
		TeamPlanCompleted,
		TeamPlanFailed,
		TeamPlanCanceled:
		return true
	default:
		return false
	}
}

func validateTeamApprovalDevice(
	device cloudapproval.DeviceKeyV1,
	agentInstanceID,
	ownerID,
	signerKeyID string,
	now time.Time,
) error {
	if device.AgentInstanceID != agentInstanceID ||
		device.OwnerID != ownerID ||
		device.KeyID != signerKeyID {
		return ErrTeamFactScope
	}
	if err := device.ValidateAt(now); err != nil {
		return ErrTeamFactScope
	}
	return nil
}

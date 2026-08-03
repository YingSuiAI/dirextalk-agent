package postgres

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
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
	Challenge      teamapproval.ChallengeV1    `json:"challenge"`
	Authorization  *teamlaunch.AuthorizationV1 `json:"authorization,omitempty"`
	ConsumedAt     *time.Time                  `json:"consumed_at,omitempty"`
	RecordRevision uint64                      `json:"record_revision"`
	CreatedAt      time.Time                   `json:"created_at"`
	UpdatedAt      time.Time                   `json:"updated_at"`
}

type TeamApprovalRecord struct {
	Signature     teamapproval.SignatureV1    `json:"signature"`
	Authorization *teamlaunch.AuthorizationV1 `json:"authorization,omitempty"`
	ApprovedAt    time.Time                   `json:"approved_at"`
	CreatedAt     time.Time                   `json:"created_at"`
}

type TeamPlanPreparationIntent struct {
	OwnerID                  string                `json:"owner_id"`
	TaskID                   string                `json:"task_id,omitempty"`
	ConnectionID             string                `json:"connection_id"`
	PlanID                   string                `json:"plan_id"`
	Revision                 uint64                `json:"revision"`
	ExpectedPreviousRevision uint64                `json:"expected_previous_revision"`
	GoalDigest               string                `json:"goal_digest"`
	TaskInput                taskinput.BindingV2   `json:"task_input"`
	Proposal                 teamplan.TeamProposal `json:"proposal"`
}

func (intent TeamPlanPreparationIntent) validate() error {
	if !validTeamOwnerID(intent.OwnerID) ||
		!canonicalTeamUUID(intent.ConnectionID) ||
		!canonicalTeamUUID(intent.PlanID) ||
		intent.Revision == 0 ||
		intent.Revision > uint64(math.MaxInt64) ||
		!teamDigestPattern.MatchString(intent.GoalDigest) ||
		intent.Proposal.Confidence == 0 ||
		intent.Proposal.Confidence > 100 ||
		len(intent.Proposal.Rationale) == 0 ||
		len(intent.Proposal.Rationale) > 4096 ||
		len(intent.Proposal.Roles) == 0 ||
		len(intent.Proposal.Roles) > 8 {
		return ErrTeamFactInvalid
	}
	if intent.TaskInput == (taskinput.BindingV2{}) {
		if intent.TaskID != "" && !canonicalTeamUUID(intent.TaskID) {
			return ErrTeamFactInvalid
		}
	} else if !canonicalTeamUUID(intent.TaskID) ||
		intent.TaskInput.ValidateFor(
			intent.OwnerID,
			intent.TaskID,
			intent.GoalDigest,
		) != nil {
		return ErrTeamFactInvalid
	}
	if intent.Revision == 1 {
		if intent.ExpectedPreviousRevision != 0 {
			return ErrTeamFactInvalid
		}
	} else if intent.ExpectedPreviousRevision != intent.Revision-1 {
		return ErrTeamFactInvalid
	}
	for _, role := range intent.Proposal.Roles {
		if len(role.RoleID) == 0 || len(role.RoleID) > 64 ||
			len(role.Title) == 0 || len(role.Title) > 160 ||
			len(role.Objective) == 0 || len(role.Objective) > 8192 ||
			len(role.RequiredCapabilities) == 0 ||
			len(role.RequiredCapabilities) > 24 ||
			len(role.PreferredFamilies) > 8 ||
			len(role.DependsOnRoleIDs) > 7 {
			return ErrTeamFactInvalid
		}
	}
	return nil
}

func (intent TeamPlanPreparationIntent) digest() ([sha256.Size]byte, error) {
	if err := intent.validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	return teamMutationDigest(intent)
}

type PreparedTeamPlanRecord struct {
	Offer    TeamOfferSnapshotRecord `json:"offer"`
	Plan     TeamPlanRecord          `json:"plan"`
	Replayed bool                    `json:"replayed"`
}

type FindPreparedTeamPlanCommand struct {
	IdempotencyKey string
	Intent         TeamPlanPreparationIntent
}

func (command FindPreparedTeamPlanCommand) validate() error {
	if err := validateTeamMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	return command.Intent.validate()
}

type PrepareTeamPlanCommand struct {
	IdempotencyKey string
	Intent         TeamPlanPreparationIntent
	Snapshot       *teamplan.OfferSnapshot
	Plan           teamplan.Plan
}

func (command PrepareTeamPlanCommand) validate() error {
	if err := validateTeamMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if err := command.Intent.validate(); err != nil ||
		command.Snapshot == nil ||
		command.Plan.Validate() != nil ||
		command.Plan.OwnerID != command.Intent.OwnerID ||
		command.Plan.PlanID != command.Intent.PlanID ||
		command.Plan.Revision != command.Intent.Revision ||
		command.Plan.GoalDigest != command.Intent.GoalDigest ||
		command.Plan.TaskInput != command.Intent.TaskInput ||
		command.Plan.ProviderScope.ConnectionID != command.Intent.ConnectionID ||
		command.Plan.PricingSnapshotID != command.Snapshot.SnapshotID() ||
		command.Plan.PricingSnapshotDigest != command.Snapshot.Digest() ||
		command.Plan.ProviderScope != command.Snapshot.ProviderScope() ||
		command.Plan.Region != command.Snapshot.Region() ||
		command.Plan.ProposalConfidence != command.Intent.Proposal.Confidence ||
		command.Plan.ProposalRationale != command.Intent.Proposal.Rationale ||
		!teamPlanMatchesPreparationIntent(command.Plan, command.Intent) {
		return ErrTeamFactInvalid
	}
	return nil
}

func teamPlanMatchesPreparationIntent(
	plan teamplan.Plan,
	intent TeamPlanPreparationIntent,
) bool {
	if plan.WorkerCount != uint32(len(intent.Proposal.Roles)) {
		return false
	}
	assignments := make(
		map[string]teamplan.WorkerAssignment,
		len(plan.Assignments),
	)
	for _, assignment := range plan.Assignments {
		assignments[assignment.RoleID] = assignment
	}
	for _, role := range intent.Proposal.Roles {
		assignment, exists := assignments[role.RoleID]
		required := append(
			[]teamplan.Capability(nil),
			role.RequiredCapabilities...,
		)
		dependencies := append(
			[]string(nil),
			role.DependsOnRoleIDs...,
		)
		slices.Sort(required)
		slices.Sort(dependencies)
		if !exists ||
			assignment.Title != role.Title ||
			assignment.Objective != role.Objective ||
			assignment.WorkClass != role.WorkClass ||
			!slices.Equal(assignment.RequiredCapabilities, required) ||
			assignment.Workspace != role.Workspace ||
			!slices.Equal(assignment.DependsOnRoleIDs, dependencies) ||
			assignment.Duration != role.Duration ||
			assignment.Tokens != role.Tokens ||
			assignment.Resources.VCPU < role.MinimumResources.VCPU ||
			assignment.Resources.MemoryMiB < role.MinimumResources.MemoryMiB ||
			assignment.Resources.DiskGiB < role.MinimumResources.DiskGiB ||
			role.MinimumResources.Arch != "" &&
				assignment.Resources.Arch != role.MinimumResources.Arch {
			return false
		}
	}
	return true
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
	if command.Plan.SchemaVersion == teamplan.SchemaV3 {
		if !canonicalTeamUUID(command.TaskID) ||
			command.Plan.TaskInput.ValidateFor(
				command.Plan.OwnerID,
				command.TaskID,
				command.Plan.GoalDigest,
			) != nil {
			return ErrTeamFactInvalid
		}
	} else if command.TaskID != "" && !canonicalTeamUUID(command.TaskID) {
		return ErrTeamFactInvalid
	}
	if command.Plan.Revision == 1 {
		if command.ExpectedPreviousRevision != 0 {
			return ErrTeamFactInvalid
		}
	} else if command.ExpectedPreviousRevision != command.Plan.Revision-1 {
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
	Authorization              teamlaunch.AuthorizationV1
}

type FindTeamApprovalChallengeCommand struct {
	IdempotencyKey             string
	OwnerID                    string
	PlanID                     string
	PlanRevision               uint64
	ExpectedPlanRecordRevision uint64
	ApprovalID                 string
	ChallengeID                string
	SignerKeyID                string
}

func (command FindTeamApprovalChallengeCommand) validate() error {
	if err := validateTeamMutationKey(command.IdempotencyKey); err != nil {
		return err
	}
	if !validTeamOwnerID(command.OwnerID) ||
		!canonicalTeamUUID(command.PlanID) ||
		command.PlanRevision == 0 ||
		command.PlanRevision > uint64(math.MaxInt64) ||
		command.ExpectedPlanRecordRevision == 0 ||
		command.ExpectedPlanRecordRevision > uint64(math.MaxInt64) ||
		!canonicalTeamUUID(command.ApprovalID) ||
		!canonicalTeamUUID(command.ChallengeID) ||
		!teamSignerKeyPattern.MatchString(command.SignerKeyID) {
		return ErrTeamFactInvalid
	}
	return nil
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
		command.ExpectedPlanRecordRevision > uint64(math.MaxInt64) ||
		!canonicalTeamUUID(command.ApprovalID) ||
		!canonicalTeamUUID(command.ChallengeID) ||
		!teamSignerKeyPattern.MatchString(command.SignerKeyID) ||
		command.Authorization.Validate() != nil ||
		command.Authorization.OwnerID != command.OwnerID ||
		command.Authorization.PlanID != command.PlanID ||
		command.Authorization.PlanRevision != command.PlanRevision ||
		command.Authorization.ApprovalID != command.ApprovalID {
		return ErrTeamFactInvalid
	}
	return nil
}

func (command CreateTeamApprovalChallengeCommand) digest() ([sha256.Size]byte, error) {
	return teamApprovalChallengeIntentDigest(
		command.OwnerID,
		command.PlanID,
		command.PlanRevision,
		command.ExpectedPlanRecordRevision,
		command.ApprovalID,
		command.ChallengeID,
		command.SignerKeyID,
	)
}

func (command FindTeamApprovalChallengeCommand) digest() ([sha256.Size]byte, error) {
	return teamApprovalChallengeIntentDigest(
		command.OwnerID,
		command.PlanID,
		command.PlanRevision,
		command.ExpectedPlanRecordRevision,
		command.ApprovalID,
		command.ChallengeID,
		command.SignerKeyID,
	)
}

func teamApprovalChallengeIntentDigest(
	ownerID,
	planID string,
	planRevision,
	expectedPlanRecordRevision uint64,
	approvalID,
	challengeID,
	signerKeyID string,
) ([sha256.Size]byte, error) {
	return teamMutationDigest(struct {
		OwnerID                    string `json:"owner_id"`
		PlanID                     string `json:"plan_id"`
		PlanRevision               uint64 `json:"plan_revision"`
		ExpectedPlanRecordRevision uint64 `json:"expected_plan_record_revision"`
		ApprovalID                 string `json:"approval_id"`
		ChallengeID                string `json:"challenge_id"`
		SignerKeyID                string `json:"signer_key_id"`
	}{
		OwnerID:                    ownerID,
		PlanID:                     planID,
		PlanRevision:               planRevision,
		ExpectedPlanRecordRevision: expectedPlanRecordRevision,
		ApprovalID:                 approvalID,
		ChallengeID:                challengeID,
		SignerKeyID:                signerKeyID,
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
		signature.Validate() != nil ||
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

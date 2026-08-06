package coreteam

import (
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxProjectionSummaryBytes = 4096

// PrepareCommand is the complete model-to-Team boundary. Cloud, credential,
// runtime, image and price choices are intentionally absent.
type PrepareCommand struct {
	Scope          Scope
	ConversationID string
	Goal           string
	Roles          []RoleProposal
	IdempotencyKey string
	RequestDigest  string
}

func (c PrepareCommand) Validate() error {
	if c.Scope.Validate() != nil || !validUUID(c.ConversationID) || !validUUID(c.IdempotencyKey) || !validDigest(c.RequestDigest) ||
		!validBoundedText(strings.TrimSpace(c.Goal), MaxGoalBytes) {
		return ErrInvalid
	}
	roles := make([]Role, len(c.Roles))
	for index, proposal := range c.Roles {
		roles[index] = Role{
			RoleID: proposal.RoleID, Goal: strings.TrimSpace(proposal.Goal),
			DependsOn: append([]string(nil), proposal.DependsOn...), Capabilities: append([]Capability(nil), proposal.Capabilities...),
		}
	}
	return validateRoles(roles)
}

type StatusQuery struct {
	Scope       Scope
	TaskID      string
	ExecutionID string
}

func (q StatusQuery) Validate() error {
	if q.Scope.Validate() != nil || (q.TaskID == "") == (q.ExecutionID == "") {
		return ErrInvalid
	}
	if (q.TaskID != "" && !validUUID(q.TaskID)) || (q.ExecutionID != "" && !validUUID(q.ExecutionID)) {
		return ErrInvalid
	}
	return nil
}

type PlanProjection struct {
	TaskID         string     `json:"task_id"`
	PlanID         string     `json:"plan_id"`
	ConfirmationID string     `json:"confirmation_id"`
	Revision       uint64     `json:"revision"`
	Status         PlanStatus `json:"status"`
	Summary        string     `json:"summary"`
}

func (p PlanProjection) Validate() error {
	if !validUUID(p.TaskID) || !validUUID(p.PlanID) || !validUUID(p.ConfirmationID) ||
		!uniqueStrings(p.TaskID, p.PlanID, p.ConfirmationID) || p.Revision == 0 || !validPlanStatus(p.Status) || !validProjectionSummary(p.Summary) {
		return ErrInvalid
	}
	return nil
}

type ExecutionProjection struct {
	ExecutionID     string          `json:"execution_id"`
	PlanID          string          `json:"plan_id"`
	TaskID          string          `json:"task_id"`
	ConfirmationID  string          `json:"confirmation_id"`
	Status          ExecutionStatus `json:"status"`
	Revision        uint64          `json:"revision"`
	CleanupVerified bool            `json:"cleanup_verified"`
	Summary         string          `json:"summary"`
}

func (p ExecutionProjection) Validate() error {
	if !validUUID(p.ExecutionID) || !validUUID(p.PlanID) || !validUUID(p.TaskID) || !validUUID(p.ConfirmationID) ||
		!uniqueStrings(p.ExecutionID, p.PlanID, p.TaskID, p.ConfirmationID) || validateExecutionStatus(p.Status) != nil ||
		p.Revision == 0 || p.CleanupVerified != IsTerminalExecution(p.Status) || !validProjectionSummary(p.Summary) {
		return ErrInvalid
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validProjectionSummary(value string) bool {
	return value == strings.TrimSpace(value) && value != "" && utf8.ValidString(value) && len(value) <= MaxProjectionSummaryBytes &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}

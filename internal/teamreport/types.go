// Package teamreport builds the durable, device-safe projection of one
// completed Team execution. It contains no cloud object coordinates, raw
// Worker output, model credentials, or provider credentials.
package teamreport

import (
	"context"
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

const SchemaV1 = "dirextalk.agent.team-execution-report/v1"

const (
	maximumRoles         = 8
	maximumFinalsPerRole = 8
	maximumListItems     = 64
	maximumTextBytes     = 8 << 10
)

var (
	ErrInvalid      = errors.New("invalid Team execution report")
	ErrFactMismatch = errors.New("Team execution report fact mismatch")
	ErrNotReady     = errors.New("Team execution report is not ready")
	ErrNotFound     = errors.New("Team execution report was not found")

	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	roleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// FinalV1 is the safe projection of a runtime final. Artifact coordinates,
// sizes, and media types remain internal; the verified content digest is
// retained so a later download can be checked against the frozen result.
type FinalV1 struct {
	ActionID       string                `json:"action_id"`
	Adapter        workerruntime.Adapter `json:"adapter"`
	Usage          workerruntime.Usage   `json:"usage"`
	Status         string                `json:"status"`
	Summary        string                `json:"summary"`
	Deliverables   []string              `json:"deliverables"`
	Tests          []string              `json:"tests"`
	Risks          []string              `json:"risks"`
	ArtifactSHA256 string                `json:"artifact_sha256"`
}

func (value FinalV1) Validate() error {
	if !actionPattern.MatchString(value.ActionID) ||
		!value.Adapter.IsSupported() ||
		value.Usage.Validate() != nil ||
		(value.Status != "completed" &&
			value.Status != "partial" &&
			value.Status != "blocked") ||
		!validText(value.Summary) ||
		!validList(value.Deliverables) ||
		!validList(value.Tests) ||
		!validList(value.Risks) ||
		!digestPattern.MatchString(value.ArtifactSHA256) {
		return ErrInvalid
	}
	return nil
}

type RoleV1 struct {
	RoleID               string                 `json:"role_id"`
	Title                string                 `json:"title"`
	RuntimeFamily        teamplan.RuntimeFamily `json:"runtime_family"`
	RuntimeAdapter       workerruntime.Adapter  `json:"runtime_adapter"`
	Outcome              task.OutcomeStatus     `json:"outcome"`
	ResultEvidenceDigest string                 `json:"result_evidence_digest"`
	Finals               []FinalV1              `json:"finals"`
}

func (value RoleV1) Validate() error {
	if !roleIDPattern.MatchString(value.RoleID) ||
		!validText(value.Title) ||
		!runtimePairMatches(
			value.RuntimeFamily,
			value.RuntimeAdapter,
		) ||
		value.Outcome != task.OutcomeSucceeded ||
		!digestPattern.MatchString(value.ResultEvidenceDigest) ||
		len(value.Finals) == 0 ||
		len(value.Finals) > maximumFinalsPerRole {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(value.Finals))
	for _, final := range value.Finals {
		if final.Validate() != nil ||
			final.Adapter != value.RuntimeAdapter {
			return ErrInvalid
		}
		if _, duplicate := seen[final.ActionID]; duplicate {
			return ErrInvalid
		}
		seen[final.ActionID] = struct{}{}
	}
	return nil
}

type ReportV1 struct {
	SchemaVersion string              `json:"schema_version"`
	ExecutionID   string              `json:"execution_id"`
	OwnerID       string              `json:"owner_id"`
	TaskID        string              `json:"task_id"`
	PlanID        string              `json:"plan_id"`
	PlanRevision  uint64              `json:"plan_revision"`
	PlanDigest    string              `json:"plan_digest"`
	Roles         []RoleV1            `json:"roles"`
	TotalUsage    workerruntime.Usage `json:"total_usage"`
}

func (value ReportV1) Validate() error {
	for _, candidate := range []string{
		value.ExecutionID,
		value.TaskID,
		value.PlanID,
	} {
		if !canonicalUUID(candidate) {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != SchemaV1 ||
		value.OwnerID == "" ||
		value.OwnerID != strings.TrimSpace(value.OwnerID) ||
		len(value.OwnerID) > 255 ||
		value.PlanRevision == 0 ||
		!digestPattern.MatchString(value.PlanDigest) ||
		len(value.Roles) == 0 ||
		len(value.Roles) > maximumRoles ||
		value.TotalUsage.Validate() != nil {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(value.Roles))
	total := workerruntime.Usage{}
	for _, role := range value.Roles {
		if role.Validate() != nil {
			return ErrInvalid
		}
		if _, duplicate := seen[role.RoleID]; duplicate {
			return ErrInvalid
		}
		seen[role.RoleID] = struct{}{}
		for _, final := range role.Finals {
			if addUsage(&total, final.Usage) != nil {
				return ErrInvalid
			}
		}
	}
	if total != value.TotalUsage {
		return ErrInvalid
	}
	return nil
}

func (value ReportV1) Digest() (string, error) {
	if value.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(value)
}

type Fact struct {
	Report       ReportV1  `json:"report"`
	ReportDigest string    `json:"report_digest"`
	GeneratedAt  time.Time `json:"generated_at"`
}

func (value Fact) Validate() error {
	digest, err := value.Report.Digest()
	if err != nil ||
		value.ReportDigest != digest ||
		!utcMicrosecond(value.GeneratedAt) {
		return ErrInvalid
	}
	return nil
}

type Reader interface {
	GetTeamExecutionReport(
		context.Context,
		string,
		string,
	) (Fact, error)
}

// Build creates one deterministic report in the immutable execution role
// order. Every role must already have completed successfully with verified
// result evidence.
func Build(
	execution teamexecution.ExecutionV1,
	operations []teamdispatch.Fact,
) (ReportV1, error) {
	if execution.Validate() != nil ||
		len(operations) != len(execution.Roles) {
		return ReportV1{}, ErrInvalid
	}
	byRole := make(map[string]teamdispatch.Fact, len(operations))
	for _, operation := range operations {
		if operation.Validate() != nil ||
			operation.Intent.ExecutionID != execution.ExecutionID ||
			operation.Intent.OwnerID != execution.OwnerID ||
			operation.Intent.TaskID != execution.TaskID ||
			operation.Intent.PlanID != execution.PlanID ||
			operation.Intent.PlanRevision != execution.PlanRevision ||
			operation.Intent.PlanDigest != execution.PlanDigest ||
			operation.Phase != teamdispatch.PhaseCompleted ||
			operation.Outcome != task.OutcomeSucceeded ||
			operation.ResultEvidence == nil {
			return ReportV1{}, ErrInvalid
		}
		if _, duplicate := byRole[operation.Intent.RoleID]; duplicate {
			return ReportV1{}, ErrInvalid
		}
		byRole[operation.Intent.RoleID] = operation
	}
	report := ReportV1{
		SchemaVersion: SchemaV1,
		ExecutionID:   execution.ExecutionID,
		OwnerID:       execution.OwnerID,
		TaskID:        execution.TaskID,
		PlanID:        execution.PlanID,
		PlanRevision:  execution.PlanRevision,
		PlanDigest:    execution.PlanDigest,
		Roles:         make([]RoleV1, 0, len(execution.Roles)),
	}
	for _, role := range execution.Roles {
		operation, found := byRole[role.RoleID]
		if !found ||
			operation.Intent.TaskStepID != role.TaskStepID ||
			operation.Intent.DeploymentID != role.DeploymentID ||
			operation.Intent.ExpectedWorkerID !=
				role.ExpectedWorkerID {
			return ReportV1{}, ErrInvalid
		}
		projected := RoleV1{
			RoleID:               role.RoleID,
			Title:                role.Title,
			RuntimeFamily:        role.RuntimeFamily,
			RuntimeAdapter:       workerruntime.Adapter(role.RuntimeAdapter),
			Outcome:              operation.Outcome,
			ResultEvidenceDigest: operation.ResultEvidenceDigest,
			Finals: make(
				[]FinalV1,
				0,
				len(operation.ResultEvidence.Finals),
			),
		}
		for _, final := range operation.ResultEvidence.Finals {
			projected.Finals = append(projected.Finals, FinalV1{
				ActionID:       final.ActionID,
				Adapter:        final.Adapter,
				Usage:          final.Usage,
				Status:         final.Status,
				Summary:        final.Summary,
				Deliverables:   slices.Clone(final.Deliverables),
				Tests:          slices.Clone(final.Tests),
				Risks:          slices.Clone(final.Risks),
				ArtifactSHA256: final.ArtifactSHA256,
			})
			if addUsage(&report.TotalUsage, final.Usage) != nil {
				return ReportV1{}, ErrInvalid
			}
		}
		report.Roles = append(report.Roles, projected)
	}
	if report.Validate() != nil {
		return ReportV1{}, ErrInvalid
	}
	return report, nil
}

func addUsage(total *workerruntime.Usage, value workerruntime.Usage) error {
	if total == nil || total.Validate() != nil || value.Validate() != nil {
		return ErrInvalid
	}
	fields := []struct {
		target *int64
		value  int64
	}{
		{&total.InputTokens, value.InputTokens},
		{&total.CachedInputTokens, value.CachedInputTokens},
		{&total.OutputTokens, value.OutputTokens},
		{&total.ReasoningOutputTokens, value.ReasoningOutputTokens},
	}
	for _, field := range fields {
		if field.value > 0 &&
			*field.target > math.MaxInt64-field.value {
			return ErrInvalid
		}
		*field.target += field.value
	}
	if total.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func runtimePairMatches(
	family teamplan.RuntimeFamily,
	adapter workerruntime.Adapter,
) bool {
	switch family {
	case teamplan.RuntimeClaudeCode:
		return adapter == workerruntime.AdapterClaudeCodeV1
	case teamplan.RuntimeCodex:
		return adapter == workerruntime.AdapterCodexV1
	case teamplan.RuntimeOpenClaw:
		return adapter == workerruntime.AdapterOpenClawV1
	case teamplan.RuntimeHermes:
		return adapter == workerruntime.AdapterHermesV1
	case teamplan.RuntimeOpenCode:
		return adapter == workerruntime.AdapterOpenCodeV1
	case teamplan.RuntimePi:
		return adapter == workerruntime.AdapterPiV1
	default:
		return false
	}
}

func validList(values []string) bool {
	if values == nil || len(values) > maximumListItems {
		return false
	}
	for _, value := range values {
		if !validText(value) {
			return false
		}
	}
	return true
}

func validText(value string) bool {
	if value == "" ||
		value != strings.TrimSpace(value) ||
		len(value) > maximumTextBytes ||
		!utf8.ValidString(value) ||
		security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) &&
			character != '\n' &&
			character != '\r' &&
			character != '\t' {
			return false
		}
	}
	return true
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == value
}

func utcMicrosecond(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Equal(value.Truncate(time.Microsecond))
}

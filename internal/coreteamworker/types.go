// Package coreteamworker owns the private, fenced protocol between Central
// Agent and one ephemeral official Pi Worker.
package coreteamworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	MaxResultSizeBytes  = 512 << 10
	MaxResultListItems  = 64
	MaxResultTextBytes  = 8 << 10
	MaxResultTokenCount = 1 << 40
	ResultSchemaVersion = 1
)

var (
	ErrInvalid            = errors.New("core Team Worker request is invalid")
	ErrNotFound           = errors.New("core Team Worker resource was not found")
	ErrConflict           = errors.New("core Team Worker request conflicts with current state")
	ErrExpired            = errors.New("core Team Worker enrollment has expired")
	ErrUnauthorized       = errors.New("core Team Worker identity is unauthorized")
	ErrLeaseConflict      = errors.New("core Team Worker lease fence conflicts with current state")
	ErrRuntimeUnavailable = errors.New("core Team Worker runtime is unavailable")
	roleIDPattern         = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

type ChallengeRequest struct {
	Scope          coreteam.Scope
	ExecutionID    string
	RoleID         string
	Attempt        uint32
	IdentityDigest string
	IdempotencyKey string
}

type Challenge struct {
	ChallengeID    string         `json:"challenge_id"`
	WorkerID       string         `json:"worker_id"`
	Scope          coreteam.Scope `json:"-"`
	ExecutionID    string         `json:"execution_id"`
	RoleID         string         `json:"role_id"`
	Attempt        uint32         `json:"attempt"`
	IdentityDigest string         `json:"-"`
	IdempotencyKey string         `json:"-"`
	RequestDigest  string         `json:"-"`
	CreatedAt      time.Time      `json:"created_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	ConsumedAt     time.Time      `json:"-"`
	Replay         bool           `json:"replay"`
}

func (c Challenge) Validate() error {
	if c.Scope.Validate() != nil || !validUUID(c.ChallengeID) || !validUUID(c.WorkerID) || !validUUID(c.ExecutionID) ||
		!validRoleID(c.RoleID) || c.Attempt == 0 || !validDigest(c.IdentityDigest) || !validUUID(c.IdempotencyKey) ||
		!validDigest(c.RequestDigest) || c.CreatedAt.IsZero() ||
		c.ExpiresAt.Sub(c.CreatedAt) < 30*time.Second || c.ExpiresAt.Sub(c.CreatedAt) > 15*time.Minute ||
		(!c.ConsumedAt.IsZero() && (c.ConsumedAt.Before(c.CreatedAt) || c.ConsumedAt.After(c.ExpiresAt))) ||
		!distinct(c.ChallengeID, c.WorkerID, c.ExecutionID) {
		return ErrInvalid
	}
	return nil
}

type EnrollmentRequest struct {
	ChallengeID string `json:"challenge_id"`
	WorkerID    string `json:"worker_id"`
}

type Enrollment struct {
	WorkerID    string    `json:"worker_id"`
	ExecutionID string    `json:"execution_id"`
	RoleID      string    `json:"role_id"`
	Attempt     uint32    `json:"attempt"`
	ExpiresAt   time.Time `json:"expires_at"`
	Replay      bool      `json:"replay"`
}

func (e Enrollment) Validate(at time.Time) error {
	if e.ValidateReceipt() != nil || !e.ExpiresAt.After(at) {
		return ErrInvalid
	}
	return nil
}

func (e Enrollment) ValidateReceipt() error {
	if !validUUID(e.WorkerID) || !validUUID(e.ExecutionID) || !validRoleID(e.RoleID) || e.Attempt == 0 ||
		e.ExpiresAt.IsZero() || e.WorkerID == e.ExecutionID {
		return ErrInvalid
	}
	return nil
}

type EnrollmentCommand struct {
	ChallengeID    string
	WorkerID       string
	IdentityDigest string
	At             time.Time
	ExpiresAt      time.Time
}

func (c EnrollmentCommand) Validate() error {
	if !validUUID(c.ChallengeID) || !validUUID(c.WorkerID) || c.ChallengeID == c.WorkerID || !validDigest(c.IdentityDigest) ||
		c.At.IsZero() || c.ExpiresAt.Sub(c.At) < time.Minute || c.ExpiresAt.Sub(c.At) > 24*time.Hour {
		return ErrInvalid
	}
	return nil
}

type AssignmentRequest struct {
	WorkerID string `json:"worker_id"`
}

type Assignment struct {
	WorkerID            string                `json:"worker_id"`
	ExecutionID         string                `json:"execution_id"`
	PlanID              string                `json:"plan_id"`
	RoleID              string                `json:"role_id"`
	Attempt             uint32                `json:"attempt"`
	PlanDigest          string                `json:"plan_digest"`
	Goal                string                `json:"goal"`
	Capabilities        []coreteam.Capability `json:"capabilities"`
	RuntimeID           string                `json:"runtime_id"`
	OutputTokens        uint32                `json:"output_tokens"`
	ResultSchemaVersion uint32                `json:"result_schema_version"`
}

func (a Assignment) Validate() error {
	if !validUUID(a.WorkerID) || !validUUID(a.ExecutionID) || !validUUID(a.PlanID) || !distinct(a.WorkerID, a.ExecutionID, a.PlanID) ||
		!validRoleID(a.RoleID) || a.Attempt == 0 || !validDigest(a.PlanDigest) || !validText(a.Goal, coreteam.MaxRoleGoalBytes) ||
		a.RuntimeID != coreteam.OfficialRuntimeID || a.OutputTokens == 0 || a.OutputTokens > coreteam.MaxOutputTokens ||
		a.ResultSchemaVersion != ResultSchemaVersion || !validCapabilities(a.Capabilities) {
		return ErrInvalid
	}
	return nil
}

type WorkerAccess struct {
	WorkerID       string
	IdentityDigest string
	At             time.Time
}

func (a WorkerAccess) Validate() error {
	if !validUUID(a.WorkerID) || !validDigest(a.IdentityDigest) || a.At.IsZero() {
		return ErrInvalid
	}
	return nil
}

type VerifiedIdentity struct {
	WorkerID string
	Digest   string
}

func (i VerifiedIdentity) Validate() error {
	if !validUUID(i.WorkerID) || !validDigest(i.Digest) {
		return ErrUnauthorized
	}
	return nil
}

type LeaseFence struct {
	ExecutionID string `json:"execution_id"`
	RoleID      string `json:"role_id"`
	WorkerID    string `json:"worker_id"`
	Attempt     uint32 `json:"attempt"`
	LeaseEpoch  uint64 `json:"lease_epoch"`
}

func (f LeaseFence) Validate() error {
	if !validUUID(f.ExecutionID) || !validRoleID(f.RoleID) || !validUUID(f.WorkerID) || f.Attempt == 0 || f.LeaseEpoch == 0 || f.ExecutionID == f.WorkerID {
		return ErrInvalid
	}
	return nil
}

type Lease struct {
	Fence     LeaseFence `json:"fence"`
	ExpiresAt time.Time  `json:"expires_at"`
	Replay    bool       `json:"replay"`
}

func (l Lease) Validate(at time.Time) error {
	if l.ValidateReceipt() != nil || !l.ExpiresAt.After(at) {
		return ErrInvalid
	}
	return nil
}

func (l Lease) ValidateReceipt() error {
	if l.Fence.Validate() != nil || l.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type ClaimRequest struct {
	WorkerID    string `json:"worker_id"`
	ExecutionID string `json:"execution_id"`
	RoleID      string `json:"role_id"`
	Attempt     uint32 `json:"attempt"`
	ClaimID     string `json:"claim_id"`
}

type ClaimCommand struct {
	Access      WorkerAccess
	ExecutionID string
	RoleID      string
	Attempt     uint32
	ClaimID     string
	TTL         time.Duration
}

func (c ClaimCommand) Validate() error {
	if c.Access.Validate() != nil || !validUUID(c.ExecutionID) || !validRoleID(c.RoleID) || c.Attempt == 0 ||
		!validUUID(c.ClaimID) || c.TTL < 10*time.Second || c.TTL > 5*time.Minute || c.Access.WorkerID == c.ExecutionID {
		return ErrInvalid
	}
	return nil
}

type HeartbeatRequest struct {
	Fence       LeaseFence `json:"fence"`
	HeartbeatID string     `json:"heartbeat_id"`
}

type HeartbeatCommand struct {
	Access      WorkerAccess
	Fence       LeaseFence
	HeartbeatID string
	TTL         time.Duration
}

func (c HeartbeatCommand) Validate() error {
	if c.Access.Validate() != nil || c.Fence.Validate() != nil || c.Access.WorkerID != c.Fence.WorkerID ||
		!validUUID(c.HeartbeatID) || c.TTL < 10*time.Second || c.TTL > 5*time.Minute {
		return ErrInvalid
	}
	return nil
}

type Stage string

const (
	StagePreparingInput   Stage = "preparing_input"
	StageRunning          Stage = "running"
	StageValidatingResult Stage = "validating_result"
)

type Health string

const (
	HealthHealthy    Health = "healthy"
	HealthDelayed    Health = "delayed"
	HealthRecovering Health = "recovering"
)

type MilestoneRequest struct {
	Fence       LeaseFence `json:"fence"`
	EventID     string     `json:"event_id"`
	Sequence    uint64     `json:"sequence"`
	Stage       Stage      `json:"stage"`
	Health      Health     `json:"health"`
	EventDigest string     `json:"event_digest"`
}

type MilestoneCommand struct {
	Access      WorkerAccess
	Fence       LeaseFence
	EventID     string
	Sequence    uint64
	Stage       Stage
	Health      Health
	EventDigest string
}

func (c MilestoneCommand) Validate() error {
	if c.Access.Validate() != nil || c.Fence.Validate() != nil || c.Access.WorkerID != c.Fence.WorkerID ||
		!validUUID(c.EventID) || c.Sequence == 0 || !validStage(c.Stage) || !validHealth(c.Health) || !validDigest(c.EventDigest) {
		return ErrInvalid
	}
	return nil
}

type MilestoneReceipt struct {
	EventID    string    `json:"event_id"`
	Sequence   uint64    `json:"sequence"`
	AcceptedAt time.Time `json:"accepted_at"`
	Replay     bool      `json:"replay"`
}

func (r MilestoneReceipt) Validate() error {
	if !validUUID(r.EventID) || r.Sequence == 0 || r.AcceptedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type CompletionOutcome string

const (
	OutcomeSucceeded CompletionOutcome = "succeeded"
	OutcomeFailed    CompletionOutcome = "failed"
)

type FailureCode string

const (
	FailureProcess       FailureCode = "process"
	FailurePi            FailureCode = "pi"
	FailureInvalidResult FailureCode = "invalid_result"
	FailureTimeout       FailureCode = "timeout"
	FailureCanceled      FailureCode = "canceled"
	FailureInternal      FailureCode = "internal"
)

type ResultUsageV1 struct {
	InputTokens           uint64 `json:"input_tokens"`
	CachedInputTokens     uint64 `json:"cached_input_tokens"`
	OutputTokens          uint64 `json:"output_tokens"`
	ReasoningOutputTokens uint64 `json:"reasoning_output_tokens"`
}

func (u ResultUsageV1) Validate() error {
	if u.InputTokens > MaxResultTokenCount || u.CachedInputTokens > MaxResultTokenCount || u.OutputTokens > MaxResultTokenCount ||
		u.ReasoningOutputTokens > MaxResultTokenCount || u.CachedInputTokens > u.InputTokens {
		return ErrInvalid
	}
	return nil
}

// ResultPayloadV1 is the only Worker-authored JSON shape that may cross the
// Complete boundary. It contains final, bounded evidence rather than runtime
// events, provider errors, tool traffic, or terminal output.
type ResultPayloadV1 struct {
	SchemaVersion uint32        `json:"schema_version"`
	Status        string        `json:"status"`
	Summary       string        `json:"summary"`
	Deliverables  []string      `json:"deliverables"`
	Tests         []string      `json:"tests"`
	Risks         []string      `json:"risks"`
	Usage         ResultUsageV1 `json:"usage"`
}

func ParseResultPayloadV1(input []byte) (ResultPayloadV1, error) {
	if len(input) == 0 || len(input) > MaxResultSizeBytes || security.ContainsLikelySecret(string(input)) {
		return ResultPayloadV1{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var payload ResultPayloadV1
	if decoder.Decode(&payload) != nil {
		return ResultPayloadV1{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ResultPayloadV1{}, ErrInvalid
	}
	if payload.SchemaVersion != ResultSchemaVersion || !validResultStatus(payload.Status) || !validResultText(payload.Summary) ||
		!validResultList(payload.Deliverables) || !validResultList(payload.Tests) || !validResultList(payload.Risks) || payload.Usage.Validate() != nil {
		return ResultPayloadV1{}, ErrInvalid
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, input) {
		return ResultPayloadV1{}, ErrInvalid
	}
	return payload, nil
}

type ResultMetadata struct {
	SchemaVersion uint32 `json:"schema_version"`
	Digest        string `json:"digest"`
	SizeBytes     uint64 `json:"size_bytes"`
	PayloadJSON   []byte `json:"result_json"`
}

func (m ResultMetadata) Validate() error {
	if m.SchemaVersion != ResultSchemaVersion || !validDigest(m.Digest) || len(m.PayloadJSON) == 0 || len(m.PayloadJSON) > MaxResultSizeBytes ||
		m.SizeBytes != uint64(len(m.PayloadJSON)) {
		return ErrInvalid
	}
	digest := sha256.Sum256(m.PayloadJSON)
	if hex.EncodeToString(digest[:]) != m.Digest {
		return ErrInvalid
	}
	if _, err := ParseResultPayloadV1(m.PayloadJSON); err != nil {
		return ErrInvalid
	}
	return nil
}

func (m ResultMetadata) IsZero() bool {
	return m.SchemaVersion == 0 && m.Digest == "" && m.SizeBytes == 0 && len(m.PayloadJSON) == 0
}

type CompleteRequest struct {
	Fence        LeaseFence        `json:"fence"`
	CompletionID string            `json:"completion_id"`
	Outcome      CompletionOutcome `json:"outcome"`
	Result       ResultMetadata    `json:"result,omitempty"`
	FailureCode  FailureCode       `json:"failure_code,omitempty"`
}

type CompleteCommand struct {
	Access       WorkerAccess
	Fence        LeaseFence
	CompletionID string
	Outcome      CompletionOutcome
	Result       ResultMetadata
	FailureCode  FailureCode
}

func (c CompleteCommand) Validate() error {
	if c.Access.Validate() != nil || c.Fence.Validate() != nil || c.Access.WorkerID != c.Fence.WorkerID || !validUUID(c.CompletionID) ||
		!validCompletion(CompleteRequest{Fence: c.Fence, CompletionID: c.CompletionID, Outcome: c.Outcome, Result: c.Result, FailureCode: c.FailureCode}) {
		return ErrInvalid
	}
	return nil
}

type CompletionReceipt struct {
	CompletionID string            `json:"completion_id"`
	Outcome      CompletionOutcome `json:"outcome"`
	AcceptedAt   time.Time         `json:"accepted_at"`
	Replay       bool              `json:"replay"`
}

func (r CompletionReceipt) Validate() error {
	if !validUUID(r.CompletionID) || (r.Outcome != OutcomeSucceeded && r.Outcome != OutcomeFailed) || r.AcceptedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type Repository interface {
	CreateChallenge(context.Context, Challenge) (Challenge, bool, error)
	GetChallenge(context.Context, string) (Challenge, error)
	Enroll(context.Context, EnrollmentCommand) (Enrollment, bool, error)
	GetAssignment(context.Context, WorkerAccess) (Assignment, error)
	Claim(context.Context, ClaimCommand) (Lease, bool, error)
	Heartbeat(context.Context, HeartbeatCommand) (Lease, bool, error)
	EmitMilestone(context.Context, MilestoneCommand) (MilestoneReceipt, bool, error)
	Complete(context.Context, CompleteCommand) (CompletionReceipt, bool, error)
}

type IdentityVerifier interface {
	VerifyEnrollment(context.Context, Challenge) (VerifiedIdentity, error)
	VerifyWorker(context.Context) (VerifiedIdentity, error)
}

func validUUID(value string) bool { return coretask.ValidUUID(value) }

func validRoleID(value string) bool { return roleIDPattern.MatchString(value) }

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validText(value string, maxBytes int) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) && len(value) <= maxBytes &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}

func validCapabilities(values []coreteam.Capability) bool {
	if len(values) == 0 || len(values) > 10 {
		return false
	}
	seen := make(map[coreteam.Capability]struct{}, len(values))
	for _, value := range values {
		switch value {
		case coreteam.CapabilityRepositoryRead, coreteam.CapabilityRepositoryWrite, coreteam.CapabilityCodeReview,
			coreteam.CapabilityShell, coreteam.CapabilityGit, coreteam.CapabilityTest, coreteam.CapabilityWebResearch,
			coreteam.CapabilityBrowser, coreteam.CapabilityMCPClient, coreteam.CapabilityStructuredResult:
		default:
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func distinct(values ...string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validStage(value Stage) bool {
	switch value {
	case StagePreparingInput, StageRunning, StageValidatingResult:
		return true
	default:
		return false
	}
}

func validHealth(value Health) bool {
	switch value {
	case HealthHealthy, HealthDelayed, HealthRecovering:
		return true
	default:
		return false
	}
}

func validFailure(value FailureCode) bool {
	switch value {
	case FailureProcess, FailurePi, FailureInvalidResult, FailureTimeout, FailureCanceled, FailureInternal:
		return true
	default:
		return false
	}
}

func validResultStatus(value string) bool {
	switch value {
	case "completed", "partial", "blocked":
		return true
	default:
		return false
	}
}

func validResultList(values []string) bool {
	if values == nil || len(values) > MaxResultListItems {
		return false
	}
	for _, value := range values {
		if !validResultText(value) {
			return false
		}
	}
	return true
}

func validResultText(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > MaxResultTextBytes || !utf8.ValidString(value) || security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t' {
			return false
		}
	}
	return true
}

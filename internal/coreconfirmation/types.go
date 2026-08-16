// Package coreconfirmation owns the shared, single-user confirmation contract
// used by MCP, Skill and AWS operations. It deliberately stores only binding
// facts and digests; secret bytes and credentials never cross this boundary.
package coreconfirmation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type State string

const TargetKindPersistentService = "persistent_service"

// TaskTerminalCommand is the narrow hook used by the task ledger after it has
// committed cancellation or timeout.  Pending/confirmed confirmations can be
// compensated immediately; consumed work must remain fenced for reconciliation
// and must never be represented as a stopped provider operation.
type TaskTerminalCommand struct {
	TaskID string
	Reason string
	At     time.Time
}

const (
	StatePending   State = "pending"
	StateConfirmed State = "confirmed"
	StateConsumed  State = "consumed"
	StateRejected  State = "rejected"
	StateExpired   State = "expired"
)

type ExtensionUncertainResolution string

const ExtensionUncertainAcknowledgedUnknownNoRetry ExtensionUncertainResolution = "acknowledged_unknown_no_retry"

// AcknowledgeExtensionExecutionUncertainCommand is the owner-only, explicit
// acknowledgement for a consumed extension execution whose provider outcome
// cannot be proven. It never retries or dispatches work.
type AcknowledgeExtensionExecutionUncertainCommand struct {
	OwnerID                      string
	AccountGeneration            uint64
	ConfirmationID               string
	TaskID                       string
	InstallationID               string
	ExpectedTaskRevision         int64
	ExpectedConfirmationRevision int64
	Resolution                   ExtensionUncertainResolution
	IdempotencyKey               string
}

type AcknowledgeExtensionExecutionUncertainResult struct {
	Confirmation        Confirmation
	Task                coretask.Task
	Resolution          ExtensionUncertainResolution
	ReservationReleased bool
}

// ExtensionUncertainAcknowledger is optional so deployments without the
// extension execution store do not accidentally advertise reconciliation.
type ExtensionUncertainAcknowledger interface {
	AcknowledgeExtensionExecutionUncertain(context.Context, AcknowledgeExtensionExecutionUncertainCommand) (AcknowledgeExtensionExecutionUncertainResult, error)
}

const (
	ReasonUserRejected = "user_rejected"
	ReasonExpired      = "confirmation_expired"
	ReasonStale        = "confirmation_stale"
)

var (
	ErrInvalid             = errors.New("invalid confirmation")
	ErrNotFound            = errors.New("confirmation not found")
	ErrConflict            = errors.New("confirmation conflict")
	ErrRevisionConflict    = errors.New("confirmation revision conflict")
	ErrIdempotencyConflict = errors.New("confirmation idempotency conflict")
	ErrStale               = errors.New("confirmation binding is stale")
	ErrExpired             = errors.New("confirmation expired")
	ErrInvalidTransition   = errors.New("invalid confirmation transition")
	ErrTaskFenceConflict   = errors.New("confirmation task fence conflict")
	ErrBindingUnavailable  = errors.New("authoritative confirmation binding unavailable")
)

// Digest is a lowercase SHA-256 hex digest. Raw content is never retained.
type Digest string

func (d Digest) Valid() bool {
	if len(d) != sha256.Size*2 || strings.ToLower(string(d)) != string(d) {
		return false
	}
	_, err := hex.DecodeString(string(d))
	return err == nil
}

// Binding is the immutable operation snapshot revalidated before confirmation
// and consumption.
type Binding struct {
	// OwnerID identifies the single Agent owner/instance that authorized this
	// operation. It is a stable identity descriptor, never a secret.
	OwnerID           string        `json:"owner_id"`
	AccountGeneration uint64        `json:"account_generation,omitempty"`
	OperationDomain   string        `json:"operation_domain"`
	TargetID          string        `json:"target_id"`
	TargetRevision    int64         `json:"target_revision"`
	TargetKind        string        `json:"target_kind"`
	SourceVersion     string        `json:"source_version"`
	SourceCommit      string        `json:"source_commit"`
	ContentDigest     Digest        `json:"content_digest"`
	ManifestDigest    Digest        `json:"manifest_digest"`
	ExecutionDigest   Digest        `json:"execution_digest"`
	PermissionDigest  Digest        `json:"permission_digest"`
	ParameterDigest   Digest        `json:"parameter_digest"`
	NetworkDigest     Digest        `json:"network_digest"`
	SecretGrantDigest Digest        `json:"secret_grant_digest"`
	SelectedTool      string        `json:"selected_tool"`
	SelectedCommand   []string      `json:"selected_command"`
	NetworkGrants     []string      `json:"network_grants"`
	SecretGrants      []SecretGrant `json:"secret_grants"`
	ExecutionID       string        `json:"execution_id,omitempty"`
	PlanID            string        `json:"plan_id,omitempty"`
	PlanRevision      int64         `json:"plan_revision,omitempty"`
	PlanDigest        Digest        `json:"plan_digest,omitempty"`
	RunID             string        `json:"run_id,omitempty"`
	RunRevision       int64         `json:"run_revision,omitempty"`
	RunDigest         Digest        `json:"run_digest,omitempty"`
	QuoteDigest       Digest        `json:"quote_digest,omitempty"`
	Quote             *LiveQuote    `json:"quote,omitempty"`
	Digest            Digest        `json:"digest,omitempty"`
}

// LiveQuote is the user-visible pricing window attached to a Cloud Worker
// confirmation. Internal pricing and authorization digests remain private.
type LiveQuote struct {
	AmountMicros                int64     `json:"amount_micros"`
	ComputeMicrosPerHour        uint64    `json:"compute_micros_per_hour"`
	Currency                    string    `json:"currency"`
	SourceTime                  time.Time `json:"source_time"`
	ExpiresAt                   time.Time `json:"expires_at"`
	MaximumAuthorizedCostMicros int64     `json:"maximum_authorized_cost_micros"`
}

// SecretGrant is a safe descriptor. It can identify an authorized secret but
// cannot represent the secret value itself.
type SecretGrant struct {
	ReferenceID   string        `json:"reference_id"`
	Purpose       SecretPurpose `json:"purpose"`
	BindingDigest Digest        `json:"binding_digest"`
}

type SecretPurpose string

const (
	SecretPurposeModelAPIKey          SecretPurpose = "model_api_key"
	SecretPurposeMCPCredential        SecretPurpose = "mcp_credential"
	SecretPurposeSkillSecret          SecretPurpose = "skill_secret"
	SecretPurposeAWSCredential        SecretPurpose = "aws_credential"
	SecretPurposeOtherExtensionSecret SecretPurpose = "other_extension_secret"
)

func (b Binding) normalized() (Binding, error) {
	b.OwnerID = strings.TrimSpace(b.OwnerID)
	b.OperationDomain = strings.TrimSpace(b.OperationDomain)
	b.TargetID = strings.TrimSpace(b.TargetID)
	b.SourceVersion = strings.TrimSpace(b.SourceVersion)
	b.SourceCommit = strings.TrimSpace(b.SourceCommit)
	b.TargetKind = strings.TrimSpace(b.TargetKind)
	b.SelectedTool = strings.TrimSpace(b.SelectedTool)
	b.ExecutionID = strings.TrimSpace(b.ExecutionID)
	b.PlanID = strings.TrimSpace(b.PlanID)
	b.RunID = strings.TrimSpace(b.RunID)
	if b.OperationDomain == "" || b.TargetID == "" || b.TargetRevision < 1 || (b.SourceVersion == "" && b.SourceCommit == "") {
		return Binding{}, ErrInvalid
	}
	for _, d := range []Digest{b.ContentDigest, b.ParameterDigest, b.NetworkDigest, b.SecretGrantDigest} {
		if !d.Valid() {
			return Binding{}, ErrInvalid
		}
	}
	for _, d := range []Digest{b.ManifestDigest, b.ExecutionDigest, b.PermissionDigest} {
		if d != "" && !d.Valid() {
			return Binding{}, ErrInvalid
		}
	}
	cloudFields := b.ExecutionID != "" || b.PlanID != "" || b.RunID != "" || b.PlanRevision != 0 || b.RunRevision != 0 || b.PlanDigest != "" || b.RunDigest != "" || b.QuoteDigest != "" || b.Digest != ""
	if cloudFields {
		if b.OperationDomain != "cloud_worker.execute" || b.AccountGeneration == 0 || !validateUUID(b.ExecutionID) || !validateUUID(b.PlanID) || !validateUUID(b.RunID) || b.ExecutionID != b.TargetID || b.PlanRevision < 1 || b.RunRevision < 1 {
			return Binding{}, ErrInvalid
		}
		for _, d := range []Digest{b.PlanDigest, b.RunDigest, b.QuoteDigest, b.Digest} {
			if !d.Valid() {
				return Binding{}, ErrInvalid
			}
		}
		if b.Quote == nil || b.Quote.AmountMicros < 0 || strings.TrimSpace(b.Quote.Currency) == "" ||
			b.Quote.MaximumAuthorizedCostMicros < b.Quote.AmountMicros || b.Quote.SourceTime.IsZero() ||
			!b.Quote.ExpiresAt.After(b.Quote.SourceTime) {
			return Binding{}, ErrInvalid
		}
		quote := *b.Quote
		quote.Currency = strings.TrimSpace(quote.Currency)
		quote.SourceTime, quote.ExpiresAt = quote.SourceTime.UTC(), quote.ExpiresAt.UTC()
		b.Quote = &quote
	}
	if b.OperationDomain == "extension.execute" {
		if b.OwnerID == "" || b.AccountGeneration == 0 {
			return Binding{}, ErrInvalid
		}
	} else if b.AccountGeneration != 0 && b.OperationDomain != "cloud_worker.execute" {
		return Binding{}, ErrInvalid
	}
	for _, command := range b.SelectedCommand {
		if command == "" || strings.ContainsAny(command, "\r\n\x00") {
			return Binding{}, ErrInvalid
		}
	}
	var err error
	b.NetworkGrants, err = normalizeGrantList(b.NetworkGrants)
	if err != nil {
		return Binding{}, err
	}
	b.SecretGrants, err = normalizeSecretGrantList(b.SecretGrants)
	if err != nil {
		return Binding{}, err
	}
	if cloudFields {
		supplied := b.Digest
		b.Digest = ""
		expected := canonicalDigest(b)
		b.Digest = supplied
		if supplied != expected {
			return Binding{}, ErrInvalid
		}
	}
	return b, nil
}

// Normalize validates and canonicalizes a binding for persistence boundaries.
func (b Binding) Normalize() (Binding, error) { return b.normalized() }

func normalizeGrantList(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n") {
			return nil, ErrInvalid
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeSecretGrantList(values []SecretGrant) ([]SecretGrant, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]SecretGrant, 0, len(values))
	for _, grant := range values {
		grant.ReferenceID = strings.TrimSpace(grant.ReferenceID)
		grant.ReferenceID = strings.TrimSpace(grant.ReferenceID)
		if !validateUUID(grant.ReferenceID) || !validSecretPurpose(grant.Purpose) || !grant.BindingDigest.Valid() {
			return nil, ErrInvalid
		}
		key := grant.ReferenceID + "\x00" + string(grant.Purpose)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, grant)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ReferenceID == result[j].ReferenceID {
			return result[i].Purpose < result[j].Purpose
		}
		return result[i].ReferenceID < result[j].ReferenceID
	})
	return result, nil
}

func validSecretPurpose(p SecretPurpose) bool {
	switch p {
	case SecretPurposeModelAPIKey, SecretPurposeMCPCredential, SecretPurposeSkillSecret, SecretPurposeAWSCredential, SecretPurposeOtherExtensionSecret:
		return true
	}
	return false
}

func (b Binding) Equal(other Binding) bool {
	a, errA := b.normalized()
	c, errB := other.normalized()
	if errA != nil || errB != nil {
		return false
	}
	return a.OwnerID == c.OwnerID && a.AccountGeneration == c.AccountGeneration && a.OperationDomain == c.OperationDomain && a.TargetID == c.TargetID && a.TargetRevision == c.TargetRevision && a.TargetKind == c.TargetKind &&
		a.SourceVersion == c.SourceVersion && a.SourceCommit == c.SourceCommit && a.ContentDigest == c.ContentDigest &&
		a.ManifestDigest == c.ManifestDigest && a.ExecutionDigest == c.ExecutionDigest && a.PermissionDigest == c.PermissionDigest &&
		a.ParameterDigest == c.ParameterDigest && a.NetworkDigest == c.NetworkDigest && a.SecretGrantDigest == c.SecretGrantDigest &&
		a.SelectedTool == c.SelectedTool && equalStrings(a.SelectedCommand, c.SelectedCommand) &&
		equalStrings(a.NetworkGrants, c.NetworkGrants) && equalSecretGrants(a.SecretGrants, c.SecretGrants) &&
		a.ExecutionID == c.ExecutionID && a.PlanID == c.PlanID && a.PlanRevision == c.PlanRevision && a.PlanDigest == c.PlanDigest &&
		a.RunID == c.RunID && a.RunRevision == c.RunRevision && a.RunDigest == c.RunDigest && a.QuoteDigest == c.QuoteDigest && equalLiveQuote(a.Quote, c.Quote) && a.Digest == c.Digest
}

func equalLiveQuote(a, b *LiveQuote) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func equalSecretGrants(a, b []SecretGrant) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type Confirmation struct {
	ConfirmationID string    `json:"confirmation_id"`
	OwnerID        string    `json:"owner_id"`
	Binding        Binding   `json:"binding"`
	TaskID         string    `json:"task_id"`
	State          State     `json:"state"`
	Revision       int64     `json:"revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	TerminalCode   string    `json:"terminal_code"`
	TerminalNote   string    `json:"terminal_note"`
	TerminalReason string    `json:"terminal_reason"`
}

type Reservation struct {
	ConfirmationID     string
	TaskID             string
	AcquiredAttempt    uint32
	AcquiredLeaseEpoch uint64
	TaskRevision       int64
	Active             bool
}

type RequestCommand struct {
	IdempotencyKey string
	RequestDigest  Digest
	Binding        Binding
	TaskID         string
	ExpiresAt      time.Time
	At             time.Time
}

type ConfirmCommand struct {
	ConfirmationID   string
	IdempotencyKey   string
	RequestDigest    Digest
	ExpectedRevision int64
	Binding          Binding // authoritative snapshot populated by Service
	At               time.Time
	ResolveBinding   func(context.Context) (Binding, error)
}

type RejectCommand struct {
	ConfirmationID   string
	IdempotencyKey   string
	RequestDigest    Digest
	ExpectedRevision int64
	Reason           string
	Note             string
	At               time.Time
}

type ConsumeCommand struct {
	ConfirmationID       string
	IdempotencyKey       string
	RequestDigest        Digest
	TaskID               string
	Attempt              uint32
	LeaseEpoch           uint64
	ExpectedRevision     int64
	ExpectedTaskRevision int64
	Binding              Binding
	At                   time.Time
	ResolveBinding       func(context.Context) (Binding, error)
	ResolveTaskFence     func(context.Context, string) (TaskFence, error)
}

type TaskFence struct {
	TaskID         string
	State          string
	FailureCode    string
	InstallationID string
	ConfirmationID string
	Attempt        uint32
	LeaseEpoch     uint64
	Revision       int64
}

type ReleaseReservationCommand struct {
	ConfirmationID       string
	TaskID               string
	AcquiredAttempt      uint32
	AcquiredLeaseEpoch   uint64
	TerminalAttempt      uint32
	TerminalLeaseEpoch   uint64
	ExpectedTaskRevision int64
	IdempotencyKey       string
	RequestDigest        Digest
	ResolveTaskFence     func(context.Context, string) (TaskFence, error)
}

type ExpireCommand struct {
	ConfirmationID   string
	IdempotencyKey   string
	RequestDigest    Digest
	ExpectedRevision int64
	Reason           string
	At               time.Time
}

type ListQuery struct {
	PageSize  int
	PageToken string
	Domain    string
	TargetID  string
	States    []State
}

type Page struct {
	Confirmations []Confirmation
	NextPageToken string
}

func cloneConfirmation(in Confirmation) Confirmation {
	if in.Binding.Quote != nil {
		quote := *in.Binding.Quote
		in.Binding.Quote = &quote
	}
	if in.Binding.NetworkGrants != nil {
		in.Binding.NetworkGrants = append(make([]string, 0, len(in.Binding.NetworkGrants)), in.Binding.NetworkGrants...)
	}
	if in.Binding.SecretGrants != nil {
		in.Binding.SecretGrants = append(make([]SecretGrant, 0, len(in.Binding.SecretGrants)), in.Binding.SecretGrants...)
	}
	if in.Binding.SelectedCommand != nil {
		in.Binding.SelectedCommand = append(make([]string, 0, len(in.Binding.SelectedCommand)), in.Binding.SelectedCommand...)
	}
	return in
}

func validateUUID(value string) bool {
	id, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && id != uuid.Nil && id.String() == strings.TrimSpace(value)
}

func validateMutation(key string, digest Digest) error {
	if !validateUUID(key) || !digest.Valid() {
		return ErrInvalid
	}
	return nil
}

func canonicalDigest(value any) Digest {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return Digest(hex.EncodeToString(sum[:]))
}

func requestDigest(command RequestCommand) Digest {
	return canonicalDigest(struct {
		Binding   Binding
		TaskID    string
		ExpiresAt time.Time
	}{command.Binding, command.TaskID, command.ExpiresAt.UTC()})
}
func confirmDigest(command ConfirmCommand) Digest {
	return canonicalDigest(struct {
		ID               string
		ExpectedRevision int64
	}{command.ConfirmationID, command.ExpectedRevision})
}
func rejectDigest(command RejectCommand) Digest {
	return canonicalDigest(struct {
		ID               string
		ExpectedRevision int64
		Reason, Note     string
	}{command.ConfirmationID, command.ExpectedRevision, command.Reason, command.Note})
}
func consumeDigest(command ConsumeCommand) Digest {
	return canonicalDigest(struct {
		ID, TaskID                             string
		Attempt, LeaseEpoch                    uint64
		ExpectedRevision, ExpectedTaskRevision int64
	}{command.ConfirmationID, command.TaskID, uint64(command.Attempt), command.LeaseEpoch, command.ExpectedRevision, command.ExpectedTaskRevision})
}
func expireDigest(command ExpireCommand) Digest {
	return canonicalDigest(struct {
		ID               string
		ExpectedRevision int64
		Reason           string
	}{command.ConfirmationID, command.ExpectedRevision, command.Reason})
}
func releaseDigest(command ReleaseReservationCommand) Digest {
	return canonicalDigest(struct {
		ID, TaskID                                                               string
		AcquiredAttempt, AcquiredLeaseEpoch, TerminalAttempt, TerminalLeaseEpoch uint64
		ExpectedTaskRevision                                                     int64
	}{command.ConfirmationID, command.TaskID, uint64(command.AcquiredAttempt), uint64(command.AcquiredLeaseEpoch), uint64(command.TerminalAttempt), uint64(command.TerminalLeaseEpoch), command.ExpectedTaskRevision})
}

func AcknowledgeExtensionExecutionUncertainDigest(command AcknowledgeExtensionExecutionUncertainCommand) Digest {
	return canonicalDigest(struct {
		OwnerID                                            string
		AccountGeneration                                  uint64
		ConfirmationID, TaskID, InstallationID             string
		ExpectedTaskRevision, ExpectedConfirmationRevision int64
		Resolution                                         ExtensionUncertainResolution
	}{command.OwnerID, command.AccountGeneration, command.ConfirmationID, command.TaskID, command.InstallationID, command.ExpectedTaskRevision, command.ExpectedConfirmationRevision, command.Resolution})
}

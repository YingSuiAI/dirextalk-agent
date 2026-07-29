// Package canonicalmemory owns the trust boundary between proposed facts,
// immutable evidence, and durable cross-task memory.
package canonicalmemory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

const (
	MaxStatementBytes       = 4096
	MaxTitleBytes           = 255
	MaxReferenceBytes       = 2048
	MaxEvidencePerCandidate = 32
	MaxListPageSize         = 100
	CandidateLifetime       = 7 * 24 * time.Hour
)

var (
	ErrInvalid          = errors.New("invalid Canonical Memory input")
	ErrNotFound         = errors.New("Canonical Memory fact was not found")
	ErrRevisionConflict = errors.New("Canonical Memory revision does not match")
	ErrState            = errors.New("Canonical Memory state does not allow the operation")
	ErrEvidence         = errors.New("Canonical Memory evidence is insufficient")
	ErrApprovalRequired = errors.New("a valid owner device approval is required")
	ErrApprovalExpired  = errors.New("Canonical Memory approval expired")
	ErrSignature        = errors.New("Canonical Memory approval signature is invalid")
	ErrFactMismatch     = errors.New("Canonical Memory persisted fact does not match")
	ErrIdempotency      = idempotency.ErrConflict
)

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	namespacePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$`)
	memoryKeyPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,254}$`)
	reasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	keyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type MemoryKind string

const (
	KindUserPreference MemoryKind = "user_preference"
	KindProjectFact    MemoryKind = "project_fact"
	KindDecision       MemoryKind = "decision"
	KindProcedure      MemoryKind = "procedure"
	KindExternalFact   MemoryKind = "external_fact"
)

type CandidateOrigin string

const (
	OriginModelCandidate CandidateOrigin = "model_candidate"
	OriginUserStatement  CandidateOrigin = "user_statement"
	OriginController     CandidateOrigin = "controller"
)

type CandidateStatus string

const (
	CandidatePending  CandidateStatus = "pending"
	CandidatePromoted CandidateStatus = "promoted"
	CandidateRejected CandidateStatus = "rejected"
)

type EvidenceKind string

const (
	EvidenceWorkerClaim    EvidenceKind = "worker_claim"
	EvidenceTaskResult     EvidenceKind = "task_result"
	EvidenceTurnValidation EvidenceKind = "turn_validation"
)

type EvidenceTrust string

const (
	TrustUntrusted     EvidenceTrust = "untrusted"
	TrustCorroborating EvidenceTrust = "corroborating"
	TrustVerified      EvidenceTrust = "verified"
)

type MemoryStatus string

const (
	MemoryActive  MemoryStatus = "active"
	MemoryRevoked MemoryStatus = "revoked"
)

type Artifact struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

func (artifact Artifact) Validate() error {
	if !validReference(artifact.Ref) || !validDigest(artifact.Digest) {
		return ErrInvalid
	}
	return nil
}

type Evidence struct {
	EvidenceID   string
	OwnerID      string
	Namespace    string
	Kind         EvidenceKind
	Trust        EvidenceTrust
	Artifact     Artifact
	TurnID       string
	TurnRevision int64
	TaskID       string
	DeploymentID string
	Attempt      int32
	LeaseEpoch   int64
	ObservedAt   time.Time
	ValidUntil   time.Time
	CreatedAt    time.Time
}

func (evidence Evidence) Validate() error {
	if !canonicalUUID(evidence.EvidenceID) ||
		!validOwnerID(evidence.OwnerID) ||
		!validNamespace(evidence.Namespace) ||
		evidence.Artifact.Validate() != nil ||
		!utcMicrosecond(evidence.ObservedAt) ||
		!utcMicrosecond(evidence.CreatedAt) ||
		(!evidence.ValidUntil.IsZero() &&
			(!utcMicrosecond(evidence.ValidUntil) ||
				!evidence.ObservedAt.Before(evidence.ValidUntil))) {
		return ErrInvalid
	}
	switch evidence.Kind {
	case EvidenceWorkerClaim:
		if evidence.Trust != TrustUntrusted ||
			evidence.TurnID != "" ||
			evidence.TurnRevision != 0 ||
			!canonicalUUID(evidence.TaskID) ||
			!canonicalUUID(evidence.DeploymentID) ||
			evidence.Attempt < 1 ||
			evidence.LeaseEpoch < 1 {
			return ErrInvalid
		}
	case EvidenceTaskResult:
		if evidence.Trust != TrustCorroborating ||
			!canonicalUUID(evidence.TurnID) ||
			evidence.TurnRevision < 1 ||
			!canonicalUUID(evidence.TaskID) ||
			evidence.DeploymentID != "" ||
			evidence.Attempt != 0 ||
			evidence.LeaseEpoch != 0 {
			return ErrInvalid
		}
	case EvidenceTurnValidation:
		if evidence.Trust != TrustVerified ||
			!canonicalUUID(evidence.TurnID) ||
			evidence.TurnRevision < 1 ||
			(evidence.TaskID != "" && !canonicalUUID(evidence.TaskID)) ||
			evidence.DeploymentID != "" ||
			evidence.Attempt != 0 ||
			evidence.LeaseEpoch != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (evidence Evidence) ValidAt(now time.Time) bool {
	if evidence.Validate() != nil || now.IsZero() {
		return false
	}
	now = now.UTC()
	return !now.Before(evidence.ObservedAt.Add(-30*time.Second)) &&
		(evidence.ValidUntil.IsZero() || now.Before(evidence.ValidUntil))
}

type Candidate struct {
	CandidateID            string
	OwnerID                string
	Namespace              string
	MemoryKey              string
	Kind                   MemoryKind
	Title                  string
	Statement              string
	CandidateDigest        string
	Origin                 CandidateOrigin
	Source                 Artifact
	EvidenceDigest         string
	Evidence               []Evidence
	Status                 CandidateStatus
	Revision               int64
	ExpiresAt              time.Time
	PromotedMemoryID       string
	PromotedMemoryRevision int64
	RejectionReason        string
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

func (candidate Candidate) Validate() error {
	if !canonicalUUID(candidate.CandidateID) ||
		!validOwnerID(candidate.OwnerID) ||
		!validNamespace(candidate.Namespace) ||
		!validMemoryKey(candidate.MemoryKey) ||
		!validMemoryKind(candidate.Kind) ||
		!validTitle(candidate.Title) ||
		!validStatement(candidate.Statement) ||
		!validCandidateOrigin(candidate.Origin) ||
		candidate.Source.Validate() != nil ||
		!validDigest(candidate.CandidateDigest) ||
		!validDigest(candidate.EvidenceDigest) ||
		candidate.Revision < 1 ||
		!utcMicrosecond(candidate.ExpiresAt) ||
		!utcMicrosecond(candidate.CreatedAt) ||
		!utcMicrosecond(candidate.UpdatedAt) ||
		!candidate.CreatedAt.Before(candidate.ExpiresAt) ||
		candidate.UpdatedAt.Before(candidate.CreatedAt) ||
		len(candidate.Evidence) > MaxEvidencePerCandidate {
		return ErrInvalid
	}
	digest, err := CandidateDigest(candidate.OwnerID, candidate.Namespace,
		candidate.MemoryKey, candidate.Kind, candidate.Title,
		candidate.Statement, candidate.Origin, candidate.Source)
	if err != nil || digest != candidate.CandidateDigest {
		return ErrInvalid
	}
	evidenceDigest, err := EvidenceSetDigest(candidate.Evidence)
	if err != nil || evidenceDigest != candidate.EvidenceDigest {
		return ErrInvalid
	}
	for _, evidence := range candidate.Evidence {
		if evidence.OwnerID != candidate.OwnerID ||
			evidence.Namespace != candidate.Namespace {
			return ErrInvalid
		}
	}
	switch candidate.Status {
	case CandidatePending:
		if candidate.Revision != 1 ||
			candidate.PromotedMemoryID != "" ||
			candidate.PromotedMemoryRevision != 0 ||
			candidate.RejectionReason != "" {
			return ErrInvalid
		}
	case CandidatePromoted:
		if candidate.Revision != 2 ||
			!canonicalUUID(candidate.PromotedMemoryID) ||
			candidate.PromotedMemoryRevision < 1 ||
			candidate.RejectionReason != "" {
			return ErrInvalid
		}
	case CandidateRejected:
		if candidate.Revision != 2 ||
			candidate.PromotedMemoryID != "" ||
			candidate.PromotedMemoryRevision != 0 ||
			!reasonCodePattern.MatchString(candidate.RejectionReason) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (candidate Candidate) PendingAt(now time.Time) bool {
	return candidate.Validate() == nil &&
		candidate.Status == CandidatePending &&
		!now.IsZero() &&
		now.UTC().Before(candidate.ExpiresAt)
}

type Memory struct {
	MemoryID        string
	OwnerID         string
	Namespace       string
	MemoryKey       string
	Kind            MemoryKind
	Status          MemoryStatus
	CurrentRevision int64
	RecordRevision  int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (memory Memory) Validate() error {
	if !canonicalUUID(memory.MemoryID) ||
		!validOwnerID(memory.OwnerID) ||
		!validNamespace(memory.Namespace) ||
		!validMemoryKey(memory.MemoryKey) ||
		!validMemoryKind(memory.Kind) ||
		(memory.Status != MemoryActive && memory.Status != MemoryRevoked) ||
		memory.CurrentRevision < 1 ||
		memory.RecordRevision < 1 ||
		!utcMicrosecond(memory.CreatedAt) ||
		!utcMicrosecond(memory.UpdatedAt) ||
		memory.UpdatedAt.Before(memory.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

type Revision struct {
	MemoryID        string
	Revision        int64
	CandidateID     string
	OwnerID         string
	Namespace       string
	MemoryKey       string
	Kind            MemoryKind
	Title           string
	Statement       string
	CandidateDigest string
	EvidenceDigest  string
	ValidFrom       time.Time
	ValidUntil      time.Time
	ApprovalID      string
	CreatedAt       time.Time
}

func (revision Revision) Validate() error {
	if !canonicalUUID(revision.MemoryID) ||
		revision.Revision < 1 ||
		!canonicalUUID(revision.CandidateID) ||
		!validOwnerID(revision.OwnerID) ||
		!validNamespace(revision.Namespace) ||
		!validMemoryKey(revision.MemoryKey) ||
		!validMemoryKind(revision.Kind) ||
		!validTitle(revision.Title) ||
		!validStatement(revision.Statement) ||
		!validDigest(revision.CandidateDigest) ||
		!validDigest(revision.EvidenceDigest) ||
		!utcMicrosecond(revision.ValidFrom) ||
		(!revision.ValidUntil.IsZero() &&
			(!utcMicrosecond(revision.ValidUntil) ||
				!revision.ValidFrom.Before(revision.ValidUntil))) ||
		!canonicalUUID(revision.ApprovalID) ||
		!utcMicrosecond(revision.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

func (revision Revision) ValidAt(now time.Time) bool {
	if revision.Validate() != nil || now.IsZero() {
		return false
	}
	now = now.UTC()
	return !now.Before(revision.ValidFrom.Add(-30*time.Second)) &&
		(revision.ValidUntil.IsZero() || now.Before(revision.ValidUntil))
}

type Fact struct {
	Memory   Memory
	Revision Revision
}

func (fact Fact) Validate() error {
	if fact.Memory.Validate() != nil ||
		fact.Revision.Validate() != nil ||
		fact.Memory.MemoryID != fact.Revision.MemoryID ||
		fact.Memory.OwnerID != fact.Revision.OwnerID ||
		fact.Memory.Namespace != fact.Revision.Namespace ||
		fact.Memory.MemoryKey != fact.Revision.MemoryKey ||
		fact.Memory.Kind != fact.Revision.Kind ||
		fact.Memory.CurrentRevision != fact.Revision.Revision {
		return ErrInvalid
	}
	return nil
}

type ListQuery struct {
	OwnerID       string
	Namespace     string
	PageSize      int
	AfterMemoryID string
	Now           time.Time
}

func (query ListQuery) Validated() (ListQuery, error) {
	query.OwnerID = strings.TrimSpace(query.OwnerID)
	query.Namespace = strings.TrimSpace(query.Namespace)
	query.AfterMemoryID = strings.TrimSpace(query.AfterMemoryID)
	if !validOwnerID(query.OwnerID) ||
		!validNamespace(query.Namespace) ||
		query.PageSize < 0 ||
		query.PageSize > MaxListPageSize ||
		(query.AfterMemoryID != "" && !canonicalUUID(query.AfterMemoryID)) ||
		!utcMicrosecond(query.Now) {
		return ListQuery{}, ErrInvalid
	}
	if query.PageSize == 0 {
		query.PageSize = 50
	}
	return query, nil
}

type Page struct {
	Facts             []Fact
	NextAfterMemoryID string
}

type RecordWorkerEvidenceCommand struct {
	IdempotencyKey string
	EvidenceID     string
	OwnerID        string
	Namespace      string
	DeploymentID   string
	Artifact       Artifact
	Attempt        int32
	LeaseEpoch     int64
}

func (command RecordWorkerEvidenceCommand) Validate() error {
	if !canonicalUUID(command.IdempotencyKey) ||
		!canonicalUUID(command.EvidenceID) ||
		!validOwnerID(command.OwnerID) ||
		!validNamespace(command.Namespace) ||
		!canonicalUUID(command.DeploymentID) ||
		command.Artifact.Validate() != nil ||
		command.Attempt < 1 ||
		command.LeaseEpoch < 1 {
		return ErrInvalid
	}
	return nil
}

func (command RecordWorkerEvidenceCommand) Digest() ([sha256.Size]byte, error) {
	if err := command.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	return digestJSON(struct {
		OwnerID      string   `json:"owner_id"`
		Namespace    string   `json:"namespace"`
		DeploymentID string   `json:"deployment_id"`
		Artifact     Artifact `json:"artifact"`
		Attempt      int32    `json:"attempt"`
		LeaseEpoch   int64    `json:"lease_epoch"`
	}{command.OwnerID, command.Namespace, command.DeploymentID,
		command.Artifact, command.Attempt, command.LeaseEpoch})
}

type RecordTurnEvidenceCommand struct {
	IdempotencyKey string
	EvidenceID     string
	OwnerID        string
	Namespace      string
	Kind           EvidenceKind
	TurnID         string
	TurnRevision   int64
	Artifact       Artifact
}

func (command RecordTurnEvidenceCommand) Validate() error {
	if !canonicalUUID(command.IdempotencyKey) ||
		!canonicalUUID(command.EvidenceID) ||
		!validOwnerID(command.OwnerID) ||
		!validNamespace(command.Namespace) ||
		(command.Kind != EvidenceTaskResult &&
			command.Kind != EvidenceTurnValidation) ||
		!canonicalUUID(command.TurnID) ||
		command.TurnRevision < 1 ||
		command.Artifact.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (command RecordTurnEvidenceCommand) Digest() ([sha256.Size]byte, error) {
	if err := command.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	return digestJSON(struct {
		OwnerID      string       `json:"owner_id"`
		Namespace    string       `json:"namespace"`
		Kind         EvidenceKind `json:"kind"`
		TurnID       string       `json:"turn_id"`
		TurnRevision int64        `json:"turn_revision"`
		Artifact     Artifact     `json:"artifact"`
	}{command.OwnerID, command.Namespace, command.Kind,
		command.TurnID, command.TurnRevision, command.Artifact})
}

type ProposeCommand struct {
	IdempotencyKey string
	CandidateID    string
	OwnerID        string
	Namespace      string
	MemoryKey      string
	Kind           MemoryKind
	Title          string
	Statement      string
	Origin         CandidateOrigin
	Source         Artifact
	EvidenceIDs    []string
	ExpiresAt      time.Time
}

func (command ProposeCommand) Validated() (ProposeCommand, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.Namespace = strings.TrimSpace(command.Namespace)
	command.MemoryKey = strings.TrimSpace(command.MemoryKey)
	command.Title = strings.TrimSpace(command.Title)
	command.Statement = strings.TrimSpace(command.Statement)
	if !canonicalUUID(command.IdempotencyKey) ||
		!canonicalUUID(command.CandidateID) ||
		!validOwnerID(command.OwnerID) ||
		!validNamespace(command.Namespace) ||
		!validMemoryKey(command.MemoryKey) ||
		!validMemoryKind(command.Kind) ||
		!validTitle(command.Title) ||
		!validStatement(command.Statement) ||
		!validCandidateOrigin(command.Origin) ||
		command.Source.Validate() != nil ||
		len(command.EvidenceIDs) > MaxEvidencePerCandidate ||
		!utcMicrosecond(command.ExpiresAt) {
		return ProposeCommand{}, ErrInvalid
	}
	seen := make(map[string]struct{}, len(command.EvidenceIDs))
	ids := make([]string, 0, len(command.EvidenceIDs))
	for _, evidenceID := range command.EvidenceIDs {
		evidenceID = strings.TrimSpace(evidenceID)
		if !canonicalUUID(evidenceID) {
			return ProposeCommand{}, ErrInvalid
		}
		if _, duplicate := seen[evidenceID]; duplicate {
			continue
		}
		seen[evidenceID] = struct{}{}
		ids = append(ids, evidenceID)
	}
	sort.Strings(ids)
	command.EvidenceIDs = ids
	return command, nil
}

func (command ProposeCommand) Digest() ([sha256.Size]byte, error) {
	validated, err := command.Validated()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return digestJSON(struct {
		OwnerID     string          `json:"owner_id"`
		Namespace   string          `json:"namespace"`
		MemoryKey   string          `json:"memory_key"`
		Kind        MemoryKind      `json:"kind"`
		Title       string          `json:"title"`
		Statement   string          `json:"statement"`
		Origin      CandidateOrigin `json:"origin"`
		Source      Artifact        `json:"source"`
		EvidenceIDs []string        `json:"evidence_ids"`
	}{validated.OwnerID, validated.Namespace, validated.MemoryKey,
		validated.Kind, validated.Title, validated.Statement,
		validated.Origin, validated.Source, validated.EvidenceIDs})
}

type RejectCommand struct {
	IdempotencyKey   string
	OwnerID          string
	CandidateID      string
	ExpectedRevision int64
	ReasonCode       string
}

func (command RejectCommand) Validate() error {
	return validateTerminalCommand(command.IdempotencyKey, command.OwnerID,
		command.CandidateID, command.ExpectedRevision, command.ReasonCode)
}

func (command RejectCommand) Digest() ([sha256.Size]byte, error) {
	if err := command.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	return digestJSON(command)
}

type RevokeCommand struct {
	IdempotencyKey         string
	OwnerID                string
	MemoryID               string
	ExpectedRecordRevision int64
	ReasonCode             string
}

func (command RevokeCommand) Validate() error {
	return validateTerminalCommand(command.IdempotencyKey, command.OwnerID,
		command.MemoryID, command.ExpectedRecordRevision, command.ReasonCode)
}

func (command RevokeCommand) Digest() ([sha256.Size]byte, error) {
	if err := command.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	return digestJSON(command)
}

type Store interface {
	RecordWorkerEvidence(context.Context, task.MutationScope, RecordWorkerEvidenceCommand) (Evidence, error)
	RecordTurnEvidence(context.Context, task.MutationScope, RecordTurnEvidenceCommand) (Evidence, error)
	ProposeCandidate(context.Context, task.MutationScope, ProposeCommand) (Candidate, error)
	GetCandidate(context.Context, string, string) (Candidate, error)
	CreateCanonicalMemoryChallenge(context.Context, task.MutationScope, CreateChallengeCommand) (ChallengeFact, error)
	ApproveCandidate(context.Context, task.MutationScope, ApproveCommand) (Fact, error)
	RejectCandidate(context.Context, task.MutationScope, RejectCommand) (Candidate, error)
	RevokeMemory(context.Context, task.MutationScope, RevokeCommand) (Fact, error)
	GetMemory(context.Context, string, string) (Fact, error)
	ListActiveMemories(context.Context, ListQuery) (Page, error)
}

func CandidateDigest(ownerID, namespace, memoryKey string, kind MemoryKind,
	title, statement string, origin CandidateOrigin, source Artifact) (string, error) {
	ownerID = strings.TrimSpace(ownerID)
	namespace = strings.TrimSpace(namespace)
	memoryKey = strings.TrimSpace(memoryKey)
	title = strings.TrimSpace(title)
	statement = strings.TrimSpace(statement)
	if !validOwnerID(ownerID) ||
		!validNamespace(namespace) ||
		!validMemoryKey(memoryKey) ||
		!validMemoryKind(kind) ||
		!validTitle(title) ||
		!validStatement(statement) ||
		!validCandidateOrigin(origin) ||
		source.Validate() != nil {
		return "", ErrInvalid
	}
	encoded, err := canonical.Marshal(struct {
		SchemaVersion string          `json:"schema_version"`
		OwnerID       string          `json:"owner_id"`
		Namespace     string          `json:"namespace"`
		MemoryKey     string          `json:"memory_key"`
		Kind          MemoryKind      `json:"kind"`
		Title         string          `json:"title"`
		Statement     string          `json:"statement"`
		Origin        CandidateOrigin `json:"origin"`
		Source        Artifact        `json:"source"`
	}{
		SchemaVersion: "dirextalk.agent.canonical-memory-candidate/v1",
		OwnerID:       ownerID, Namespace: namespace, MemoryKey: memoryKey,
		Kind: kind, Title: title, Statement: statement,
		Origin: origin, Source: source,
	})
	if err != nil {
		return "", ErrInvalid
	}
	return SHA256(encoded), nil
}

func EvidenceSetDigest(evidence []Evidence) (string, error) {
	if len(evidence) > MaxEvidencePerCandidate {
		return "", ErrInvalid
	}
	cloned := append([]Evidence(nil), evidence...)
	sort.Slice(cloned, func(left, right int) bool {
		return cloned[left].EvidenceID < cloned[right].EvidenceID
	})
	items := make([]struct {
		EvidenceID   string        `json:"evidence_id"`
		Kind         EvidenceKind  `json:"kind"`
		Trust        EvidenceTrust `json:"trust"`
		Artifact     Artifact      `json:"artifact"`
		TurnID       string        `json:"turn_id"`
		TurnRevision int64         `json:"turn_revision"`
		TaskID       string        `json:"task_id"`
		DeploymentID string        `json:"deployment_id"`
		Attempt      int32         `json:"attempt"`
		LeaseEpoch   int64         `json:"lease_epoch"`
		ObservedAt   time.Time     `json:"observed_at"`
		ValidUntil   time.Time     `json:"valid_until"`
	}, 0, len(cloned))
	previous := ""
	for _, item := range cloned {
		if item.Validate() != nil || item.EvidenceID == previous {
			return "", ErrInvalid
		}
		previous = item.EvidenceID
		items = append(items, struct {
			EvidenceID   string        `json:"evidence_id"`
			Kind         EvidenceKind  `json:"kind"`
			Trust        EvidenceTrust `json:"trust"`
			Artifact     Artifact      `json:"artifact"`
			TurnID       string        `json:"turn_id"`
			TurnRevision int64         `json:"turn_revision"`
			TaskID       string        `json:"task_id"`
			DeploymentID string        `json:"deployment_id"`
			Attempt      int32         `json:"attempt"`
			LeaseEpoch   int64         `json:"lease_epoch"`
			ObservedAt   time.Time     `json:"observed_at"`
			ValidUntil   time.Time     `json:"valid_until"`
		}{
			EvidenceID: item.EvidenceID, Kind: item.Kind, Trust: item.Trust,
			Artifact: item.Artifact, TurnID: item.TurnID,
			TurnRevision: item.TurnRevision, TaskID: item.TaskID,
			DeploymentID: item.DeploymentID, Attempt: item.Attempt,
			LeaseEpoch: item.LeaseEpoch, ObservedAt: item.ObservedAt,
			ValidUntil: item.ValidUntil,
		})
	}
	encoded, err := canonical.Marshal(struct {
		SchemaVersion string `json:"schema_version"`
		Evidence      any    `json:"evidence"`
	}{
		SchemaVersion: "dirextalk.agent.canonical-memory-evidence-set/v1",
		Evidence:      items,
	})
	if err != nil {
		return "", ErrInvalid
	}
	return SHA256(encoded), nil
}

func DeriveMemoryID(agentInstanceID, ownerID, namespace, memoryKey string) (string, error) {
	agentID, err := uuid.Parse(agentInstanceID)
	if err != nil || agentID == uuid.Nil ||
		agentID.String() != agentInstanceID ||
		!validOwnerID(ownerID) ||
		!validNamespace(namespace) ||
		!validMemoryKey(memoryKey) {
		return "", ErrInvalid
	}
	material := "dirextalk.agent.canonical-memory/v1\x00" +
		ownerID + "\x00" + namespace + "\x00" + memoryKey
	return uuid.NewSHA1(agentID, []byte(material)).String(), nil
}

func SHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func digestJSON(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return sha256.Sum256(encoded), nil
}

func validateTerminalCommand(idempotencyKey, ownerID, entityID string,
	expectedRevision int64, reason string) error {
	if !canonicalUUID(idempotencyKey) ||
		!validOwnerID(ownerID) ||
		!canonicalUUID(entityID) ||
		expectedRevision < 1 ||
		!reasonCodePattern.MatchString(reason) ||
		security.ContainsLikelySecret(reason) {
		return ErrInvalid
	}
	return nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validOwnerID(value string) bool {
	return validText(value, 255, false)
}

func validNamespace(value string) bool {
	return value == strings.TrimSpace(value) &&
		namespacePattern.MatchString(value) &&
		!security.ContainsLikelySecret(value)
}

func validMemoryKey(value string) bool {
	return value == strings.TrimSpace(value) &&
		memoryKeyPattern.MatchString(value) &&
		!strings.Contains(value, "..") &&
		!security.ContainsLikelySecret(value)
}

func validTitle(value string) bool {
	return validText(value, MaxTitleBytes, false)
}

func validStatement(value string) bool {
	return validText(value, MaxStatementBytes, false)
}

func validText(value string, maximumBytes int, allowEmpty bool) bool {
	if value != strings.TrimSpace(value) ||
		len(value) > maximumBytes ||
		(!allowEmpty && value == "") ||
		!utf8.ValidString(value) ||
		strings.IndexByte(value, 0) >= 0 ||
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

func validReference(value string) bool {
	return validText(value, MaxReferenceBytes, false)
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func validMemoryKind(kind MemoryKind) bool {
	switch kind {
	case KindUserPreference, KindProjectFact, KindDecision,
		KindProcedure, KindExternalFact:
		return true
	default:
		return false
	}
}

func validCandidateOrigin(origin CandidateOrigin) bool {
	switch origin {
	case OriginModelCandidate, OriginUserStatement, OriginController:
		return true
	default:
		return false
	}
}

func validSignerKeyID(value string) bool {
	return keyIDPattern.MatchString(value) &&
		!security.ContainsLikelySecret(value)
}

func utcMicrosecond(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Nanosecond()%1000 == 0
}

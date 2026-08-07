// Package corememory owns the deterministic automatic-memory policy used by
// Agent Core. Model output enters this package only as untrusted candidates;
// it never receives a persistence handle.
package corememory

import (
	"errors"
	"math"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("corememory: invalid")

const (
	CandidateSchemaVersion = 1
	PolicyVersion          = 1
	MaxCandidates          = 10
	MaxCanonicalKeyBytes   = 120
	MaxMemoryTextBytes     = 600
	MaxEvidenceBytes       = 500
	MaxReasonBytes         = 500
)

type Operation string

const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
	OperationNoop   Operation = "noop"
)

type MemoryType string

const (
	MemoryTypeFact       MemoryType = "fact"
	MemoryTypePreference MemoryType = "preference"
)

type Scope string

const (
	ScopeOwner        Scope = "owner"
	ScopeConversation Scope = "conversation"
)

type Sensitivity string

const (
	SensitivityLow       Sensitivity = "low"
	SensitivitySensitive Sensitivity = "sensitive"
	SensitivitySecret    Sensitivity = "secret"
)

// Candidate is one bounded, untrusted model proposal. Operation is a hint;
// the reconciler derives the actual mutation from canonical state.
type Candidate struct {
	Operation   Operation   `json:"operation"`
	Key         string      `json:"key"`
	Text        string      `json:"text"`
	Type        MemoryType  `json:"type"`
	Scope       Scope       `json:"scope"`
	Confidence  float64     `json:"confidence"`
	Importance  float64     `json:"importance"`
	Sensitivity Sensitivity `json:"sensitivity"`
	Evidence    string      `json:"evidence"`
	Reason      string      `json:"reason"`
}

func (c Candidate) Normalize() Candidate {
	c.Key = strings.ToLower(strings.TrimSpace(c.Key))
	c.Text = strings.TrimSpace(c.Text)
	c.Evidence = strings.TrimSpace(c.Evidence)
	c.Reason = strings.TrimSpace(c.Reason)
	return c
}

func (c Candidate) Validate() error {
	c = c.Normalize()
	if !validOperation(c.Operation) || !validMemoryType(c.Type) || !validScope(c.Scope) || !validSensitivity(c.Sensitivity) || !boundedUTF8(c.Key, MaxCanonicalKeyBytes) || !boundedUTF8(c.Evidence, MaxEvidenceBytes) || !boundedOptionalUTF8(c.Reason, MaxReasonBytes) {
		return ErrInvalid
	}
	if c.Operation != OperationDelete && c.Operation != OperationNoop && !boundedUTF8(c.Text, MaxMemoryTextBytes) {
		return ErrInvalid
	}
	if (c.Operation == OperationDelete || c.Operation == OperationNoop) && !boundedOptionalUTF8(c.Text, MaxMemoryTextBytes) {
		return ErrInvalid
	}
	if math.IsNaN(c.Confidence) || math.IsInf(c.Confidence, 0) || c.Confidence < 0 || c.Confidence > 1 || math.IsNaN(c.Importance) || math.IsInf(c.Importance, 0) || c.Importance < 0 || c.Importance > 1 {
		return ErrInvalid
	}
	return nil
}

func validOperation(value Operation) bool {
	return value == OperationCreate || value == OperationUpdate || value == OperationDelete || value == OperationNoop
}

func validMemoryType(value MemoryType) bool {
	return value == MemoryTypeFact || value == MemoryTypePreference
}

func validScope(value Scope) bool { return value == ScopeOwner || value == ScopeConversation }

func validSensitivity(value Sensitivity) bool {
	return value == SensitivityLow || value == SensitivitySensitive || value == SensitivitySecret
}

func boundedUTF8(value string, max int) bool {
	return value != "" && utf8.ValidString(value) && len([]byte(value)) <= max
}

func boundedOptionalUTF8(value string, max int) bool {
	return utf8.ValidString(value) && len([]byte(value)) <= max
}

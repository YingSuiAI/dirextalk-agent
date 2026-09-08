package coreconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const MaxSystemPromptBytes = 131072

// SystemPrompt is instance-wide: each Agent instance belongs to one owner.
// It is independent of model profiles and is never included in diagnostic logs.
type SystemPrompt struct {
	Revision int64  `json:"revision"`
	Prompt   string `json:"system_prompt"`
}

type SystemPromptUpdate struct {
	IdempotencyKey   string `json:"idempotency_key"`
	ExpectedRevision int64  `json:"expected_revision"`
	Prompt           string `json:"system_prompt"`
}

type SystemPromptStore interface {
	GetSystemPrompt(context.Context) (SystemPrompt, error)
	UpdateSystemPrompt(context.Context, string, SystemPromptUpdate) (SystemPrompt, error)
}

func (u SystemPromptUpdate) Validate() error {
	if _, err := uuid.Parse(u.IdempotencyKey); err != nil || u.IdempotencyKey != strings.TrimSpace(u.IdempotencyKey) || u.ExpectedRevision < 0 || !utf8.ValidString(u.Prompt) || len(u.Prompt) > MaxSystemPromptBytes {
		return ErrInvalid
	}
	return nil
}

func (u SystemPromptUpdate) Digest(owner string) (string, error) {
	if strings.TrimSpace(owner) == "" {
		return "", ErrInvalid
	}
	if err := u.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		Owner  string
		Update SystemPromptUpdate
	}{owner, u})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

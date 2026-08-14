package corememory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrRevisionConflict       = errors.New("core memory revision conflict")
	ErrIdempotencyConflict    = errors.New("core memory idempotency conflict")
	ErrLeaseConflict          = errors.New("core memory observation lease conflict")
	ErrRepository             = errors.New("core memory repository unavailable")
	ErrEmbeddingNotConfigured = errors.New("core memory embedding model is not configured")
)

type Config struct {
	Enabled             bool       `json:"enabled"`
	EmbeddingConfigured bool       `json:"embedding_configured"`
	EmbeddingProfileID  string     `json:"embedding_profile_id,omitempty"`
	EmbeddingModel      string     `json:"embedding_model,omitempty"`
	Revision            int64      `json:"revision"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
}

func DefaultConfig() Config { return Config{} }

type ConfigMutation struct {
	IdempotencyKey   string
	RequestDigest    string
	ExpectedRevision int64
	Enabled          bool
	Now              time.Time
}

type UpdateConfigCommand struct {
	IdempotencyKey   string
	ExpectedRevision int64
	Enabled          bool
}

type Status struct {
	Config
	Facts                   []Fact          `json:"facts"`
	Timeline                []TimelineEvent `json:"timeline"`
	ActiveFactCount         int64           `json:"active_fact_count"`
	TimelineEventCount      int64           `json:"timeline_event_count"`
	PendingObservationCount int64           `json:"pending_observation_count"`
	FailedObservationCount  int64           `json:"failed_observation_count"`
}

type FactMutation struct {
	IdempotencyKey string
	RequestDigest  string
	FactID         string
	Value          string
	Now            time.Time
}

type UpdateFactCommand struct {
	IdempotencyKey string
	FactID         string
	Value          string
}

type DeleteFactCommand struct {
	IdempotencyKey string
	FactID         string
}

type FactDeletion struct {
	FactID  string `json:"fact_id"`
	Deleted bool   `json:"deleted"`
}

func (s *Service) GetConfig(ctx context.Context) (Config, error) {
	value, err := s.store.GetConfig(ctx)
	if err != nil {
		return Config{}, err
	}
	return value, nil
}

func (s *Service) UpdateConfig(ctx context.Context, command UpdateConfigCommand) (Config, error) {
	command.IdempotencyKey = strings.TrimSpace(command.IdempotencyKey)
	if uuid.Validate(command.IdempotencyKey) != nil || command.ExpectedRevision < 0 {
		return Config{}, ErrInvalid
	}
	digest := sha256.Sum256([]byte(command.IdempotencyKey + "\x00" + strconv.FormatBool(command.Enabled) + "\x00" + strconv.FormatInt(command.ExpectedRevision, 10)))
	return s.store.UpdateConfig(ctx, ConfigMutation{
		IdempotencyKey: command.IdempotencyKey, RequestDigest: hex.EncodeToString(digest[:]),
		ExpectedRevision: command.ExpectedRevision, Enabled: command.Enabled, Now: s.now(),
	})
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	return s.store.Status(ctx, MaxExtractionFacts, 64)
}

func (s *Service) UpdateFact(ctx context.Context, command UpdateFactCommand) (Fact, error) {
	command.IdempotencyKey = strings.TrimSpace(command.IdempotencyKey)
	command.FactID = strings.TrimSpace(command.FactID)
	command.Value = strings.TrimSpace(command.Value)
	if uuid.Validate(command.IdempotencyKey) != nil || uuid.Validate(command.FactID) != nil || command.Value == "" || !utf8.ValidString(command.Value) || utf8.RuneCountInString(command.Value) > 2048 {
		return Fact{}, ErrInvalid
	}
	digest := sha256.Sum256([]byte("update_fact\x00" + command.FactID + "\x00" + command.Value))
	return s.store.UpdateFact(ctx, FactMutation{IdempotencyKey: command.IdempotencyKey, RequestDigest: hex.EncodeToString(digest[:]), FactID: command.FactID, Value: command.Value, Now: s.now()})
}

func (s *Service) DeleteFact(ctx context.Context, command DeleteFactCommand) (FactDeletion, error) {
	command.IdempotencyKey = strings.TrimSpace(command.IdempotencyKey)
	command.FactID = strings.TrimSpace(command.FactID)
	if uuid.Validate(command.IdempotencyKey) != nil || uuid.Validate(command.FactID) != nil {
		return FactDeletion{}, ErrInvalid
	}
	digest := sha256.Sum256([]byte("delete_fact\x00" + command.FactID))
	return s.store.DeleteFact(ctx, FactMutation{IdempotencyKey: command.IdempotencyKey, RequestDigest: hex.EncodeToString(digest[:]), FactID: command.FactID, Now: s.now()})
}

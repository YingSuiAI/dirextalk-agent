// Package corememory owns the Agent's structured, user-level long-term memory.
package corememory

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxCandidates       = 16
	MaxActiveFacts      = 512
	MaxExtractionFacts  = 128
	DefaultRecallFacts  = 32
	DefaultRecallEvents = 12
)

var predicatePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
var credentialValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?i)\b(?:sk|rk|pk)-[a-z0-9_-]{16,}\b`),
	regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`),
}

type Observation struct {
	ID, ConversationID, ProfileID string
	UserText, AssistantText       string
	ObservedAt                    time.Time
}

type ObservationLease struct {
	Observation
	LeaseID string
	Attempt int
}

type Fact struct {
	ID              string    `json:"id"`
	Subject         string    `json:"subject"`
	Predicate       string    `json:"predicate"`
	Value           string    `json:"value"`
	Kind            string    `json:"kind"`
	Confidence      float64   `json:"confidence"`
	ValidFrom       time.Time `json:"valid_from"`
	LastConfirmedAt time.Time `json:"last_confirmed_at"`
}

type TimelineEvent struct {
	Kind        string    `json:"kind"`
	Summary     string    `json:"summary"`
	EffectiveAt time.Time `json:"effective_at"`
	OccurredAt  time.Time `json:"observed_at"`
}

type Snapshot struct {
	Facts  []Fact
	Events []TimelineEvent
}

// Candidate is a model-proposed mutation. The store remains authoritative for
// conflict resolution: an upsert with the same subject/predicate supersedes
// the prior value atomically while retaining its timeline event.
type Candidate struct {
	Operation   string  `json:"operation"`
	Subject     string  `json:"subject"`
	Predicate   string  `json:"predicate"`
	Value       string  `json:"value"`
	Kind        string  `json:"kind"`
	Confidence  float64 `json:"confidence"`
	EffectiveAt string  `json:"effective_at,omitempty"`
}

func (c *Candidate) Normalize() error {
	c.Operation = strings.ToLower(strings.TrimSpace(c.Operation))
	c.Subject = strings.ToLower(strings.TrimSpace(c.Subject))
	c.Predicate = strings.ToLower(strings.TrimSpace(c.Predicate))
	c.Value = strings.Join(strings.Fields(c.Value), " ")
	c.Kind = strings.ToLower(strings.TrimSpace(c.Kind))
	c.EffectiveAt = strings.TrimSpace(c.EffectiveAt)
	if c.Subject == "" {
		c.Subject = "user"
	}
	if c.Kind == "" {
		c.Kind = "fact"
	}
	if (c.Operation != "upsert" && c.Operation != "retract") || c.Subject != "user" || !predicatePattern.MatchString(c.Predicate) || !validFactKind(c.Kind) || len(c.Value) > 2048 || !utf8.ValidString(c.Value) || math.IsNaN(c.Confidence) || math.IsInf(c.Confidence, 0) || c.Confidence < 0 || c.Confidence > 1 {
		return ErrInvalid
	}
	if c.Operation == "upsert" && c.Value == "" {
		return ErrInvalid
	}
	if c.EffectiveAt != "" {
		effective, err := time.Parse(time.RFC3339, c.EffectiveAt)
		if err != nil {
			return ErrInvalid
		}
		c.EffectiveAt = effective.UTC().Format(time.RFC3339)
	}
	return nil
}

func (c Candidate) EffectiveTime(fallback time.Time) time.Time {
	if c.EffectiveAt == "" {
		return fallback.UTC()
	}
	effective, err := time.Parse(time.RFC3339, c.EffectiveAt)
	if err != nil {
		return fallback.UTC()
	}
	return effective.UTC()
}

func validFactKind(kind string) bool {
	switch kind {
	case "identity", "preference", "relationship", "goal", "constraint", "context", "fact":
		return true
	default:
		return false
	}
}

var ErrInvalid = errors.New("core memory input is invalid")

type Store interface {
	GetConfig(context.Context) (Config, error)
	UpdateConfig(context.Context, ConfigMutation) (Config, error)
	UpdateFact(context.Context, FactMutation) (Fact, error)
	DeleteFact(context.Context, FactMutation) (FactDeletion, error)
	Status(context.Context, int, int) (Status, error)
	ClaimObservation(context.Context, time.Time, time.Duration) (ObservationLease, bool, error)
	ListActiveFacts(context.Context, int) ([]Fact, error)
	ApplyObservation(context.Context, ObservationLease, []Candidate, time.Time) error
	RetryObservation(context.Context, ObservationLease, string, time.Time) error
	Recall(context.Context, int, int) (Snapshot, error)
}

type Extractor interface {
	Extract(context.Context, Observation, []Fact) ([]Candidate, error)
}

type Service struct {
	store     Store
	extractor Extractor
	now       func() time.Time
}

func NewService(store Store, extractor Extractor) (*Service, error) {
	if store == nil || extractor == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, extractor: extractor, now: func() time.Time { return time.Now().UTC() }}, nil
}

// ProcessNext consolidates one durable conversation observation. Provider
// failures are recorded for bounded retry and do not fail the owning chat.
func (s *Service) ProcessNext(ctx context.Context) (bool, error) {
	now := s.now()
	lease, ok, err := s.store.ClaimObservation(ctx, now, 2*time.Minute)
	if err != nil || !ok {
		return ok, err
	}
	facts, err := s.store.ListActiveFacts(ctx, MaxExtractionFacts)
	if err != nil {
		return true, err
	}
	candidates, err := s.extractor.Extract(ctx, lease.Observation, facts)
	if err == nil {
		if len(candidates) > MaxCandidates {
			err = ErrInvalid
		} else {
			safe := candidates[:0]
			seen := make(map[string]struct{}, len(candidates))
			for i := range candidates {
				if candidateErr := candidates[i].Normalize(); candidateErr != nil {
					err = candidateErr
					break
				}
				if !candidateContainsCredential(candidates[i]) {
					key := candidates[i].Subject + "\x00" + candidates[i].Predicate
					if _, duplicate := seen[key]; duplicate {
						err = ErrInvalid
						break
					}
					seen[key] = struct{}{}
					safe = append(safe, candidates[i])
				}
			}
			candidates = safe
		}
		if err == nil {
			applyErr := s.store.ApplyObservation(ctx, lease, candidates, now)
			if errors.Is(applyErr, ErrLeaseConflict) {
				slog.Warn("[memory.consolidation] observation lease changed before apply", "observation_id", lease.ID, "attempt", lease.Attempt)
				return true, nil
			}
			return true, applyErr
		}
	}
	// Error details can contain provider internals. Persist only a stable class.
	if retryErr := s.store.RetryObservation(ctx, lease, "memory_consolidation_failed", now); retryErr != nil {
		if errors.Is(retryErr, ErrLeaseConflict) {
			slog.Warn("[memory.consolidation] observation lease changed before retry", "observation_id", lease.ID, "attempt", lease.Attempt)
			return true, nil
		}
		return true, retryErr
	}
	slog.Warn("[memory.consolidation] retry scheduled", "observation_id", lease.ID, "attempt", lease.Attempt, "code", "memory_consolidation_failed")
	return true, nil
}

func candidateContainsCredential(candidate Candidate) bool {
	key := strings.ReplaceAll(strings.ReplaceAll(candidate.Predicate, "-", "_"), ".", "_")
	for _, marker := range []string{"password", "passphrase", "secret", "token", "credential", "api_key", "apikey", "private_key", "access_key"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	for _, pattern := range credentialValuePatterns {
		if pattern.MatchString(candidate.Value) {
			return true
		}
	}
	return false
}

func (s *Service) Recall(ctx context.Context, prompt string) (Snapshot, error) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return Snapshot{}, ErrInvalid
	}
	snapshot, err := s.store.Recall(ctx, MaxActiveFacts, DefaultRecallEvents)
	if err != nil {
		return Snapshot{}, err
	}
	type rankedFact struct {
		Fact
		score int
		order int
	}
	ranked := make([]rankedFact, 0, len(snapshot.Facts))
	for index, fact := range snapshot.Facts {
		ranked = append(ranked, rankedFact{Fact: fact, score: factRelevance(prompt, fact), order: index})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].order < ranked[j].order
	})
	if len(ranked) > DefaultRecallFacts {
		ranked = ranked[:DefaultRecallFacts]
	}
	snapshot.Facts = make([]Fact, len(ranked))
	for index := range ranked {
		snapshot.Facts[index] = ranked[index].Fact
	}
	return snapshot, nil
}

func factRelevance(prompt string, fact Fact) int {
	prompt = strings.ToLower(prompt)
	value := strings.ToLower(strings.TrimSpace(fact.Value))
	predicate := strings.ToLower(strings.TrimSpace(fact.Predicate))
	score := 0
	if value != "" && strings.Contains(prompt, value) {
		score += 100
	}
	for _, token := range strings.FieldsFunc(predicate+" "+value, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsNumber(r))
	}) {
		if utf8.RuneCountInString(token) >= 2 && strings.Contains(prompt, token) {
			score += 10
		}
	}
	return score
}

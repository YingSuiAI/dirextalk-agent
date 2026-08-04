// Package corevoice owns Native Agent voice sessions.  Voice is deliberately
// kept separate from chat: a session has a provider handle, RTC lifecycle,
// transcript turns, and a durable event stream.  The message-server only
// forwards the public action envelope to this package.
package corevoice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MaxSessionIDBytes   = 256
	MaxOwnerIDBytes     = 256
	MaxConversationID   = 256
	MaxProviderTaskID   = 256
	MaxProviderError    = 4096
	MaxTranscriptBytes  = 1 << 20
	MaxAnswerBytes      = 1 << 20
	MaxEventBytes       = 1 << 20
	MaxEventsPerSession = 1024
	SessionTTL          = time.Hour
	TombstoneTTL        = time.Hour
)

type SessionState string

const (
	SessionCreated  SessionState = "created"
	SessionStarted  SessionState = "started"
	SessionStopping SessionState = "stopping"
	SessionEnded    SessionState = "ended"
)

// ProviderIntent is the durable operation marker used to reconcile a crash
// window around an external voice-provider call.  An intent remains set until
// the provider call and the corresponding local state transition are both
// durably observed; restart recovery retries the same deterministic task.
type ProviderIntent string

const (
	ProviderIntentNone      ProviderIntent = ""
	ProviderIntentCreate    ProviderIntent = "create"
	ProviderIntentStart     ProviderIntent = "start"
	ProviderIntentInterrupt ProviderIntent = "interrupt"
	ProviderIntentEnd       ProviderIntent = "end"
)

type TurnState string

const (
	TurnPending     TurnState = "pending"
	TurnRunning     TurnState = "running"
	TurnCompleted   TurnState = "completed"
	TurnInterrupted TurnState = "interrupted"
	TurnFailed      TurnState = "failed"
	TurnUncertain   TurnState = "uncertain"
)

var (
	ErrInvalid            = errors.New("corevoice: invalid")
	ErrNotFound           = errors.New("corevoice: not found")
	ErrConflict           = errors.New("corevoice: conflict")
	ErrForbidden          = errors.New("corevoice: owner or account generation mismatch")
	ErrTerminal           = errors.New("corevoice: terminal")
	ErrUnavailable        = errors.New("corevoice: provider unavailable")
	ErrProvider           = errors.New("corevoice: provider operation failed")
	ErrTranscriptDisabled = errors.New("corevoice: client transcript submit disabled")
	ErrBusy               = errors.New("corevoice: session already has an active turn")
	ErrExpired            = errors.New("corevoice: session expired")
)

// Session is the durable, redacted voice session. Token is an ephemeral
// response value and must not be written to the session store.
type Session struct {
	ID                      string         `json:"session_id"`
	OwnerID                 string         `json:"owner_id"`
	AccountGeneration       int64          `json:"account_generation"`
	ConversationID          string         `json:"conversation_id"`
	ConversationProfileID   string         `json:"conversation_profile_id"`
	SpeechProfileID         string         `json:"speech_profile_id"`
	AppID                   string         `json:"app_id,omitempty"`
	VoiceChatAppID          string         `json:"voice_chat_app_id,omitempty"`
	AIUserID                string         `json:"ai_user_id,omitempty"`
	RoomID                  string         `json:"room_id,omitempty"`
	UserID                  string         `json:"user_id,omitempty"`
	ProviderHandle          string         `json:"provider_handle,omitempty"`
	ProviderTaskID          string         `json:"provider_task_id,omitempty"`
	ProviderIntent          ProviderIntent `json:"provider_intent,omitempty"`
	ProviderUncertain       bool           `json:"provider_uncertain"`
	ProviderLastError       string         `json:"provider_last_error,omitempty"`
	ExpiresAt               time.Time      `json:"expires_at"`
	State                   SessionState   `json:"state"`
	StartedAt               *time.Time     `json:"started_at,omitempty"`
	EndedAt                 *time.Time     `json:"ended_at,omitempty"`
	TombstoneExpiresAt      *time.Time     `json:"tombstone_expires_at,omitempty"`
	ActiveTurnID            string         `json:"active_turn_id,omitempty"`
	TurnSequence            int64          `json:"turn_sequence"`
	Revision                int64          `json:"revision"`
	ProviderStopped         bool           `json:"provider_stopped"`
	ProviderStopPending     bool           `json:"provider_stop_pending"`
	ClientTranscriptEnabled bool           `json:"client_transcript_submit_enabled"`
	CreatedAt               time.Time      `json:"created_at"`
	UpdatedAt               time.Time      `json:"updated_at"`
}

// ProviderSession is returned only from Provider.Create. Token is never
// persisted; the provider handle is an opaque, non-secret identifier used by
// restart cleanup.
type ProviderSession struct {
	AppID          string
	VoiceChatAppID string
	AIUserID       string
	RoomID         string
	UserID         string
	Token          string
	ProviderHandle string
	ExpiresAt      time.Time
}

type ProfileBinding struct {
	ConversationProfileID   string
	SpeechProfileID         string
	ClientTranscriptEnabled bool
	Provider                string
	AppID                   string
	VoiceChatAppID          string
	AIUserID                string
	AccessKeyID             string `json:"-"`
	SecretAccessKey         string `json:"-"`
	RTCAppKey               string `json:"-"`
	WebhookURL              string `json:"-"`
	WebhookSecret           string `json:"-"`
	CustomLLMURL            string `json:"-"`
	TTSResourceID           string `json:"-"`
	TTSSpeaker              string `json:"-"`
	TTSSpeechRate           int    `json:"-"`
	TTSSpeechLoudness       int    `json:"-"`
	TTSPitch                int    `json:"-"`
}

type CreateRequest struct {
	ConversationID        string `json:"conversation_id"`
	ConversationProfileID string `json:"conversation_profile_id,omitempty"`
	SpeechProfileID       string `json:"speech_profile_id,omitempty"`
}

type CreateResponse struct {
	OK                      bool   `json:"ok"`
	SessionID               string `json:"session_id"`
	ConversationID          string `json:"conversation_id"`
	Token                   string `json:"token"`
	AppID                   string `json:"app_id"`
	VoiceChatAppID          string `json:"voice_chat_app_id"`
	RoomID                  string `json:"room_id"`
	UserID                  string `json:"user_id"`
	AIUserID                string `json:"ai_user_id"`
	ExpiresAt               string `json:"expires_at"`
	ConversationProfileID   string `json:"conversation_profile_id"`
	SpeechProfileID         string `json:"speech_profile_id"`
	ClientTranscriptEnabled bool   `json:"client_transcript_submit_enabled"`
}

type Turn struct {
	ID                string    `json:"turn_id"`
	SessionID         string    `json:"session_id"`
	OwnerID           string    `json:"owner_id"`
	AccountGeneration int64     `json:"account_generation"`
	Transcript        string    `json:"transcript"`
	Answer            string    `json:"answer,omitempty"`
	State             TurnState `json:"state"`
	ErrorCode         string    `json:"error_code,omitempty"`
	ErrorMessage      string    `json:"error_message,omitempty"`
	Revision          int64     `json:"revision"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Event struct {
	SessionID string    `json:"session_id"`
	Sequence  int64     `json:"sequence"`
	Event     string    `json:"event"`
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

// ProfileResolver resolves model/speech profile pins without returning
// credentials to the voice domain. The provider adapter owns credentials.
type ProfileResolver interface {
	Resolve(context.Context, string, CreateRequest) (ProfileBinding, error)
}

// Provider owns the external RTC/voice provider. The service never calls a
// provider synchronously from a product callback; all callbacks are terminal
// or event-only and are fenced by the session owner/generation.
type Provider interface {
	Create(context.Context, string, Session, ProfileBinding) (ProviderSession, error)
	Start(context.Context, string, Session, ProfileBinding) error
	Interrupt(context.Context, string, Session, ProfileBinding) error
	End(context.Context, string, Session, ProfileBinding) error
}

type TranscriptRunner interface {
	Run(context.Context, string, Session, Turn, func(StreamEvent) error) error
	Cancel(context.Context, string, string) error
}

type StreamEvent struct {
	Event string
	Text  string
	Error error
}

type Store interface {
	CreateSession(context.Context, Session) error
	FindSession(context.Context, string) (Session, error)
	GetSession(context.Context, string, string, int64) (Session, error)
	SaveSession(context.Context, Session, int64) error
	CreateTurn(context.Context, Turn) error
	GetTurn(context.Context, string, string, string, int64) (Turn, error)
	SaveTurn(context.Context, Turn, int64) error
	AppendEvent(context.Context, Event) (Event, error)
	ListEvents(context.Context, string, string, int64, int64, int) ([]Event, error)
	Replay(context.Context, string, int64, string, string, string) ([]byte, bool, error)
	SaveReplay(context.Context, string, int64, string, string, string, []byte) error
	Recover(context.Context, time.Time) error
	ListPendingStops(context.Context) ([]Session, error)
	ListProviderIntents(context.Context) ([]Session, error)
}

// AtomicCreateStore is an optional stronger write boundary for Create.  It
// commits the durable session and its idempotency receipt in one transaction,
// preventing a crash from leaving a provider session without a replay record.
// Stores that cannot provide a transaction may omit this interface; the
// service retains the compatible two-step fallback for them.
type AtomicCreateStore interface {
	CreateSessionWithReplay(context.Context, Session, string, int64, string, string, string, []byte) error
}

func validateIdentity(owner string, generation int64) error {
	if strings.TrimSpace(owner) == "" || len(owner) > MaxOwnerIDBytes || generation <= 0 {
		return ErrForbidden
	}
	return nil
}

func validateSession(s Session) error {
	if strings.TrimSpace(s.ID) == "" || len(s.ID) > MaxSessionIDBytes || strings.TrimSpace(s.OwnerID) == "" || len(s.OwnerID) > MaxOwnerIDBytes || s.AccountGeneration <= 0 || strings.TrimSpace(s.ConversationID) == "" || len(s.ConversationID) > MaxConversationID || s.ExpiresAt.IsZero() || s.Revision <= 0 || s.State == "" {
		return ErrInvalid
	}
	if s.State == SessionEnded && s.EndedAt == nil {
		return ErrInvalid
	}
	if len(s.ProviderTaskID) > MaxProviderTaskID || len(s.ProviderLastError) > MaxProviderError {
		return ErrInvalid
	}
	switch s.ProviderIntent {
	case ProviderIntentNone, ProviderIntentCreate, ProviderIntentStart, ProviderIntentInterrupt, ProviderIntentEnd:
	default:
		return ErrInvalid
	}
	return nil
}

func validateTurn(t Turn) error {
	if strings.TrimSpace(t.ID) == "" || strings.TrimSpace(t.SessionID) == "" || strings.TrimSpace(t.OwnerID) == "" || t.AccountGeneration <= 0 || len(t.Transcript) == 0 || len(t.Transcript) > MaxTranscriptBytes || t.Revision <= 0 || t.State == "" {
		return ErrInvalid
	}
	if len(t.Answer) > MaxAnswerBytes {
		return ErrInvalid
	}
	return nil
}

func validateEvent(e Event) error {
	if strings.TrimSpace(e.SessionID) == "" || strings.TrimSpace(e.Event) == "" || len(e.Data) == 0 || len(e.Data) > MaxEventBytes {
		return ErrInvalid
	}
	return nil
}

func stateTerminal(state TurnState) bool {
	return state == TurnCompleted || state == TurnInterrupted || state == TurnFailed || state == TurnUncertain
}

func fmtProvider(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrProvider, err)
}

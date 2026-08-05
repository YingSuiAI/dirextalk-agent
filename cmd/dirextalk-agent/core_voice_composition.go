package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/corevoice"
	"github.com/google/uuid"
)

// coreVoiceProfileResolver resolves the conversation model through the
// Agent-owned profile service and reads provider credentials from protected
// mounted files on each lifecycle operation.  The returned binding is
// request-local; no secret is passed to or persisted by corevoice.Store.
type coreVoiceProfileResolver struct {
	profiles *coremodel.Service
	config   config.Config
}

func (r coreVoiceProfileResolver) Resolve(ctx context.Context, owner string, req corevoice.CreateRequest) (corevoice.ProfileBinding, error) {
	if r.profiles == nil {
		return corevoice.ProfileBinding{}, corevoice.ErrUnavailable
	}
	conversationID := strings.TrimSpace(req.ConversationProfileID)
	if conversationID == "" {
		conversationID = strings.TrimSpace(r.config.CoreVoiceConversationProfileID)
	}
	if conversationID == "" {
		return corevoice.ProfileBinding{}, corevoice.ErrInvalid
	}
	conversation, err := resolveVoiceModelProfile(ctx, r.profiles, conversationID)
	if err != nil {
		return corevoice.ProfileBinding{}, fmt.Errorf("resolve voice conversation profile: %w", err)
	}
	speechID := strings.TrimSpace(req.SpeechProfileID)
	if speechID == "" {
		speechID = strings.TrimSpace(r.config.CoreVoiceSpeechProfileID)
	}
	if speechID == "" || (r.config.CoreVoiceSpeechProfileID != "" && speechID != r.config.CoreVoiceSpeechProfileID) {
		return corevoice.ProfileBinding{}, corevoice.ErrForbidden
	}
	accessKey, err := config.ReadMountedSecretText(r.config.CoreVoiceAccessKeyIDFile)
	if err != nil {
		return corevoice.ProfileBinding{}, fmt.Errorf("read voice access key: %w", err)
	}
	secretKey, err := config.ReadMountedSecretText(r.config.CoreVoiceSecretAccessKeyFile)
	if err != nil {
		return corevoice.ProfileBinding{}, fmt.Errorf("read voice secret key: %w", err)
	}
	rtcKey, err := config.ReadMountedSecretText(r.config.CoreVoiceRTCAppKeyFile)
	if err != nil {
		return corevoice.ProfileBinding{}, fmt.Errorf("read voice rtc key: %w", err)
	}
	webhookSecret, err := config.ReadMountedSecretText(r.config.CoreVoiceWebhookSecretFile)
	if err != nil {
		return corevoice.ProfileBinding{}, fmt.Errorf("read voice callback secret: %w", err)
	}
	return corevoice.ProfileBinding{
		ConversationProfileID:   conversation.ID,
		SpeechProfileID:         speechID,
		ClientTranscriptEnabled: r.config.CoreVoiceClientTranscriptEnabled,
		Provider:                r.config.CoreVoiceProvider,
		AppID:                   r.config.CoreVoiceAppID,
		VoiceChatAppID:          r.config.CoreVoiceChatAppID,
		AIUserID:                r.config.CoreVoiceAIUserID,
		AccessKeyID:             accessKey,
		SecretAccessKey:         secretKey,
		RTCAppKey:               rtcKey,
		WebhookURL:              r.config.CoreVoiceWebhookURL,
		WebhookSecret:           webhookSecret,
		CustomLLMURL:            r.config.CoreVoiceCustomLLMURL,
	}, nil
}

func resolveVoiceModelProfile(ctx context.Context, profiles *coremodel.Service, id string) (coremodel.Profile, error) {
	if profiles == nil {
		return coremodel.Profile{}, corevoice.ErrUnavailable
	}
	if profile, err := profiles.ResolveProfile(ctx, id); err == nil {
		return profile, nil
	}
	page, err := profiles.List(ctx, coremodel.ListProfileCommand{Limit: 100})
	if err != nil {
		return coremodel.Profile{}, err
	}
	for _, candidate := range page.Profiles {
		if candidate.ClientProfileID == id {
			return profiles.ResolveProfile(ctx, candidate.ID)
		}
	}
	return coremodel.Profile{}, coremodel.ErrProfileNotFound
}

// coreConversationVoiceRunner adapts the durable Core conversation turn
// protocol to the voice TranscriptRunner port.  A deterministic UUID derived
// from the voice turn gives provider retries the same conversation turn
// identity while allowing product room ids that are not UUIDs.
type coreConversationVoiceRunner struct {
	conversation coreConversationTurnService
	profiles     *coremodel.Service
}

type coreConversationTurnService interface {
	GetTurnByRequestID(context.Context, string) (coreconversation.Turn, error)
	StartTurn(context.Context, coreconversation.TurnStartCommand) (coreconversation.Turn, error)
	WatchTurnEvents(context.Context, string, int64, int) (<-chan coreconversation.TurnEvent, error)
	CancelTurn(context.Context, coreconversation.TurnCancelCommand) (coreconversation.Turn, error)
}

func (r coreConversationVoiceRunner) Run(ctx context.Context, _ string, session corevoice.Session, turn corevoice.Turn, emit func(corevoice.StreamEvent) error) error {
	if r.conversation == nil {
		return corevoice.ErrUnavailable
	}
	requestID := voiceUUID("voice-request:" + turn.ID)
	conversationID := voiceUUID("voice-conversation:" + session.ConversationID)
	if existing, lookupErr := r.conversation.GetTurnByRequestID(ctx, requestID); lookupErr == nil {
		if existing.ID == "" || existing.RequestID != requestID || existing.ConversationID != conversationID || existing.Prompt != turn.Transcript {
			return corevoice.ErrConflict
		}
		return r.watchTurn(ctx, existing.ID, emit)
	} else if !errors.Is(lookupErr, coreconversation.ErrConflict) {
		return lookupErr
	}
	if r.profiles == nil {
		return corevoice.ErrUnavailable
	}
	profile, err := r.profiles.ResolveProfile(ctx, session.ConversationProfileID)
	if err != nil {
		return fmt.Errorf("resolve voice conversation profile: %w", err)
	}
	snapshot := coremodel.SnapshotFromProfile(profile)
	accepted, err := r.conversation.StartTurn(ctx, coreconversation.TurnStartCommand{RequestID: requestID, ConversationID: conversationID, Prompt: turn.Transcript, ProfileID: snapshot.ProfileID, ExpectedProfileRevision: snapshot.Revision, ExpectedCredentialVersion: snapshot.CredentialVersion, ProfileSnapshot: snapshot})
	if err != nil {
		return err
	}
	return r.watchTurn(ctx, accepted.ID, emit)
}

func (r coreConversationVoiceRunner) watchTurn(ctx context.Context, turnID string, emit func(corevoice.StreamEvent) error) error {
	events, err := r.conversation.WatchTurnEvents(ctx, turnID, 0, 256)
	if err != nil {
		return err
	}
	for event := range events {
		if event.Err != nil {
			return event.Err
		}
		if event.ReplayGap {
			return fmt.Errorf("voice conversation event replay gap")
		}
		switch event.Kind {
		case coreconversation.TurnEventDelta:
			if event.Text != "" {
				if err := emit(corevoice.StreamEvent{Event: "delta", Text: event.Text}); err != nil {
					return err
				}
			}
		case coreconversation.TurnEventDone:
			return emit(corevoice.StreamEvent{Event: "done"})
		case coreconversation.TurnEventError:
			return fmt.Errorf("voice conversation turn failed: %s", event.ErrorSummary)
		case coreconversation.TurnEventCanceled:
			return context.Canceled
		}
	}
	return nil
}

func (r coreConversationVoiceRunner) Cancel(ctx context.Context, _ string, turnID string) error {
	if r.conversation == nil {
		return corevoice.ErrUnavailable
	}
	requestID := voiceUUID("voice-request:" + turnID)
	turn, err := r.conversation.GetTurnByRequestID(ctx, requestID)
	if err != nil {
		return err
	}
	_, err = r.conversation.CancelTurn(ctx, coreconversation.TurnCancelCommand{RequestID: requestID, TurnID: turn.ID, ExpectedRevision: turn.Revision})
	return err
}

func voiceUUID(value string) string {
	if parsed, err := uuid.Parse(strings.TrimSpace(value)); err == nil && parsed != uuid.Nil {
		return parsed.String()
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(value)).String()
}

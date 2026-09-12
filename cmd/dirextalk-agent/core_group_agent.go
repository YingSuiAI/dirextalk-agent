package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type groupProduct interface {
	PullGroupAgentRequests(context.Context, string) (capabilityclient.GroupAgentPage, error)
	ValidateGroupAgentRequest(context.Context, string, int64) (capabilityclient.GroupAgentBindingCheck, error)
	ReadGroupAgentHistory(context.Context, string, int64, int) (capabilityclient.GroupAgentHistory, error)
	PublishGroupAgentReply(context.Context, capabilityclient.GroupAgentPublish) error
	CompleteGroupAgentRequest(context.Context, string, int64, string) error
}

type groupTurns interface {
	StartGroupTurn(context.Context, coreconversation.TurnStartCommand, coreconversation.GroupOrigin) (coreconversation.Turn, error)
	GetTurn(context.Context, string) (coreconversation.Turn, error)
	CancelTurn(context.Context, coreconversation.TurnCancelCommand) (coreconversation.Turn, error)
	ListActiveGroupTurns(context.Context) ([]coreconversation.Turn, error)
}

type groupModelProfiles interface {
	ResolveDefaultProfileID(context.Context, string) (string, error)
	ResolveProfile(context.Context, string) (coremodel.Profile, error)
}

// groupAgentLoop observes the Product-owned event references and the
// Agent-owned durable turns. The original request UUID is always the turn UUID,
// including after a lost acknowledgement or either process restarting.
// There is no second model executor or client-owned group task queue.
type groupAgentLoop struct {
	product    groupProduct
	turns      groupTurns
	profiles   groupModelProfiles
	generation uint64
	interval   time.Duration
	once       sync.Once
	done       chan struct{}
}

func newGroupAgentLoop(product groupProduct, turns groupTurns, profiles groupModelProfiles, generation uint64) *groupAgentLoop {
	return &groupAgentLoop{product: product, turns: turns, profiles: profiles, generation: generation, interval: 2 * time.Second, done: make(chan struct{})}
}

func (l *groupAgentLoop) ValidateGroupOrigin(ctx context.Context, origin coreconversation.GroupOrigin) error {
	if origin.Validate() != nil || origin.AccountGeneration != l.generation {
		return coreconversation.ErrGroupAuthorization
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	check, err := l.product.ValidateGroupAgentRequest(checkCtx, origin.RequestID, origin.BindingRevision)
	if err != nil {
		return err
	}
	if !check.Allowed {
		return coreconversation.ErrGroupAuthorization
	}
	return nil
}

func (l *groupAgentLoop) Run(ctx context.Context) error {
	if l == nil || l.product == nil || l.turns == nil || l.profiles == nil || l.generation == 0 {
		return errors.New("invalid group Agent loop")
	}
	defer l.once.Do(func() { close(l.done) })
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			if err := l.tick(ctx); err != nil && ctx.Err() == nil {
				// Never include request bodies, private provider data or credentials.
				slog.Warn("[group-agent] delivery retry pending", "error", groupAgentErrorSummary(err))
			}
			timer.Reset(l.interval)
		}
	}
}

func (l *groupAgentLoop) Wait(ctx context.Context) error {
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *groupAgentLoop) tick(ctx context.Context) error {
	if err := l.cancelRevoked(ctx); err != nil {
		return err
	}
	// One group shares one conversation, so two answers cannot be committed at
	// the same revision. A request for a conversation that is still answering
	// stays pending and is delivered on the next tick.
	busy, err := l.busyGroupConversations(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for after := ""; ; {
		pageCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		page, err := l.product.PullGroupAgentRequests(pageCtx, after)
		cancel()
		if err != nil {
			return err
		}
		for _, request := range page.Requests {
			if busy[groupRequestConversationID(request)] {
				continue
			}
			requestCtx, requestCancel := context.WithTimeout(ctx, 15*time.Second)
			if err = l.processRequest(requestCtx, request); err != nil {
				failures = append(failures, err)
			}
			requestCancel()
		}
		if !page.HasMore {
			return errors.Join(failures...)
		}
		if page.NextAfterRequestID <= after || page.NextAfterRequestID == "" {
			return errors.New("invalid group delivery cursor")
		}
		after = page.NextAfterRequestID
	}
}

func (l *groupAgentLoop) busyGroupConversations(ctx context.Context) (map[string]bool, error) {
	turns, err := l.turns.ListActiveGroupTurns(ctx)
	if err != nil {
		return nil, err
	}
	busy := make(map[string]bool, len(turns))
	for _, turn := range turns {
		if turn.GroupOrigin == nil || strings.TrimSpace(turn.ConversationID) == "" {
			continue
		}
		busy[turn.ConversationID] = true
	}
	return busy, nil
}

// groupRequestConversationID derives the identity of the shared group
// conversation without starting the turn.
func groupRequestConversationID(request capabilityclient.GroupAgentRequest) string {
	origin := coreconversation.GroupOrigin{RequestID: request.RequestID, RoomID: request.RoomID, EventID: request.EventID,
		ActorID: request.SenderMXID, OwnerID: request.OwnerMXID, AgentMXID: request.AgentMXID,
		AccountGeneration: request.AccountGeneration, BindingRevision: request.BindingRevision}
	if origin.Validate() != nil {
		return ""
	}
	return origin.ConversationID()
}

// groupAgentErrorSummary keeps diagnostics useful without logging untrusted
// bodies: one bounded line.
func groupAgentErrorSummary(err error) string {
	if err == nil {
		return ""
	}
	summary := strings.TrimSpace(err.Error())
	if len(summary) > 240 {
		summary = summary[:240]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, summary)
}

func (l *groupAgentLoop) cancelRevoked(ctx context.Context) error {
	turns, err := l.turns.ListActiveGroupTurns(ctx)
	if err != nil {
		return err
	}
	for _, turn := range turns {
		if turn.GroupOrigin == nil {
			continue
		}
		err = l.ValidateGroupOrigin(ctx, *turn.GroupOrigin)
		// A temporary network failure is not a user's cancellation. Core still
		// fails closed before tool execution and publication until validation.
		if errors.Is(err, coreconversation.ErrGroupAuthorization) {
			_, cancelErr := l.turns.CancelTurn(ctx, coreconversation.TurnCancelCommand{TurnID: turn.ID, RequestID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("group-revoked:"+turn.ID)).String()})
			if cancelErr != nil {
				return cancelErr
			}
		}
	}
	return nil
}

func (l *groupAgentLoop) processRequest(ctx context.Context, request capabilityclient.GroupAgentRequest) error {
	origin := coreconversation.GroupOrigin{RequestID: request.RequestID, RoomID: request.RoomID, EventID: request.EventID,
		ActorID: request.SenderMXID, OwnerID: request.OwnerMXID, AgentMXID: request.AgentMXID,
		AccountGeneration: request.AccountGeneration, BindingRevision: request.BindingRevision}
	if origin.Validate() != nil || origin.AccountGeneration != l.generation || strings.TrimSpace(request.Body) == "" {
		return errors.New("invalid authenticated group request")
	}
	if err := l.ValidateGroupOrigin(ctx, origin); err != nil {
		if errors.Is(err, coreconversation.ErrGroupAuthorization) {
			return l.product.CompleteGroupAgentRequest(ctx, origin.RequestID, origin.BindingRevision, "cancelled")
		}
		return err
	}
	turn, err := l.turns.GetTurn(ctx, request.RequestID)
	// Core's durable lookup reports ErrConflict for an absent request. The
	// atomic admission rechecks that UUID before creating anything.
	if errors.Is(err, coreconversation.ErrConflict) {
		profileID, profileErr := l.profiles.ResolveDefaultProfileID(ctx, coremodel.ModelKindConversation)
		if profileErr != nil {
			return l.publish(ctx, origin, groupReply(request.Body, "请群主先配置 Ying 的默认对话模型，然后重新提问。", "Ask the group owner to configure Ying's default conversation model, then send the request again."), "final", "failed")
		}
		profile, profileErr := l.profiles.ResolveProfile(ctx, profileID)
		if profileErr != nil {
			return l.publish(ctx, origin, groupReply(request.Body, "Ying 的模型暂时不可用，请群主检查模型配置后重试。", "Ying's model is unavailable. Ask the group owner to check its configuration and retry."), "final", "failed")
		}
		turn, err = l.turns.StartGroupTurn(ctx, coreconversation.TurnStartCommand{TurnID: request.RequestID, RequestID: request.RequestID,
			OwnerID: request.OwnerMXID, AccountGeneration: request.AccountGeneration, Prompt: groupAgentTurnPrompt(request),
			ProfileID: profileID, ExpectedProfileRevision: profile.Revision, ExpectedCredentialVersion: profile.CredentialVersion}, origin)
	}
	if err != nil {
		return err
	}
	if turn.GroupOrigin == nil || *turn.GroupOrigin != origin || turn.ID != request.RequestID {
		return errors.New("group request does not match its durable turn")
	}
	switch turn.State {
	case coreconversation.TurnAccepted, coreconversation.TurnRunning:
		return l.publish(ctx, origin, groupReply(request.Body, "Ying 已收到请求，正在处理。", "Ying has received the request and is working on it."), "progress", "working")
	case coreconversation.TurnWaitingConfirmation:
		return l.publish(ctx, origin, groupReply(request.Body, "这个任务需要群主批准。请群主打开 Ying 的任务管理，查看并确认；群成员无需重复发送。", "This task needs the group owner's approval. The owner can review it in Ying's task manager; group members do not need to resend it."), "progress", "waiting_owner")
	case coreconversation.TurnCanceled:
		return l.product.CompleteGroupAgentRequest(ctx, origin.RequestID, origin.BindingRevision, "cancelled")
	case coreconversation.TurnCompleted, coreconversation.TurnFailed:
		body := ""
		if turn.Response != nil {
			body = strings.TrimSpace(turn.Response.Message.Content)
		}
		status := "completed"
		if turn.State == coreconversation.TurnFailed || body == "" {
			status = "failed"
			if body == "" {
				body = groupReply(request.Body, "Ying 暂时未能完成这次请求。已完成的结果会保留在群主的任务记录中；请稍后重试。", "Ying could not finish this request. Completed work is retained in the owner's task history; please try again later.")
			}
		}
		return l.publish(ctx, origin, body, "final", status)
	default:
		return errors.New("invalid group turn state")
	}
}

func (l *groupAgentLoop) publish(ctx context.Context, origin coreconversation.GroupOrigin, body, kind, status string) error {
	if len(body) > 60<<10 {
		// Retain the full authoritative response in Agent history; don't trap
		// a completed task in an endless oversized-publication retry loop.
		body = groupReply(body, "任务结果已保存。内容过长，未完整发送到群里；请群主打开此任务查看完整结果。", "The result has been saved. It is too long to post in this group; the owner can open the task to view the complete result.")
	}
	return l.product.PublishGroupAgentReply(ctx, capabilityclient.GroupAgentPublish{RequestID: origin.RequestID, BindingRevision: origin.BindingRevision, Body: body, Kind: kind, Status: status})
}

func groupReply(prompt, chinese, english string) string {
	for _, r := range prompt {
		if unicode.Is(unicode.Han, r) {
			return chinese
		}
	}
	return english
}

const groupAgentSpeakerNameMaxRunes = 64

// groupAgentTurnPrompt renders the model-facing text of one group request. The
// whole group shares a single conversation, so the speaker belongs to the
// message: the model can attribute, compare and combine what different members
// said. The visible reply, the language choice and the durable turn identity
// keep using the raw body.
func groupAgentTurnPrompt(request capabilityclient.GroupAgentRequest) string {
	mxid := strings.TrimSpace(request.SenderMXID)
	name := sanitizeGroupAgentSpeakerName(request.SenderDisplayName)
	if name == "" || name == mxid {
		return mxid + ": " + request.Body
	}
	return name + " (" + mxid + "): " + request.Body
}

// sanitizeGroupAgentSpeakerName treats the member-controlled name as display
// data: one bounded line, no control characters, no injected line breaks.
func sanitizeGroupAgentSpeakerName(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || !utf8.ValidString(value) {
		return ""
	}
	var out strings.Builder
	space := false
	written := 0
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == utf8.RuneError {
			space = out.Len() > 0
			continue
		}
		if space {
			out.WriteByte(' ')
			written++
			space = false
		}
		if written >= groupAgentSpeakerNameMaxRunes {
			break
		}
		out.WriteRune(r)
		written++
	}
	return strings.TrimSpace(out.String())
}

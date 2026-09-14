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
	ListGroupAgentBindings(context.Context) (capabilityclient.GroupAgentBindings, error)
	ReadGroupAgentTranscript(context.Context, string, int64, int64, int, string) (capabilityclient.GroupAgentHistory, error)
	ReadGroupAgentMembers(context.Context, string, int64, int) (capabilityclient.GroupAgentMembers, error)
	ValidateGroupAgentRequest(context.Context, string, int64) (capabilityclient.GroupAgentBindingCheck, error)
	ReadGroupAgentHistory(context.Context, string, int64, int, string) (capabilityclient.GroupAgentHistory, error)
	PublishGroupAgentReply(context.Context, capabilityclient.GroupAgentPublish) error
	CompleteGroupAgentRequest(context.Context, string, int64, string) error
	RecordGroupMemory(context.Context, capabilityclient.GroupAgentMemoryMirror) error
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
	ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error)
}

// groupModelOverrides resolves an optional per-group conversation model. A
// group with an override answers with the model its owner picked for that group;
// without one it inherits the owner's default conversation model.
type groupModelOverrides interface {
	ResolveGroupConversationModel(context.Context, string, uint64, string) (string, bool, error)
}

// groupAgentLoop observes the Product-owned event references and the
// Agent-owned durable turns. The original request UUID is always the turn UUID,
// including after a lost acknowledgement or either process restarting.
// There is no second model executor or client-owned group task queue.
type groupAgentLoop struct {
	product    groupProduct
	turns      groupTurns
	profiles   groupModelProfiles
	models     groupModelOverrides
	summaries  groupSummaryStore
	generation uint64
	interval   time.Duration
	// summaryInterval and the sweep fence keep the derived group digests fresh
	// without blocking request delivery.
	summaryInterval time.Duration
	// summaryClientFactory is overridable in tests; production uses the utility
	// model client for the same profile.
	summaryClientFactory func(coremodel.Profile) (coremodel.Client, error)
	summarySweepAt       time.Time
	summarySweepBusy     bool
	summaryMu            sync.Mutex
	// waitingMu guards waitingNotices, the set of parked group turns whose
	// owner-approval notice this process already posted. The Product dedupes
	// the notice per request, so this only stops a two-second tick from
	// repeating the call.
	waitingMu      sync.Mutex
	waitingNotices map[string]struct{}
	once           sync.Once
	done           chan struct{}
}

func newGroupAgentLoop(product groupProduct, turns groupTurns, profiles groupModelProfiles, generation uint64, summaries groupSummaryStore) *groupAgentLoop {
	loop := &groupAgentLoop{product: product, turns: turns, profiles: profiles, summaries: summaries,
		generation: generation, interval: 2 * time.Second, summaryInterval: groupSummarySweepInterval,
		waitingNotices: make(map[string]struct{}), done: make(chan struct{})}
	if summaries != nil {
		if service, ok := turns.(interface {
			SetGroupSummaryReader(coreconversation.GroupSummaryReader)
		}); ok {
			service.SetGroupSummaryReader(summaries)
		}
	}
	return loop
}

// SetGroupModelOverrides wires the owner's per-group conversation model choice.
// The loop keeps inheriting the owner's default when a group has no binding.
func (l *groupAgentLoop) SetGroupModelOverrides(overrides groupModelOverrides) {
	if l != nil {
		l.models = overrides
	}
}

// resolveConversationProfileID returns the profile one group turn answers with:
// the group's own choice when the owner configured one, otherwise the owner's
// default conversation model.
func (l *groupAgentLoop) resolveConversationProfileID(ctx context.Context, origin coreconversation.GroupOrigin) (string, error) {
	if l.models != nil {
		profileID, ok, err := l.models.ResolveGroupConversationModel(ctx, origin.OwnerID, origin.AccountGeneration, origin.RoomID)
		if err != nil {
			// The per-group choice is optional: an unreadable override must not
			// stop a member's request, so the group falls back to the owner's
			// default conversation model.
			slog.Warn("[group-agent] group model override unavailable; using the owner default", "error", groupAgentErrorSummary(err))
		} else if ok {
			return profileID, nil
		}
	}
	return l.profiles.ResolveDefaultProfileID(ctx, coremodel.ModelKindConversation)
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
	busy, err := l.activeGroupTurns(ctx)
	if err != nil {
		return err
	}
	l.retainWaitingNotices(busy)
	l.scheduleSummarySweep(ctx)
	var failures []error
	// A single tick can still deliver several members' requests: only the first
	// one per conversation may start work, the rest wait for a later tick.
	started := make(map[string]bool, len(busy))
	for after := ""; ; {
		pageCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		page, err := l.product.PullGroupAgentRequests(pageCtx, after)
		cancel()
		if err != nil {
			return err
		}
		for _, request := range page.Requests {
			conversationID := groupRequestConversationID(request)
			if turn, parked := busy[conversationID]; conversationID != "" && parked {
				// A turn parked on the owner's confirmation still owns the
				// conversation, so no second answer may race the one the owner
				// is about to approve. The group has to learn it is waiting
				// instead of seeing only "working", and the same delivery path
				// produces that notice.
				if turn.State == coreconversation.TurnWaitingConfirmation && turn.ID == request.RequestID &&
					!l.waitingNoticeSent(turn.ID) {
					requestCtx, requestCancel := context.WithTimeout(ctx, 10*time.Second)
					if err = l.processRequest(requestCtx, request); err != nil {
						failures = append(failures, err)
					} else {
						l.markWaitingNotice(turn.ID)
					}
					requestCancel()
				}
				continue
			}
			if conversationID != "" && started[conversationID] {
				continue
			}
			requestCtx, requestCancel := context.WithTimeout(ctx, 15*time.Second)
			if err = l.processRequest(requestCtx, request); err != nil {
				failures = append(failures, err)
			}
			requestCancel()
			if conversationID != "" {
				started[conversationID] = true
			}
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

// scheduleSummarySweep refreshes the derived group digests in the background so
// a slow model call never delays a member's answer.
func (l *groupAgentLoop) scheduleSummarySweep(ctx context.Context) {
	if l.summaries == nil || l.profiles == nil || l.summaryInterval <= 0 {
		return
	}
	l.summaryMu.Lock()
	due := !l.summarySweepBusy && time.Since(l.summarySweepAt) >= l.summaryInterval
	if due {
		l.summarySweepBusy = true
		l.summarySweepAt = time.Now()
	}
	l.summaryMu.Unlock()
	if !due {
		return
	}
	go func() {
		defer func() {
			l.summaryMu.Lock()
			l.summarySweepBusy = false
			l.summaryMu.Unlock()
		}()
		sweepCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), groupSummarySweepTimeout)
		defer cancel()
		if err := l.refreshGroupSummaries(sweepCtx); err != nil && sweepCtx.Err() == nil {
			slog.Warn("[group-agent] group summary sweep failed", "error", groupAgentErrorSummary(err))
		}
	}()
}

// activeGroupTurns indexes the turns that still own a group conversation by
// conversation id. A parked waiting_confirmation turn keeps owning its
// conversation: its commit may still arrive once the owner approves, and a
// second answer in the same conversation would race that revision.
func (l *groupAgentLoop) activeGroupTurns(ctx context.Context) (map[string]coreconversation.Turn, error) {
	turns, err := l.turns.ListActiveGroupTurns(ctx)
	if err != nil {
		return nil, err
	}
	active := make(map[string]coreconversation.Turn, len(turns))
	for _, turn := range turns {
		if turn.GroupOrigin == nil || strings.TrimSpace(turn.ConversationID) == "" {
			continue
		}
		active[turn.ConversationID] = turn
	}
	return active, nil
}

// retainWaitingNotices forgets parked turns that already stopped waiting, so
// the notice set stays bounded by the group's currently parked turns.
func (l *groupAgentLoop) retainWaitingNotices(active map[string]coreconversation.Turn) {
	parked := make(map[string]struct{}, len(active))
	for _, turn := range active {
		if turn.State == coreconversation.TurnWaitingConfirmation {
			parked[turn.ID] = struct{}{}
		}
	}
	l.waitingMu.Lock()
	defer l.waitingMu.Unlock()
	for turnID := range l.waitingNotices {
		if _, ok := parked[turnID]; !ok {
			delete(l.waitingNotices, turnID)
		}
	}
}

func (l *groupAgentLoop) waitingNoticeSent(turnID string) bool {
	l.waitingMu.Lock()
	defer l.waitingMu.Unlock()
	_, sent := l.waitingNotices[turnID]
	return sent
}

func (l *groupAgentLoop) markWaitingNotice(turnID string) {
	l.waitingMu.Lock()
	defer l.waitingMu.Unlock()
	if l.waitingNotices == nil {
		l.waitingNotices = make(map[string]struct{})
	}
	l.waitingNotices[turnID] = struct{}{}
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
		profileID, profileErr := l.resolveConversationProfileID(ctx, origin)
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
				body = groupReply(request.Body, groupFailureReply(turn.TerminalCode), groupFailureReplyEN(turn.TerminalCode))
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

// groupFailureReply explains one failed group turn in words the member can act
// on. An interrupted model call (restart, network loss) never produced an
// answer, so the group is told that plainly instead of a generic failure.
const groupTurnInterruptedCode = "provider_uncertain"

func groupFailureReply(terminalCode string) string {
	switch strings.TrimSpace(terminalCode) {
	case groupTurnInterruptedCode:
		return "Ying 这次的回复被中断了（服务重启或网络中断），本次没有产生任何结果，也没有执行任何操作；请重新发一次。"
	default:
		return "Ying 暂时未能完成这次请求。已完成的结果会保留在群主的任务记录中；请稍后重试。"
	}
}

func groupFailureReplyEN(terminalCode string) string {
	switch strings.TrimSpace(terminalCode) {
	case groupTurnInterruptedCode:
		return "Ying's reply was interrupted (service restart or network loss). Nothing was produced or executed for that request; please send it again."
	default:
		return "Ying could not finish this request. Completed work is retained in the owner's task history; please try again later."
	}
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

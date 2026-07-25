package coreconversation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	store      Store
	models     ModelRunner
	extensions ExtensionResolver
	snapshots  SnapshotProfileResolver
	now        func() time.Time
	leaseTTL   time.Duration
}

// Orchestrator is the public name used by callers that embed the chat flow.
type Orchestrator = Service

func NewService(store Store, models ModelRunner, extensions ExtensionResolver, profiles SnapshotProfileResolver) (*Service, error) {
	if store == nil || models == nil || profiles == nil {
		return nil, ErrInvalid
	}
	if extensions == nil {
		extensions = noopExtensions{}
	}
	return &Service{store: store, models: models, extensions: extensions, snapshots: profiles, now: func() time.Time { return time.Now().UTC() }, leaseTTL: 2 * time.Minute}, nil
}

func NewOrchestrator(store Store, models ModelRunner, extensions ExtensionResolver, profiles SnapshotProfileResolver) (*Orchestrator, error) {
	return NewService(store, models, extensions, profiles)
}

type noopExtensions struct{}

func (noopExtensions) ResolveExtensions(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
	return nil, nil
}
func leaseTTL(c ChatCommand, d time.Duration) time.Duration {
	if c.LeaseTTL > 0 {
		return c.LeaseTTL
	}
	return d
}
func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func digestExtensions(e []ResolvedExtension) string {
	type item struct {
		Kind                ExtensionKind `json:"kind"`
		ID, Version, Digest string
		Allowed             []string `json:"allowed_tools"`
	}
	items := make([]item, 0, len(e))
	for _, x := range e {
		a := append([]string(nil), x.Selection.AllowedTools...)
		sort.Strings(a)
		items = append(items, item{x.Selection.Kind, x.Selection.ID, x.Selection.Version, x.Selection.Digest, a})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].ID < items[j].ID
	})
	b, _ := json.Marshal(items)
	return digest(string(b))
}
func digestSelections(e []ExtensionSelection) string {
	r := make([]ResolvedExtension, len(e))
	for i, x := range e {
		r[i] = ResolvedExtension{Selection: x}
	}
	return digestExtensions(r)
}
func stableIDs(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func stableStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func (s *Service) clock() time.Time { return s.now().UTC() }
func nextMessageTime(c Conversation, t time.Time) time.Time {
	t = t.UTC()
	if len(c.Messages) > 0 && !t.After(c.Messages[len(c.Messages)-1].CreatedAt) {
		return c.Messages[len(c.Messages)-1].CreatedAt.Add(time.Nanosecond)
	}
	return t
}
func (s *Service) runModel(ctx context.Context, req ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
	if emit != nil {
		if runner, ok := s.models.(StreamingModelRunner); ok {
			return runner.Stream(ctx, req, emit)
		}
		return ModelRunResult{}, ErrInvalid
	}
	return s.models.Run(ctx, req)
}
func (s *Service) runModelHeartbeat(ctx context.Context, req ModelRunRequest, lease *ChatLease, cmd ChatCommand, emit func(ModelDelta) error) (ModelRunResult, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	resultCh := make(chan struct {
		r   ModelRunResult
		err error
	}, 1)
	go func() {
		r, e := s.runModel(child, req, emit)
		resultCh <- struct {
			r   ModelRunResult
			err error
		}{r, e}
	}()
	interval := leaseTTL(cmd, s.leaseTTL) / 3
	if interval <= 0 || interval > time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case out := <-resultCh:
			return out.r, out.err
		case <-ticker.C:
			renewed, err := s.store.RenewChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch, s.clock(), leaseTTL(cmd, s.leaseTTL))
			if err != nil {
				cancel()
				return ModelRunResult{}, err
			}
			*lease = renewed
		case <-ctx.Done():
			cancel()
			return ModelRunResult{}, ErrCanceled
		}
	}
}

func (s *Service) bindProfileSnapshot(ctx context.Context, cmd ChatCommand, lease *ChatLease) error {
	if lease.ProfileSnapshotDigest != "" {
		if err := lease.ProfileSnapshot.Validate(); err != nil || lease.ProfileSnapshot.Digest() != lease.ProfileSnapshotDigest {
			return ErrConflict
		}
		return nil
	}
	binder, ok := s.store.(ChatProfileSnapshotBinder)
	if !ok {
		return ErrInvalid
	}
	if s.snapshots == nil {
		return ErrInvalid
	}
	snap, err := s.snapshots.ResolveProfileSnapshot(ctx, cmd.ProfileID)
	if err != nil {
		return err
	}
	if err := snap.Validate(); err != nil {
		return err
	}
	bound, err := binder.BindChatProfileSnapshot(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch, lease.Fingerprint, snap)
	if err != nil {
		return err
	}
	*lease = bound
	return nil
}
func (s *Service) executeToolHeartbeat(ctx context.Context, req ToolExecutionRequest, tl *ToolLease, cl *ChatLease, cmd ChatCommand, execute func(context.Context, ToolExecutionRequest) (ToolResult, error)) (ToolResult, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	out := make(chan struct {
		r   ToolResult
		err error
	}, 1)
	go func() {
		r, e := execute(child, req)
		out <- struct {
			r   ToolResult
			err error
		}{r, e}
	}()
	interval := leaseTTL(cmd, s.leaseTTL) / 3
	if interval <= 0 || interval > time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case x := <-out:
			return x.r, x.err
		case <-ticker.C:
			nr, e := s.store.RenewChat(ctx, cmd.RequestID, cl.LeaseID, cl.Epoch, s.clock(), leaseTTL(cmd, s.leaseTTL))
			if e != nil {
				cancel()
				return ToolResult{}, e
			}
			*cl = nr
			nt, e := s.store.RenewToolExecution(ctx, cmd.RequestID, tl.ToolCallID, tl.LeaseID, tl.Epoch, s.clock(), leaseTTL(cmd, s.leaseTTL))
			if e != nil {
				cancel()
				return ToolResult{}, e
			}
			*tl = nt
		case <-ctx.Done():
			cancel()
			return ToolResult{}, ErrCanceled
		}
	}
}

func (s *Service) Chat(ctx context.Context, cmd ChatCommand) (ChatResponse, error) {
	if err := cmd.Validate(); err != nil {
		return ChatResponse{}, err
	}
	fp, _ := cmd.Fingerprint()
	now := s.clock()
	ttl := cmd.LeaseTTL
	if ttl <= 0 {
		ttl = s.leaseTTL
	}
	normExt := cmd.NormalizedExtensions()
	lease, err := s.store.ClaimChat(ctx, cmd.RequestID, cmd.ConversationID, fp, cmd.ProfileID, normExt, now, ttl)
	if err != nil {
		return ChatResponse{}, err
	}
	if lease.ProfileID != "" && lease.ProfileID != cmd.ProfileID {
		return ChatResponse{}, ErrConflict
	}
	if len(lease.Extensions) > 0 && digestSelections(lease.Extensions) != digestSelections(cmd.NormalizedExtensions()) {
		return ChatResponse{}, ErrConflict
	}
	if lease.Status == ClaimCompleted && lease.Response != nil {
		return *lease.Response, nil
	}
	if lease.Status == ClaimConflict {
		return ChatResponse{}, ErrConflict
	}
	if lease.Status == ClaimInFlight {
		return ChatResponse{}, ErrInFlight
	}
	if lease.Status == ClaimFailed {
		return ChatResponse{}, ErrChatFailed
	}
	if err := s.bindProfileSnapshot(ctx, cmd, &lease); err != nil {
		_ = s.store.ReleaseChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch)
		return ChatResponse{}, err
	}
	conv, err := s.loadOrCreate(ctx, cmd, lease)
	if err != nil {
		_ = s.store.ReleaseChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch)
		return ChatResponse{}, err
	}
	resp, err := s.run(ctx, cmd, conv, &lease, nil)
	if err != nil {
		_ = s.store.ReleaseChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch)
		return ChatResponse{}, err
	}
	return resp, nil
}

func (s *Service) loadOrCreate(ctx context.Context, cmd ChatCommand, lease ChatLease) (Conversation, error) {
	if cmd.ConversationID != "" {
		c, err := s.store.LoadConversation(ctx, cmd.ConversationID)
		if err != nil {
			return Conversation{}, err
		}
		if c.DeletedAt != nil {
			return Conversation{}, ErrDeleted
		}
		if cmd.ExpectedRevision != nil && c.Revision != *cmd.ExpectedRevision {
			return Conversation{}, ErrConflict
		}
		return c, nil
	}
	id := lease.ConversationID
	if !validUUID(id) {
		id = uuid.NewString()
	}
	now := s.clock()
	return Conversation{ID: id, Revision: 0, CreatedAt: now, UpdatedAt: now, Messages: nil}, nil
}

func (s *Service) run(ctx context.Context, cmd ChatCommand, conv Conversation, lease *ChatLease, emit func(StreamEvent)) (ChatResponse, error) {
	if emit != nil {
		emit(StreamEvent{Kind: EventStarted, RequestID: cmd.RequestID, ConversationID: conv.ID})
	}
	user := Message{ID: uuid.NewString(), Role: RoleUser, Content: cmd.Prompt, CreatedAt: nextMessageTime(conv, s.clock()), ModelProfileID: cmd.ProfileID}
	conv.Messages = append(conv.Messages, user)
	profile := lease.ProfileSnapshot.Profile()
	resolvedProfile := ResolvedProfile{ID: profile.ID, DisplayName: profile.DisplayName, Provider: string(profile.Provider), Model: profile.Model, SystemPrompt: profile.SystemPrompt}
	var err error
	exts, err := s.extensions.ResolveExtensions(ctx, ChatCommand{Extensions: cmd.NormalizedExtensions()}.Extensions)
	if err != nil {
		return ChatResponse{}, err
	}
	var relatedTasks []string
	var toolSummaries []string
	for round := 0; round < 8; round++ {
		if err := ctx.Err(); err != nil {
			return ChatResponse{}, ErrCanceled
		}
		if renewed, err := s.store.RenewChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch, s.clock(), leaseTTL(cmd, s.leaseTTL)); err != nil {
			return ChatResponse{}, err
		} else {
			*lease = renewed
		}
		var deltaEmit func(ModelDelta) error
		if emit != nil {
			deltaEmit = func(d ModelDelta) error {
				if emit == nil {
					return nil
				}
				if d.Text != "" {
					emit(StreamEvent{Kind: EventDelta, RequestID: cmd.RequestID, ConversationID: conv.ID, Text: d.Text})
				}
				return nil
			}
		}
		result, replayed, err := s.store.LoadModelStep(ctx, cmd.RequestID, lease.LeaseID, lease.Fingerprint, lease.Epoch, cmd.ProfileID, round)
		if err != nil {
			return ChatResponse{}, err
		}
		if !replayed {
			result, err = s.runModelHeartbeat(ctx, ModelRunRequest{Conversation: conv.Snapshot(), Profile: resolvedProfile, Snapshot: lease.ProfileSnapshot, Extensions: exts}, lease, cmd, deltaEmit)
			if err != nil {
				return ChatResponse{}, err
			}
		}
		if err := ctx.Err(); err != nil {
			return ChatResponse{}, ErrCanceled
		}
		if len(result.Message.ToolCalls) == 0 && len(result.ToolCalls) > 0 {
			result.Message.ToolCalls = append([]ToolCall(nil), result.ToolCalls...)
		}
		result.Message.ModelProfileID = cmd.ProfileID
		result.Message.RelatedTaskIDs = append([]string(nil), result.RelatedTaskIDs...)
		result.Message.ToolSummaries = append([]string(nil), result.ToolSummaries...)
		result.Message.RelatedTaskIDs = stableIDs(append(result.Message.RelatedTaskIDs, relatedTasks...))
		result.Message.ToolSummaries = stableStrings(append(result.Message.ToolSummaries, toolSummaries...))
		result.Message.CreatedAt = nextMessageTime(conv, result.Message.CreatedAt)
		if err := result.Message.Validate(); err != nil {
			return ChatResponse{}, fmt.Errorf("model message: %w", err)
		}
		if result.Done && len(result.Message.ToolCalls) > 0 {
			return ChatResponse{}, ErrInvalid
		}
		if !replayed {
			result.Message.RelatedTaskIDs = stableIDs(result.Message.RelatedTaskIDs)
			result.Message.ToolSummaries = stableStrings(result.Message.ToolSummaries)
			result.Message.ModelProfileID = cmd.ProfileID
			result.Message.ToolCalls = append([]ToolCall(nil), result.Message.ToolCalls...)
			result.RelatedTaskIDs = append([]string(nil), result.Message.RelatedTaskIDs...)
			result.ToolSummaries = append([]string(nil), result.Message.ToolSummaries...)
			result.ToolCalls = nil
			if err := s.store.RecordModelStep(ctx, cmd.RequestID, lease.LeaseID, lease.Fingerprint, lease.Epoch, cmd.ProfileID, round, result); err != nil {
				return ChatResponse{}, err
			}
		}
		conv.Messages = append(conv.Messages, result.Message)
		if len(result.Message.ToolCalls) == 0 {
			conv.Revision++
			conv.UpdatedAt = s.clock()
			if err := conv.ValidateForPersistence(); err != nil {
				return ChatResponse{}, fmt.Errorf("conversation: %w", err)
			}
			if err := ctx.Err(); err != nil {
				return ChatResponse{}, ErrCanceled
			}
			var allToolResults []ToolResult
			for _, persistedMessage := range conv.Messages {
				allToolResults = append(allToolResults, persistedMessage.ToolResults...)
			}
			resp := ChatResponse{RequestID: cmd.RequestID, ConversationID: conv.ID, Revision: conv.Revision, Message: result.Message, Done: true, ModelProfileID: cmd.ProfileID, RelatedTaskIDs: result.Message.RelatedTaskIDs, ToolSummaries: result.Message.ToolSummaries, ToolResults: allToolResults}
			if renewed, err := s.store.RenewChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch, s.clock(), leaseTTL(cmd, s.leaseTTL)); err != nil {
				return ChatResponse{}, err
			} else {
				*lease = renewed
			}
			if _, err := s.store.CommitChatCompletion(ctx, AtomicCompletion{RequestID: cmd.RequestID, LeaseID: lease.LeaseID, Epoch: lease.Epoch, Fingerprint: lease.Fingerprint, ExpectedRevision: conv.Revision - 1, Conversation: conv, Response: resp}); err != nil {
				return ChatResponse{}, err
			}
			if emit != nil {
				emit(StreamEvent{Kind: EventDone, RequestID: cmd.RequestID, ConversationID: conv.ID, Response: &resp})
			}
			return resp, nil
		}
		for _, call := range result.Message.ToolCalls {
			var tr ToolResult
			found := false
			argsDigest := digest(call.Arguments)
			extDigest := digestExtensions(exts)
			tlease, claimErr := s.store.ClaimToolExecution(ctx, cmd.RequestID, call.ID, argsDigest, extDigest, s.clock(), leaseTTL(cmd, s.leaseTTL))
			if claimErr != nil {
				return ChatResponse{}, claimErr
			}
			if tlease.Status == ToolClaimCompleted && tlease.Result != nil {
				if tlease.Result.CallID != call.ID {
					return ChatResponse{}, ErrConflict
				}
				tr = *tlease.Result
				found = true
				call.ExecutionID = tlease.ExecutionID
				for i := range conv.Messages[len(conv.Messages)-1].ToolCalls {
					if conv.Messages[len(conv.Messages)-1].ToolCalls[i].ID == call.ID {
						conv.Messages[len(conv.Messages)-1].ToolCalls[i].ExecutionID = call.ExecutionID
					}
				}
			}
			if tlease.Status == ToolClaimInFlight || tlease.Status == ToolClaimConflict {
				return ChatResponse{}, ErrConflict
			}
			if tlease.Status == ToolClaimUncertain || tlease.Status == ToolClaimDispatched {
				if err := s.store.TerminalizeToolUncertain(ctx, cmd.RequestID, call.ID, tlease.LeaseID, tlease.Epoch, lease.LeaseID, lease.Epoch, "tool_uncertain", "tool execution outcome is uncertain"); err != nil {
					return ChatResponse{}, err
				}
				return ChatResponse{}, ErrChatFailed
			}
			toolCompleted := tlease.Status == ToolClaimCompleted
			dispatched := false
			if !toolCompleted {
				defer func() {
					if !toolCompleted {
						if dispatched {
							_ = s.store.TerminalizeToolUncertain(context.Background(), cmd.RequestID, call.ID, tlease.LeaseID, tlease.Epoch, lease.LeaseID, lease.Epoch, "tool_uncertain", "tool execution outcome is uncertain")
						} else {
							_ = s.store.ReleaseToolExecution(context.Background(), cmd.RequestID, call.ID, tlease.LeaseID, tlease.Epoch)
						}
					}
				}()
			}
			if !found {
				var candidates []ResolvedExtension
				for _, e := range exts {
					allowed := len(e.Selection.AllowedTools) == 0
					for _, n := range e.Selection.AllowedTools {
						if n == call.Name {
							allowed = true
						}
					}
					if allowed && e.Execute != nil {
						candidates = append(candidates, e)
					}
				}
				if len(candidates) > 1 {
					return ChatResponse{}, ErrConflict
				}
				if len(candidates) == 1 {
					if renewed, renewErr := s.store.RenewChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch, s.clock(), leaseTTL(cmd, s.leaseTTL)); renewErr != nil {
						return ChatResponse{}, renewErr
					} else {
						*lease = renewed
					}
					if renewed, renewErr := s.store.RenewToolExecution(ctx, cmd.RequestID, call.ID, tlease.LeaseID, tlease.Epoch, s.clock(), leaseTTL(cmd, s.leaseTTL)); renewErr != nil {
						return ChatResponse{}, renewErr
					} else {
						tlease = renewed
					}
					call.ExecutionID = tlease.ExecutionID
					for i := range conv.Messages[len(conv.Messages)-1].ToolCalls {
						if conv.Messages[len(conv.Messages)-1].ToolCalls[i].ID == call.ID {
							conv.Messages[len(conv.Messages)-1].ToolCalls[i].ExecutionID = call.ExecutionID
						}
					}
					if err := s.store.MarkToolDispatched(ctx, cmd.RequestID, call.ID, tlease.LeaseID, tlease.Epoch); err != nil {
						return ChatResponse{}, err
					}
					dispatched = true
					rq := ToolExecutionRequest{RequestID: cmd.RequestID, ToolCallID: call.ID, ExecutionID: call.ExecutionID, ArgsDigest: argsDigest, ExtensionDigest: extDigest, Call: call}
					tr, err = s.executeToolHeartbeat(ctx, rq, &tlease, lease, cmd, candidates[0].Execute)
					found = true
				}
			}
			if !found {
				err = errors.New("tool unavailable")
			}
			if err != nil {
				return ChatResponse{}, err
			}
			if tr.CallID == "" {
				tr.CallID = call.ID
			}
			tr.ToolName = call.Name
			if tr.CallID != call.ID {
				return ChatResponse{}, ErrConflict
			}
			if tr.Validate() != nil {
				return ChatResponse{}, ErrInvalid
			}
			if tlease.Status != ToolClaimCompleted {
				if tlease.Status == ToolClaimConflict || tlease.Status == ToolClaimInFlight {
					return ChatResponse{}, ErrConflict
				}
				if renewed, renewErr := s.store.RenewToolExecution(ctx, cmd.RequestID, call.ID, tlease.LeaseID, tlease.Epoch, s.clock(), leaseTTL(cmd, s.leaseTTL)); renewErr != nil {
					return ChatResponse{}, renewErr
				} else {
					tlease = renewed
				}
				if _, err := s.store.CompleteToolExecution(ctx, ToolCompletion{RequestID: cmd.RequestID, ToolCallID: call.ID, LeaseID: tlease.LeaseID, Epoch: tlease.Epoch, ArgsDigest: argsDigest, ExtensionDigest: extDigest, Result: tr}); err != nil {
					return ChatResponse{}, err
				}
				toolCompleted = true
			}
			if emit != nil {
				cc := call
				emit(StreamEvent{Kind: EventToolCall, RequestID: cmd.RequestID, ConversationID: conv.ID, ToolCall: &cc})
			}
			tm := Message{ID: uuid.NewString(), Role: RoleTool, ToolResults: []ToolResult{tr}, CreatedAt: nextMessageTime(conv, s.clock()), ModelProfileID: cmd.ProfileID}
			tm.RelatedTaskIDs = stableIDs(tr.RelatedTaskIDs)
			if tr.Summary != "" {
				tm.ToolSummaries = []string{tr.Summary}
			}
			relatedTasks = append(relatedTasks, tr.RelatedTaskIDs...)
			if tr.Summary != "" {
				toolSummaries = append(toolSummaries, tr.Summary)
			}
			conv.Messages = append(conv.Messages, tm)
			if emit != nil {
				tt := tr
				emit(StreamEvent{Kind: EventToolResult, RequestID: cmd.RequestID, ConversationID: conv.ID, ToolResult: &tt})
			}
		}
	}
	return ChatResponse{}, errors.New("tool exchange exceeded limit")
}

func (s *Service) StreamChat(ctx context.Context, cmd ChatCommand) (<-chan StreamEvent, error) {
	if err := cmd.Validate(); err != nil {
		return nil, err
	}
	ch := make(chan StreamEvent, 16)
	go func() {
		defer close(ch)
		send := func(e StreamEvent) bool {
			select {
			case ch <- e:
				return true
			case <-ctx.Done():
				return false
			}
		}
		fp, _ := cmd.Fingerprint()
		now := s.clock()
		ttl := cmd.LeaseTTL
		if ttl <= 0 {
			ttl = s.leaseTTL
		}
		lease, err := s.store.ClaimChat(ctx, cmd.RequestID, cmd.ConversationID, fp, cmd.ProfileID, cmd.NormalizedExtensions(), now, ttl)
		if err != nil {
			send(safeStreamError(cmd.RequestID, "claim_failed"))
			return
		}
		if (lease.ProfileID != "" && lease.ProfileID != cmd.ProfileID) || (len(lease.Extensions) > 0 && digestSelections(lease.Extensions) != digestSelections(cmd.NormalizedExtensions())) {
			send(safeStreamError(cmd.RequestID, "conflict"))
			return
		}
		if lease.Status == ClaimCompleted && lease.Response != nil {
			r := *lease.Response
			send(StreamEvent{Kind: EventDone, RequestID: r.RequestID, ConversationID: r.ConversationID, Response: &r})
			return
		}
		if lease.Status == ClaimConflict || lease.Status == ClaimInFlight {
			e := ErrConflict
			if lease.Status == ClaimInFlight {
				e = ErrInFlight
			}
			code := "conflict"
			if e == ErrInFlight {
				code = "in_flight"
			}
			send(safeStreamError(cmd.RequestID, code))
			return
		}
		if lease.Status == ClaimFailed {
			send(safeStreamError(cmd.RequestID, lease.FailureCode))
			return
		}
		if err := s.bindProfileSnapshot(ctx, cmd, &lease); err != nil {
			_ = s.store.ReleaseChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch)
			send(safeStreamError(cmd.RequestID, "profile_snapshot_failed"))
			return
		}
		conv, err := s.loadOrCreate(ctx, cmd, lease)
		if err == nil {
			_, err = s.run(ctx, cmd, conv, &lease, func(e StreamEvent) {
				select {
				case ch <- e:
				case <-ctx.Done():
				}
			})
		}
		if err != nil {
			_ = s.store.ReleaseChat(ctx, cmd.RequestID, lease.LeaseID, lease.Epoch)
			if ctx.Err() != nil {
				err = ErrCanceled
			}
			e := safeStreamError(cmd.RequestID, "execution_failed")
			e.ConversationID = conv.ID
			send(e)
		}
	}()
	return ch, nil
}

func safeStreamError(requestID, code string) StreamEvent {
	return StreamEvent{Kind: EventError, RequestID: requestID, ErrCode: code, ErrSummary: "chat request failed"}
}

func (s *Service) DeleteConversation(ctx context.Context, id string, expected uint64, callerKey ...string) error {
	if !validUUID(id) {
		return ErrInvalid
	}
	rid := ""
	if len(callerKey) > 0 {
		rid = callerKey[0]
	} else {
		rid = uuid.NewSHA1(uuid.NameSpaceOID, []byte("delete:"+id+fmt.Sprint(expected))).String()
	}
	cmd := DeleteConversationCommand{RequestID: rid, ConversationID: id, ExpectedRevision: expected, Fingerprint: digest(fmt.Sprintf("%s:%d", id, expected))}
	if err := cmd.Validate(); err != nil {
		return err
	}
	_, err := s.store.DeleteConversationMutation(ctx, cmd)
	return err
}

func (s *Service) CreateConversation(ctx context.Context, conversation Conversation, idempotencyKey string) (Conversation, error) {
	if !validUUID(conversation.ID) || conversation.Revision == 0 {
		return Conversation{}, ErrInvalid
	}
	conversation.CreatedAt = time.Time{}
	conversation.UpdatedAt = time.Time{}
	cmd := CreateConversationCommand{RequestID: idempotencyKey, Conversation: conversation, Fingerprint: digestConversation(conversation)}
	if err := cmd.Validate(); err != nil {
		return Conversation{}, err
	}
	r, err := s.store.CreateConversationMutation(ctx, cmd)
	if err != nil {
		return Conversation{}, err
	}
	return r.Conversation, nil
}
func digestConversation(c Conversation) string {
	canonical := struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Revision uint64 `json:"revision"`
	}{c.ID, c.Title, c.Revision}
	b, _ := json.Marshal(canonical)
	return digest(string(b))
}
func (s *Service) GetConversation(ctx context.Context, id string) (Conversation, error) {
	if !validUUID(id) {
		return Conversation{}, ErrInvalid
	}
	return s.store.LoadConversation(ctx, id)
}
func (s *Service) ListConversations(ctx context.Context, cursor string, limit int) ([]Conversation, string, error) {
	if limit <= 0 || limit > 1000 {
		return nil, "", ErrInvalid
	}
	return s.store.ListConversations(ctx, cursor, limit)
}

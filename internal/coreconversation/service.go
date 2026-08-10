package coreconversation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type Service struct {
	store           Store
	models          ModelRunner
	extensions      ExtensionResolver
	intrinsics      IntrinsicResolver
	memoryRecall    MemoryRecallResolver
	snapshots       SnapshotProfileResolver
	now             func() time.Time
	leaseTTL        time.Duration
	turns           TurnStore
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	workers         sync.WaitGroup
	cancelMu        sync.Mutex
	cancelSignals   map[string]chan struct{}
	runtimeMu       sync.Mutex
	runtime         map[string]*turnRuntime
}

// MemoryRecallResolver supplies a bounded, already-delimited model-only
// context for a new conversation. Implementations must never return raw
// credentials, source metadata, or unbounded content.
type MemoryRecallResolver interface {
	RecallMemory(context.Context, string) (string, error)
}

// SetExtensionResolver wires the production resolver after composition has
// validated the runner/confirmation graph. Basic conversation remains usable
// when the graph is intentionally disabled.
func (s *Service) SetExtensionResolver(resolver ExtensionResolver) {
	if s == nil {
		return
	}
	if resolver == nil {
		s.extensions = noopExtensions{}
		return
	}
	s.extensions = resolver
}

// SetIntrinsicResolver wires Core-owned tools after their transactional
// stores and trusted context resolvers are ready. A nil resolver removes the
// intrinsic catalog; production readiness is responsible for failing closed
// when Cloud Worker is configured but this graph is incomplete.
func (s *Service) SetIntrinsicResolver(resolver IntrinsicResolver) {
	if s == nil {
		return
	}
	s.intrinsics = resolver
}

// SetMemoryRecallResolver wires the optional Agent-owned long-term-memory
// search after Knowledge composition has passed its readiness checks.
func (s *Service) SetMemoryRecallResolver(resolver MemoryRecallResolver) {
	if s == nil {
		return
	}
	s.memoryRecall = resolver
}

type turnRuntime struct {
	cancel chan struct{}
	wake   chan struct{}
	done   chan struct{}
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
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	s := &Service{store: store, models: models, extensions: extensions, snapshots: profiles, now: func() time.Time { return time.Now().UTC() }, leaseTTL: 2 * time.Minute, lifecycleCtx: lifecycleCtx, lifecycleCancel: lifecycleCancel, cancelSignals: map[string]chan struct{}{}, runtime: map[string]*turnRuntime{}}
	if turns, ok := store.(TurnStore); ok {
		s.turns = turns
	}
	return s, nil
}

func NewOrchestrator(store Store, models ModelRunner, extensions ExtensionResolver, profiles SnapshotProfileResolver) (*Orchestrator, error) {
	return NewService(store, models, extensions, profiles)
}

type noopExtensions struct{}

func (noopExtensions) ResolveExtensions(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
	return nil, nil
}

func snapshotForResolved(ext ResolvedExtension) ExtensionExecutionSnapshot {
	snap := ext.Snapshot
	if snap.Selection.ID == "" {
		snap.Selection = ext.Selection
	}
	if snap.ContentDigest == "" {
		snap.ContentDigest = snap.Selection.Digest
	}
	if snap.VersionID == "" {
		snap.VersionID = snap.Selection.Version
	}
	if len(snap.ToolNames) == 0 {
		snap.ToolNames = append([]string(nil), snap.Selection.AllowedTools...)
	}
	return snap
}

func snapshotSelections(in []ExtensionExecutionSnapshot) []ExtensionSelection {
	out := make([]ExtensionSelection, 0, len(in))
	for _, s := range in {
		out = append(out, s.Selection)
	}
	return out
}

func validateUniqueSnapshotTools(in []ExtensionExecutionSnapshot) error {
	seen := map[string]struct{}{}
	for _, ext := range in {
		for _, name := range ext.ToolNames {
			if _, exists := seen[name]; exists {
				return ErrConflict
			}
			seen[name] = struct{}{}
		}
	}
	return nil
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
func stableReferences(in []Reference) []Reference {
	seen := make(map[string]struct{}, len(in))
	out := make([]Reference, 0, len(in))
	for _, value := range in {
		key := referenceKey(value)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}
func (s *Service) clock() time.Time { return s.now().UTC() }
func nextMessageTime(c Conversation, t time.Time) time.Time {
	// PostgreSQL timestamptz persists microseconds. Normalize before comparing
	// so strict ordering cannot collapse to equal timestamps after a DB round trip.
	t = t.UTC().Truncate(time.Microsecond)
	if len(c.Messages) > 0 {
		previous := c.Messages[len(c.Messages)-1].CreatedAt.UTC().Truncate(time.Microsecond)
		if !t.After(previous) {
			return previous.Add(time.Microsecond)
		}
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
		if err := validateProfilePins(lease.ProfileSnapshot, cmd.ProfileID, cmd.ExpectedProfileRevision, cmd.ExpectedCredentialVersion); err != nil {
			return err
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
	if err := validateProfilePins(snap, cmd.ProfileID, cmd.ExpectedProfileRevision, cmd.ExpectedCredentialVersion); err != nil {
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
	// Extensions are durable-turn-only. Keeping unary Chat extension-free
	// prevents a caller from creating an execution history without the durable
	// confirmation/recovery ledger.
	if len(cmd.Extensions) > 0 {
		return ChatResponse{}, ErrExtensionsUnsupported
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
	if lease.ProfileSnapshotDigest != "" {
		if err := validateProfilePins(lease.ProfileSnapshot, cmd.ProfileID, cmd.ExpectedProfileRevision, cmd.ExpectedCredentialVersion); err != nil {
			return ChatResponse{}, err
		}
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
	if err := validateProfilePins(lease.ProfileSnapshot, cmd.ProfileID, cmd.ExpectedProfileRevision, cmd.ExpectedCredentialVersion); err != nil {
		return ChatResponse{}, err
	}
	if emit != nil {
		emit(StreamEvent{Kind: EventStarted, RequestID: cmd.RequestID, ConversationID: conv.ID})
	}
	persistedMessageCount := len(conv.Messages)
	var recalledMemory string
	memoryRecallResolved := false
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
	var relatedPlans []string
	var references []Reference
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
			if persistedMessageCount == 0 && !memoryRecallResolved && s.memoryRecall != nil {
				recallCtx, recallCancel := context.WithTimeout(ctx, 15*time.Second)
				recalledMemory, err = s.memoryRecall.RecallMemory(recallCtx, cmd.Prompt)
				recallCancel()
				if err != nil {
					return ChatResponse{}, ErrMemoryRecallUnavailable
				}
				memoryRecallResolved = true
			}
			modelConversation, modelContextErr := modelConversationWithRecalledMemory(conv, persistedMessageCount, recalledMemory, cmd.ProfileID, cmd.RequestID)
			if modelContextErr != nil {
				return ChatResponse{}, modelContextErr
			}
			result, err = s.runModelHeartbeat(ctx, ModelRunRequest{Conversation: modelConversation, Profile: resolvedProfile, Snapshot: lease.ProfileSnapshot, Extensions: exts}, lease, cmd, deltaEmit)
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
		result.Message.RelatedPlanIDs = append([]string(nil), result.RelatedPlanIDs...)
		result.Message.References = cloneReferences(result.References)
		result.Message.ToolSummaries = append([]string(nil), result.ToolSummaries...)
		result.Message.RelatedTaskIDs = stableIDs(append(result.Message.RelatedTaskIDs, relatedTasks...))
		result.Message.RelatedPlanIDs = stableIDs(append(result.Message.RelatedPlanIDs, relatedPlans...))
		result.Message.References = stableReferences(append(result.Message.References, references...))
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
			result.Message.RelatedPlanIDs = stableIDs(result.Message.RelatedPlanIDs)
			result.Message.References = stableReferences(result.Message.References)
			result.Message.ToolSummaries = stableStrings(result.Message.ToolSummaries)
			result.Message.ModelProfileID = cmd.ProfileID
			result.Message.ToolCalls = append([]ToolCall(nil), result.Message.ToolCalls...)
			result.RelatedTaskIDs = append([]string(nil), result.Message.RelatedTaskIDs...)
			result.RelatedPlanIDs = append([]string(nil), result.Message.RelatedPlanIDs...)
			result.References = cloneReferences(result.Message.References)
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
			resp := ChatResponse{RequestID: cmd.RequestID, ConversationID: conv.ID, Revision: conv.Revision, Message: result.Message, Done: true, ModelProfileID: cmd.ProfileID, RelatedTaskIDs: result.Message.RelatedTaskIDs, RelatedPlanIDs: result.Message.RelatedPlanIDs, References: cloneReferences(result.Message.References), ToolSummaries: result.Message.ToolSummaries, ToolResults: allToolResults}
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
					tlease.Status = ToolClaimDispatched
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
			tm.RelatedPlanIDs = stableIDs(tr.RelatedPlanIDs)
			tm.References = stableReferences(tr.References)
			if tr.Summary != "" {
				tm.ToolSummaries = []string{tr.Summary}
			}
			relatedTasks = append(relatedTasks, tr.RelatedTaskIDs...)
			relatedPlans = append(relatedPlans, tr.RelatedPlanIDs...)
			references = append(references, tr.References...)
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
	if len(cmd.Extensions) > 0 {
		return nil, ErrExtensionsUnsupported
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
		if lease.ProfileSnapshotDigest != "" {
			if pinErr := validateProfilePins(lease.ProfileSnapshot, cmd.ProfileID, cmd.ExpectedProfileRevision, cmd.ExpectedCredentialVersion); pinErr != nil {
				send(safeStreamError(cmd.RequestID, "conflict"))
				return
			}
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
	_, err := s.DeleteConversationReceipt(ctx, id, expected, callerKey...)
	return err
}

// DeleteConversationReceipt returns the durable mutation snapshot together
// with its exact replay marker for capability adapters.
func (s *Service) DeleteConversationReceipt(ctx context.Context, id string, expected uint64, callerKey ...string) (ConversationMutationResponse, error) {
	if !validUUID(id) {
		return ConversationMutationResponse{}, ErrInvalid
	}
	rid := ""
	if len(callerKey) > 0 {
		rid = callerKey[0]
	} else {
		rid = uuid.NewSHA1(uuid.NameSpaceOID, []byte("delete:"+id+fmt.Sprint(expected))).String()
	}
	cmd := DeleteConversationCommand{RequestID: rid, ConversationID: id, ExpectedRevision: expected, Fingerprint: digest(fmt.Sprintf("%s:%d", id, expected))}
	if err := cmd.Validate(); err != nil {
		return ConversationMutationResponse{}, err
	}
	store, ok := s.store.(ConversationMutationStore)
	if !ok {
		return ConversationMutationResponse{}, ErrConflict
	}
	return store.DeleteConversationMutation(ctx, cmd)
}

func (s *Service) CreateConversation(ctx context.Context, conversation Conversation, idempotencyKey string) (Conversation, error) {
	receipt, err := s.CreateConversationReceipt(ctx, conversation, idempotencyKey)
	return receipt.Conversation, err
}

// CreateConversationReceipt returns the durable mutation snapshot together
// with its exact replay marker for capability adapters.
func (s *Service) CreateConversationReceipt(ctx context.Context, conversation Conversation, idempotencyKey string) (ConversationMutationResponse, error) {
	if !validUUID(conversation.ID) || conversation.Revision == 0 {
		return ConversationMutationResponse{}, ErrInvalid
	}
	conversation.CreatedAt = time.Time{}
	conversation.UpdatedAt = time.Time{}
	cmd := CreateConversationCommand{RequestID: idempotencyKey, Conversation: conversation, Fingerprint: digestConversation(conversation)}
	if err := cmd.Validate(); err != nil {
		return ConversationMutationResponse{}, err
	}
	store, ok := s.store.(ConversationMutationStore)
	if !ok {
		return ConversationMutationResponse{}, ErrConflict
	}
	return store.CreateConversationMutation(ctx, cmd)
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

// RenameConversation applies a revision-bound, idempotent title mutation. A
// production store should implement ConversationRenameStore so the replay
// record and row update share one transaction.
func (s *Service) RenameConversation(ctx context.Context, id, title string, expected uint64, callerKey ...string) (Conversation, error) {
	receipt, err := s.RenameConversationReceipt(ctx, id, title, expected, callerKey...)
	return receipt.Conversation, err
}

// RenameConversationReceipt returns the durable mutation snapshot together
// with its exact replay marker for capability adapters.
func (s *Service) RenameConversationReceipt(ctx context.Context, id, title string, expected uint64, callerKey ...string) (ConversationMutationResponse, error) {
	if !validUUID(id) || expected == 0 || len(title) > 512 || !utf8.ValidString(title) {
		return ConversationMutationResponse{}, ErrInvalid
	}
	key := ""
	if len(callerKey) > 0 {
		key = callerKey[0]
	}
	if key == "" {
		key = uuid.NewSHA1(uuid.NameSpaceOID, []byte("rename:"+id+fmt.Sprint(expected)+":"+title)).String()
	}
	if !validUUID(key) {
		return ConversationMutationResponse{}, ErrInvalid
	}
	if renamer, ok := s.store.(ConversationRenameStore); ok {
		result, err := renamer.RenameConversationMutation(ctx, id, title, expected, key)
		return result, err
	}
	conversation, err := s.store.LoadConversation(ctx, id)
	if err != nil {
		return ConversationMutationResponse{}, err
	}
	if conversation.DeletedAt != nil || conversation.Revision != expected {
		return ConversationMutationResponse{}, ErrConflict
	}
	conversation.Title = title
	conversation.Revision++
	conversation.UpdatedAt = s.clock()
	if err := s.store.SaveConversation(ctx, conversation, expected); err != nil {
		return ConversationMutationResponse{}, err
	}
	return ConversationMutationResponse{Conversation: conversation}, nil
}

// ListTurns lists durable turn metadata for one conversation. Message bodies
// and event history remain separate Watch/Get concerns.
func (s *Service) ListTurns(ctx context.Context, conversationID, cursor string, limit int) ([]Turn, string, error) {
	if s == nil || s.turns == nil || !validUUID(conversationID) || limit <= 0 || limit > 1000 {
		return nil, "", ErrInvalid
	}
	lister, ok := s.turns.(TurnLister)
	if !ok {
		return nil, "", ErrInvalid
	}
	return lister.ListTurns(ctx, conversationID, cursor, limit)
}

func (s *Service) BeginTurnAttachmentUpload(ctx context.Context, command BeginTurnAttachmentUploadCommand) (TurnAttachmentUpload, error) {
	if s == nil {
		return TurnAttachmentUpload{}, ErrInvalid
	}
	store, ok := s.turns.(TurnAttachmentUploadStore)
	if !ok {
		return TurnAttachmentUpload{}, ErrInvalid
	}
	return store.BeginTurnAttachmentUpload(ctx, command)
}

func (s *Service) AppendTurnAttachmentUpload(ctx context.Context, command AppendTurnAttachmentUploadCommand) (TurnAttachmentUpload, error) {
	if s == nil {
		return TurnAttachmentUpload{}, ErrInvalid
	}
	store, ok := s.turns.(TurnAttachmentUploadStore)
	if !ok {
		return TurnAttachmentUpload{}, ErrInvalid
	}
	return store.AppendTurnAttachmentUpload(ctx, command)
}

func (s *Service) CommitTurnAttachmentUpload(ctx context.Context, command CommitTurnAttachmentUploadCommand) (TurnAttachment, error) {
	if s == nil {
		return TurnAttachment{}, ErrInvalid
	}
	store, ok := s.turns.(TurnAttachmentUploadStore)
	if !ok {
		return TurnAttachment{}, ErrInvalid
	}
	return store.CommitTurnAttachmentUpload(ctx, command)
}

// StartTurn durably accepts a prompt before starting any model work. The
// execution goroutine intentionally uses a background context; disconnecting
// the initiating RPC therefore cannot abandon an accepted turn.
func (s *Service) StartTurn(ctx context.Context, cmd TurnStartCommand) (Turn, error) {
	if s.turns == nil {
		return Turn{}, ErrInvalid
	}
	if !validUUID(cmd.RequestID) || !validUUID(cmd.ProfileID) || (cmd.ConversationID != "" && !validUUID(cmd.ConversationID)) || cmd.ExpectedProfileRevision <= 0 || cmd.ExpectedCredentialVersion <= 0 {
		return Turn{}, ErrInvalid
	}
	if err := validateText(cmd.Prompt, MaxContentBytes); err != nil {
		return Turn{}, err
	}
	if cmd.ConversationID == "" {
		// Derive a stable private conversation identity from the request UUID so
		// an idempotent retry binds the same conversation before execution.
		cmd.ConversationID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation:"+cmd.RequestID)).String()
	}
	if cmd.TurnID == "" {
		cmd.TurnID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn:"+cmd.RequestID)).String()
	}
	cmd.AcceptedAttachmentIDs = append([]string(nil), cmd.AcceptedAttachmentIDs...)
	if lookup, ok := s.turns.(TurnRequestLookup); ok {
		if existing, lookupErr := lookup.GetTurnByRequestID(ctx, cmd.RequestID); lookupErr == nil {
			// Replays are checked against the immutable snapshot already bound to
			// the request. Never resolve the current profile for this path.
			check := cmd
			check.ProfileSnapshot = existing.ProfileSnapshot
			check.ExtensionSnapshots = append([]ExtensionExecutionSnapshot(nil), existing.ExtensionSnapshots...)
			check.AttachmentSources = append([]TurnAttachment(nil), existing.AttachmentSources...)
			if len(check.Extensions) == 0 {
				check.Extensions = snapshotSelections(existing.ExtensionSnapshots)
			}
			if err := check.Validate(); err != nil {
				return Turn{}, err
			}
			if existing.RequestFingerprint != check.Fingerprint() {
				return Turn{}, ErrConflict
			}
			if existing.State == TurnAccepted || existing.State == TurnRunning {
				s.startTurnSupervisor(existing.ID, context.WithoutCancel(ctx))
			}
			return existing, nil
		} else if !errors.Is(lookupErr, ErrConflict) {
			return Turn{}, lookupErr
		}
	}
	if cmd.ProfileSnapshot.ProfileID == "" {
		if s.snapshots == nil {
			return Turn{}, ErrInvalid
		}
		snapshot, err := s.snapshots.ResolveProfileSnapshot(ctx, cmd.ProfileID)
		if err != nil {
			return Turn{}, err
		}
		cmd.ProfileSnapshot = snapshot
	}
	if err := validateProfilePins(cmd.ProfileSnapshot, cmd.ProfileID, cmd.ExpectedProfileRevision, cmd.ExpectedCredentialVersion); err != nil {
		return Turn{}, err
	}
	if len(cmd.ExtensionSnapshots) == 0 {
		if s.extensions == nil {
			return Turn{}, ErrInvalid
		}
		resolved, err := s.extensions.ResolveExtensions(ctx, append([]ExtensionSelection(nil), cmd.Extensions...))
		if err != nil {
			return Turn{}, err
		}
		for _, selection := range cmd.Extensions {
			matched := false
			for _, candidate := range resolved {
				if candidate.Selection.ID == selection.ID && candidate.Selection.Version == selection.Version && candidate.Selection.Digest == selection.Digest {
					matched = true
					break
				}
			}
			if !matched {
				return Turn{}, ErrConflict
			}
		}
		cmd.ExtensionSnapshots = make([]ExtensionExecutionSnapshot, 0, len(resolved))
		for _, ext := range resolved {
			snap := snapshotForResolved(ext)
			if snap.Selection.ID == "" || snap.Selection.ID != ext.Selection.ID || snap.Selection.Version != ext.Selection.Version || snap.Selection.Digest != ext.Selection.Digest {
				return Turn{}, ErrConflict
			}
			cmd.ExtensionSnapshots = append(cmd.ExtensionSnapshots, snap)
		}
		if err := validateUniqueSnapshotTools(cmd.ExtensionSnapshots); err != nil {
			return Turn{}, err
		}
	}
	if err := cmd.Validate(); err != nil {
		return Turn{}, err
	}
	turn, err := s.turns.StartTurn(ctx, cmd)
	if err != nil {
		return Turn{}, err
	}
	if turn.State == TurnAccepted || turn.State == TurnRunning {
		s.startTurnSupervisor(turn.ID, context.WithoutCancel(ctx))
	}
	return turn, nil
}

func (s *Service) GetTurn(ctx context.Context, id string) (Turn, error) {
	if s.turns == nil || !validUUID(id) {
		return Turn{}, ErrInvalid
	}
	return s.turns.GetTurn(ctx, id)
}

// GetTurnByRequestID resolves the durable turn identity used by an external
// adapter (for example the Native Voice runner).  Request ids are not turn
// ids, so adapters must not guess or hash the storage primary key.
func (s *Service) GetTurnByRequestID(ctx context.Context, requestID string) (Turn, error) {
	if s.turns == nil || !validUUID(requestID) {
		return Turn{}, ErrInvalid
	}
	lookup, ok := s.turns.(TurnRequestLookup)
	if !ok {
		return Turn{}, ErrInvalid
	}
	return lookup.GetTurnByRequestID(ctx, requestID)
}

// RecoverTurns is called after process startup. It only resumes accepted or
// leased turns and never creates a new request identity.
func (s *Service) RecoverTurns(ctx context.Context) error {
	if s.turns == nil {
		return ErrInvalid
	}
	turns, err := s.turns.ListRecoverableTurns(ctx)
	if err != nil {
		return err
	}
	for _, turn := range turns {
		s.startTurnSupervisor(turn.ID, ctx)
	}
	return nil
}

func (s *Service) CancelTurn(ctx context.Context, cmd TurnCancelCommand) (Turn, error) {
	if s.turns == nil || !validUUID(cmd.TurnID) || !validUUID(cmd.RequestID) || cmd.ExpectedRevision == 0 {
		return Turn{}, ErrInvalid
	}
	turn, err := s.turns.RequestTurnCancel(ctx, cmd)
	if err == nil {
		s.runtimeMu.Lock()
		if runtime := s.runtime[cmd.TurnID]; runtime != nil {
			select {
			case runtime.wake <- struct{}{}:
			default:
			}
			select {
			case <-runtime.cancel:
			default:
				close(runtime.cancel)
			}
		}
		s.runtimeMu.Unlock()
		s.cancelMu.Lock()
		if signal := s.cancelSignals[cmd.TurnID]; signal != nil {
			select {
			case <-signal:
			default:
				close(signal)
			}
		}
		s.cancelMu.Unlock()
	}
	if err == nil && turn.State == TurnAccepted {
		s.startTurnSupervisor(turn.ID, nil)
	}
	if err == nil && turn.State == TurnRunning {
		s.startTurnSupervisor(turn.ID, nil)
	}
	return turn, err
}

// SteerTurn appends user guidance to the current durable turn. The store
// invalidates the active provider lease before this method interrupts the
// in-flight model context, so a late result from the superseded generation
// cannot commit or dispatch a tool.
func (s *Service) SteerTurn(ctx context.Context, cmd TurnSteerCommand) (Turn, error) {
	if s.turns == nil || !validUUID(cmd.TurnID) || !validUUID(cmd.RequestID) || cmd.ExpectedRevision == 0 {
		return Turn{}, ErrInvalid
	}
	cmd.Instruction = strings.TrimSpace(cmd.Instruction)
	if err := validateText(cmd.Instruction, MaxContentBytes); err != nil {
		return Turn{}, err
	}
	store, ok := s.turns.(TurnSteerStore)
	if !ok {
		return Turn{}, ErrInvalid
	}
	turn, applied, err := store.RequestTurnSteer(ctx, cmd)
	if err != nil {
		return Turn{}, err
	}
	if !applied {
		return turn, nil
	}
	s.cancelMu.Lock()
	if signal := s.cancelSignals[cmd.TurnID]; signal != nil {
		select {
		case <-signal:
		default:
			close(signal)
		}
	}
	s.cancelMu.Unlock()
	s.runtimeMu.Lock()
	if runtime := s.runtime[cmd.TurnID]; runtime != nil {
		select {
		case runtime.wake <- struct{}{}:
		default:
		}
	}
	s.runtimeMu.Unlock()
	if turn.State == TurnAccepted || turn.State == TurnRunning {
		s.startTurnSupervisor(turn.ID, context.WithoutCancel(ctx))
	}
	return turn, nil
}

func (s *Service) runTurnSupervisor(ctx context.Context, id string) {
	backoff := time.Second
	var wake <-chan struct{}
	s.runtimeMu.Lock()
	if runtime := s.runtime[id]; runtime != nil {
		wake = runtime.wake
	}
	s.runtimeMu.Unlock()
	for {
		if ctx.Err() != nil {
			return
		}
		turn, err := s.turns.GetTurn(ctx, id)
		if err != nil {
			if errors.Is(err, ErrConflict) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrDeleted) {
				return
			}
			if !waitTurnSupervisor(ctx, backoff, wake) {
				return
			}
			backoff = nextTurnSupervisorBackoff(backoff)
			continue
		}
		if turn.State == TurnCompleted || turn.State == TurnCanceled || turn.State == TurnFailed {
			return
		}
		if turn.State == TurnWaitingConfirmation {
			if recovery, ok := s.turns.(ConversationToolRecoveryStore); ok {
				attempt, observeErr := recovery.ObserveConversationTool(ctx, id)
				if observeErr == nil && (attempt.State == "completed" || attempt.State == "denied" || attempt.State == "canceled") {
					_ = recovery.ResumeConversationTurn(ctx, id)
					continue
				}
			}
			if !waitTurnSupervisor(ctx, backoff, wake) {
				return
			}
			backoff = nextTurnSupervisorBackoff(backoff)
			continue
		}
		if turn.CancelRequested {
			if cancelStore, ok := s.turns.(TurnCancelStore); ok {
				if _, cancelErr := cancelStore.MarkTurnCanceledRequested(ctx, id); cancelErr == nil {
					return
				}
			}
			if !waitTurnSupervisor(ctx, backoff, wake) {
				return
			}
			backoff = nextTurnSupervisorBackoff(backoff)
			continue
		}
		if turn.DispatchState == "uncertain" {
			if uncertainStore, ok := s.turns.(TurnUncertainStore); ok {
				if _, uncertainErr := uncertainStore.FailTurnUncertain(ctx, id, "provider_uncertain", "model dispatch outcome is unknown"); uncertainErr == nil {
					return
				}
			}
			if !waitTurnSupervisor(ctx, backoff, wake) {
				return
			}
			backoff = nextTurnSupervisorBackoff(backoff)
			continue
		}
		s.executeTurn(ctx, id)
		if !waitTurnSupervisor(ctx, backoff, wake) {
			return
		}
		backoff = nextTurnSupervisorBackoff(backoff)
	}
}

func nextTurnSupervisorBackoff(backoff time.Duration) time.Duration {
	if backoff < 10*time.Second {
		backoff *= 2
		if backoff > 10*time.Second {
			return 10 * time.Second
		}
	}
	return backoff
}

func waitTurnSupervisor(ctx context.Context, backoff time.Duration, wake <-chan struct{}) bool {
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-wake:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Service) startTurnSupervisor(id string, parent context.Context) {
	s.runtimeMu.Lock()
	if existing := s.runtime[id]; existing != nil {
		select {
		case existing.wake <- struct{}{}:
		default:
		}
		s.runtimeMu.Unlock()
		return
	}
	runtime := &turnRuntime{cancel: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{})}
	s.runtime[id] = runtime
	s.runtimeMu.Unlock()
	if parent == nil {
		parent = s.lifecycleCtx
	}
	ctx, cancel := context.WithCancel(parent)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		defer cancel()
		defer close(runtime.done)
		defer func() { s.runtimeMu.Lock(); delete(s.runtime, id); s.runtimeMu.Unlock() }()
		stop := make(chan struct{})
		go func() {
			select {
			case <-s.lifecycleCtx.Done():
				cancel()
			case <-stop:
			}
		}()
		s.runTurnSupervisor(ctx, id)
		close(stop)
	}()
}

// Close fences all turn workers before the caller closes the database pool.
func (s *Service) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *Service) CloseContext(ctx context.Context) error {
	if s.lifecycleCancel != nil {
		s.lifecycleCancel()
	}
	done := make(chan struct{})
	go func() { s.workers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) WatchTurnEvents(ctx context.Context, id string, after int64, limit int) (<-chan TurnEvent, error) {
	if s.turns == nil || !validUUID(id) || after < 0 {
		return nil, ErrInvalid
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if _, err := s.turns.GetTurn(ctx, id); err != nil {
		return nil, err
	}
	out := make(chan TurnEvent, 16)
	go func() {
		defer close(out)
		cursor := after
		if first, last, err := s.turns.TurnEventBounds(ctx, id); err != nil {
			select {
			case out <- TurnEvent{TurnID: id, Err: err}:
			case <-ctx.Done():
			}
			return
		} else if first > 0 && cursor < first-1 {
			select {
			case out <- TurnEvent{TurnID: id, ReplayGap: true, FirstSequence: first, LastSequence: last}:
			case <-ctx.Done():
				return
			}
			cursor = first - 1
		}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			events, err := s.turns.LoadTurnEvents(ctx, id, cursor, limit)
			if err != nil {
				select {
				case out <- TurnEvent{TurnID: id, Err: err}:
				case <-ctx.Done():
				}
				return
			}
			for _, event := range events {
				select {
				case out <- event:
					if event.Sequence > cursor {
						cursor = event.Sequence
					}
				case <-ctx.Done():
					return
				}
			}
			turn, err := s.turns.GetTurn(ctx, id)
			if err != nil {
				select {
				case out <- TurnEvent{TurnID: id, Err: err}:
				case <-ctx.Done():
				}
				return
			}
			if turn.State == TurnCompleted || turn.State == TurnCanceled || turn.State == TurnFailed {
				if _, last, boundsErr := s.turns.TurnEventBounds(ctx, id); boundsErr != nil {
					select {
					case out <- TurnEvent{TurnID: id, Err: boundsErr}:
					case <-ctx.Done():
					}
					return
				} else if cursor >= last {
					return
				}
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (s *Service) executeTurn(ctx context.Context, id string) {
	if s.turns == nil {
		return
	}
	lease, err := s.turns.ClaimTurn(ctx, id, s.clock(), s.leaseTTL)
	if err != nil {
		return
	}
	if lease.Turn.State == TurnCompleted || lease.Turn.State == TurnCanceled || lease.Turn.State == TurnFailed {
		return
	}
	if lease.Turn.CancelRequested {
		if lease.LeaseID == "" {
			if cancelStore, ok := s.turns.(TurnCancelStore); ok {
				_, _ = cancelStore.MarkTurnCanceledRequested(ctx, id)
			}
		} else {
			_, _ = s.turns.MarkTurnCanceled(ctx, lease)
		}
		return
	}
	if started, appendErr := s.turns.AppendTurnEvent(ctx, id, TurnEvent{Kind: TurnEventStarted, CreatedAt: s.clock()}); appendErr == nil {
		lease.Turn.LastSequence = started.Sequence
	}
	turn := lease.Turn
	conv, err := s.store.LoadConversation(ctx, turn.ConversationID)
	if err != nil {
		conv = Conversation{ID: turn.ConversationID, Revision: 0, CreatedAt: s.clock(), UpdatedAt: s.clock()}
	}
	persistedMessageCount := len(conv.Messages)
	resolvedExtensions, err := s.resolveAcceptedTurnExtensions(ctx, turn.ExtensionSnapshots)
	if err != nil {
		_, _ = s.turns.FailTurn(ctx, lease, "extension_snapshot_unavailable", "accepted extension snapshot is unavailable")
		return
	}
	if err = s.appendReadOnlyTurnToolHistory(ctx, turn, &conv); err != nil {
		_, _ = s.turns.FailTurn(ctx, lease, "tool_history_unavailable", "durable tool history is unavailable")
		return
	}
	if turn.ExpectedRevision != nil && conv.Revision != *turn.ExpectedRevision {
		_, _ = s.turns.FailTurn(ctx, lease, "revision_conflict", "conversation revision changed")
		return
	}
	// A completed/denied conversation-tool attempt is part of the next model
	// round's input. It is reconstructed from the bounded Agent-side result;
	// the intermediate assistant/tool messages are not exposed as Message
	// Server history until the final turn commit.
	if recovery, ok := s.turns.(ConversationToolRecoveryStore); ok {
		if attempt, observeErr := recovery.ObserveConversationTool(ctx, id); observeErr == nil && (attempt.State == "completed" || attempt.State == "denied" || attempt.State == "canceled") {
			content := attempt.SafeSummary
			if len(attempt.Result) > 0 {
				var stored coretask.Result
				if json.Unmarshal(attempt.Result, &stored) == nil {
					if stored.Text != "" {
						content = stored.Text
					} else if len(stored.JSON) > 0 {
						content = string(stored.JSON)
					}
				}
			}
			if attempt.State != "completed" && content == "" {
				content = "tool call denied"
			}
			assistant := Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "", ToolCalls: []ToolCall{{ID: attempt.CallID, Name: attempt.ToolName, Arguments: `{}`}}, CreatedAt: nextMessageTime(conv, s.clock()), ModelProfileID: turn.ProfileID}
			tool := Message{ID: uuid.NewString(), Role: RoleTool, ToolResults: []ToolResult{{CallID: attempt.CallID, ToolName: attempt.ToolName, Content: content, IsError: attempt.State != "completed"}}, CreatedAt: nextMessageTime(conv, s.clock().Add(time.Nanosecond)), ModelProfileID: turn.ProfileID}
			conv.Messages = append(conv.Messages, assistant, tool)
			_ = recovery.ResumeConversationTurn(ctx, id)
			turn.State = TurnAccepted
		}
	}
	dispatchStore, durableDispatch := s.turns.(TurnDispatchStore)
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	cancelSignal := make(chan struct{})
	s.cancelMu.Lock()
	s.cancelSignals[id] = cancelSignal
	s.cancelMu.Unlock()
	defer func() { s.cancelMu.Lock(); delete(s.cancelSignals, id); s.cancelMu.Unlock() }()
	resultCh := make(chan struct {
		result ModelRunResult
		err    error
	}, 1)
	var replay ModelRunResult
	var replayed bool
	if durableDispatch {
		replay, replayed, err = dispatchStore.LoadTurnModelResult(ctx, turn.ID)
		if err != nil {
			return
		}
	}
	var recalledMemory string
	if !replayed && persistedMessageCount == 0 && s.memoryRecall != nil {
		recallCtx, recallCancel := context.WithTimeout(ctx, 15*time.Second)
		recalledMemory, err = s.memoryRecall.RecallMemory(recallCtx, turn.Prompt)
		recallCancel()
		if err != nil {
			_, _ = s.turns.FailTurn(ctx, lease, "memory_recall_unavailable", "long-term memory recall is unavailable")
			return
		}
	}
	var modelConversation Conversation
	if !replayed {
		modelConversation, err = modelConversationForTurn(conv, persistedMessageCount, turn, recalledMemory, s.clock())
		if err != nil {
			_, _ = s.turns.FailTurn(ctx, lease, "invalid_model_context", "model context is invalid")
			return
		}
		if steerStore, ok := s.turns.(TurnSteerStore); ok {
			steers, steerErr := steerStore.ListTurnSteers(ctx, turn.ID)
			if steerErr != nil {
				_, _ = s.turns.FailTurn(ctx, lease, "turn_steer_unavailable", "same-turn guidance is unavailable")
				return
			}
			modelConversation, err = appendTurnSteers(modelConversation, turn, steers, s.clock())
			if err != nil {
				_, _ = s.turns.FailTurn(ctx, lease, "invalid_model_context", "model context is invalid")
				return
			}
		}
	}
	intrinsicTools, err := s.resolveIntrinsicTools(ctx, lease)
	if err != nil {
		_, _ = s.turns.FailTurn(ctx, lease, "intrinsic_unavailable", "Core intrinsic tool is unavailable")
		return
	}
	if len(intrinsicTools) != 0 {
		seen := make(map[string]struct{}, len(intrinsicTools))
		for _, intrinsic := range intrinsicTools {
			if !coremodel.IsIntrinsicToolName(intrinsic.Tool.Name) || intrinsic.Tool.InputSchema == nil || intrinsic.Execute == nil {
				_, _ = s.turns.FailTurn(ctx, lease, "intrinsic_invalid", "Core intrinsic tool binding is invalid")
				return
			}
			if _, duplicate := seen[intrinsic.Tool.Name]; duplicate {
				_, _ = s.turns.FailTurn(ctx, lease, "intrinsic_conflict", "Core intrinsic tool binding is ambiguous")
				return
			}
			seen[intrinsic.Tool.Name] = struct{}{}
		}
	}
	if durableDispatch {
		if !replayed {
			if _, err = dispatchStore.PrepareTurnModel(ctx, lease); err != nil {
				if current, getErr := s.turns.GetTurn(ctx, turn.ID); getErr == nil && current.DispatchState == "dispatched" {
					_ = dispatchStore.MarkTurnModelUncertain(ctx, lease, "provider_uncertain", "model dispatch outcome is unknown")
					_, _ = s.turns.FailTurn(ctx, lease, "provider_uncertain", "model dispatch outcome is unknown")
				}
				return
			}
		}
	}
	if replayed {
		resultCh <- struct {
			result ModelRunResult
			err    error
		}{replay, nil}
	} else {
		go func() {
			profile := turn.ProfileSnapshot.Profile()
			result, runErr := s.models.Run(child, ModelRunRequest{
				Conversation: modelConversation,
				Profile: ResolvedProfile{
					ID:           profile.ID,
					DisplayName:  profile.DisplayName,
					Provider:     string(profile.Provider),
					Model:        profile.Model,
					SystemPrompt: profile.SystemPrompt,
				},
				Snapshot:           turn.ProfileSnapshot,
				ProfileSnapshot:    turn.ProfileSnapshot,
				Intrinsics:         append([]ResolvedIntrinsic(nil), intrinsicTools...),
				Extensions:         resolvedExtensions,
				ExtensionSnapshots: append([]ExtensionExecutionSnapshot(nil), turn.ExtensionSnapshots...),
			})
			resultCh <- struct {
				result ModelRunResult
				err    error
			}{result, runErr}
		}()
	}
	interval := s.leaseTTL / 3
	if interval <= 0 {
		interval = time.Second
	}
	heartbeat := time.NewTicker(interval)
	defer heartbeat.Stop()
	for {
		select {
		case out := <-resultCh:
			if out.err != nil {
				if t, e := s.turns.GetTurn(ctx, id); e == nil && t.CancelRequested {
					if cancelStore, ok := s.turns.(TurnCancelStore); ok {
						_, _ = cancelStore.MarkTurnCanceledRequested(ctx, id)
					}
				} else {
					if durableDispatch {
						_ = dispatchStore.MarkTurnModelUncertain(ctx, lease, "provider_uncertain", "model dispatch outcome is unknown")
					}
					_, _ = s.turns.FailTurn(ctx, lease, "provider_uncertain", "model dispatch outcome is unknown")
				}
				return
			}
			if t, e := s.turns.GetTurn(ctx, id); e == nil && t.CancelRequested {
				if cancelStore, ok := s.turns.(TurnCancelStore); ok {
					_, _ = cancelStore.MarkTurnCanceledRequested(ctx, id)
				}
				return
			}
			if len(out.result.ToolCalls) != 0 || len(out.result.Message.ToolCalls) != 0 {
				calls := out.result.ToolCalls
				if len(calls) == 0 {
					calls = out.result.Message.ToolCalls
				}
				hasIntrinsic := false
				for _, call := range calls {
					if coremodel.IsIntrinsicToolName(call.Name) {
						hasIntrinsic = true
						break
					}
				}
				if len(calls) != 1 {
					if hasIntrinsic {
						_, _ = s.turns.FailTurn(ctx, lease, "intrinsic_batch_rejected", "Core intrinsic tool must be the only call in a model round")
					} else {
						_, _ = s.turns.FailTurn(ctx, lease, "tool_batch_rejected", "Conversation tool must be the only call in a durable model round")
					}
					return
				}
				call := calls[0]
				if coremodel.IsIntrinsicToolName(call.Name) {
					var intrinsic *ResolvedIntrinsic
					for index := range intrinsicTools {
						if intrinsicTools[index].Tool.Name == call.Name {
							intrinsic = &intrinsicTools[index]
							break
						}
					}
					if intrinsic == nil {
						_, _ = s.turns.FailTurn(ctx, lease, "intrinsic_unavailable", "Core intrinsic tool is unavailable")
						return
					}
					arguments, argumentsErr := canonicalJSON(call.Arguments, MaxToolArgumentsBytes)
					if argumentsErr != nil {
						_, _ = s.turns.FailTurn(ctx, lease, "invalid_intrinsic_arguments", "Core intrinsic arguments are invalid")
						return
					}
					if durableDispatch && !replayed {
						if recordErr := dispatchStore.RecordTurnModelResult(ctx, lease, out.result); recordErr != nil {
							return
						}
					}
					intrinsicResult, intrinsicErr := intrinsic.Execute(ctx, IntrinsicExecutionRequest{
						Lease: lease, Call: call, CanonicalArguments: arguments,
						ConversationRevision: conv.Revision,
					})
					if intrinsicErr != nil || !intrinsicResult.TurnCommitted {
						code, summary := intrinsicTerminalFailure(call.Name, intrinsicErr)
						_, _ = s.turns.FailTurn(ctx, lease, code, summary)
					}
					return
				}
				toolStore, ok := s.turns.(ConversationToolStore)
				if !ok || len(turn.ExtensionSnapshots) == 0 {
					_, _ = s.turns.FailTurn(ctx, lease, "extensions_unavailable", "conversation tool store is unavailable")
					return
				}
				var bound ExtensionExecutionSnapshot
				var executable *ResolvedExtension
				for _, candidate := range turn.ExtensionSnapshots {
					if containsTool(candidate.ToolNames, call.Name) {
						if bound.Selection.ID != "" {
							_, _ = s.turns.FailTurn(ctx, lease, "tool_conflict", "tool name is not uniquely bound")
							return
						}
						bound = candidate
					}
				}
				if bound.Selection.ID == "" {
					_, _ = s.turns.FailTurn(ctx, lease, "tool_unavailable", "requested tool is not in the accepted snapshot")
					return
				}
				for index := range resolvedExtensions {
					candidate := &resolvedExtensions[index]
					if candidate.Selection.ID == bound.Selection.ID && containsTool(candidate.Snapshot.ToolNames, call.Name) {
						executable = candidate
						break
					}
				}
				if bound.ReadOnly && executable != nil && executable.Execute != nil {
					if durableDispatch && !replayed {
						if err := dispatchStore.RecordTurnModelResult(ctx, lease, out.result); err != nil {
							return
						}
					}
					result, executeErr := executable.Execute(child, ToolExecutionRequest{Call: call})
					if executeErr != nil {
						_, _ = s.turns.FailTurn(ctx, lease, "tool_execution_failed", "read-only tool execution failed")
						return
					}
					readOnlyStore, ok := s.turns.(ReadOnlyConversationToolStore)
					if !ok {
						_, _ = s.turns.FailTurn(ctx, lease, "tool_store_unavailable", "read-only tool store is unavailable")
						return
					}
					if _, err = readOnlyStore.ContinueTurnAfterReadOnlyTool(ctx, lease, call, result); err != nil {
						return
					}
					return
				}
				args, argsErr := canonicalJSON(call.Arguments, MaxToolArgumentsBytes)
				if argsErr != nil {
					_, _ = s.turns.FailTurn(ctx, lease, "invalid_tool_arguments", "tool arguments are invalid")
					return
				}
				argsDigest := digest(string(args))
				attemptID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-tool:"+turn.RequestID+":"+call.ID)).String()
				round := uint32(0)
				if recovery, recoveryOK := s.turns.(ConversationToolRecoveryStore); recoveryOK {
					if previous, previousErr := recovery.ObserveConversationTool(ctx, id); previousErr == nil {
						round = previous.Round + 1
					}
				}
				attemptID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("conversation-tool:%s:%d:%s", turn.RequestID, round, call.ID))).String()
				attempt, _, _, prepErr := toolStore.PrepareConversationTool(ctx, PrepareToolCommand{Lease: lease, Round: round, Call: call, Snapshot: bound, CanonicalArguments: args, ArgumentsDigest: argsDigest, SafeSummary: "conversation tool call " + call.Name, IdempotencyKey: attemptID, ExpiresAt: s.clock().Add(10 * time.Minute)})
				if prepErr != nil {
					_, _ = s.turns.FailTurn(ctx, lease, "tool_prepare_failed", "conversation tool preparation failed")
					return
				}
				_, _ = s.turns.AppendTurnEvent(ctx, id, TurnEvent{Kind: TurnEventWaitingConfirmation, ConfirmationID: attempt.ConfirmationID, AttemptID: attempt.ID, ExecutionID: attempt.ExecutionID, Status: attempt.State})
				return
			}
			if durableDispatch && !replayed {
				if err := dispatchStore.RecordTurnModelResult(ctx, lease, out.result); err != nil {
					return
				}
			}
			m := out.result.Message
			m.RelatedTaskIDs = stableIDs(append(m.RelatedTaskIDs, out.result.RelatedTaskIDs...))
			m.RelatedPlanIDs = stableIDs(append(m.RelatedPlanIDs, out.result.RelatedPlanIDs...))
			m.References = stableReferences(append(m.References, out.result.References...))
			m.ToolSummaries = stableStrings(append(m.ToolSummaries, out.result.ToolSummaries...))
			userTime := nextMessageTime(conv, s.clock())
			m.ModelProfileID, m.Role, m.CreatedAt = turn.ProfileID, RoleAssistant, userTime.Add(time.Microsecond)
			if m.ID == "" {
				m.ID = uuid.NewString()
			}
			if err := m.Validate(); err != nil {
				_, _ = s.turns.FailTurn(ctx, lease, "invalid_model_result", "model returned invalid message")
				return
			}
			conv.Messages = append(conv.Messages, Message{ID: uuid.NewString(), Role: RoleUser, Content: turn.Prompt, ModelProfileID: turn.ProfileID, CreatedAt: userTime}, m)
			conv.Revision++
			conv.UpdatedAt = s.clock()
			response := ChatResponse{RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: conv.Revision, Message: m, Done: true, ModelProfileID: turn.ProfileID, RelatedTaskIDs: append([]string(nil), m.RelatedTaskIDs...), RelatedPlanIDs: append([]string(nil), m.RelatedPlanIDs...), References: cloneReferences(m.References), ToolSummaries: append([]string(nil), m.ToolSummaries...)}
			_, _ = s.turns.CommitTurn(ctx, lease, response)
			return
		case <-heartbeat.C:
			t, e := s.turns.GetTurn(ctx, id)
			if e == nil && t.CancelRequested {
				cancel()
			}
			lease, err = s.turns.RenewTurn(ctx, id, lease.LeaseID, lease.Epoch, s.clock(), s.leaseTTL)
			if err != nil {
				cancel()
			}
		case <-cancelSignal:
			cancel()
		}
	}
}

func intrinsicTerminalFailure(toolName string, err error) (string, string) {
	if toolName == coremodel.IntrinsicScheduleCreateToolName {
		if errors.Is(err, ErrInvalid) {
			return "invalid_intrinsic_arguments", "Core intrinsic arguments are invalid"
		}
		return "schedule_persistence_failed", "Schedule could not be saved"
	}
	return "intrinsic_failed", "Core intrinsic operation failed"
}

func (s *Service) resolveAcceptedTurnExtensions(ctx context.Context, snapshots []ExtensionExecutionSnapshot) ([]ResolvedExtension, error) {
	if len(snapshots) == 0 {
		return nil, nil
	}
	selections := make([]ExtensionSelection, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.Source == "builtin:web_search:tavily" || snapshot.Source == "builtin:knowledge:semantic" || snapshot.Source == "product-capability" {
			continue
		}
		selections = append(selections, snapshot.Selection)
	}
	resolved, err := s.extensions.ResolveExtensions(ctx, selections)
	if err != nil || len(resolved) != len(snapshots) {
		return nil, ErrConflict
	}
	remaining := make(map[string]string, len(snapshots))
	for _, snapshot := range snapshots {
		remaining[snapshot.Selection.ID] = snapshot.ContentDigest + ":" + snapshot.ArtifactDigest + ":" + snapshot.ToolSchemaDigest
	}
	for _, extension := range resolved {
		snapshot := snapshotForResolved(extension)
		want, ok := remaining[snapshot.Selection.ID]
		if !ok || want != snapshot.ContentDigest+":"+snapshot.ArtifactDigest+":"+snapshot.ToolSchemaDigest {
			return nil, ErrConflict
		}
		delete(remaining, snapshot.Selection.ID)
	}
	if len(remaining) != 0 {
		return nil, ErrConflict
	}
	return resolved, nil
}

func (s *Service) appendReadOnlyTurnToolHistory(ctx context.Context, turn Turn, conversation *Conversation) error {
	if conversation == nil {
		return ErrInvalid
	}
	hasReadOnly := false
	for _, snapshot := range turn.ExtensionSnapshots {
		if snapshot.ReadOnly {
			hasReadOnly = true
			break
		}
	}
	if !hasReadOnly {
		return nil
	}
	events, err := s.turns.LoadTurnEvents(ctx, turn.ID, 0, 1000)
	if err != nil {
		return err
	}
	calls := make(map[string]ToolCall)
	for _, event := range events {
		if event.Kind == TurnEventToolCall && event.ToolCall != nil {
			calls[event.ToolCall.ID] = *event.ToolCall
			continue
		}
		if event.Kind != TurnEventToolResult || event.ToolResult == nil {
			continue
		}
		call, ok := calls[event.ToolResult.CallID]
		if !ok {
			return ErrConflict
		}
		createdAt := nextMessageTime(*conversation, event.CreatedAt)
		conversation.Messages = append(conversation.Messages,
			Message{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-read-only-call:"+turn.ID+":"+call.ID)).String(), Role: RoleAssistant, ToolCalls: []ToolCall{call}, CreatedAt: createdAt, ModelProfileID: turn.ProfileID},
			Message{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-read-only-result:"+turn.ID+":"+call.ID)).String(), Role: RoleTool, ToolResults: []ToolResult{*event.ToolResult}, CreatedAt: createdAt.Add(time.Nanosecond), ModelProfileID: turn.ProfileID},
		)
		delete(calls, call.ID)
	}
	return nil
}

func modelConversationForTurn(conv Conversation, insertAt int, turn Turn, recalledMemory string, now time.Time) (Conversation, error) {
	if insertAt < 0 || insertAt > len(conv.Messages) || !validUUID(turn.ID) || !validUUID(turn.ProfileID) {
		return Conversation{}, ErrInvalid
	}
	out := conv.Snapshot()
	prefix := append([]Message(nil), out.Messages[:insertAt]...)
	suffix := append([]Message(nil), out.Messages[insertAt:]...)
	createdAt := turn.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = now.UTC()
	}
	if len(prefix) > 0 && !createdAt.After(prefix[len(prefix)-1].CreatedAt) {
		createdAt = prefix[len(prefix)-1].CreatedAt.Add(time.Nanosecond)
	}
	transient := make([]Message, 0, 2)
	if memory := strings.TrimSpace(recalledMemory); memory != "" {
		message := Message{
			ID:             uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-memory-recall:"+turn.ID)).String(),
			Role:           RoleUser,
			Content:        memory,
			CreatedAt:      createdAt,
			ModelProfileID: turn.ProfileID,
		}
		if err := message.Validate(); err != nil {
			return Conversation{}, err
		}
		transient = append(transient, message)
		createdAt = createdAt.Add(time.Nanosecond)
	}
	user := Message{
		ID:             uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-user-prompt:"+turn.ID)).String(),
		Role:           RoleUser,
		Content:        turn.Prompt,
		CreatedAt:      createdAt,
		ModelProfileID: turn.ProfileID,
	}
	if err := user.Validate(); err != nil {
		return Conversation{}, err
	}
	transient = append(transient, user)
	out.Messages = append(prefix, transient...)
	out.Messages = append(out.Messages, suffix...)
	return out, nil
}

func appendTurnSteers(conversation Conversation, turn Turn, steers []TurnSteer, now time.Time) (Conversation, error) {
	out := conversation.Snapshot()
	for _, steer := range steers {
		if !validUUID(steer.RequestID) || steer.ExpectedRevision == 0 {
			return Conversation{}, ErrConflict
		}
		instruction := strings.TrimSpace(steer.Instruction)
		if err := validateText(instruction, MaxContentBytes); err != nil {
			return Conversation{}, err
		}
		createdAt := steer.CreatedAt.UTC()
		if createdAt.IsZero() {
			createdAt = now.UTC()
		}
		if len(out.Messages) > 0 && !createdAt.After(out.Messages[len(out.Messages)-1].CreatedAt) {
			createdAt = out.Messages[len(out.Messages)-1].CreatedAt.Add(time.Nanosecond)
		}
		message := Message{
			ID:             uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-steer-user:"+steer.RequestID)).String(),
			Role:           RoleUser,
			Content:        instruction,
			CreatedAt:      createdAt,
			ModelProfileID: turn.ProfileID,
		}
		if err := message.Validate(); err != nil {
			return Conversation{}, err
		}
		out.Messages = append(out.Messages, message)
	}
	return out, nil
}

func modelConversationWithRecalledMemory(conv Conversation, insertAt int, recalledMemory, profileID, requestID string) (Conversation, error) {
	out := conv.Snapshot()
	memory := strings.TrimSpace(recalledMemory)
	if memory == "" {
		return out, nil
	}
	if insertAt < 0 || insertAt >= len(out.Messages) || !validUUID(profileID) || !validUUID(requestID) || out.Messages[insertAt].Role != RoleUser {
		return Conversation{}, ErrInvalid
	}
	createdAt := out.Messages[insertAt].CreatedAt
	message := Message{
		ID:             uuid.NewSHA1(uuid.NameSpaceOID, []byte("chat-memory-recall:"+requestID)).String(),
		Role:           RoleUser,
		Content:        memory,
		CreatedAt:      createdAt,
		ModelProfileID: profileID,
	}
	if err := message.Validate(); err != nil {
		return Conversation{}, err
	}
	prefix := append([]Message(nil), out.Messages[:insertAt]...)
	suffix := append([]Message(nil), out.Messages[insertAt:]...)
	out.Messages = append(prefix, message)
	out.Messages = append(out.Messages, suffix...)
	return out, nil
}

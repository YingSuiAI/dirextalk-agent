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

const (
	MaxTurnModelDispatches          = 24
	MaxTurnModelActiveDuration      = 20 * time.Minute
	MaxTurnToolCalls                = 20
	toolLoopNudgeGuidance           = "The latest tool action and result are repeating without new evidence. Change approach or synthesize from what is already available; do not repeat the same action."
	toolLoopSynthesisGuidance       = "The tool loop continued without new evidence. Do not call tools. Produce the best useful answer now from all accumulated evidence and explicitly state remaining gaps."
	outputContinuationGuidance      = "Continue the previous assistant response by emitting only the missing suffix. Do not restart or repeat any prior analysis, reasoning, plan, or response text. Preserve the work already completed. If a tool call was cut off, issue it again once as one complete call."
	staticSitePublishCorrection     = "static_site_publish arguments are invalid; invoke static_site_publish again immediately with the required non-empty html string containing the complete page, and do not repeat analysis or draft the page outside the tool call"
	conversationConvergenceGuidance = "When sufficient information is available, act or call the needed tool, then synthesize the result without restating the user's request or tool instructions."
)

type Service struct {
	store            Store
	models           ModelRunner
	extensions       ExtensionResolver
	intrinsics       IntrinsicResolver
	staticSites      StaticSitePublisher
	staticSiteOrigin string
	memoryRecall     MemoryRecallResolver
	titleGenerator   ConversationTitleGenerator
	snapshots        SnapshotProfileResolver
	now              func() time.Time
	leaseTTL         time.Duration
	turns            TurnStore
	lifecycleCtx     context.Context
	lifecycleCancel  context.CancelFunc
	workers          sync.WaitGroup
	cancelMu         sync.Mutex
	cancelSignals    map[string]chan struct{}
	runtimeMu        sync.Mutex
	runtime          map[string]*turnRuntime
	turnOrderingMu   sync.Mutex
	turnOrdering     map[string]*turnDeltaOrdering
}

// MemoryRecallResolver supplies a bounded, already-delimited model-only
// context for the current turn. Implementations must never return raw
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

// SetStaticSitePublisher exposes the Agent-owned, single-file static-site
// intrinsic only after its immutable filesystem root has passed readiness.
// A nil publisher removes the tool from the model catalog.
func (s *Service) SetStaticSitePublisher(publisher StaticSitePublisher, publicOrigin string) {
	if s == nil {
		return
	}
	s.staticSites = publisher
	s.staticSiteOrigin = strings.TrimRight(strings.TrimSpace(publicOrigin), "/")
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
	s := &Service{store: store, models: models, extensions: extensions, snapshots: profiles, now: func() time.Time { return time.Now().UTC() }, leaseTTL: 2 * time.Minute, lifecycleCtx: lifecycleCtx, lifecycleCancel: lifecycleCancel, cancelSignals: map[string]chan struct{}{}, runtime: map[string]*turnRuntime{}, turnOrdering: map[string]*turnDeltaOrdering{}}
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
	conversationTitleUserText := firstConversationUserText(conv, cmd.Prompt)
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
	var reasoningContent strings.Builder
	var continuationContent strings.Builder
	var continuationReasoning strings.Builder
	var continuationMessages []Message
	for round := 0; ; round++ {
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
				if d.Text != "" || d.ReasoningContent != "" {
					emit(StreamEvent{Kind: EventDelta, RequestID: cmd.RequestID, ConversationID: conv.ID, Text: d.Text, ReasoningContent: d.ReasoningContent})
				}
				return nil
			}
		}
		result, replayed, err := s.store.LoadModelStep(ctx, cmd.RequestID, lease.LeaseID, lease.Fingerprint, lease.Epoch, cmd.ProfileID, round)
		if err != nil {
			return ChatResponse{}, err
		}
		if !replayed {
			if !memoryRecallResolved && s.memoryRecall != nil {
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
			modelConversation.Messages = append(modelConversation.Messages, continuationMessages...)
			if len(continuationMessages) != 0 {
				continuation, continuationErr := outputContinuationMessage(modelConversation, cmd.ProfileID, fmt.Sprintf("chat:%s:%d", cmd.RequestID, round), s.clock())
				if continuationErr != nil {
					return ChatResponse{}, continuationErr
				}
				modelConversation.Messages = append(modelConversation.Messages, continuation)
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
		if !result.Continue && len(continuationMessages) != 0 {
			result.Message.Content = continuationContent.String() + result.Message.Content
			result.Message.ReasoningContent = continuationReasoning.String() + result.Message.ReasoningContent
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
		if result.Continue && !validModelContinuation(result) {
			return ChatResponse{}, ErrInvalid
		}
		if !result.Continue {
			if validationErr := result.Message.Validate(); validationErr != nil {
				return ChatResponse{}, fmt.Errorf("model message: %w", validationErr)
			}
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
		if result.Continue {
			continuationContent.WriteString(result.Message.Content)
			continuationReasoning.WriteString(result.Message.ReasoningContent)
			continuationMessages = append(continuationMessages, result.Message.Snapshot())
			continue
		}
		continuationContent.Reset()
		continuationReasoning.Reset()
		continuationMessages = nil
		reasoningContent.WriteString(result.Message.ReasoningContent)
		if len(result.Message.ToolCalls) == 0 {
			result.Message.ReasoningContent = reasoningContent.String()
			if err := result.Message.Validate(); err != nil {
				return ChatResponse{}, fmt.Errorf("model message: %w", err)
			}
		}
		conv.Messages = append(conv.Messages, result.Message)
		if len(result.Message.ToolCalls) == 0 {
			conv.Revision++
			conv.UpdatedAt = s.clock()
			conv.Title = s.automaticConversationTitle(ctx, conv.Title, conversationTitleUserText, result.Message.Content)
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
			call.ExecutionID = tlease.ExecutionID
			for i := range conv.Messages[len(conv.Messages)-1].ToolCalls {
				if conv.Messages[len(conv.Messages)-1].ToolCalls[i].ID == call.ID {
					conv.Messages[len(conv.Messages)-1].ToolCalls[i].ExecutionID = call.ExecutionID
				}
			}
			// The model step and tool execution claim are durable at this point,
			// but no extension has been dispatched. Publish the existing public
			// tool_call now so a streaming client can show real progress while
			// execution is in flight. The dispatched fence below still prevents
			// recovery from repeating an unknown external mutation.
			if emit != nil {
				cc := call
				emit(StreamEvent{Kind: EventToolCall, RequestID: cmd.RequestID, ConversationID: conv.ID, ToolCall: &cc})
			}
			if tlease.Status == ToolClaimCompleted && tlease.Result != nil {
				if tlease.Result.CallID != call.ID {
					return ChatResponse{}, ErrConflict
				}
				tr = *tlease.Result
				found = true
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
	if automatic, ok := s.extensions.(AutomaticExtensionSelector); ok {
		var mergeErr error
		cmd.Extensions, mergeErr = automatic.MergeAutomaticExtensions(ctx, cmd.Extensions)
		if mergeErr != nil {
			return Turn{}, mergeErr
		}
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
	if s.turns == nil || !validUUID(cmd.TurnID) || !validUUID(cmd.RequestID) {
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
	if len(cmd.AcceptedAttachmentIDs) > MaxTurnAttachments {
		return Turn{}, ErrInvalid
	}
	seenAttachments := map[string]struct{}{}
	for _, id := range cmd.AcceptedAttachmentIDs {
		if !validUUID(id) {
			return Turn{}, ErrInvalid
		}
		if _, exists := seenAttachments[id]; exists {
			return Turn{}, ErrConflict
		}
		seenAttachments[id] = struct{}{}
	}
	store, ok := s.turns.(TurnSteerStore)
	if !ok {
		return Turn{}, ErrInvalid
	}
	ordering := s.currentTurnOrdering(cmd.TurnID)
	var turn Turn
	var interrupt bool
	commit := func() error {
		var commitErr error
		turn, interrupt, commitErr = store.RequestTurnSteer(ctx, cmd)
		return commitErr
	}
	var err error
	if ordering == nil {
		err = commit()
	} else {
		err = ordering.buffer.Fence(commit)
	}
	if err != nil {
		return Turn{}, err
	}
	if !interrupt {
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
		if turn.State == TurnAccepted {
			if recovery, ok := s.turns.(ConversationToolRecoveryStore); ok {
				if attempt, observeErr := recovery.ObserveConversationTool(ctx, id); observeErr == nil && (attempt.State == "completed" || attempt.State == "denied" || attempt.State == "canceled") {
					if resumeErr := recovery.ResumeConversationTurn(ctx, id); resumeErr != nil {
						if !waitTurnSupervisor(ctx, backoff, wake) {
							return
						}
						backoff = nextTurnSupervisorBackoff(backoff)
						continue
					}
				}
			}
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
				code, summary := uncertainModelFailure(turn)
				if _, uncertainErr := uncertainStore.FailTurnUncertain(ctx, id, code, summary); uncertainErr == nil {
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
			case out <- TurnEvent{TurnID: id, Sequence: first - 1, ReplayGap: true, FirstSequence: first, LastSequence: last}:
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
	conversationTitleUserText := s.durableConversationTitleSource(ctx, conv, turn)
	conv, persistedMessageCount, currentUserCommitted, err := conversationForTurnContinuation(conv, turn)
	if err != nil {
		_, _ = s.turns.FailTurn(ctx, lease, "invalid_model_context", "durable conversation context is invalid")
		return
	}
	dispatchStore, durableDispatch := s.turns.(TurnDispatchStore)
	var replay ModelRunResult
	var replayed bool
	if durableDispatch {
		replay, replayed, err = dispatchStore.LoadTurnModelResult(ctx, turn.ID)
		if err != nil {
			return
		}
	}
	history, err := s.appendTurnToolHistory(ctx, turn, &conv, replayed && !replay.Continue)
	if err != nil {
		_, _ = s.turns.FailTurn(ctx, lease, "tool_history_unavailable", "durable tool history is unavailable")
		return
	}
	toolCallAuthorities := history.authorities
	var turnSteers []TurnSteer
	if steerStore, ok := s.turns.(TurnSteerStore); ok {
		turnSteers, err = steerStore.ListTurnSteers(ctx, turn.ID)
		if err != nil {
			_, _ = s.turns.FailTurn(ctx, lease, "turn_steer_unavailable", "same-turn guidance is unavailable")
			return
		}
	}
	workerContent, appliedWorkerSteers, terminalWorker := terminalCloudWorkerContent(toolCallAuthorities)
	failedWorkerContent, failedWorker := terminalFailedCloudWorkerContent(toolCallAuthorities)
	workerSteersApplied := appliedWorkerSteers
	if failedWorker {
		_, _, workerSteersApplied, _ = terminalCloudWorkerResult(toolCallAuthorities, "failed")
	}
	unappliedWorkerSteer := hasUnappliedDeferredWorkerSteer(turnSteers, workerSteersApplied)
	autoFinalizeWorker := terminalWorker && !unappliedWorkerSteer
	var resolvedExtensions []ResolvedExtension
	if !autoFinalizeWorker {
		resolvedExtensions, err = s.resolveAcceptedTurnExtensionsForContinuation(ctx, turn.ExtensionSnapshots, terminalWorker)
		if err != nil {
			_, _ = s.turns.FailTurn(ctx, lease, "extension_snapshot_unavailable", "accepted extension snapshot is unavailable")
			return
		}
	}
	modelExtensions := resolvedExtensions
	modelExtensionSnapshots := append([]ExtensionExecutionSnapshot(nil), turn.ExtensionSnapshots...)
	if turn.ExpectedRevision != nil {
		expectedRevision := *turn.ExpectedRevision
		if currentUserCommitted {
			expectedRevision++
		}
		if conv.Revision != expectedRevision {
			_, _ = s.turns.FailTurn(ctx, lease, "revision_conflict", "conversation revision changed")
			return
		}
	}
	if autoFinalizeWorker {
		historyTasks, historyPlans, historyReferences, historySummaries, historyResults := turnToolMetadata(conv.Messages[persistedMessageCount:])
		userTime := nextMessageTime(conv, s.clock())
		message := Message{
			ID: uuid.NewString(), Role: RoleAssistant, Content: workerContent, ModelProfileID: turn.ProfileID,
			CreatedAt: userTime.Add(time.Microsecond), RelatedTaskIDs: historyTasks, RelatedPlanIDs: historyPlans,
			References: historyReferences, ToolSummaries: historySummaries,
		}
		if err := message.Validate(); err != nil {
			_, _ = s.turns.FailTurn(ctx, lease, "invalid_worker_result", "Cloud Worker returned an invalid completion")
			return
		}
		conv.Revision++
		response := ChatResponse{
			RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: conv.Revision,
			Message: message, Done: true, ModelProfileID: turn.ProfileID,
			RelatedTaskIDs: append([]string(nil), historyTasks...), RelatedPlanIDs: append([]string(nil), historyPlans...),
			References: cloneReferences(historyReferences), ToolSummaries: append([]string(nil), historySummaries...),
			ToolResults: historyResults, ConversationTitle: conversationTitleFallback(conversationTitleUserText), ConversationTitleSource: conversationTitleUserText,
		}
		if _, commitErr := s.turns.CommitTurn(ctx, lease, response); commitErr != nil {
			current, readErr := s.turns.GetTurn(ctx, turn.ID)
			if readErr == nil && current.State == TurnCompleted {
				return
			}
			_, _ = s.turns.FailTurn(ctx, lease, "turn_commit_failed", "conversation response could not be committed")
		}
		return
	}
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
	var recalledMemory string
	if !replayed && s.memoryRecall != nil {
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
		if len(turnSteers) != 0 {
			modelConversation, err = appendTurnSteers(modelConversation, turn, turnSteers, s.clock())
			if err != nil {
				_, _ = s.turns.FailTurn(ctx, lease, "invalid_model_context", "model context is invalid")
				return
			}
		}
		if history.continueOutput {
			continuation, continuationErr := outputContinuationMessage(modelConversation, turn.ProfileID, fmt.Sprintf("turn:%s:%d", turn.ID, turn.LastSequence), s.clock())
			if continuationErr != nil {
				_, _ = s.turns.FailTurn(ctx, lease, "invalid_model_context", "model continuation context is invalid")
				return
			}
			modelConversation.Messages = append(modelConversation.Messages, continuation)
		}
	}
	var inputParts map[string][]coremodel.MessageInputPart
	if !replayed {
		inputParts, err = s.resolveTurnAttachmentInputParts(ctx, turn, turnSteers)
		if err != nil {
			_, _ = s.turns.FailTurn(ctx, lease, "unsupported_attachment", "turn attachment is not supported by the selected model input")
			return
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
	modelIntrinsicTools := intrinsicTools
	toolCallBudgetExhausted := len(toolCallAuthorities) >= MaxTurnToolCalls
	if toolCallBudgetExhausted {
		history.forcedToolName = ""
	}
	if toolCallBudgetExhausted || (history.loopRecovery == toolLoopSynthesize && history.forcedToolName == "") {
		modelExtensions = nil
		modelExtensionSnapshots = nil
		modelIntrinsicTools = nil
	}
	modelCtx := child
	modelCancel := func() {}
	if durableDispatch {
		if !replayed {
			prepared, prepareErr := dispatchStore.PrepareTurnModel(ctx, lease)
			if errors.Is(prepareErr, ErrModelBudgetExhausted) {
				_, _ = s.turns.FailTurn(ctx, lease, modelBudgetExhaustedCode, modelBudgetExhaustedSummary)
				return
			}
			if prepareErr != nil {
				if current, getErr := s.turns.GetTurn(ctx, turn.ID); getErr == nil && current.DispatchState == "dispatched" {
					_ = dispatchStore.MarkTurnModelUncertain(ctx, lease, "provider_uncertain", "model dispatch outcome is unknown")
					_, _ = s.turns.FailTurn(ctx, lease, "provider_uncertain", "model dispatch outcome is unknown")
				}
				return
			}
			turn.ModelDispatchCount = prepared.ModelDispatchCount
			turn.ModelActiveDuration = prepared.ModelActiveDuration
			remaining := MaxTurnModelActiveDuration - prepared.ModelActiveDuration
			if remaining <= 0 {
				_ = dispatchStore.MarkTurnModelUncertain(ctx, lease, modelBudgetExhaustedCode, modelBudgetExhaustedSummary)
				_, _ = s.turns.FailTurn(ctx, lease, modelBudgetExhaustedCode, modelBudgetExhaustedSummary)
				return
			}
			modelCtx, modelCancel = context.WithTimeout(child, remaining)
		}
	}
	defer modelCancel()
	if replayed {
		resultCh <- struct {
			result ModelRunResult
			err    error
		}{replay, nil}
	} else {
		deltaBuffer := newTurnDeltaBuffer(defaultTurnDeltaFlushBytes, defaultTurnDeltaFlushInterval, func(delta ModelDelta) error {
			_, appendErr := s.turns.AppendTurnEvent(ctx, id, TurnEvent{
				Kind:             TurnEventDelta,
				Text:             delta.Text,
				ReasoningContent: delta.ReasoningContent,
			})
			return appendErr
		})
		ordering := &turnDeltaOrdering{buffer: deltaBuffer}
		s.registerTurnOrdering(id, ordering)
		go func() {
			defer modelCancel()
			defer s.unregisterTurnOrdering(id, ordering)
			profile := turn.ProfileSnapshot.Profile()
			systemPrompt := appendSystemPrompt(profile.SystemPrompt, conversationConvergenceGuidance)
			if containsStaticSiteIntrinsic(modelIntrinsicTools) {
				systemPrompt = staticSiteSystemPrompt(systemPrompt)
			}
			if containsCloudWorkerIntrinsic(modelIntrinsicTools) {
				systemPrompt = cloudWorkerSystemPrompt(systemPrompt)
			}
			if toolCallBudgetExhausted {
				systemPrompt = appendSystemPrompt(systemPrompt, toolLoopSynthesisGuidance)
			} else if history.forcedToolName == "" {
				switch history.loopRecovery {
				case toolLoopNudge:
					systemPrompt = appendSystemPrompt(systemPrompt, toolLoopNudgeGuidance)
				case toolLoopSynthesize:
					systemPrompt = appendSystemPrompt(systemPrompt, toolLoopSynthesisGuidance)
				}
			}
			// Force the current streaming runner so active provider streams are
			// bounded only by their inactivity watchdog. Visible assistant text and
			// provider reasoning use the same durable delta ordering.
			result, runErr := s.runModel(modelCtx, ModelRunRequest{
				Conversation: modelConversation,
				Profile: ResolvedProfile{
					ID:           profile.ID,
					DisplayName:  profile.DisplayName,
					Provider:     string(profile.Provider),
					Model:        profile.Model,
					SystemPrompt: systemPrompt,
				},
				Snapshot:              turn.ProfileSnapshot,
				ProfileSnapshot:       turn.ProfileSnapshot,
				ForcedToolName:        history.forcedToolName,
				Intrinsics:            append([]ResolvedIntrinsic(nil), modelIntrinsicTools...),
				Extensions:            modelExtensions,
				ExtensionSnapshots:    modelExtensionSnapshots,
				InputPartsByMessageID: inputParts,
			}, deltaBuffer.Append)
			flushErr := deltaBuffer.Close()
			if runErr == nil && flushErr != nil {
				runErr = flushErr
			}
			if errors.Is(modelCtx.Err(), context.DeadlineExceeded) && child.Err() == nil {
				runErr = ErrModelBudgetExhausted
			}
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
					code, summary := classifyModelDispatchFailure(out.err)
					if durableDispatch {
						_ = dispatchStore.MarkTurnModelUncertain(ctx, lease, code, summary)
					}
					_, _ = s.turns.FailTurn(ctx, lease, code, summary)
				}
				return
			}
			if t, e := s.turns.GetTurn(ctx, id); e == nil && t.CancelRequested {
				if cancelStore, ok := s.turns.(TurnCancelStore); ok {
					_, _ = cancelStore.MarkTurnCanceledRequested(ctx, id)
				}
				return
			}
			if out.result.Continue {
				out.result.Message.ModelProfileID = turn.ProfileID
				out.result.Message.CreatedAt = nextMessageTime(conv, s.clock())
				if out.result.Message.ID == "" {
					out.result.Message.ID = uuid.NewString()
				}
				if !validModelContinuation(out.result) {
					_, _ = s.turns.FailTurn(ctx, lease, "invalid_model_result", "model returned an invalid continuation")
					return
				}
				if !durableDispatch {
					_, _ = s.turns.FailTurn(ctx, lease, "model_continuation_unavailable", "model continuation could not be persisted")
					return
				}
				if !replayed {
					if err := dispatchStore.RecordTurnModelResult(ctx, lease, out.result); err != nil {
						return
					}
				}
				roundStore, ok := s.turns.(OrderedConversationToolStore)
				if !ok {
					_, _ = s.turns.FailTurn(ctx, lease, "model_continuation_unavailable", "model continuation could not be persisted")
					return
				}
				if _, err := roundStore.CompleteConversationToolRound(ctx, lease); err != nil {
					return
				}
				return
			}
			if failedWorker && !unappliedWorkerSteer && modelResultCallsTool(out.result, coremodel.IntrinsicCloudWorkerProposeToolName) {
				out.result.Done = true
				out.result.ToolCalls = nil
				out.result.Message.Content = failedWorkerContent
				out.result.Message.ToolCalls = nil
			}
			if len(out.result.ToolCalls) != 0 || len(out.result.Message.ToolCalls) != 0 {
				calls := out.result.ToolCalls
				if len(calls) == 0 {
					calls = out.result.Message.ToolCalls
				}
				seenCallIDs := make(map[string]struct{}, len(calls))
				newToolCalls := 0
				for index, call := range calls {
					if call.Validate() != nil {
						correctableIntrinsic := call.validateIdentityAndBounds() == nil
						if correctableIntrinsic {
							correctableIntrinsic = false
							for _, intrinsic := range intrinsicTools {
								if intrinsic.Tool.Name == call.Name {
									correctableIntrinsic = true
									break
								}
							}
						}
						if !correctableIntrinsic {
							_, _ = s.turns.FailTurn(ctx, lease, "invalid_tool_call", "model returned an invalid tool call")
							return
						}
						call.Arguments = `{}`
						calls[index] = call
						for callIndex := range out.result.ToolCalls {
							if out.result.ToolCalls[callIndex].ID == call.ID {
								out.result.ToolCalls[callIndex] = call
							}
						}
						for callIndex := range out.result.Message.ToolCalls {
							if out.result.Message.ToolCalls[callIndex].ID == call.ID {
								out.result.Message.ToolCalls[callIndex] = call
							}
						}
					}
					if _, duplicate := seenCallIDs[call.ID]; duplicate {
						_, _ = s.turns.FailTurn(ctx, lease, "duplicate_tool_call", "model returned a duplicate tool call")
						return
					}
					if previous, exists := toolCallAuthorities[call.ID]; exists && previous.state == turnToolCallTerminal && !replayed {
						_, _ = s.turns.FailTurn(ctx, lease, "duplicate_tool_call", "model reused a completed tool call identity")
						return
					}
					if _, exists := toolCallAuthorities[call.ID]; !exists {
						newToolCalls++
					}
					seenCallIDs[call.ID] = struct{}{}
					if coremodel.IsIntrinsicToolName(call.Name) && index != len(calls)-1 {
						_, _ = s.turns.FailTurn(ctx, lease, "intrinsic_order_invalid", "Core intrinsic tool must be the final call in a model round")
						return
					}
				}
				if len(toolCallAuthorities)+newToolCalls > MaxTurnToolCalls {
					if durableDispatch && !replayed {
						if err := dispatchStore.RecordTurnModelResult(ctx, lease, out.result); err != nil {
							return
						}
					}
					_, _ = s.turns.FailTurn(ctx, lease, toolBudgetExhaustedCode, toolBudgetExhaustedSummary)
					return
				}
				if durableDispatch && !replayed {
					if err := dispatchStore.RecordTurnModelResult(ctx, lease, out.result); err != nil {
						return
					}
				}
				roundStore, ordered := s.turns.(OrderedConversationToolStore)
				if !ordered {
					_, _ = s.turns.FailTurn(ctx, lease, "tool_store_unavailable", "ordered conversation tool store is unavailable")
					return
				}
				for callIndex, call := range calls {
					if previous, complete := toolCallAuthorities[call.ID]; complete && previous.state == turnToolCallTerminal {
						continue
					}
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
							if recordErr := recordCorrectableIntrinsicError(ctx, roundStore, lease, call); recordErr != nil {
								_, _ = s.turns.FailTurn(ctx, lease, "intrinsic_error_result_failed", "Core intrinsic error result could not be saved")
							}
							return
						}
						if intrinsic.ReadOnly {
							if err = roundStore.RecordConversationToolCall(ctx, lease, call); err != nil {
								return
							}
							execute, dispatchErr := roundStore.BeginConversationToolDispatch(ctx, lease, call)
							if dispatchErr != nil {
								return
							}
							if !execute {
								_, _ = roundStore.FailConversationToolDispatch(ctx, lease, call, "tool_dispatch_uncertain", "read-only intrinsic dispatch outcome is unknown")
								return
							}
							intrinsicResult, intrinsicErr := intrinsic.Execute(ctx, IntrinsicExecutionRequest{
								Lease: lease, Call: call, CanonicalArguments: arguments,
								ConversationRevision: conv.Revision,
							})
							if intrinsicErr != nil {
								if child.Err() != nil {
									return
								}
								code, summary := intrinsicTerminalFailure(call.Name, intrinsicErr)
								_, _ = roundStore.FailConversationToolDispatch(ctx, lease, call, code, summary)
								return
							}
							if intrinsicResult.TurnCommitted || intrinsicResult.ToolResult == nil {
								_, _ = roundStore.FailConversationToolDispatch(ctx, lease, call, "invalid_intrinsic_result", "read-only intrinsic returned an invalid result")
								return
							}
							result := *intrinsicResult.ToolResult
							if result.CallID == "" {
								result.CallID = call.ID
							}
							if result.ToolName == "" {
								result.ToolName = call.Name
							}
							if result.Validate() != nil || result.CallID != call.ID || result.ToolName != call.Name {
								_, _ = roundStore.FailConversationToolDispatch(ctx, lease, call, "invalid_intrinsic_result", "read-only intrinsic returned an invalid result")
								return
							}
							if err = roundStore.RecordConversationToolResult(ctx, lease, result); err != nil {
								return
							}
							toolCallAuthorities[call.ID] = turnToolCallAuthority{call: call, state: turnToolCallTerminal, result: &result}
							continue
						}
						intrinsicResult, intrinsicErr := intrinsic.Execute(ctx, IntrinsicExecutionRequest{
							Lease: lease, Call: call, CanonicalArguments: arguments,
							ConversationRevision: conv.Revision,
						})
						if errors.Is(intrinsicErr, ErrInvalid) {
							if recordErr := recordCorrectableIntrinsicError(ctx, roundStore, lease, call); recordErr != nil {
								_, _ = s.turns.FailTurn(ctx, lease, "intrinsic_error_result_failed", "Core intrinsic error result could not be saved")
							}
							return
						}
						if intrinsicErr != nil || !intrinsicResult.TurnCommitted || intrinsicResult.ToolResult != nil {
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
					if err = roundStore.RecordConversationToolCall(ctx, lease, call); err != nil {
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
						execute, dispatchErr := roundStore.BeginConversationToolDispatch(ctx, lease, call)
						if dispatchErr != nil {
							return
						}
						if !execute {
							_, _ = roundStore.FailConversationToolDispatch(ctx, lease, call, "tool_dispatch_uncertain", "read-only tool dispatch outcome is unknown")
							return
						}
						result, executeErr := executable.Execute(child, ToolExecutionRequest{Call: call})
						if executeErr != nil {
							if child.Err() != nil {
								return
							}
							// Tool errors are model observations, not conversation failures.
							// Returning a bounded error result lets the model correct invalid
							// arguments or choose another tool in the next round.
							result = ToolResult{
								CallID:   call.ID,
								ToolName: call.Name,
								Content:  "tool execution failed; correct the arguments or use another available tool",
								IsError:  true,
							}
						}
						if result.CallID == "" {
							result.CallID = call.ID
						}
						result.ToolName = call.Name
						if result.Validate() != nil || result.CallID != call.ID {
							_, _ = roundStore.FailConversationToolDispatch(ctx, lease, call, "invalid_tool_result", "read-only tool returned an invalid result")
							return
						}
						if err = roundStore.RecordConversationToolResult(ctx, lease, result); err != nil {
							return
						}
						toolCallAuthorities[call.ID] = turnToolCallAuthority{call: call, state: turnToolCallTerminal, result: &result}
						continue
					}
					args, argsErr := canonicalJSON(call.Arguments, MaxToolArgumentsBytes)
					if argsErr != nil {
						_, _ = s.turns.FailTurn(ctx, lease, "invalid_tool_arguments", "tool arguments are invalid")
						return
					}
					argsDigest := digest(string(args))
					round := uint32(callIndex)
					if recovery, recoveryOK := s.turns.(ConversationToolRecoveryStore); recoveryOK {
						if previous, previousErr := recovery.ObserveConversationTool(ctx, id); previousErr == nil {
							if previous.Round >= round {
								round = previous.Round + 1
							}
						}
					}
					attemptID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("conversation-tool:%s:%d:%s", turn.RequestID, round, call.ID))).String()
					_, _, _, prepErr := toolStore.PrepareConversationTool(ctx, PrepareToolCommand{Lease: lease, Round: round, Call: call, Snapshot: bound, CanonicalArguments: args, ArgumentsDigest: argsDigest, SafeSummary: "conversation tool call " + call.Name, IdempotencyKey: attemptID, ExpiresAt: s.clock().Add(10 * time.Minute)})
					if prepErr != nil {
						_, _ = s.turns.FailTurn(ctx, lease, "tool_prepare_failed", "conversation tool preparation failed")
						return
					}
					return
				}
				if _, err = roundStore.CompleteConversationToolRound(ctx, lease); err != nil {
					return
				}
				return
			}
			if durableDispatch && !replayed {
				if err := dispatchStore.RecordTurnModelResult(ctx, lease, out.result); err != nil {
					return
				}
			}
			m := out.result.Message
			m.Content = history.continuationContent + m.Content
			m.ReasoningContent = history.priorReasoning + m.ReasoningContent
			historyTasks, historyPlans, historyReferences, historySummaries, historyResults := turnToolMetadata(conv.Messages[persistedMessageCount:])
			m.RelatedTaskIDs = stableIDs(append(append(m.RelatedTaskIDs, out.result.RelatedTaskIDs...), historyTasks...))
			m.RelatedPlanIDs = stableIDs(append(append(m.RelatedPlanIDs, out.result.RelatedPlanIDs...), historyPlans...))
			m.References = stableReferences(append(append(m.References, out.result.References...), historyReferences...))
			m.ToolSummaries = stableStrings(append(append(m.ToolSummaries, out.result.ToolSummaries...), historySummaries...))
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
			conversationTitle := s.replaceProvisionalConversationTitle(ctx, conv.Title, conversationTitleUserText, m.Content)
			response := ChatResponse{RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: conv.Revision, Message: m, Done: true, ModelProfileID: turn.ProfileID, RelatedTaskIDs: append([]string(nil), m.RelatedTaskIDs...), RelatedPlanIDs: append([]string(nil), m.RelatedPlanIDs...), References: cloneReferences(m.References), ToolSummaries: append([]string(nil), m.ToolSummaries...), ToolResults: historyResults, ConversationTitle: conversationTitle, ConversationTitleSource: conversationTitleUserText}
			if _, commitErr := s.turns.CommitTurn(ctx, lease, response); commitErr != nil {
				current, readErr := s.turns.GetTurn(ctx, turn.ID)
				if readErr == nil && current.State == TurnCompleted {
					return
				}
				_, _ = s.turns.FailTurn(ctx, lease, "turn_commit_failed", "conversation response could not be committed")
			}
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

func (s *Service) registerTurnOrdering(id string, ordering *turnDeltaOrdering) {
	s.turnOrderingMu.Lock()
	s.turnOrdering[id] = ordering
	s.turnOrderingMu.Unlock()
}

func (s *Service) unregisterTurnOrdering(id string, ordering *turnDeltaOrdering) {
	s.turnOrderingMu.Lock()
	if s.turnOrdering[id] == ordering {
		delete(s.turnOrdering, id)
	}
	s.turnOrderingMu.Unlock()
}

func (s *Service) currentTurnOrdering(id string) *turnDeltaOrdering {
	s.turnOrderingMu.Lock()
	defer s.turnOrderingMu.Unlock()
	return s.turnOrdering[id]
}

func (s *Service) resolveTurnAttachmentInputParts(ctx context.Context, turn Turn, steers []TurnSteer) (map[string][]coremodel.MessageInputPart, error) {
	resolver, _ := s.turns.(TurnAttachmentContentResolver)
	return resolveTurnAttachmentInputParts(ctx, resolver, turn, steers)
}

func resolveTurnAttachmentInputParts(ctx context.Context, resolver TurnAttachmentContentResolver, turn Turn, steers []TurnSteer) (map[string][]coremodel.MessageInputPart, error) {
	all := []struct {
		id, text    string
		attachments []TurnAttachment
	}{{uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-user-prompt:"+turn.ID)).String(), turn.Prompt, turn.AttachmentSources}}
	for _, steer := range steers {
		all = append(all, struct {
			id, text    string
			attachments []TurnAttachment
		}{uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-steer-user:"+steer.RequestID)).String(), steer.Instruction, steer.AttachmentSources})
	}
	result := make(map[string][]coremodel.MessageInputPart)
	for _, input := range all {
		if len(input.attachments) == 0 {
			continue
		}
		parts := []coremodel.MessageInputPart{{Type: coremodel.MessageInputPartText, Text: input.text}}
		modelAttachmentCount := 0
		for _, attachment := range input.attachments {
			if !IsTurnModelReadableAttachment(attachment) {
				continue
			}
			if resolver == nil {
				return nil, ErrInvalid
			}
			data, err := resolver.ResolveTurnAttachment(ctx, turn, attachment)
			if err != nil {
				return nil, err
			}
			if err = ValidateTurnModelAttachmentContent(attachment, data); err != nil {
				clear(data)
				return nil, err
			}
			switch {
			case attachment.Kind == TurnAttachmentKindImage:
				parts = append(parts, coremodel.MessageInputPart{Type: coremodel.MessageInputPartImage, Image: coremodel.NewImageInput(attachment.MediaType, data)})
				modelAttachmentCount++
			case attachment.Kind == TurnAttachmentKindFile:
				parts = append(parts, coremodel.MessageInputPart{Type: coremodel.MessageInputPartText, Text: "[UNTRUSTED ATTACHMENT: " + attachment.Name + "]\n" + string(data) + "\n[END UNTRUSTED ATTACHMENT]"})
				modelAttachmentCount++
			default:
				clear(data)
				return nil, ErrInvalid
			}
			clear(data)
		}
		if modelAttachmentCount != 0 {
			result[input.id] = parts
		}
	}
	return result, nil
}

const (
	modelDispatchUncertainCode    = "provider_uncertain"
	modelDispatchUncertainSummary = "model dispatch outcome is unknown"
	modelResponseTimeoutCode      = "provider_timeout"
	modelResponseTimeoutSummary   = "model stream stopped producing progress; outcome is unknown; send a new turn to retry"
	modelBudgetExhaustedCode      = "model_budget_exhausted"
	modelBudgetExhaustedSummary   = "model execution budget was exhausted before a final response"
	toolBudgetExhaustedCode       = "tool_budget_exhausted"
	toolBudgetExhaustedSummary    = "tool call budget was exhausted before a final response"
	modelProviderRejectedCode     = "provider_rejected"
	modelProviderRejectedSummary  = "model provider rejected the request"
)

func classifyModelDispatchFailure(err error) (string, string) {
	if errors.Is(err, ErrModelBudgetExhausted) {
		return modelBudgetExhaustedCode, modelBudgetExhaustedSummary
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return modelResponseTimeoutCode, modelResponseTimeoutSummary
	}
	if coremodel.SafeFailureClass(err) == "provider_http_4xx" {
		return modelProviderRejectedCode, modelProviderRejectedSummary
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return modelResponseTimeoutCode, modelResponseTimeoutSummary
	}
	return modelDispatchUncertainCode, modelDispatchUncertainSummary
}

func validModelContinuation(result ModelRunResult) bool {
	if !result.Continue || result.Done || len(result.ToolCalls) != 0 || len(result.Message.ToolCalls) != 0 ||
		(result.Message.Content == "" && result.Message.ReasoningContent == "") {
		return false
	}
	message := result.Message
	if message.Content == "" {
		message.Content = "continuation"
	}
	return message.Validate() == nil
}

func uncertainModelFailure(turn Turn) (string, string) {
	if strings.TrimSpace(turn.TerminalCode) != "" && strings.TrimSpace(turn.TerminalSummary) != "" {
		return turn.TerminalCode, turn.TerminalSummary
	}
	return modelDispatchUncertainCode, modelDispatchUncertainSummary
}

func conversationToolAttemptContent(attempt ToolAttempt) string {
	content := attempt.SafeSummary
	if len(attempt.Result) > 0 {
		var stored coretask.Result
		if json.Unmarshal(attempt.Result, &stored) == nil && stored.Validate() == nil {
			switch {
			case stored.Text != "":
				content = stored.Text
			case len(stored.JSON) > 0:
				content = string(stored.JSON)
			case stored.Summary != "":
				content = stored.Summary
			}
		}
	}
	if attempt.State != "completed" && content == "" {
		return "tool call denied"
	}
	return content
}

func intrinsicTerminalFailure(toolName string, err error) (string, string) {
	if errors.Is(err, ErrInvalid) {
		return "invalid_intrinsic_arguments", "Core intrinsic arguments are invalid"
	}
	if toolName == coremodel.IntrinsicCloudWorkerDestroyToolName {
		return "cloud_worker_destroy_failed", "Worker could not be destroyed"
	}
	if toolName == coremodel.IntrinsicScheduleCreateToolName {
		return "schedule_persistence_failed", "Schedule could not be saved"
	}
	if toolName == coremodel.IntrinsicStaticSitePublishToolName {
		return "static_site_publish_failed", "Static page could not be published"
	}
	return "intrinsic_failed", "Core intrinsic operation failed"
}

func recordCorrectableIntrinsicError(ctx context.Context, store OrderedConversationToolStore, lease TurnLease, call ToolCall) error {
	if err := store.RecordConversationToolCall(ctx, lease, call); err != nil {
		return err
	}
	if _, err := store.BeginConversationToolDispatch(ctx, lease, call); err != nil {
		return err
	}
	content := "tool arguments are invalid; correct them according to the tool schema and call again"
	if call.Name == coremodel.IntrinsicStaticSitePublishToolName {
		content = staticSitePublishCorrection
	}
	result := ToolResult{
		CallID: call.ID, ToolName: call.Name, IsError: true,
		Content: content,
	}
	if err := store.RecordConversationToolResult(ctx, lease, result); err != nil {
		return err
	}
	_, err := store.CompleteConversationToolRound(ctx, lease)
	return err
}

func (s *Service) resolveAcceptedTurnExtensions(ctx context.Context, snapshots []ExtensionExecutionSnapshot) ([]ResolvedExtension, error) {
	return s.resolveAcceptedTurnExtensionsForContinuation(ctx, snapshots, false)
}

func (s *Service) resolveAcceptedTurnExtensionsForContinuation(ctx context.Context, snapshots []ExtensionExecutionSnapshot, omitContextBound bool) ([]ResolvedExtension, error) {
	if len(snapshots) == 0 {
		return nil, nil
	}
	selections := make([]ExtensionSelection, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if contextBoundExtensionSource(snapshot.Source) {
			continue
		}
		selections = append(selections, snapshot.Selection)
	}
	resolved, err := s.extensions.ResolveExtensions(ctx, selections)
	if err != nil {
		return nil, ErrConflict
	}
	expected := make(map[string]string, len(snapshots))
	for _, snapshot := range snapshots {
		if omitContextBound && contextBoundExtensionSource(snapshot.Source) {
			continue
		}
		expected[snapshot.Selection.ID] = snapshot.ContentDigest + ":" + snapshot.ArtifactDigest + ":" + snapshot.ToolSchemaDigest
	}
	accepted := make([]ResolvedExtension, 0, len(snapshots))
	matched := make(map[string]struct{}, len(snapshots))
	for _, extension := range resolved {
		snapshot := snapshotForResolved(extension)
		want, ok := expected[snapshot.Selection.ID]
		if !ok {
			// Resolver chains may expose tools that became available after this
			// turn was accepted. They are outside the immutable turn snapshot:
			// exclude them without invalidating the accepted tools.
			continue
		}
		if _, duplicate := matched[snapshot.Selection.ID]; duplicate || want != snapshot.ContentDigest+":"+snapshot.ArtifactDigest+":"+snapshot.ToolSchemaDigest {
			return nil, ErrConflict
		}
		matched[snapshot.Selection.ID] = struct{}{}
		accepted = append(accepted, extension)
	}
	if len(matched) != len(expected) {
		return nil, ErrConflict
	}
	return accepted, nil
}

func contextBoundExtensionSource(source string) bool {
	return source == "builtin:web_search:tavily" || source == "builtin:knowledge:semantic" || source == "product-capability"
}

func appendSystemPrompt(base, guidance string) string {
	if strings.TrimSpace(base) == "" {
		return guidance
	}
	return strings.TrimSpace(base) + "\n\n" + guidance
}

type toolLoopRecovery uint8

const (
	toolLoopNone toolLoopRecovery = iota
	toolLoopNudge
	toolLoopSynthesize
)

func toolLoopRecoveryFor(pairs []string) toolLoopRecovery {
	if repeatedTail(pairs, 4) || alternatingTail(pairs, 8) {
		return toolLoopSynthesize
	}
	if repeatedTail(pairs, 3) || alternatingTail(pairs, 6) {
		return toolLoopNudge
	}
	return toolLoopNone
}

func repeatedTail(values []string, count int) bool {
	if len(values) < count {
		return false
	}
	tail := values[len(values)-count:]
	for index := 1; index < len(tail); index++ {
		if tail[index] != tail[0] {
			return false
		}
	}
	return true
}

func alternatingTail(values []string, count int) bool {
	if len(values) < count || count < 4 {
		return false
	}
	tail := values[len(values)-count:]
	if tail[0] == tail[1] {
		return false
	}
	for index := 2; index < len(tail); index++ {
		if tail[index] != tail[index%2] {
			return false
		}
	}
	return true
}

func toolLoopPairIdentity(call ToolCall, result ToolResult) (string, error) {
	arguments, err := canonicalJSON(call.Arguments, MaxToolArgumentsBytes)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(call.Name) == "local_sandbox_run" {
		var values map[string]any
		if json.Unmarshal(arguments, &values) != nil {
			return "", ErrInvalid
		}
		if script, ok := values["script"].(string); ok {
			values["script"] = normalizeSimpleShellSpacing(script)
			arguments, err = json.Marshal(values)
			if err != nil {
				return "", err
			}
		}
	}
	type resultIdentity struct {
		Content string `json:"content"`
		IsError bool   `json:"is_error"`
		Summary string `json:"summary,omitempty"`
	}
	normalizedResult, err := json.Marshal(resultIdentity{
		Content: normalizeToolLoopPayload(result.Content),
		IsError: result.IsError,
		Summary: normalizeToolLoopPayload(result.Summary),
	})
	if err != nil {
		return "", err
	}
	return digest(strings.TrimSpace(call.Name) + "\n" + string(arguments) + "\n" + string(normalizedResult)), nil
}

func normalizeSimpleShellSpacing(raw string) string {
	for _, value := range raw {
		switch value {
		case '\'', '"', '\\', '\n', '\r', ';', '&', '|', '<', '>', '(', ')', '{', '}', '$', '`', '#', '*', '?', '[', ']', '~':
			return raw
		}
	}
	trimmed := strings.Trim(raw, " \t")
	if trimmed == "" {
		return ""
	}
	var normalized strings.Builder
	normalized.Grow(len(trimmed))
	spacing := false
	for index := 0; index < len(trimmed); index++ {
		switch trimmed[index] {
		case ' ', '\t':
			spacing = true
		default:
			if spacing && normalized.Len() != 0 {
				normalized.WriteByte(' ')
			}
			spacing = false
			normalized.WriteByte(trimmed[index])
		}
	}
	return normalized.String()
}

func normalizeToolLoopPayload(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var value any
	if json.Unmarshal([]byte(trimmed), &value) == nil {
		removeToolLoopTransportFields(value)
		if canonical, err := json.Marshal(value); err == nil {
			return string(canonical)
		}
	}
	return strings.Join(strings.Fields(trimmed), " ")
}

func removeToolLoopTransportFields(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalizedKey := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
			switch normalizedKey {
			case "callid", "timestamp", "createdat", "updatedat":
				delete(typed, key)
			default:
				removeToolLoopTransportFields(child)
			}
		}
	case []any:
		for _, child := range typed {
			removeToolLoopTransportFields(child)
		}
	}
}

type turnToolCallState uint8

const (
	turnToolCallPending turnToolCallState = iota + 1
	turnToolCallTerminal
)

type turnToolCallAuthority struct {
	call   ToolCall
	state  turnToolCallState
	result *ToolResult
}

func terminalCloudWorkerContent(authorities map[string]turnToolCallAuthority) (string, []string, bool) {
	content, workerID, appliedSteerIDs, ok := terminalCloudWorkerResult(authorities, "succeeded")
	if !ok {
		return "", nil, false
	}
	if workerID != "" {
		content += "\n\nWorker " + workerID + " is retained for reuse. Do you want to destroy it?"
	}
	return content, appliedSteerIDs, true
}

func terminalFailedCloudWorkerContent(authorities map[string]turnToolCallAuthority) (string, bool) {
	content, _, _, ok := terminalCloudWorkerResult(authorities, "failed")
	if !ok {
		return "", false
	}
	return "Cloud Worker failed: " + content, true
}

func terminalCloudWorkerResult(authorities map[string]turnToolCallAuthority, status string) (string, string, []string, bool) {
	for _, authority := range authorities {
		if authority.state != turnToolCallTerminal || authority.call.Name != coremodel.IntrinsicCloudWorkerProposeToolName ||
			authority.result == nil || authority.result.ToolName != coremodel.IntrinsicCloudWorkerProposeToolName {
			continue
		}
		var completion struct {
			Schema          string   `json:"schema"`
			Status          string   `json:"status"`
			WorkerID        string   `json:"worker_id"`
			WorkerReport    string   `json:"worker_report"`
			AppliedSteerIDs []string `json:"applied_steer_ids"`
		}
		if json.Unmarshal([]byte(authority.result.Content), &completion) != nil ||
			completion.Schema != "dirextalk.ssh-worker-completion/v1" || completion.Status != status {
			continue
		}
		content := strings.TrimSpace(completion.WorkerReport)
		if content == "" {
			content = strings.TrimSpace(authority.result.Summary)
		}
		if content == "" {
			continue
		}
		return content, strings.TrimSpace(completion.WorkerID), completion.AppliedSteerIDs, true
	}
	return "", "", nil, false
}

func modelResultCallsTool(result ModelRunResult, toolName string) bool {
	for _, calls := range [][]ToolCall{result.ToolCalls, result.Message.ToolCalls} {
		for _, call := range calls {
			if call.Name == toolName {
				return true
			}
		}
	}
	return false
}

func hasUnappliedDeferredWorkerSteer(steers []TurnSteer, appliedSteerIDs []string) bool {
	applied := make(map[string]struct{}, len(appliedSteerIDs))
	for _, id := range appliedSteerIDs {
		applied[id] = struct{}{}
	}
	for _, steer := range steers {
		if steer.Deferred {
			if _, ok := applied[steer.RequestID]; !ok {
				return true
			}
		}
	}
	return false
}

type turnHistoryReplay struct {
	authorities         map[string]turnToolCallAuthority
	continuationContent string
	priorReasoning      string
	continueOutput      bool
	forcedToolName      string
	loopRecovery        toolLoopRecovery
}

func (s *Service) appendTurnToolHistory(ctx context.Context, turn Turn, conversation *Conversation, ignoreLatestOutputFragment bool) (turnHistoryReplay, error) {
	if conversation == nil {
		return turnHistoryReplay{}, ErrInvalid
	}
	const pageSize = 1000
	var events []TurnEvent
	for cursor := int64(0); ; {
		page, err := s.turns.LoadTurnEvents(ctx, turn.ID, cursor, pageSize)
		if err != nil {
			return turnHistoryReplay{}, err
		}
		if len(page) == 0 {
			break
		}
		events = append(events, page...)
		next := page[len(page)-1].Sequence
		if next <= cursor {
			return turnHistoryReplay{}, ErrConflict
		}
		cursor = next
		if len(page) < pageSize {
			break
		}
	}
	authorities := make(map[string]turnToolCallAuthority)
	loopActions := make(map[string]ToolCall)
	loopPairs := make([]string, 0, 8)
	type batchResult struct {
		result    ToolResult
		createdAt time.Time
	}
	type toolBatch struct {
		content       strings.Builder
		reasoning     strings.Builder
		calls         []ToolCall
		results       map[string]batchResult
		createdAt     time.Time
		firstSequence int64
	}
	batch := toolBatch{results: make(map[string]batchResult)}
	var continuationContent strings.Builder
	var completedReasoning strings.Builder
	continueOutput := false
	forcedToolName := ""
	batchComplete := func() bool {
		return len(batch.calls) != 0 && len(batch.results) == len(batch.calls)
	}
	flushBatch := func() error {
		if len(batch.calls) == 0 {
			return nil
		}
		if !batchComplete() {
			return ErrConflict
		}
		continueOutput = false
		createdAt := nextMessageTime(*conversation, batch.createdAt)
		conversation.Messages = append(conversation.Messages, Message{
			ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-tool-batch:"+turn.ID+":"+batch.calls[0].ID)).String(),
			Role: RoleAssistant, Content: batch.content.String(), ReasoningContent: batch.reasoning.String(),
			ToolCalls: append([]ToolCall(nil), batch.calls...), CreatedAt: createdAt, ModelProfileID: turn.ProfileID,
		})
		completedReasoning.WriteString(batch.reasoning.String())
		for _, call := range batch.calls {
			stored := batch.results[call.ID]
			createdAt = nextMessageTime(*conversation, stored.createdAt)
			conversation.Messages = append(conversation.Messages, Message{
				ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-tool-result:"+turn.ID+":"+call.ID)).String(),
				Role: RoleTool, ToolResults: []ToolResult{stored.result}, References: cloneReferences(stored.result.References),
				CreatedAt: createdAt, ModelProfileID: turn.ProfileID,
			})
		}
		batch = toolBatch{results: make(map[string]batchResult)}
		return nil
	}
	flushContinuation := func() {
		if len(batch.calls) != 0 || (batch.content.Len() == 0 && batch.reasoning.Len() == 0) {
			return
		}
		createdAt := nextMessageTime(*conversation, batch.createdAt)
		conversation.Messages = append(conversation.Messages, Message{
			ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("turn-output-fragment:%s:%d", turn.ID, batch.firstSequence))).String(),
			Role: RoleAssistant, Content: batch.content.String(), ReasoningContent: batch.reasoning.String(),
			CreatedAt: createdAt, ModelProfileID: turn.ProfileID,
		})
		continuationContent.WriteString(batch.content.String())
		completedReasoning.WriteString(batch.reasoning.String())
		continueOutput = true
		batch = toolBatch{results: make(map[string]batchResult)}
	}
	for _, event := range events {
		switch event.Kind {
		case TurnEventSteered:
			flushContinuation()
			continueOutput = false
			loopActions = make(map[string]ToolCall)
			loopPairs = loopPairs[:0]
		case TurnEventStarted:
			if batchComplete() {
				if err := flushBatch(); err != nil {
					return turnHistoryReplay{}, err
				}
			} else if ignoreLatestOutputFragment && event.Sequence == turn.LastSequence {
				batch = toolBatch{results: make(map[string]batchResult)}
			} else {
				flushContinuation()
			}
		case TurnEventDelta:
			if batch.firstSequence == 0 {
				batch.firstSequence = event.Sequence
				batch.createdAt = event.CreatedAt
			}
			batch.content.WriteString(event.Text)
			batch.reasoning.WriteString(event.ReasoningContent)
		case TurnEventToolCall:
			if event.ToolCall == nil || event.ToolCall.Validate() != nil {
				return turnHistoryReplay{}, ErrConflict
			}
			if _, exists := authorities[event.ToolCall.ID]; exists {
				return turnHistoryReplay{}, ErrConflict
			}
			continueOutput = false
			authorities[event.ToolCall.ID] = turnToolCallAuthority{call: *event.ToolCall, state: turnToolCallPending}
			loopActions[event.ToolCall.ID] = *event.ToolCall
			if len(batch.calls) == 0 {
				batch.createdAt = event.CreatedAt
			}
			batch.calls = append(batch.calls, *event.ToolCall)
		case TurnEventToolResult:
			if event.ToolResult == nil || event.ToolResult.Validate() != nil {
				return turnHistoryReplay{}, ErrConflict
			}
			authority, exists := authorities[event.ToolResult.CallID]
			if !exists || authority.state == turnToolCallTerminal || event.ToolResult.ToolName != authority.call.Name {
				return turnHistoryReplay{}, ErrConflict
			}
			result := *event.ToolResult
			if coremodel.IsIntrinsicToolName(result.ToolName) {
				forcedToolName = ""
				if result.ToolName == coremodel.IntrinsicStaticSitePublishToolName && result.IsError && result.Content == staticSitePublishCorrection {
					forcedToolName = result.ToolName
				}
			}
			authority.state, authority.result = turnToolCallTerminal, &result
			authorities[event.ToolResult.CallID] = authority
			batch.results[event.ToolResult.CallID] = batchResult{result: result, createdAt: event.CreatedAt}
			if action, ok := loopActions[event.ToolResult.CallID]; ok {
				identity, identityErr := toolLoopPairIdentity(action, result)
				if identityErr != nil {
					return turnHistoryReplay{}, ErrConflict
				}
				if len(loopPairs) == cap(loopPairs) {
					copy(loopPairs, loopPairs[1:])
					loopPairs = loopPairs[:len(loopPairs)-1]
				}
				loopPairs = append(loopPairs, identity)
				delete(loopActions, event.ToolResult.CallID)
			}
		}
	}
	if batchComplete() {
		if err := flushBatch(); err != nil {
			return turnHistoryReplay{}, err
		}
	}
	return turnHistoryReplay{
		authorities: authorities, continuationContent: continuationContent.String(), priorReasoning: completedReasoning.String(),
		continueOutput: continueOutput, forcedToolName: forcedToolName, loopRecovery: toolLoopRecoveryFor(loopPairs),
	}, nil
}

func conversationForTurnContinuation(conversation Conversation, turn Turn) (Conversation, int, bool, error) {
	out := conversation.Snapshot()
	currentUserID := TurnUserMessageID(turn.RequestID)
	for index, message := range out.Messages {
		if message.ID != currentUserID {
			continue
		}
		if message.Role != RoleUser || message.Content != turn.Prompt || message.ModelProfileID != turn.ProfileID {
			return Conversation{}, 0, false, ErrConflict
		}
		out.Messages = append([]Message(nil), out.Messages[:index]...)
		return out, index, true, nil
	}
	return out, len(out.Messages), false, nil
}

func turnToolMetadata(messages []Message) ([]string, []string, []Reference, []string, []ToolResult) {
	var taskIDs, planIDs []string
	var references []Reference
	var summaries []string
	var results []ToolResult
	for _, message := range messages {
		for _, result := range message.ToolResults {
			result.RelatedTaskIDs = append([]string(nil), result.RelatedTaskIDs...)
			result.RelatedPlanIDs = append([]string(nil), result.RelatedPlanIDs...)
			result.References = cloneReferences(result.References)
			results = append(results, result)
			taskIDs = append(taskIDs, result.RelatedTaskIDs...)
			planIDs = append(planIDs, result.RelatedPlanIDs...)
			references = append(references, result.References...)
			if result.Summary != "" {
				summaries = append(summaries, result.Summary)
			}
		}
	}
	return stableIDs(taskIDs), stableIDs(planIDs), stableReferences(references), stableStrings(summaries), results
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

func outputContinuationMessage(conversation Conversation, profileID, identity string, now time.Time) (Message, error) {
	message := Message{
		ID:             uuid.NewSHA1(uuid.NameSpaceOID, []byte("model-output-continuation:"+identity)).String(),
		Role:           RoleUser,
		Content:        outputContinuationGuidance,
		CreatedAt:      nextMessageTime(conversation, now),
		ModelProfileID: profileID,
	}
	if err := message.Validate(); err != nil {
		return Message{}, err
	}
	return message, nil
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

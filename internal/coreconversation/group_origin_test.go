package coreconversation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type groupGuardFunc func(context.Context, GroupOrigin) error

func (f groupGuardFunc) ValidateGroupOrigin(ctx context.Context, origin GroupOrigin) error {
	return f(ctx, origin)
}

func testGroupOrigin() GroupOrigin {
	return GroupOrigin{RequestID: uuid.NewString(), RoomID: "!group:example.test", EventID: "$event",
		ActorID: "@member:example.test", OwnerID: "@owner:example.test", AgentMXID: "@ying:example.test",
		AccountGeneration: 3, BindingRevision: 7}
}

type groupAdmissionStore struct{ *terminalAdmissionStore }

func (s *groupAdmissionStore) LoadConversation(_ context.Context, id string) (Conversation, error) {
	s.fakeStore.mu.Lock()
	defer s.fakeStore.mu.Unlock()
	conversation, found := s.fakeStore.conv[id]
	if !found {
		return Conversation{}, ErrConflict
	}
	return conversation.Snapshot(), nil
}

func (s *groupAdmissionStore) PrepareTurnRuntimeAdmission(ctx context.Context, command TurnStartCommand) (Turn, error) {
	turn, err := s.publicActiveTurnStore.PrepareTurnRuntimeAdmission(ctx, command)
	turn.GroupOrigin = cloneGroupOrigin(command.GroupOrigin)
	return turn, err
}

type groupReplayAdmissionStore struct {
	*groupAdmissionStore
	accepted *Turn
}

func (s *groupReplayAdmissionStore) GetTurnByRequestID(context.Context, string) (Turn, error) {
	if s.accepted == nil {
		return Turn{}, ErrConflict
	}
	return *s.accepted, nil
}

func (s *groupReplayAdmissionStore) StartTurnWithRuntime(ctx context.Context, command TurnStartCommand, runtime TurnRuntimeSnapshot) (Turn, error) {
	turn, err := s.terminalAdmissionStore.StartTurnWithRuntime(ctx, command, runtime)
	turn.GroupOrigin = cloneGroupOrigin(command.GroupOrigin)
	turn.ExpectedRevision = command.ExpectedRevision
	turn.RequestFingerprint = command.Fingerprint()
	turn.RuntimeSnapshot = &runtime
	s.accepted = &turn
	return turn, err
}

type forbiddenOwnerExtensions struct{ calls int }

func (r *forbiddenOwnerExtensions) ResolveExtensions(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
	r.calls++
	return nil, errors.New("private owner resolver must not be reached")
}

func (r *forbiddenOwnerExtensions) MergeAutomaticExtensions(context.Context, []ExtensionSelection) ([]ExtensionSelection, error) {
	r.calls++
	return nil, errors.New("private automatic catalog must not be reached")
}

type groupProjectionProbeStore struct {
	*attemptTurnStore
	calls int
}

func (s *groupProjectionProbeStore) ProjectModelContext(context.Context, Conversation, string, uint64) (Conversation, error) {
	s.calls++
	return Conversation{}, errors.New("private context projection must not be called")
}

func TestGroupOriginSeparatesConversationScopeFromEventIdentity(t *testing.T) {
	origin := testGroupOrigin()
	if err := origin.Validate(); err != nil {
		t.Fatal(err)
	}
	next := origin
	next.RequestID, next.EventID, next.ActorID = uuid.NewString(), "$next", "@another:example.test"
	if next.ConversationID() != origin.ConversationID() {
		t.Fatal("events in one binding must share the group conversation")
	}
	for _, mutate := range []func(*GroupOrigin){
		func(g *GroupOrigin) { g.RoomID = "!other:example.test" },
		func(g *GroupOrigin) { g.OwnerID = "@other:example.test" },
		func(g *GroupOrigin) { g.AgentMXID = "@other-ying:example.test" },
		func(g *GroupOrigin) { g.AccountGeneration++ },
		func(g *GroupOrigin) { g.BindingRevision++ },
	} {
		changed := origin
		mutate(&changed)
		if changed.ConversationID() == origin.ConversationID() {
			t.Fatal("different group authority reused a conversation")
		}
	}
	if _, ok := GroupOriginFromContext(context.Background()); ok {
		t.Fatal("ordinary context acquired group authority")
	}
}

func TestStartGroupTurnExcludesOwnerPromptAndAutomaticExtensions(t *testing.T) {
	origin := testGroupOrigin()
	profile := testTurnSnapshot()
	profile.SystemPrompt = "PRIVATE OWNER GLOBAL INSTRUCTIONS"
	private := &forbiddenOwnerExtensions{}
	store := &groupAdmissionStore{&terminalAdmissionStore{publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()}}}
	service, err := NewService(store, &fakeModel{}, private, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	guardCalls := 0
	service.SetGroupAuthorizationGuard(groupGuardFunc(func(_ context.Context, got GroupOrigin) error {
		guardCalls++
		if got != origin {
			t.Fatal("changed trusted origin")
		}
		return nil
	}))
	command := TurnStartCommand{RequestID: origin.RequestID, OwnerID: origin.OwnerID, AccountGeneration: origin.AccountGeneration,
		Prompt: "answer the group question", ProfileID: profile.ProfileID, ExpectedProfileRevision: profile.Revision,
		ExpectedCredentialVersion: profile.CredentialVersion}
	if _, err := service.StartGroupTurn(context.Background(), command, origin); err != nil {
		t.Fatal(err)
	}
	if guardCalls == 0 || private.calls != 0 || len(store.commands) != 1 || len(store.runtimes) != 1 {
		t.Fatalf("guard=%d private=%d admissions=%d", guardCalls, private.calls, len(store.commands))
	}
	accepted, runtime := store.commands[0], store.runtimes[0]
	if accepted.ConversationID != origin.ConversationID() || accepted.ProfileSnapshot.SystemPrompt != "" ||
		!sameGroupOrigin(accepted.GroupOrigin, &origin) || !sameGroupOrigin(runtime.GroupOrigin, &origin) ||
		strings.Contains(runtime.CompiledSystemPrompt, "PRIVATE OWNER") || !strings.Contains(runtime.CompiledSystemPrompt, groupSystemGuidance) ||
		!strings.Contains(runtime.CompiledSystemPrompt, origin.ActorID) || accepted.Prompt != command.Prompt ||
		len(runtime.IntrinsicTools) != 0 || len(accepted.ExtensionSnapshots) != 0 {
		t.Fatal("group admission inherited owner state")
	}
	if err := runtime.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(runtime)
	var restored TurnRuntimeSnapshot
	if json.Unmarshal(raw, &restored) != nil || restored.Digest() != runtime.Digest() || !sameGroupOrigin(restored.GroupOrigin, &origin) {
		t.Fatal("origin did not survive runtime recovery")
	}
	changed := accepted
	changed.GroupOrigin = cloneGroupOrigin(accepted.GroupOrigin)
	changed.GroupOrigin.ActorID = "@another:example.test"
	if changed.Fingerprint() == accepted.Fingerprint() {
		t.Fatal("request fingerprint omitted group origin")
	}
}

func TestGroupAdmissionBindsConversationRevisionAndReplaysOriginalRevision(t *testing.T) {
	origin := testGroupOrigin()
	profile := testTurnSnapshot()
	store := &groupReplayAdmissionStore{groupAdmissionStore: &groupAdmissionStore{&terminalAdmissionStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
	}}}
	scope := origin.Scope()
	store.conv[origin.ConversationID()] = Conversation{ID: origin.ConversationID(), GroupScope: &scope, Revision: 7}
	service, _ := NewService(store, &fakeModel{}, nil,
		snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	defer service.Close()
	service.SetGroupAuthorizationGuard(groupGuardFunc(func(context.Context, GroupOrigin) error { return nil }))
	command := TurnStartCommand{RequestID: origin.RequestID, OwnerID: origin.OwnerID, AccountGeneration: origin.AccountGeneration,
		Prompt: "保留消息原文", ProfileID: profile.ProfileID, ExpectedProfileRevision: profile.Revision, ExpectedCredentialVersion: profile.CredentialVersion}
	first, err := service.StartGroupTurn(context.Background(), command, origin)
	if err != nil || first.ExpectedRevision == nil || *first.ExpectedRevision != 7 {
		t.Fatalf("group revision was not pinned: revision=%v err=%v", first.ExpectedRevision, err)
	}
	conversation := store.conv[origin.ConversationID()]
	conversation.Revision = 8
	store.conv[conversation.ID] = conversation
	replay, err := service.StartGroupTurn(context.Background(), command, origin)
	if err != nil || replay.ID != first.ID || replay.RequestFingerprint != first.RequestFingerprint ||
		replay.ExpectedRevision == nil || *replay.ExpectedRevision != 7 || len(store.commands) != 1 {
		t.Fatalf("redelivered group event acquired new revision: admissions=%d err=%v", len(store.commands), err)
	}
}

func TestGroupAdmissionRejectsPublicSpoofAndPrivateContextImports(t *testing.T) {
	origin := testGroupOrigin()
	profile := testTurnSnapshot()
	service, _ := NewService(&publicActiveTurnStore{fakeStore: newFakeStore()}, &fakeModel{}, nil,
		snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	defer service.Close()
	command := TurnStartCommand{RequestID: origin.RequestID, OwnerID: origin.OwnerID, AccountGeneration: origin.AccountGeneration,
		Prompt: "hello", ProfileID: profile.ProfileID, ExpectedProfileRevision: profile.Revision, ExpectedCredentialVersion: profile.CredentialVersion}
	spoof := command
	spoof.GroupOrigin = &origin
	if _, err := service.StartTurn(context.Background(), spoof); !errors.Is(err, ErrGroupAuthorization) {
		t.Fatalf("ordinary admission accepted group origin: %v", err)
	}
	if _, err := service.StartGroupTurn(context.Background(), command, origin); !errors.Is(err, ErrGroupAuthorization) {
		t.Fatalf("missing live guard accepted group turn: %v", err)
	}
	service.SetGroupAuthorizationGuard(groupGuardFunc(func(context.Context, GroupOrigin) error { return nil }))
	for _, mutate := range []func(*TurnStartCommand){
		func(c *TurnStartCommand) { c.ConversationID = uuid.NewString() },
		func(c *TurnStartCommand) { c.OwnerID = "@other:example.test" },
		func(c *TurnStartCommand) { c.RequestID = uuid.NewString() },
		func(c *TurnStartCommand) { c.AccountGeneration++ },
		func(c *TurnStartCommand) { c.AcceptedAttachmentIDs = []string{uuid.NewString()} },
	} {
		bad := command
		mutate(&bad)
		if _, err := service.StartGroupTurn(context.Background(), bad, origin); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted private/group cross-scope input: %v", err)
		}
	}
}

func newIsolatedGroupExecution(t *testing.T) (*Service, *attemptTurnStore, *retrySequenceModel, GroupOrigin) {
	t.Helper()
	model := &retrySequenceModel{}
	service, store, turn := newAttemptTurnService(t, model)
	t.Cleanup(func() { _ = service.Close() })
	origin := testGroupOrigin()
	turn.GroupOrigin = &origin
	turn.RequestID, turn.ConversationID = origin.RequestID, origin.ConversationID()
	turn.OwnerID, turn.AccountGeneration = origin.OwnerID, origin.AccountGeneration
	turn.ProfileSnapshot.SystemPrompt = ""
	turn.ProfileSnapshotDigest = turn.ProfileSnapshot.Digest()
	service.SetGroupAuthorizationGuard(groupGuardFunc(func(context.Context, GroupOrigin) error { return nil }))
	runtime, err := service.buildTurnAdmissionRuntime(withGroupOrigin(context.Background(), origin), turn, nil, "", TurnExecutionInteractive, TurnConstrainedWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	turn.RuntimeSnapshot = &runtime
	store.turn = turn
	scope := origin.Scope()
	store.conv[turn.ConversationID] = Conversation{GroupScope: &scope, ID: turn.ConversationID, Revision: 1,
		CreatedAt: turn.CreatedAt, UpdatedAt: turn.CreatedAt}
	return service, store, model, origin
}

func TestGroupRecoverySkipsPrivateMemoryAndFailsClosedAfterRevocation(t *testing.T) {
	t.Run("isolated model context", func(t *testing.T) {
		service, store, model, origin := newIsolatedGroupExecution(t)
		projection := &groupProjectionProbeStore{attemptTurnStore: store}
		service.store = projection
		service.SetExtensionResolver(&forbiddenOwnerExtensions{})
		service.SetMemoryRecallResolver(memoryRecallFunc(func(context.Context, string) (string, error) {
			t.Error("group execution reached private memory")
			return "PRIVATE MEMORY", nil
		}))
		service.executeTurn(context.Background(), store.turn.ID)
		if model.callCount() != 1 || store.turn.State != TurnCompleted || projection.calls != 0 {
			t.Fatalf("requests=%d state=%s error=%s", model.callCount(), store.turn.State, store.failedCode)
		}
		request := model.requests[0]
		if request.Conversation.ID != origin.ConversationID() || len(request.Conversation.Messages) != 1 ||
			strings.Contains(request.Profile.SystemPrompt, "PRIVATE") {
			t.Fatal("group model context included private state")
		}
	})
	t.Run("revoked recovered turn", func(t *testing.T) {
		service, store, model, _ := newIsolatedGroupExecution(t)
		service.SetGroupAuthorizationGuard(groupGuardFunc(func(context.Context, GroupOrigin) error { return errors.New("disabled") }))
		service.executeTurn(context.Background(), store.turn.ID)
		if model.callCount() != 0 || store.turn.State != TurnFailed || store.failedCode != "group_authorization_revoked" {
			t.Fatalf("revoked recovered turn ran: calls=%d state=%s failure=%s", model.callCount(), store.turn.State, store.failedCode)
		}
	})
	t.Run("private conversation substituted", func(t *testing.T) {
		service, store, model, _ := newIsolatedGroupExecution(t)
		private := store.conv[store.turn.ConversationID]
		private.GroupScope = nil
		store.conv[private.ID] = private
		service.executeTurn(context.Background(), store.turn.ID)
		if model.callCount() != 0 || store.failedCode != "group_scope_invalid" {
			t.Fatal("group recovery read a private conversation")
		}
	})
}

func TestGroupCapabilitiesDenyPrivateSourcesAndRevalidateBeforeEachTool(t *testing.T) {
	origin := testGroupOrigin()
	service, _, _, _ := newIsolatedGroupExecution(t)
	allowed := true
	service.SetGroupAuthorizationGuard(groupGuardFunc(func(context.Context, GroupOrigin) error {
		if !allowed {
			return errors.New("binding changed")
		}
		return nil
	}))
	selection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "v1", Digest: strings.Repeat("a", 64), AllowedTools: []string{"group_read"}}
	snapshot := ExtensionExecutionSnapshot{Selection: selection, InstallationID: selection.ID, VersionID: "v1", Source: "group-message",
		ContentDigest: selection.Digest, ArtifactDigest: selection.Digest, ReadOnly: true, ToolNames: []string{"group_read"}}
	toolCalls := 0
	service.SetGroupExtensionResolver(extensionResolverFunc(func(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
		return []ResolvedExtension{{Selection: selection, Snapshot: snapshot, Tools: []coremodel.Tool{{Name: "group_read", InputSchema: map[string]any{"type": "object"}}},
			Execute: func(context.Context, ToolExecutionRequest) (ToolResult, error) { toolCalls++; return ToolResult{}, nil }}}, nil
	}))
	ctx := withGroupOrigin(context.Background(), origin)
	resolved, err := service.resolveAcceptedTurnExtensions(ctx, []ExtensionExecutionSnapshot{snapshot})
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolve=%d err=%v", len(resolved), err)
	}
	if _, err := resolved[0].Execute(ctx, ToolExecutionRequest{}); err != nil {
		t.Fatal(err)
	}
	allowed = false
	if _, err := resolved[0].Execute(ctx, ToolExecutionRequest{}); !errors.Is(err, ErrGroupAuthorization) || toolCalls != 1 {
		t.Fatalf("revoked tool executed: calls=%d err=%v", toolCalls, err)
	}
	for _, source := range []string{"message-mcp", "github-mcp", "product-capability", "builtin:knowledge:semantic", "third-party"} {
		private := snapshot
		private.Source = source
		if _, err := service.resolveAcceptedTurnExtensions(ctx, []ExtensionExecutionSnapshot{private}); !errors.Is(err, ErrGroupAuthorization) {
			t.Fatalf("private source %q accepted: %v", source, err)
		}
	}
	if _, err := service.commitAuthorizedTurn(ctx, TurnLease{Turn: Turn{GroupOrigin: &origin}}, ChatResponse{}); !errors.Is(err, ErrGroupAuthorization) {
		t.Fatalf("revoked final answer committed: %v", err)
	}
}

func TestGroupIntrinsicsUseSeparateWorkerOfferCatalogAndLiveGuard(t *testing.T) {
	service, store, _, origin := newIsolatedGroupExecution(t)
	service.SetIntrinsicResolver(intrinsicResolverFunc(func(context.Context, TurnLease) ([]ResolvedIntrinsic, error) {
		t.Error("private-owner intrinsic resolver was called")
		return nil, ErrInvalid
	}))
	allowed := true
	service.SetGroupAuthorizationGuard(groupGuardFunc(func(context.Context, GroupOrigin) error {
		if !allowed {
			return ErrGroupAuthorization
		}
		return nil
	}))
	executions := 0
	service.SetGroupIntrinsicResolver(intrinsicResolverFunc(func(ctx context.Context, lease TurnLease) ([]ResolvedIntrinsic, error) {
		got, ok := GroupOriginFromContext(ctx)
		if !ok || got != origin || !sameGroupOrigin(lease.Turn.GroupOrigin, &origin) {
			t.Fatal("group intrinsic resolver lost trusted origin")
		}
		return []ResolvedIntrinsic{
			{Tool: coremodel.Tool{Name: coremodel.IntrinsicStaticSiteReadToolName, InputSchema: map[string]any{"type": "object"}}, ReadOnly: true},
			{Tool: coremodel.Tool{Name: coremodel.IntrinsicScheduleCreateToolName, InputSchema: map[string]any{"type": "object"}}},
			{Tool: coremodel.Tool{Name: coremodel.IntrinsicCloudWorkerProposeToolName, InputSchema: map[string]any{"type": "object"}},
				Execute: func(context.Context, IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
					executions++
					return IntrinsicExecutionResult{}, nil
				}},
		}, nil
	}))
	lease := TurnLease{Turn: store.turn, LeaseID: "test", Epoch: 1}
	resolved, err := service.resolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(resolved) != 1 || resolved[0].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName {
		t.Fatalf("private intrinsic was exposed: count=%d err=%v", len(resolved), err)
	}
	if _, err := resolved[0].Execute(context.Background(), IntrinsicExecutionRequest{Lease: lease}); err != nil {
		t.Fatal(err)
	}
	allowed = false
	if _, err := resolved[0].Execute(context.Background(), IntrinsicExecutionRequest{Lease: lease}); !errors.Is(err, ErrGroupAuthorization) || executions != 1 {
		t.Fatalf("revoked Worker offer executed: calls=%d err=%v", executions, err)
	}
}

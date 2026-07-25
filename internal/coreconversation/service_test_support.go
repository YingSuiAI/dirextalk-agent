package coreconversation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type fakeStore struct {
	mu         sync.Mutex
	conv       map[string]Conversation
	leases     map[string]ChatLease
	responses  map[string]ChatResponse
	committed  int
	calls      []ToolCall
	results    []ToolResult
	toolLeases map[string]ToolLease
	renewFail  bool
	modelSteps map[string]ModelRunResult
	mutations  map[string]struct {
		digest   string
		response ConversationMutationResponse
	}
	terminalizeFail bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{conv: map[string]Conversation{}, leases: map[string]ChatLease{}, responses: map[string]ChatResponse{}, toolLeases: map[string]ToolLease{}, modelSteps: map[string]ModelRunResult{}, mutations: map[string]struct {
		digest   string
		response ConversationMutationResponse
	}{}}
}
func (f *fakeStore) LoadModelStep(_ context.Context, req, lease, fp string, epoch uint64, profile string, round int) (ModelRunResult, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.leases[req]; l.LeaseID != lease || l.Epoch != epoch || l.Fingerprint != fp {
		return ModelRunResult{}, false, ErrConflict
	}
	r, ok := f.modelSteps[fmt.Sprintf("%s:%d", req, round)]
	return r, ok, nil
}
func (f *fakeStore) RecordModelStep(_ context.Context, req, lease, fp string, epoch uint64, profile string, round int, r ModelRunResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.leases[req]; l.LeaseID != lease || l.Epoch != epoch || l.Fingerprint != fp {
		return ErrConflict
	}
	f.modelSteps[fmt.Sprintf("%s:%d", req, round)] = r
	return nil
}
func (f *fakeStore) MarkToolDispatched(_ context.Context, req, call, lease string, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.toolLeases[req+":"+call]
	if l.LeaseID != lease || l.Epoch != epoch || (l.Status != ToolClaimNew && l.Status != ToolClaimReclaimed) {
		return ErrConflict
	}
	l.Status = ToolClaimDispatched
	f.toolLeases[req+":"+call] = l
	return nil
}
func (f *fakeStore) MarkToolUncertain(_ context.Context, req, call, lease string, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.toolLeases[req+":"+call]
	if l.LeaseID != lease || l.Epoch != epoch || l.Status != ToolClaimDispatched {
		return ErrConflict
	}
	l.Status = ToolClaimUncertain
	f.toolLeases[req+":"+call] = l
	return nil
}
func (f *fakeStore) TerminalizeToolUncertain(_ context.Context, req, call, tlease string, tepoch uint64, clease string, cepoch uint64, code, summary string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.terminalizeFail {
		return ErrConflict
	}
	tl := f.toolLeases[req+":"+call]
	cl := f.leases[req]
	if tl.LeaseID != tlease || tl.Epoch != tepoch || (tl.Status != ToolClaimDispatched && tl.Status != ToolClaimUncertain) || cl.LeaseID != clease || cl.Epoch != cepoch {
		return ErrConflict
	}
	if tl.Status == ToolClaimUncertain && cl.Status == ClaimFailed {
		return nil
	}
	tl.Status = ToolClaimUncertain
	f.toolLeases[req+":"+call] = tl
	cl.Status = ClaimFailed
	cl.FailureCode = code
	cl.FailureSummary = summary
	f.leases[req] = cl
	return nil
}
func (f *fakeStore) CreateConversation(_ context.Context, c Conversation, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.conv[c.ID]; ok {
		return ErrConflict
	}
	f.conv[c.ID] = c
	return nil
}
func (f *fakeStore) CreateConversationMutation(ctx context.Context, c CreateConversationCommand) (ConversationMutationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := "create:" + c.RequestID
	if old, ok := f.mutations[k]; ok {
		if old.digest != c.Fingerprint {
			return ConversationMutationResponse{}, ErrConflict
		}
		return old.response, nil
	}
	if err := c.Validate(); err != nil {
		return ConversationMutationResponse{}, err
	}
	if _, ok := f.conv[c.Conversation.ID]; ok {
		return ConversationMutationResponse{}, ErrConflict
	}
	conversation := c.Conversation
	now := time.Now().UTC()
	conversation.CreatedAt, conversation.UpdatedAt = now, now
	f.conv[c.Conversation.ID] = conversation
	r := ConversationMutationResponse{Conversation: conversation, RequestID: c.RequestID}
	f.mutations[k] = struct {
		digest   string
		response ConversationMutationResponse
	}{c.Fingerprint, r}
	return r, nil
}
func (f *fakeStore) DeleteConversationMutation(ctx context.Context, c DeleteConversationCommand) (ConversationMutationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := "delete:" + c.RequestID
	if old, ok := f.mutations[k]; ok {
		if old.digest != c.Fingerprint {
			return ConversationMutationResponse{}, ErrConflict
		}
		return old.response, nil
	}
	if err := c.Validate(); err != nil {
		return ConversationMutationResponse{}, err
	}
	conv, ok := f.conv[c.ConversationID]
	if !ok || conv.Revision != c.ExpectedRevision {
		return ConversationMutationResponse{}, ErrConflict
	}
	now := time.Now().UTC()
	conv.DeletedAt = &now
	conv.Revision++
	conv.UpdatedAt = now
	f.conv[c.ConversationID] = conv
	r := ConversationMutationResponse{Conversation: conv, RequestID: c.RequestID, Deleted: true}
	f.mutations[k] = struct {
		digest   string
		response ConversationMutationResponse
	}{c.Fingerprint, r}
	return r, nil
}
func (f *fakeStore) ListConversations(_ context.Context, cursor string, limit int) ([]Conversation, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Conversation, 0, limit)
	for _, c := range f.conv {
		if c.DeletedAt == nil && len(out) < limit {
			out = append(out, c)
		}
	}
	return out, "", nil
}
func (f *fakeStore) LoadConversation(_ context.Context, id string) (Conversation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.conv[id]
	if !ok {
		return Conversation{}, errors.New("not found")
	}
	return c.Snapshot(), nil
}
func (f *fakeStore) SaveConversation(_ context.Context, c Conversation, _ uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conv[c.ID] = c
	return nil
}
func (f *fakeStore) DeleteConversation(_ context.Context, id string, expected uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.conv[id]
	if c.Revision != expected {
		return ErrConflict
	}
	t := time.Now().UTC()
	c.DeletedAt = &t
	c.Revision++
	f.conv[id] = c
	return nil
}
func (f *fakeStore) ClaimChat(_ context.Context, id, conv, fp, profile string, exts []ExtensionSelection, now time.Time, ttl time.Duration) (ChatLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.leases[id]; ok {
		if old.Status == ClaimFailed {
			return old, nil
		}
		if old.Fingerprint != fp {
			old.Status = ClaimConflict
			return old, nil
		}
		if r, ok := f.responses[id]; ok {
			old.Status = ClaimCompleted
			old.Response = &r
			return old, nil
		}
		if old.ExpiresAt.After(now) {
			old.Status = ClaimInFlight
			return old, nil
		}
		old.Status = ClaimReclaimed
		old.Epoch++
		old.LeaseID = uuid.NewString()
		old.ExpiresAt = now.Add(ttl)
		f.leases[id] = old
		return old, nil
	}
	l := ChatLease{RequestID: id, ConversationID: conv, LeaseID: uuid.NewString(), Fingerprint: fp, ProfileID: profile, Extensions: exts, ExpiresAt: now.Add(ttl), Status: ClaimNew, Epoch: 1}
	if l.ConversationID == "" {
		l.ConversationID = uuid.NewString()
	}
	f.leases[id] = l
	return l, nil
}
func (f *fakeStore) BindChatProfileSnapshot(_ context.Context, id, lease string, epoch uint64, fp string, snapshot coremodel.ExecutionSnapshot) (ChatLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := snapshot.Validate(); err != nil {
		return ChatLease{}, err
	}
	l, ok := f.leases[id]
	if !ok || l.LeaseID != lease || l.Epoch != epoch || l.Fingerprint != fp || l.ProfileID != snapshot.ProfileID {
		return ChatLease{}, ErrConflict
	}
	l.ProfileSnapshot = snapshot
	l.ProfileSnapshotDigest = snapshot.Digest()
	f.leases[id] = l
	return l, nil
}
func (f *fakeStore) RenewChat(_ context.Context, id, lease string, epoch uint64, now time.Time, ttl time.Duration) (ChatLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.renewFail {
		return ChatLease{}, ErrConflict
	}
	l := f.leases[id]
	if l.LeaseID != lease || l.Epoch != epoch {
		return ChatLease{}, ErrConflict
	}
	l.Epoch++
	l.ExpiresAt = now.Add(ttl)
	f.leases[id] = l
	return l, nil
}
func (f *fakeStore) ReleaseChat(_ context.Context, id, lease string, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.leases[id]; l.LeaseID == lease && l.Epoch == epoch && l.Status != ClaimFailed {
		delete(f.leases, id)
		return nil
	}
	return ErrConflict
}
func (f *fakeStore) FailChat(_ context.Context, id, lease string, epoch uint64, code, summary string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.leases[id]
	if l.LeaseID != lease || l.Epoch != epoch {
		return ErrConflict
	}
	l.Status = ClaimFailed
	l.FailureCode = code
	l.FailureSummary = summary
	f.leases[id] = l
	return nil
}
func (f *fakeStore) ClaimToolExecution(_ context.Context, req, call, args, ext string, now time.Time, ttl time.Duration) (ToolLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := req + ":" + call
	if old, ok := f.toolLeases[k]; ok {
		if old.ArgsDigest != args || old.ExtensionDigest != ext {
			old.Status = ToolClaimConflict
			return old, nil
		}
		if old.Status == ToolClaimCompleted {
			return old, nil
		}
		if old.Status == ToolClaimUncertain || old.Status == ToolClaimDispatched {
			return old, nil
		}
		if old.ExpiresAt.After(now) {
			old.Status = ToolClaimInFlight
			return old, nil
		}
		old.Status = ToolClaimReclaimed
		old.Epoch++
		old.LeaseID = uuid.NewString()
		old.ExpiresAt = now.Add(ttl)
		f.toolLeases[k] = old
		return old, nil
	}
	l := ToolLease{RequestID: req, ToolCallID: call, LeaseID: uuid.NewString(), ExecutionID: req + ":" + call, ArgsDigest: args, ExtensionDigest: ext, ExpiresAt: now.Add(ttl), Status: ToolClaimNew, Epoch: 1}
	f.toolLeases[k] = l
	return l, nil
}
func (f *fakeStore) CompleteToolExecution(_ context.Context, c ToolCompletion) (ToolResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := c.RequestID + ":" + c.ToolCallID
	l := f.toolLeases[k]
	if l.LeaseID != c.LeaseID || l.Epoch != c.Epoch || l.Status != ToolClaimDispatched || l.ArgsDigest != c.ArgsDigest || l.ExtensionDigest != c.ExtensionDigest {
		return ToolResult{}, ErrConflict
	}
	l.Status = ToolClaimCompleted
	r := c.Result
	l.Result = &r
	f.toolLeases[k] = l
	f.results = append(f.results, r)
	return r, nil
}
func (f *fakeStore) RenewToolExecution(_ context.Context, req, call, lease string, epoch uint64, now time.Time, ttl time.Duration) (ToolLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := req + ":" + call
	l := f.toolLeases[k]
	if l.LeaseID != lease || l.Epoch != epoch {
		return ToolLease{}, ErrConflict
	}
	l.Epoch++
	l.ExpiresAt = now.Add(ttl)
	f.toolLeases[k] = l
	return l, nil
}
func (f *fakeStore) ReleaseToolExecution(_ context.Context, req, call, lease string, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := req + ":" + call
	l := f.toolLeases[k]
	if l.LeaseID == lease && l.Epoch == epoch {
		delete(f.toolLeases, k)
		return nil
	}
	return ErrConflict
}
func (f *fakeStore) CommitChatCompletion(_ context.Context, a AtomicCompletion) (ChatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.leases[a.RequestID]
	if l.LeaseID != a.LeaseID || l.Epoch != a.Epoch {
		return ChatResponse{}, ErrConflict
	}
	if c, ok := f.conv[a.Conversation.ID]; ok && c.Revision != a.ExpectedRevision {
		return ChatResponse{}, ErrConflict
	}
	f.conv[a.Conversation.ID] = a.Conversation
	f.responses[a.RequestID] = a.Response
	f.committed++
	return a.Response, nil
}

type fakeModel struct {
	runs int
	tool bool
}

type failCompletionStore struct {
	*fakeStore
	failCommit bool
}

func (s *failCompletionStore) CommitChatCompletion(ctx context.Context, completion AtomicCompletion) (ChatResponse, error) {
	if s.failCommit {
		s.failCommit = false
		return ChatResponse{}, ErrConflict
	}
	return s.fakeStore.CommitChatCompletion(ctx, completion)
}

type multiToolModel struct{ runs int }

func (m *multiToolModel) Run(_ context.Context, r ModelRunRequest) (ModelRunResult, error) {
	m.runs++
	if m.runs == 1 {
		return ModelRunResult{Message: Message{ID: uuid.NewString(), Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "call-1", Name: "echo", Arguments: `{"x":1}`}, {ID: "call-2", Name: "lookup", Arguments: `{"x":2}`}}, CreatedAt: time.Now().UTC()}}, nil
	}
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "done", CreatedAt: time.Now().UTC()}}, nil
}
func (m *multiToolModel) Stream(ctx context.Context, r ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
	return m.Run(ctx, r)
}

func (m *fakeModel) Run(_ context.Context, r ModelRunRequest) (ModelRunResult, error) {
	m.runs++
	if m.tool && m.runs == 1 {
		return ModelRunResult{Message: Message{ID: uuid.NewString(), Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "call-1", Name: "echo", Arguments: `{"x":1}`}}, CreatedAt: time.Now().UTC()}}, nil
	}
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "ok", CreatedAt: time.Now().UTC()}}, nil
}
func (m *fakeModel) Stream(ctx context.Context, r ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
	out, err := m.Run(ctx, r)
	if err != nil {
		return out, err
	}
	if out.Message.Content != "" {
		if err := emit(ModelDelta{Text: out.Message.Content}); err != nil {
			return out, err
		}
	}
	return out, nil
}

type fakeProfile struct{}

func (fakeProfile) ResolveProfileSnapshot(_ context.Context, id string) (coremodel.ExecutionSnapshot, error) {
	return coremodel.ExecutionSnapshot{ProfileID: id, Revision: 1, Provider: coremodel.ProviderOpenAICompatible, Model: "test", APIKey: "test-key"}, nil
}

type trackingProfile struct{}

func (trackingProfile) ResolveProfileSnapshot(_ context.Context, id string) (coremodel.ExecutionSnapshot, error) {
	return coremodel.ExecutionSnapshot{ProfileID: id, Revision: 1, Provider: coremodel.ProviderOpenAICompatible, Model: "test", APIKey: "test-key"}, nil
}

type trackingModel struct {
	mu   sync.Mutex
	runs []string
}

func (m *trackingModel) Run(_ context.Context, req ModelRunRequest) (ModelRunResult, error) {
	m.mu.Lock()
	m.runs = append(m.runs, req.Profile.ID)
	m.mu.Unlock()
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: req.Profile.ID, CreatedAt: time.Now().UTC()}}, nil
}

func (m *trackingModel) Stream(ctx context.Context, req ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
	out, err := m.Run(ctx, req)
	if err != nil {
		return out, err
	}
	if emit != nil {
		if err := emit(ModelDelta{Text: out.Message.Content}); err != nil {
			return ModelRunResult{}, err
		}
	}
	return out, nil
}

func (m *trackingModel) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.runs)
}

type fakeExt struct{}

func (fakeExt) ResolveExtensions(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
	return []ResolvedExtension{{Selection: ExtensionSelection{ID: uuid.NewString(), Kind: ExtensionMCP, Version: "1", Digest: "sha256:x", AllowedTools: []string{"echo"}}, Execute: func(context.Context, ToolExecutionRequest) (ToolResult, error) {
		return ToolResult{CallID: "call-1", Content: "echoed"}, nil
	}}}, nil
}

func command() ChatCommand {
	return ChatCommand{RequestID: uuid.NewString(), Prompt: "hello", ProfileID: uuid.NewString()}
}

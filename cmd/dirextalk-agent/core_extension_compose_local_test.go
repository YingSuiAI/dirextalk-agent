package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/google/uuid"
)

type localLimitsConversationStore struct {
	finished string
	result   json.RawMessage
	code     string
	summary  string
}

func (*localLimitsConversationStore) BeginConversationTool(context.Context, coretask.Task) (coreconversation.ToolAttempt, error) {
	return coreconversation.ToolAttempt{}, nil
}

func (s *localLimitsConversationStore) FinishConversationTool(_ context.Context, _ coretask.Task, state string, result json.RawMessage, code, summary string) error {
	s.finished = state
	s.result = append(json.RawMessage(nil), result...)
	s.code = code
	s.summary = summary
	return nil
}

type localLimitsInvocationResolver struct {
	invocation execution.Invocation
	err        error
	calls      int
	cancel     context.CancelFunc
}

func (r *localLimitsInvocationResolver) ResolveConversationInvocation(context.Context, coretask.Task) (execution.Invocation, error) {
	r.calls++
	if r.cancel != nil {
		r.cancel()
	}
	return r.invocation, r.err
}

type localLimitsRunner struct {
	request extensionrunner.RequestV2
	calls   int
	stdin   []byte
	stdout  []byte
	status  *extensionrunner.StatusV1
	err     error
}

func (r *localLimitsRunner) RunV2(_ context.Context, request extensionrunner.RequestV2, files []*os.File) (extensionrunner.StatusV1, error) {
	r.calls++
	r.request = request
	if request.Stdin != nil {
		r.stdin = make([]byte, request.Stdin.Size)
		if _, err := files[request.Stdin.Index].ReadAt(r.stdin, 0); err != nil {
			return extensionrunner.StatusV1{}, err
		}
	}
	if r.status != nil {
		status := *r.status
		status.RunID = request.RunID
		return status, r.err
	}
	if r.err != nil {
		return extensionrunner.StatusV1{}, r.err
	}
	stdout := r.stdout
	if stdout == nil {
		stdout = []byte("ok")
	}
	return extensionrunner.StatusV1{RunID: request.RunID, Phase: extensionrunner.PhaseTombstone, Status: "succeeded", Stdout: stdout}, nil
}

func localMCPResourceInvocation(t *testing.T) execution.Invocation {
	t.Helper()
	digest := strings.Repeat("a", 64)
	return execution.Invocation{Kind: coreextension.KindMCP, Local: &execution.LocalInvocation{
		TaskID: uuid.NewString(), TaskFence: uuid.NewString(), InstallationID: uuid.NewString(), VersionID: uuid.NewString(),
		InstallDigest: digest, ContentDigest: digest, ArtifactDigest: digest, EntryPath: "entry", Tool: "write_html",
		Input: json.RawMessage(`{"content":"ok"}`), Workspace: t.TempDir(), Timeout: time.Minute, Limits: execution.LocalSandboxLimitsV2(),
	}}
}

func TestConversationToolLocalResourceReceiptsAreDeterministicFailures(t *testing.T) {
	tests := []struct {
		name        string
		status      extensionrunner.StatusV1
		wantErr     error
		wantCode    string
		wantSummary string
	}{
		{name: "busy", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorUnavailableBackend, Status: "capacity", Stderr: []byte("protected detail")}, wantErr: execution.ErrLocalResourceBusy, wantCode: execution.LocalResourceBusyCode, wantSummary: execution.LocalResourceBusySummary},
		{name: "request limits", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorInvalidRequest, Status: "limits", Stderr: []byte("protected detail")}, wantErr: execution.ErrLocalResourceExhausted, wantCode: execution.LocalResourceExhaustedCode, wantSummary: execution.LocalResourceExhaustedSummary},
		{name: "exhausted", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorExecution, Status: "output_limit", Stderr: []byte("protected detail")}, wantErr: execution.ErrLocalResourceExhausted, wantCode: execution.LocalResourceExhaustedCode, wantSummary: execution.LocalResourceExhaustedSummary},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocation := localMCPResourceInvocation(t)
			store := &localLimitsConversationStore{}
			resolver := &localLimitsInvocationResolver{invocation: invocation}
			runner := &localLimitsRunner{status: &test.status}
			handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil)
			out := handler(context.Background(), coretask.Task{ID: invocation.Local.TaskID})
			if !errors.Is(out.Err, test.wantErr) || !out.TerminalOwned || runner.calls != 1 || store.finished != "failed" || store.code != test.wantCode || store.summary != test.wantSummary || len(store.result) != 0 {
				t.Fatalf("out=%+v calls=%d state=%q code=%q summary=%q result=%s", out, runner.calls, store.finished, store.code, store.summary, store.result)
			}
			if strings.Contains(store.summary, "protected detail") {
				t.Fatalf("runner diagnostics leaked in summary %q", store.summary)
			}
		})
	}
}

func TestConversationToolLocalTransportFailureRemainsUncertain(t *testing.T) {
	invocation := localMCPResourceInvocation(t)
	store := &localLimitsConversationStore{}
	resolver := &localLimitsInvocationResolver{invocation: invocation}
	runner := &localLimitsRunner{err: context.DeadlineExceeded}
	handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: invocation.Local.TaskID})
	if !errors.Is(out.Err, context.DeadlineExceeded) || !errors.Is(out.Err, execution.ErrLocalOutcomeUncertain) || !out.TerminalOwned || runner.calls != 1 || store.finished != "uncertain" || store.code != "tool_uncertain" || store.summary != "tool dispatch outcome is unknown" {
		t.Fatalf("out=%+v calls=%d state=%q code=%q summary=%q", out, runner.calls, store.finished, store.code, store.summary)
	}
}

func TestConversationToolExecutableSkillDispatchBindsExactLocalSandboxLimits(t *testing.T) {
	taskID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	limits := execution.LocalSandboxLimitsV2()
	resolver := &localLimitsInvocationResolver{invocation: execution.Invocation{Kind: coreextension.KindSkill, Skill: &execution.SkillInvocation{
		Entry:          coreextension.SkillEntry{RelativePath: "entry", Digest: digest, Executable: true, Argv: []string{"entry"}},
		InstallDigest:  digest,
		Workspace:      t.TempDir(),
		TaskID:         taskID,
		TaskFence:      uuid.NewString(),
		InstallationID: uuid.NewString(),
		VersionID:      uuid.NewString(),
		ContentDigest:  digest,
		ArtifactDigest: digest,
		Limits:         limits,
	}}}
	store := &localLimitsConversationStore{}
	runner := &localLimitsRunner{}
	handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: taskID})
	if out.Err != nil || !out.TerminalOwned || store.finished != "completed" {
		t.Fatalf("out=%+v finished=%q", out, store.finished)
	}
	if runner.calls != 1 || runner.request.Limits != limits {
		t.Fatalf("calls=%d limits=%+v want=%+v", runner.calls, runner.request.Limits, limits)
	}
}

func TestConversationToolLocalMCPDispatchUsesResolvedToolAndInput(t *testing.T) {
	taskID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	input, err := json.Marshal(map[string]any{"content": "<h1>Hello from Dirextalk</h1>"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &localLimitsInvocationResolver{invocation: execution.Invocation{Kind: coreextension.KindMCP, Local: &execution.LocalInvocation{
		TaskID: taskID, TaskFence: uuid.NewString(), InstallationID: uuid.NewString(), VersionID: uuid.NewString(),
		InstallDigest: digest, ContentDigest: digest, ArtifactDigest: digest, EntryPath: "entry", Argv: []string{"entry"},
		Tool: "write_html", Input: input, Workspace: t.TempDir(), Timeout: 30 * time.Second, Limits: execution.LocalSandboxLimitsV2(),
	}}}
	store := &localLimitsConversationStore{}
	runner := &localLimitsRunner{stdout: []byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"<h1>Hello from Dirextalk</h1>"}]}}`)}
	handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: taskID})
	if out.Err != nil || !out.TerminalOwned || store.finished != "completed" || runner.calls != 1 || !strings.Contains(string(store.result), "Hello from Dirextalk") {
		t.Fatalf("out=%+v finished=%q calls=%d result=%s", out, store.finished, runner.calls, store.result)
	}
	lines := strings.Split(strings.TrimSpace(string(runner.stdin)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[2], `"method":"tools/call"`) || !strings.Contains(lines[2], `"name":"write_html"`) || !strings.Contains(lines[2], `"content":"\u003ch1\u003eHello from Dirextalk\u003c/h1\u003e"`) {
		t.Fatalf("unexpected MCP stdin=%q", runner.stdin)
	}
}

type recoveringConversationStore struct {
	beginErr     error
	finishState  string
	finishCtxErr error
	finishCalls  int
}

func (s *recoveringConversationStore) BeginConversationTool(context.Context, coretask.Task) (coreconversation.ToolAttempt, error) {
	return coreconversation.ToolAttempt{}, s.beginErr
}

func (s *recoveringConversationStore) FinishConversationTool(ctx context.Context, _ coretask.Task, state string, _ json.RawMessage, _, _ string) error {
	s.finishCalls++
	s.finishState = state
	s.finishCtxErr = ctx.Err()
	return nil
}

func TestConversationToolReclaimTerminalizesDispatchedAttemptWithoutProviderReplay(t *testing.T) {
	store := &recoveringConversationStore{beginErr: coreconversation.ErrToolDispatchStarted}
	resolver := &localLimitsInvocationResolver{}
	handler := conversationToolTaskHandler(store, resolver, nil, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: uuid.NewString()})
	if out.Err != nil || !out.TerminalOwned || store.finishCalls != 1 || store.finishState != "uncertain" || store.finishCtxErr != nil || resolver.calls != 0 {
		t.Fatalf("out=%+v finish_calls=%d finish_state=%q finish_ctx_err=%v resolver_calls=%d", out, store.finishCalls, store.finishState, store.finishCtxErr, resolver.calls)
	}
}

func TestConversationToolPostDispatchFailureUsesDetachedTerminalContext(t *testing.T) {
	store := &recoveringConversationStore{}
	ctx, cancel := context.WithCancel(context.Background())
	resolver := &localLimitsInvocationResolver{err: context.Canceled, cancel: cancel}
	handler := conversationToolTaskHandler(store, resolver, nil, nil, nil)
	out := handler(ctx, coretask.Task{ID: uuid.NewString()})
	if !errors.Is(out.Err, context.Canceled) || !out.TerminalOwned || store.finishCalls != 1 || store.finishState != "uncertain" || store.finishCtxErr != nil || resolver.calls != 1 {
		t.Fatalf("out=%+v finish_calls=%d finish_state=%q finish_ctx_err=%v resolver_calls=%d", out, store.finishCalls, store.finishState, store.finishCtxErr, resolver.calls)
	}
}

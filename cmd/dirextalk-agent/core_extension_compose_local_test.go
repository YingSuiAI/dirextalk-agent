package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/google/uuid"
)

type localLimitsConversationStore struct {
	attempt  coreconversation.ToolAttempt
	finished string
	result   json.RawMessage
	code     string
	summary  string
}

func (s *localLimitsConversationStore) BeginConversationTool(context.Context, coretask.Task) (coreconversation.ToolAttempt, error) {
	return s.attempt, nil
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
	results []*os.File
}

func (r *localLimitsRunner) RunV2WithResultFiles(ctx context.Context, request extensionrunner.RequestV2, files []*os.File) (extensionrunner.StatusV1, []*os.File, error) {
	status, err := r.RunV2(ctx, request, files)
	results := r.results
	r.results = nil
	return status, results, err
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
			handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil, nil)
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
	handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: invocation.Local.TaskID})
	if !errors.Is(out.Err, context.DeadlineExceeded) || !errors.Is(out.Err, execution.ErrLocalOutcomeUncertain) || !out.TerminalOwned || runner.calls != 1 || store.finished != "uncertain" || store.code != "tool_uncertain" || store.summary != "tool dispatch outcome is unknown" {
		t.Fatalf("out=%+v calls=%d state=%q code=%q summary=%q", out, runner.calls, store.finished, store.code, store.summary)
	}
}

func TestConversationToolVerifiedLocalFailureReturnsToModel(t *testing.T) {
	invocation := localMCPResourceInvocation(t)
	invocation.Local.Tool = coreextension.BuiltinLocalSandboxToolName
	invocation.Local.Argv = []string{"entry", "local_sandbox"}
	invocation.Local.Input = json.RawMessage(`{"result_paths":["summary.md"],"script":"cat /work/summary.md"}`)
	invocation.Local.ResultFiles = []string{"summary.md"}
	store := &localLimitsConversationStore{}
	resolver := &localLimitsInvocationResolver{invocation: invocation}
	runner := &localLimitsRunner{status: &extensionrunner.StatusV1{
		Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorExecution, Status: "result_handoff",
	}}
	handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: invocation.Local.TaskID})
	if !errors.Is(out.Err, execution.ErrLocalExecutionFailed) || errors.Is(out.Err, execution.ErrLocalOutcomeUncertain) ||
		!out.TerminalOwned || runner.calls != 1 || store.finished != "failed" ||
		store.code != execution.LocalExecutionFailedCode || store.summary != execution.LocalExecutionFailedSummary {
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
	handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil, nil)
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
	handler := conversationToolTaskHandler(store, resolver, &execution.LocalExecutor{Runner: runner}, nil, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: taskID})
	if out.Err != nil || !out.TerminalOwned || store.finished != "completed" || runner.calls != 1 || !strings.Contains(string(store.result), "Hello from Dirextalk") {
		t.Fatalf("out=%+v finished=%q calls=%d result=%s", out, store.finished, runner.calls, store.result)
	}
	lines := strings.Split(strings.TrimSpace(string(runner.stdin)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[2], `"method":"tools/call"`) || !strings.Contains(lines[2], `"name":"write_html"`) || !strings.Contains(lines[2], `"content":"\u003ch1\u003eHello from Dirextalk\u003c/h1\u003e"`) {
		t.Fatalf("unexpected MCP stdin=%q", runner.stdin)
	}
}

func TestLocalSandboxConversationStoresVerifiedArtifactsUnderTurnAuthority(t *testing.T) {
	taskID, executionID := uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("a", 64)
	content := []byte("<h1>verified</h1>")
	contentDigest := sha256.Sum256(content)
	resultFile, err := os.CreateTemp(t.TempDir(), "verified-*.html")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resultFile.Write(content); err != nil {
		t.Fatal(err)
	}
	if _, err = resultFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultFile.Close() })
	ownerID, generation := "@owner:example.test", uint64(7)
	invocation := execution.Invocation{Kind: coreextension.KindMCP, OwnerID: ownerID, AccountGeneration: generation, Local: &execution.LocalInvocation{
		TaskID: taskID, TaskFence: uuid.NewString(), InstallationID: uuid.NewString(), VersionID: uuid.NewString(),
		InstallDigest: digest, ContentDigest: digest, ArtifactDigest: digest, EntryPath: "entry", Argv: []string{"entry", "local_sandbox"},
		Tool: coreextension.BuiltinLocalSandboxToolName, Input: json.RawMessage(`{"result_paths":["report.html"],"script":"printf report"}`),
		Workspace: t.TempDir(), Timeout: 30 * time.Second, Limits: execution.LocalSandboxLimitsV2(), ResultFiles: []string{"report.html"},
	}}
	stdout := []byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"done"}],"structuredContent":{"stdout":"done","stderr":"","exit_code":0,"result_files":[]},"isError":false}}`)
	runner := &localLimitsRunner{status: &extensionrunner.StatusV1{Phase: extensionrunner.PhaseTombstone, Status: "succeeded", Stdout: stdout,
		ResultFiles: []extensionrunner.ResultFile{{Path: "report.html", SHA256: fmt.Sprintf("%x", contentDigest), Size: int64(len(content))}}}, results: []*os.File{resultFile}}
	repository, err := localartifact.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &localLimitsConversationStore{attempt: coreconversation.ToolAttempt{ExecutionID: executionID}}
	handler := conversationToolTaskHandler(store, &localLimitsInvocationResolver{invocation: invocation}, &execution.LocalExecutor{Runner: runner}, nil, nil, repository)
	out := handler(context.Background(), coretask.Task{ID: taskID})
	if out.Err != nil || !out.TerminalOwned || store.finished != "completed" {
		t.Fatalf("out=%+v state=%q", out, store.finished)
	}
	authority := localartifact.Authority{OwnerID: ownerID, AccountGeneration: generation}
	artifacts, next, err := repository.ListLocalSandbox(context.Background(), authority, executionID, "", 20)
	if err != nil || next != "" || len(artifacts) != 3 {
		t.Fatalf("artifacts=%+v next=%q err=%v", artifacts, next, err)
	}
	var report localartifact.Artifact
	for _, artifact := range artifacts {
		if artifact.Name == "report.html" {
			report = artifact
		}
		if artifact.OwnerID != ownerID || artifact.AccountGeneration != generation || artifact.ExecutionID != executionID {
			t.Fatalf("artifact authority=%+v", artifact)
		}
	}
	if report.ArtifactID == "" || report.SHA256 != fmt.Sprintf("%x", contentDigest) || report.SizeBytes != int64(len(content)) {
		t.Fatalf("report=%+v", report)
	}
	var stored coretask.Result
	if json.Unmarshal(store.result, &stored) != nil || !strings.Contains(string(stored.JSON), report.ArtifactID) || !strings.Contains(string(stored.JSON), `"record_kind":"local_sandbox"`) {
		t.Fatalf("stored=%s", store.result)
	}
	executionOutput, err := repository.GetLocalSandboxExecution(context.Background(), authority, executionID)
	if err != nil || executionOutput.ExitCode != 0 || executionOutput.StdoutArtifactID == "" || executionOutput.StderrArtifactID == "" {
		t.Fatalf("execution=%+v err=%v", executionOutput, err)
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
	handler := conversationToolTaskHandler(store, resolver, nil, nil, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: uuid.NewString()})
	if out.Err != nil || !out.TerminalOwned || store.finishCalls != 1 || store.finishState != "uncertain" || store.finishCtxErr != nil || resolver.calls != 0 {
		t.Fatalf("out=%+v finish_calls=%d finish_state=%q finish_ctx_err=%v resolver_calls=%d", out, store.finishCalls, store.finishState, store.finishCtxErr, resolver.calls)
	}
}

func TestConversationToolResolutionFailureUsesDetachedTerminalContext(t *testing.T) {
	store := &recoveringConversationStore{}
	ctx, cancel := context.WithCancel(context.Background())
	resolver := &localLimitsInvocationResolver{err: context.Canceled, cancel: cancel}
	handler := conversationToolTaskHandler(store, resolver, nil, nil, nil, nil)
	out := handler(ctx, coretask.Task{ID: uuid.NewString()})
	if !errors.Is(out.Err, context.Canceled) || !out.TerminalOwned || store.finishCalls != 1 || store.finishState != "failed" || store.finishCtxErr != nil || resolver.calls != 1 {
		t.Fatalf("out=%+v finish_calls=%d finish_state=%q finish_ctx_err=%v resolver_calls=%d", out, store.finishCalls, store.finishState, store.finishCtxErr, resolver.calls)
	}
}

func TestConversationToolInvalidArgumentsAreDeterministic(t *testing.T) {
	store := &localLimitsConversationStore{}
	handler := conversationToolTaskHandler(store, &localLimitsInvocationResolver{err: coreextension.ErrInvalid}, nil, nil, nil, nil)
	out := handler(context.Background(), coretask.Task{ID: uuid.NewString()})
	if !errors.Is(out.Err, coreextension.ErrInvalid) || !out.TerminalOwned || store.finished != "failed" || store.code != "tool_arguments_invalid" || store.summary != "tool arguments are invalid" {
		t.Fatalf("out=%+v state=%q code=%q summary=%q", out, store.finished, store.code, store.summary)
	}
}

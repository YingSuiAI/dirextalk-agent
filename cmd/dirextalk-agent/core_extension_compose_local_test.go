package main

import (
	"context"
	"encoding/json"
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
}

func (*localLimitsConversationStore) BeginConversationTool(context.Context, coretask.Task) (coreconversation.ToolAttempt, error) {
	return coreconversation.ToolAttempt{}, nil
}

func (s *localLimitsConversationStore) FinishConversationTool(_ context.Context, _ coretask.Task, state string, result json.RawMessage, _, _ string) error {
	s.finished = state
	s.result = append(json.RawMessage(nil), result...)
	return nil
}

type localLimitsInvocationResolver struct {
	invocation execution.Invocation
}

func (r localLimitsInvocationResolver) ResolveConversationInvocation(context.Context, coretask.Task) (execution.Invocation, error) {
	return r.invocation, nil
}

type localLimitsRunner struct {
	request extensionrunner.RequestV2
	calls   int
	stdin   []byte
	stdout  []byte
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
	stdout := r.stdout
	if stdout == nil {
		stdout = []byte("ok")
	}
	return extensionrunner.StatusV1{RunID: request.RunID, Phase: extensionrunner.PhaseTombstone, Status: "succeeded", Stdout: stdout}, nil
}

func TestConversationToolExecutableSkillDispatchBindsExactLocalSandboxLimits(t *testing.T) {
	taskID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	limits := execution.LocalSandboxLimitsV2()
	resolver := localLimitsInvocationResolver{invocation: execution.Invocation{Kind: coreextension.KindSkill, Skill: &execution.SkillInvocation{
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
	resolver := localLimitsInvocationResolver{invocation: execution.Invocation{Kind: coreextension.KindMCP, Local: &execution.LocalInvocation{
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

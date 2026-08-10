package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/google/uuid"
)

type localLimitsConversationStore struct {
	finished string
}

func (*localLimitsConversationStore) BeginConversationTool(context.Context, coretask.Task) (coreconversation.ToolAttempt, error) {
	return coreconversation.ToolAttempt{}, nil
}

func (s *localLimitsConversationStore) FinishConversationTool(_ context.Context, _ coretask.Task, state string, result json.RawMessage, _, _ string) error {
	s.finished = state
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
}

func (r *localLimitsRunner) RunV2(_ context.Context, request extensionrunner.RequestV2, _ []*os.File) (extensionrunner.StatusV1, error) {
	r.calls++
	r.request = request
	return extensionrunner.StatusV1{RunID: request.RunID, Phase: extensionrunner.PhaseTombstone, Status: "succeeded", Stdout: []byte("ok")}, nil
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

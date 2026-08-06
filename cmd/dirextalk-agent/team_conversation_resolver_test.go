package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

type resolverTeamService struct {
	ready         bool
	prepareCalls  []coreteam.PrepareCommand
	statusCalls   []coreteam.StatusQuery
	prepareResult coreteam.PlanProjection
	statusResult  coreteam.ExecutionProjection
	prepareErr    error
	statusErr     error
	createdByKey  map[string]coreteam.PlanProjection
	createdPlans  int
}

func (s *resolverTeamService) ReadyForPublication() bool { return s != nil && s.ready }
func (s *resolverTeamService) PreparePlan(_ context.Context, command coreteam.PrepareCommand) (coreteam.PlanProjection, error) {
	s.prepareCalls = append(s.prepareCalls, command)
	if s.prepareErr != nil {
		return coreteam.PlanProjection{}, s.prepareErr
	}
	if s.createdByKey == nil {
		s.createdByKey = make(map[string]coreteam.PlanProjection)
	}
	if replay, ok := s.createdByKey[command.IdempotencyKey]; ok {
		return replay, nil
	}
	s.createdPlans++
	s.createdByKey[command.IdempotencyKey] = s.prepareResult
	return s.prepareResult, nil
}
func (s *resolverTeamService) TaskStatus(_ context.Context, query coreteam.StatusQuery) (coreteam.ExecutionProjection, error) {
	s.statusCalls = append(s.statusCalls, query)
	if s.statusErr != nil {
		return coreteam.ExecutionProjection{}, s.statusErr
	}
	return s.statusResult, nil
}

type fixedConversationResolver struct {
	resolved []coreconversation.ResolvedExtension
	err      error
}

func (r fixedConversationResolver) ResolveExtensions(context.Context, []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	return append([]coreconversation.ResolvedExtension(nil), r.resolved...), r.err
}

func teamResolverContext(owner string, generation int64) context.Context {
	return capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{
		ChainId: uuid.NewString(), RootOperationId: uuid.NewString(),
	}, &capv1.PermissionContext{AuthenticatedOwnerId: owner, AccountGeneration: generation})
}

func TestTeamConversationResolverPublishesExactlyTwoClosedToolsWhenReady(t *testing.T) {
	base := coreconversation.ResolvedExtension{
		Selection: coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: uuid.NewString(), Version: "1", Digest: strings.Repeat("a", 64), AllowedTools: []string{"echo"}},
		Tools:     []coremodel.Tool{{Name: "echo", InputSchema: map[string]any{"type": "object"}}},
	}
	service := &resolverTeamService{ready: true}
	resolver := &teamConversationResolver{base: fixedConversationResolver{resolved: []coreconversation.ResolvedExtension{base}}, team: service}
	resolved, err := resolver.ResolveExtensions(teamResolverContext("@owner:example.test", 7), nil)
	if err != nil || len(resolved) != 2 {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	team := resolved[1]
	if err := team.Snapshot.Validate(); err != nil {
		t.Fatalf("snapshot=%#v err=%v", team.Snapshot, err)
	}
	if !team.Snapshot.PrivateArguments {
		t.Fatal("Team proposal arguments were not marked private")
	}
	want := map[string]bool{"team_plan_prepare": true, "team_task_status": true}
	for _, extension := range resolved {
		for _, tool := range extension.Tools {
			delete(want, tool.Name)
			if strings.HasPrefix(tool.Name, "team_") {
				assertClosedToolSchema(t, tool.InputSchema)
			}
		}
	}
	if len(want) != 0 || len(team.Tools) != 2 || !sameStrings(team.Selection.AllowedTools, []string{"team_plan_prepare", "team_task_status"}) {
		t.Fatalf("missing Team tools=%v extension=%#v", want, team)
	}
	prepareProperties := team.Tools[0].InputSchema["properties"].(map[string]any)
	roleItems := prepareProperties["roles"].(map[string]any)["items"].(map[string]any)
	roleProperties := roleItems["properties"].(map[string]any)
	if prepareProperties["goal"].(map[string]any)["maxLength"] != float64(coreteam.MaxGoalBytes/4) ||
		roleProperties["goal"].(map[string]any)["maxLength"] != float64(coreteam.MaxRoleGoalBytes/4) {
		t.Fatalf("Team schema character limits do not fit UTF-8 byte limits: %#v", team.Tools[0].InputSchema)
	}
	snapshotJSON, _ := json.Marshal(team.Snapshot)
	for _, forbidden := range []string{"credential", "ami-", "image_digest", "instance_id", "access_key", "secret"} {
		if bytes.Contains(bytes.ToLower(snapshotJSON), []byte(forbidden)) {
			t.Fatalf("Team snapshot leaked %q: %s", forbidden, snapshotJSON)
		}
	}

	for name, ctx := range map[string]context.Context{
		"missing permission": context.Background(),
		"missing owner":      teamResolverContext("", 7),
		"missing generation": teamResolverContext("@owner:example.test", 0),
	} {
		t.Run(name, func(t *testing.T) {
			items, err := resolver.ResolveExtensions(ctx, nil)
			if err != nil || len(items) != 1 || items[0].Tools[0].Name != "echo" {
				t.Fatalf("items=%#v err=%v", items, err)
			}
		})
	}
	service.ready = false
	items, err := resolver.ResolveExtensions(teamResolverContext("@owner:example.test", 7), nil)
	if err != nil || len(items) != 1 {
		t.Fatalf("unready items=%#v err=%v", items, err)
	}
}

func TestTeamConversationResolverRejectsReservedToolNamesFromSkillOrMCP(t *testing.T) {
	for _, conflict := range []coreconversation.ResolvedExtension{
		{Selection: coreconversation.ExtensionSelection{AllowedTools: []string{"team_plan_prepare"}}},
		{Tools: []coremodel.Tool{{Name: "team_task_status"}}},
	} {
		resolver := &teamConversationResolver{base: fixedConversationResolver{resolved: []coreconversation.ResolvedExtension{conflict}}}
		if _, err := resolver.ResolveExtensions(context.Background(), nil); !errors.Is(err, coreconversation.ErrConflict) {
			t.Fatalf("reserved conflict err=%v", err)
		}
	}
}

func TestTeamConversationResolverPreparesBoundedPlanWithStableIdempotency(t *testing.T) {
	service := &resolverTeamService{ready: true, prepareResult: coreteam.PlanProjection{
		TaskID: "11111111-1111-4111-8111-111111111111", PlanID: "22222222-2222-4222-8222-222222222222",
		ConfirmationID: "33333333-3333-4333-8333-333333333333", Revision: 1,
		Status: coreteam.PlanWaitingUser, Summary: "credential-secret-canary on i-0123456789 in us-east-1",
	}}
	owner := "@owner:example.test"
	ctx := teamResolverContext(owner, 7)
	resolved, err := (&teamConversationResolver{team: service}).ResolveExtensions(ctx, nil)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolve=%#v err=%v", resolved, err)
	}
	prepare := teamTool(t, resolved[0], "team_plan_prepare")
	arguments := canonicalJSON(t, map[string]any{
		"goal": "research, implement, and review",
		"roles": []any{
			map[string]any{"role_id": "research", "goal": "research", "capabilities": []any{"web.research"}},
			map[string]any{"role_id": "build", "goal": "implement", "depends_on": []any{"research"}, "capabilities": []any{"repository.read", "repository.write", "shell", "test"}},
			map[string]any{"role_id": "review", "goal": "review", "depends_on": []any{"build"}, "capabilities": []any{"code.review"}},
		},
	})
	request := teamToolRequest("team_plan_prepare", arguments)
	result, err := prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(service.prepareCalls) != 1 || service.createdPlans != 1 {
		t.Fatalf("prepare calls=%d created=%d", len(service.prepareCalls), service.createdPlans)
	}
	command := service.prepareCalls[0]
	if command.Scope != (coreteam.Scope{OwnerID: owner, AccountGeneration: 7}) || command.ConversationID != request.ConversationID || command.IdempotencyKey != request.ExecutionID || command.RequestDigest != teamPrepareRequestDigest(command.Scope, request.ConversationID, request.ArgsDigest) || command.RequestDigest == request.ArgsDigest || len(command.Roles) != 3 {
		t.Fatalf("prepare command=%#v", command)
	}
	if !sameStrings(result.RelatedTaskIDs, []string{service.prepareResult.TaskID}) || result.Summary != "Team plan prepared; confirmation is required" {
		t.Fatalf("result=%#v", result)
	}
	assertSafeTeamResult(t, result.Content)
	for _, want := range []string{service.prepareResult.TaskID, service.prepareResult.PlanID, service.prepareResult.ConfirmationID, "Team plan is waiting for user confirmation."} {
		if !strings.Contains(result.Content, want) {
			t.Fatalf("result missing %q: %s", want, result.Content)
		}
	}
	if strings.Contains(result.Content, "credential-secret-canary") || strings.Contains(result.Content, "i-0123456789") || strings.Contains(result.Content, "us-east-1") {
		t.Fatalf("unsafe plan summary=%s", result.Content)
	}

	replay, err := prepare(ctx, request)
	if err != nil || replay.Content != result.Content || service.createdPlans != 1 || len(service.prepareCalls) != 2 {
		t.Fatalf("replay=%#v calls=%d created=%d err=%v", replay, len(service.prepareCalls), service.createdPlans, err)
	}
}

func TestTeamConversationResolverRejectsInvalidPlanArgumentsAndIdentityRaces(t *testing.T) {
	service := &resolverTeamService{ready: true, prepareResult: coreteam.PlanProjection{
		TaskID: uuid.NewString(), PlanID: uuid.NewString(), ConfirmationID: uuid.NewString(), Revision: 1,
		Status: coreteam.PlanWaitingUser, Summary: "safe",
	}}
	resolved, err := (&teamConversationResolver{team: service}).ResolveExtensions(teamResolverContext("@owner:example.test", 7), nil)
	if err != nil {
		t.Fatal(err)
	}
	prepare := teamTool(t, resolved[0], "team_plan_prepare")
	validRole := map[string]any{"role_id": "build", "goal": "build", "capabilities": []any{"shell"}}
	fourRoles := []any{
		validRole,
		map[string]any{"role_id": "b", "goal": "b", "capabilities": []any{"shell"}},
		map[string]any{"role_id": "c", "goal": "c", "capabilities": []any{"shell"}},
		map[string]any{"role_id": "d", "goal": "d", "capabilities": []any{"shell"}},
	}
	cyclicRoles := []any{
		map[string]any{"role_id": "a", "goal": "a", "depends_on": []any{"b"}, "capabilities": []any{"shell"}},
		map[string]any{"role_id": "b", "goal": "b", "depends_on": []any{"a"}, "capabilities": []any{"test"}},
	}
	tests := []struct {
		name  string
		input map[string]any
	}{
		{name: "unknown field", input: map[string]any{"goal": "build", "roles": []any{validRole}, "credential_id": "secret-canary"}},
		{name: "zero roles", input: map[string]any{"goal": "build", "roles": []any{}}},
		{name: "four roles", input: map[string]any{"goal": "build", "roles": fourRoles}},
		{name: "cycle", input: map[string]any{"goal": "build", "roles": cyclicRoles}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := teamToolRequest("team_plan_prepare", canonicalJSON(t, tt.input))
			if _, err := prepare(teamResolverContext("@owner:example.test", 7), request); !errors.Is(err, coreteam.ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if len(service.prepareCalls) != 0 {
		t.Fatalf("invalid inputs reached service: %#v", service.prepareCalls)
	}
	valid := teamToolRequest("team_plan_prepare", canonicalJSON(t, map[string]any{"goal": "build", "roles": []any{validRole}}))
	for name, ctx := range map[string]context.Context{
		"owner replacement":      teamResolverContext("@other:example.test", 7),
		"generation replacement": teamResolverContext("@owner:example.test", 8),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := prepare(ctx, valid); !errors.Is(err, coreconversation.ErrConflict) {
				t.Fatalf("identity race err=%v", err)
			}
		})
	}
	service.ready = false
	if _, err := prepare(teamResolverContext("@owner:example.test", 7), valid); !errors.Is(err, coreteam.ErrRuntimeUnavailable) {
		t.Fatalf("readiness race err=%v", err)
	}
}

func TestTeamConversationResolverReturnsSafeStatusAndRedactsServiceErrors(t *testing.T) {
	service := &resolverTeamService{ready: true, statusResult: coreteam.ExecutionProjection{
		ExecutionID: "44444444-4444-4444-8444-444444444444", PlanID: "22222222-2222-4222-8222-222222222222",
		TaskID: "11111111-1111-4111-8111-111111111111", ConfirmationID: "33333333-3333-4333-8333-333333333333",
		Status: coreteam.ExecutionRunning, Revision: 4, CleanupVerified: false, Summary: "credential-secret-canary on i-0123456789 in us-east-1",
	}}
	ctx := teamResolverContext("@owner:example.test", 7)
	resolved, err := (&teamConversationResolver{team: service}).ResolveExtensions(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	status := teamTool(t, resolved[0], "team_task_status")
	request := teamToolRequest("team_task_status", canonicalJSON(t, map[string]any{"task_id": service.statusResult.TaskID}))
	result, err := status(ctx, request)
	if err != nil || len(service.statusCalls) != 1 || service.statusCalls[0].Scope.OwnerID != "@owner:example.test" || service.statusCalls[0].TaskID != service.statusResult.TaskID {
		t.Fatalf("result=%#v calls=%#v err=%v", result, service.statusCalls, err)
	}
	assertSafeTeamResult(t, result.Content)
	if !sameStrings(result.RelatedTaskIDs, []string{service.statusResult.TaskID}) || result.Summary != "Team execution status: running" || !strings.Contains(result.Content, "Team execution is running.") {
		t.Fatalf("status result=%#v", result)
	}
	if strings.Contains(result.Content, "credential-secret-canary") || strings.Contains(result.Content, "i-0123456789") || strings.Contains(result.Content, "us-east-1") {
		t.Fatalf("unsafe execution summary=%s", result.Content)
	}
	executionRequest := teamToolRequest("team_task_status", canonicalJSON(t, map[string]any{"execution_id": service.statusResult.ExecutionID}))
	if _, err := status(ctx, executionRequest); err != nil || len(service.statusCalls) != 2 || service.statusCalls[1].ExecutionID != service.statusResult.ExecutionID {
		t.Fatalf("execution status calls=%#v err=%v", service.statusCalls, err)
	}
	for _, input := range []map[string]any{
		{},
		{"task_id": service.statusResult.TaskID, "execution_id": service.statusResult.ExecutionID},
		{"task_id": "not-a-uuid"},
	} {
		invalid := teamToolRequest("team_task_status", canonicalJSON(t, input))
		if _, err := status(ctx, invalid); !errors.Is(err, coreteam.ErrInvalid) {
			t.Fatalf("input=%v err=%v", input, err)
		}
	}
	service.statusErr = errors.New("provider leaked secret-sentinel and i-0123456789")
	if _, err := status(ctx, request); !errors.Is(err, coreconversation.ErrChatFailed) || strings.Contains(err.Error(), "secret-sentinel") || strings.Contains(err.Error(), "i-0123456789") {
		t.Fatalf("unsafe service error=%v", err)
	}
}

func TestTeamConversationResolverSnapshotAndResultDoNotPersistProposalArguments(t *testing.T) {
	secret := "proposal-secret-canary"
	service := &resolverTeamService{ready: true, prepareResult: coreteam.PlanProjection{
		TaskID: uuid.NewString(), PlanID: uuid.NewString(), ConfirmationID: uuid.NewString(), Revision: 1,
		Status: coreteam.PlanWaitingUser, Summary: "safe summary",
	}}
	resolved, err := (&teamConversationResolver{team: service}).ResolveExtensions(teamResolverContext("@owner:example.test", 7), nil)
	if err != nil {
		t.Fatal(err)
	}
	arguments := canonicalJSON(t, map[string]any{"goal": secret, "roles": []any{map[string]any{"role_id": "build", "goal": "bounded", "capabilities": []any{"shell"}}}})
	result, err := teamTool(t, resolved[0], "team_plan_prepare")(teamResolverContext("@owner:example.test", 7), teamToolRequest("team_plan_prepare", arguments))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := json.Marshal(resolved[0].Snapshot)
	if bytes.Contains(snapshot, []byte(secret)) || strings.Contains(result.Content, secret) || strings.Contains(result.Summary, secret) {
		t.Fatalf("proposal leaked snapshot=%s result=%#v", snapshot, result)
	}
}

func assertClosedToolSchema(t *testing.T, schema map[string]any) {
	t.Helper()
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("tool schema is not closed: %#v", schema)
	}
}

func teamTool(t *testing.T, extension coreconversation.ResolvedExtension, name string) func(context.Context, coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
	t.Helper()
	for _, tool := range extension.Tools {
		if tool.Name == name {
			return extension.Execute
		}
	}
	t.Fatalf("tool %q not found: %#v", name, extension.Tools)
	return nil
}

func teamToolRequest(name, arguments string) coreconversation.ToolExecutionRequest {
	sum := sha256.Sum256([]byte(arguments))
	callID := uuid.NewString()
	return coreconversation.ToolExecutionRequest{
		RequestID: uuid.NewString(), ConversationID: "99999999-9999-4999-8999-999999999999",
		ToolCallID: callID, ExecutionID: "88888888-8888-4888-8888-888888888888",
		ArgsDigest: hex.EncodeToString(sum[:]), Call: coreconversation.ToolCall{ID: callID, Name: name, Arguments: arguments},
	}
}

func canonicalJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := capv1.CanonicalizeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

func assertSafeTeamResult(t *testing.T, content string) {
	t.Helper()
	if !json.Valid([]byte(content)) {
		t.Fatalf("invalid Team result: %s", content)
	}
	for _, forbidden := range []string{"owner_id", "account_generation", "credential", "image_digest", "ami_id", "adapter", "worker_id", "instance_id", "private_ip", "public_ip", "tool_traffic", "audit_log"} {
		if strings.Contains(strings.ToLower(content), forbidden) {
			t.Fatalf("Team result leaked %q: %s", forbidden, content)
		}
	}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

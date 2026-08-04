package coreexecutionv2

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	owner      = "@owner:example.test"
	projectID  = "11111111-1111-4111-8111-111111111111"
	analysisID = "22222222-2222-4222-8222-222222222222"
	targetID   = "33333333-3333-4333-8333-333333333333"
)

func newTestService(t *testing.T, providers Providers) (*Service, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	service, err := NewService(Config{Store: store, Providers: providers, Now: func() time.Time { return time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return service, store
}

func TestExecutionV2ActionsAreFrozen(t *testing.T) {
	if got := len(Actions()); got != 33 {
		t.Fatalf("actions=%d, want 33", got)
	}
	seen := map[string]bool{}
	for _, action := range Actions() {
		if !strings.HasPrefix(action, "agent.execution.v2.") || seen[action] {
			t.Fatalf("invalid or duplicate action %q", action)
		}
		seen[action] = true
	}
}

func TestExecutionV2AnalysisReplayAndOwnerIsolation(t *testing.T) {
	service, _ := newTestService(t, Providers{Analyze: func(_ context.Context, owner string, in map[string]any) (map[string]any, error) {
		return map[string]any{"analysis_id": deterministicID(owner, "agent.execution.v2.projects.analyze", stringParam(in, "idempotency_key")), "project_id": stringParam(in, "project_id"), "status": "ready", "schema_version": SchemaVersion}, nil
	}})
	in := map[string]any{"project_id": projectID, "source": map[string]any{"kind": "git_https", "location": "https://github.com/example/project", "commit": strings.Repeat("a", 40), "immutable": true}, "idempotency_key": "44444444-4444-4444-8444-444444444444"}
	first, err := service.Handle(context.Background(), owner, "agent.execution.v2.projects.analyze", in)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Handle(context.Background(), owner, "agent.execution.v2.projects.analyze", in)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(replay)
	if string(a) != string(b) {
		t.Fatalf("replay changed: %s != %s", a, b)
	}
	if _, err := service.Handle(context.Background(), "@other:example.test", "agent.execution.v2.analyses.get", map[string]any{"analysis_id": first["analysis"].(map[string]any)["analysis_id"]}); err == nil {
		t.Fatal("cross-owner read succeeded")
	}
	changed := map[string]any{"project_id": projectID, "source": in["source"], "idempotency_key": in["idempotency_key"]}
	changed["project_id"] = "55555555-5555-4555-8555-555555555555"
	if _, err := service.Handle(context.Background(), owner, "agent.execution.v2.projects.analyze", changed); err == nil {
		t.Fatal("idempotency mismatch was accepted")
	}
}

func TestExecutionV2RunConfirmationAndRevision(t *testing.T) {
	service, _ := newTestService(t, Providers{})
	planIn := map[string]any{"project_id": projectID, "analysis_id": analysisID, "target_id": targetID, "target_revision": 1.0, "intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service", "idempotency_key": "44444444-4444-4444-8444-444444444444"}
	plan, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.create", planIn)
	if err != nil {
		t.Fatal(err)
	}
	planID := plan["plan"].(map[string]any)["plan_id"].(string)
	run, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.create", map[string]any{"plan_id": planID, "plan_revision": 1.0, "operation": "deploy", "idempotency_key": "66666666-6666-4666-8666-666666666666"})
	if err != nil {
		t.Fatal(err)
	}
	runValue := run["run"].(map[string]any)
	confirmationID := runValue["confirmation_id"].(string)
	confirmed, err := service.Handle(context.Background(), owner, "agent.execution.v2.confirmations.confirm", map[string]any{"confirmation_id": confirmationID, "expected_revision": 1.0, "idempotency_key": "77777777-7777-4777-8777-777777777777"})
	if err != nil {
		t.Fatal(err)
	}
	if confirmed["confirmation"].(map[string]any)["state"] != "confirmed" {
		t.Fatalf("confirmation=%v", confirmed)
	}
	revised, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.revise", map[string]any{"plan_id": planID, "target_id": targetID, "target_revision": 1.0, "expected_revision": 1.0, "intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service", "idempotency_key": "99999999-9999-4999-8999-999999999999"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.get", map[string]any{"plan_id": planID, "revision": 1.0}); err != nil {
		t.Fatalf("historical plan read failed after revision: %v", err)
	}
	if revised["plan"].(map[string]any)["revision"].(uint64) != 2 {
		t.Fatalf("revised plan=%v", revised)
	}
	_, err = service.Handle(context.Background(), owner, "agent.execution.v2.confirmations.confirm", map[string]any{"confirmation_id": confirmationID, "expected_revision": 1.0, "idempotency_key": "88888888-8888-4888-8888-888888888888"})
	if err == nil {
		t.Fatal("stale confirmation revision accepted")
	}
}

func TestExecutionV2RetryCreatesFreshStageAndConfirmationBinding(t *testing.T) {
	service, _ := newTestService(t, Providers{})
	plan, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.create", map[string]any{
		"project_id": projectID, "analysis_id": analysisID, "target_id": targetID, "target_revision": uint64(1),
		"intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service", "idempotency_key": "21212121-2121-4121-8121-212121212121",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.create", map[string]any{
		"plan_id": plan["plan"].(map[string]any)["plan_id"], "plan_revision": uint64(1), "operation": "deploy", "idempotency_key": "22222222-2222-4222-8222-222222222222",
	})
	if err != nil {
		t.Fatal(err)
	}
	retried, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.retry", map[string]any{
		"run_id": first["run"].(map[string]any)["run_id"], "expected_revision": uint64(1), "idempotency_key": "23232323-2323-4232-8232-232323232323",
	})
	if err != nil {
		t.Fatal(err)
	}
	firstView := first["run"].(map[string]any)
	retryView := retried["run"].(map[string]any)
	if retryView["run_id"] == firstView["run_id"] || stringParam(retryView, "stage_id") == stringParam(firstView, "stage_id") || stringParam(retryView, "confirmation_id") == stringParam(firstView, "confirmation_id") {
		t.Fatalf("retry reused immutable binding: first=%v retry=%v", firstView, retryView)
	}
	if len(retried["stages"].([]any)) != 1 {
		t.Fatalf("retry stages=%v", retried["stages"])
	}
	if _, err := service.Handle(context.Background(), owner, "agent.execution.v2.confirmations.confirm", map[string]any{
		"confirmation_id": retryView["confirmation_id"], "expected_revision": uint64(1), "idempotency_key": "24242424-2424-4242-8242-242424242424",
	}); err != nil {
		t.Fatalf("retry confirmation binding failed: %v", err)
	}
}

func TestExecutionV2PlanCompilesAndStageIsDurableAcrossReplay(t *testing.T) {
	service, store := newTestService(t, Providers{Reconcile: func(_ context.Context, _ string, in map[string]any) (map[string]any, error) {
		return map[string]any{"status": "succeeded", "stage_id": stringParam(in, "stage_id"), "target_id": targetID}, nil
	}})
	plan, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.create", map[string]any{"project_id": projectID, "analysis_id": analysisID, "target_id": targetID, "target_revision": uint64(1), "intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service", "idempotency_key": "12121212-1212-4121-8121-121212121212"})
	if err != nil {
		t.Fatal(err)
	}
	planView := plan["plan"].(map[string]any)
	if len(planView["command_steps"].([]any)) == 0 || stringParam(planView, "command_steps_digest") == "" || stringParam(planView, "recipe_digest") == "" {
		t.Fatalf("compiled plan is incomplete: %#v", planView)
	}
	planID := planView["plan_id"].(string)
	run, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.create", map[string]any{"plan_id": planID, "plan_revision": uint64(1), "operation": "deploy", "idempotency_key": "13131313-1313-4131-8131-131313131313"})
	if err != nil {
		t.Fatal(err)
	}
	stages := run["stages"].([]any)
	if len(stages) != 1 {
		t.Fatalf("stages=%v", stages)
	}
	stage := stages[0].(map[string]any)
	stageID := stringParam(stage, "id")
	if stageID == "" || stringParam(stage, "task_id") == "" || stringParam(stage, "confirmation_id") == "" || stringParam(stage, "digest") == "" {
		t.Fatalf("stage binding is incomplete: %#v", stage)
	}
	confirmationID := stringParam(run["run"].(map[string]any), "confirmation_id")
	if _, err = service.Handle(context.Background(), owner, "agent.execution.v2.confirmations.confirm", map[string]any{"confirmation_id": confirmationID, "expected_revision": uint64(1), "idempotency_key": "14141414-1414-4141-8141-141414141414"}); err != nil {
		t.Fatal(err)
	}
	result, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.reconcile", map[string]any{"run_id": run["run"].(map[string]any)["run_id"], "stage_id": stageID, "expected_revision": uint64(2), "idempotency_key": "15151515-1515-4151-8151-151515151515"})
	if err != nil || result["run"].(map[string]any)["status"] != "succeeded" {
		t.Fatalf("reconcile result=%v err=%v", result, err)
	}
	read, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.get", map[string]any{"run_id": run["run"].(map[string]any)["run_id"]})
	if err != nil || len(read["stages"].([]any)) != 1 || read["stages"].([]any)[0].(map[string]any)["status"] != "succeeded" {
		t.Fatalf("run readback=%v err=%v", read, err)
	}
	if _, err = store.Read(context.Background(), owner, "stage", stageID, 1); err != nil {
		t.Fatalf("stage historical revision missing: %v", err)
	}
	// A new Service instance over the same durable store reconstructs the same
	// stage envelope; the replay slot remains stable after restart.
	restarted, err := NewService(Config{Store: store, Providers: service.providers, Now: func() time.Time { return time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.Handle(context.Background(), owner, "agent.execution.v2.runs.create", map[string]any{"plan_id": planID, "plan_revision": uint64(1), "operation": "deploy", "idempotency_key": "13131313-1313-4131-8131-131313131313"})
	if err != nil || replay["stages"].([]any)[0].(map[string]any)["id"] != stageID {
		t.Fatalf("restart replay=%v err=%v", replay, err)
	}
}

func TestExecutionV2ReconcileRequiresBoundConfirmationAndStageIdentity(t *testing.T) {
	providerCalls := 0
	service, _ := newTestService(t, Providers{Reconcile: func(_ context.Context, _ string, in map[string]any) (map[string]any, error) {
		providerCalls++
		return map[string]any{"status": "succeeded", "stage_id": "00000000-0000-4000-8000-000000000000"}, nil
	}})
	plan, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.create", map[string]any{
		"project_id": projectID, "analysis_id": analysisID, "target_id": targetID, "target_revision": uint64(1),
		"intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service", "idempotency_key": "16161616-1616-4161-8161-161616161616",
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.create", map[string]any{
		"plan_id": plan["plan"].(map[string]any)["plan_id"], "plan_revision": uint64(1), "operation": "deploy", "idempotency_key": "17171717-1717-4171-8171-171717171717",
	})
	if err != nil {
		t.Fatal(err)
	}
	runView := run["run"].(map[string]any)
	stageID := run["stages"].([]any)[0].(map[string]any)["id"].(string)
	if _, err = service.Handle(context.Background(), owner, "agent.execution.v2.runs.reconcile", map[string]any{
		"run_id": runView["run_id"], "stage_id": stageID, "expected_revision": uint64(1), "idempotency_key": "18181818-1818-4181-8181-181818181818",
	}); err == nil {
		t.Fatal("reconcile ran before confirmation")
	}
	if providerCalls != 0 {
		t.Fatalf("provider called before confirmation: %d", providerCalls)
	}
	if _, err = service.Handle(context.Background(), owner, "agent.execution.v2.confirmations.confirm", map[string]any{
		"confirmation_id": runView["confirmation_id"], "expected_revision": uint64(1), "idempotency_key": "19191919-1919-4191-8191-191919191919",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Handle(context.Background(), owner, "agent.execution.v2.runs.reconcile", map[string]any{
		"run_id": runView["run_id"], "stage_id": stageID, "expected_revision": uint64(2), "idempotency_key": "20202020-2020-4202-8202-202020202020",
	}); err == nil {
		t.Fatal("provider stage identity drift was accepted")
	}
	if providerCalls != 1 {
		t.Fatalf("provider calls=%d, want 1 after confirmed reconcile", providerCalls)
	}
}

func TestExecutionV2SecretsNeverReturnPlaintext(t *testing.T) {
	service, _ := newTestService(t, Providers{})
	result, err := service.Handle(context.Background(), owner, "agent.execution.v2.secrets.create", map[string]any{"provider": "openrouter", "purpose": "ai_provider_api_key", "value": "sk-test-not-for-output", "idempotency_key": "44444444-4444-4444-8444-444444444444"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "sk-test-not-for-output") || strings.Contains(string(raw), `"value"`) {
		t.Fatalf("secret leaked: %s", raw)
	}
	ref := result["secret"].(map[string]any)["secret_ref"].(string)
	read, err := service.Handle(context.Background(), owner, "agent.execution.v2.secrets.get", map[string]any{"secret_ref": ref})
	if err != nil {
		t.Fatal(err)
	}
	readRaw, _ := json.Marshal(read)
	if strings.Contains(string(readRaw), "sk-test-not-for-output") {
		t.Fatalf("read leaked secret: %s", readRaw)
	}
}

func TestExecutionV2ProviderPortsFailClosedAndSanitizeInvoke(t *testing.T) {
	service, _ := newTestService(t, Providers{})
	_, err := service.Handle(context.Background(), owner, "agent.execution.v2.targets.reserve", map[string]any{"credential_id": projectID, "credential_revision": 1.0, "instance_type": "t3.micro", "volume_gib": 8.0, "idempotency_key": analysisID})
	if err != ErrMissingPort {
		t.Fatalf("reserve err=%v, want missing port", err)
	}
	service, _ = newTestService(t, Providers{Invoke: func(context.Context, string, map[string]any) (map[string]any, error) {
		return map[string]any{"authorization": "never"}, nil
	}})
	_, err = service.Handle(context.Background(), owner, "agent.execution.v2.service_bindings.invoke", map[string]any{"binding_id": projectID, "operation": "status", "expected_revision": 1.0, "idempotency_key": analysisID, "input": map[string]any{}})
	if err != ErrUnsafeOutput {
		t.Fatalf("unsafe invoke err=%v", err)
	}
}

func TestExecutionV2RequestDigestExcludesIdempotencyKey(t *testing.T) {
	first, _, err := requestDigest("agent.execution.v2.projects.analyze", map[string]any{"project_id": projectID, "idempotency_key": "44444444-4444-4444-8444-444444444444"})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := requestDigest("agent.execution.v2.projects.analyze", map[string]any{"project_id": projectID, "idempotency_key": "55555555-5555-4555-8555-555555555555"})
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(first, second) {
		t.Fatal("idempotency key changed the canonical business digest")
	}
}

func TestExecutionV2TypedPortsAreAdaptedAndFailClosedPerRoute(t *testing.T) {
	called := map[string]bool{}
	service, _ := newTestService(t, ConfigProvidersForTest(TypedPorts{
		Analyze: func(_ context.Context, _ string, req AnalyzeRequest) (map[string]any, error) {
			called["analyze"] = req.ProjectID == projectID
			return map[string]any{"analysis_id": analysisID, "status": "ready"}, nil
		},
		ImportTarget: func(_ context.Context, _ string, req TargetImportRequest) (map[string]any, error) {
			called["import"] = req.InstanceID == "i-0123456789abcdef0"
			return map[string]any{"target_id": targetID, "status": "active"}, nil
		},
		ReserveTarget: func(_ context.Context, _ string, req TargetReserveRequest) (map[string]any, error) {
			called["reserve"] = req.InstanceType == "t3.micro" && req.VolumeGiB == 8
			return map[string]any{"target_id": "66666666-6666-4666-8666-666666666666", "status": "active"}, nil
		},
		Observe: func(_ context.Context, _ string, req TargetObserveRequest) (map[string]any, error) {
			called["observe"] = req.TargetID == targetID
			return map[string]any{"target_id": targetID, "status": "active"}, nil
		},
		Invoke: func(_ context.Context, _ string, req InvokeRequest) (map[string]any, error) {
			called["invoke"] = req.BindingID == targetID && req.Operation == "status"
			return map[string]any{"state": "ready"}, nil
		},
		Reconcile: func(_ context.Context, _ string, req ReconcileRequest) (map[string]any, error) {
			called["reconcile"] = req.RunID != "" && req.StageID != ""
			return map[string]any{"status": "succeeded"}, nil
		},
	}))
	_, err := service.Handle(context.Background(), owner, "agent.execution.v2.projects.analyze", map[string]any{"project_id": projectID, "source": map[string]any{"kind": "git_https", "location": "https://github.com/example/project", "commit": strings.Repeat("a", 40), "immutable": true}, "idempotency_key": "44444444-4444-4444-8444-444444444444"})
	if err != nil {
		t.Fatalf("typed analyze: %v", err)
	}
	_, err = service.Handle(context.Background(), owner, "agent.execution.v2.targets.import", map[string]any{"credential_id": projectID, "credential_revision": 1.0, "instance_id": "i-0123456789abcdef0", "idempotency_key": "55555555-5555-4555-8555-555555555555"})
	if err != nil {
		t.Fatalf("typed import: %v", err)
	}
	_, err = service.Handle(context.Background(), owner, "agent.execution.v2.targets.observe", map[string]any{"target_id": targetID, "target_revision": 1.0, "idempotency_key": "66666666-6666-4666-8666-666666666666"})
	if err != nil {
		t.Fatalf("typed observe: %v", err)
	}
	_, err = service.Handle(context.Background(), owner, "agent.execution.v2.targets.reserve", map[string]any{"credential_id": projectID, "credential_revision": 1.0, "instance_type": "t3.micro", "volume_gib": 8.0, "idempotency_key": "66666666-6666-4666-8666-666666666667"})
	if err != nil {
		t.Fatalf("typed reserve: %v", err)
	}
	_, err = service.Handle(context.Background(), owner, "agent.execution.v2.service_bindings.invoke", map[string]any{"binding_id": targetID, "operation": "status", "expected_revision": 1.0, "idempotency_key": "77777777-7777-4777-8777-777777777777", "input": map[string]any{}})
	if err != nil {
		t.Fatalf("typed invoke: %v", err)
	}
	// Build a run and confirmation, then prove reconciliation goes through the
	// typed port rather than silently terminalizing an unknown provider result.
	plan, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.create", map[string]any{"project_id": projectID, "analysis_id": analysisID, "target_id": targetID, "target_revision": 1.0, "intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service", "idempotency_key": "88888888-8888-4888-8888-888888888888"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	run, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.create", map[string]any{"plan_id": plan["plan"].(map[string]any)["plan_id"], "plan_revision": 1.0, "operation": "deploy", "idempotency_key": "99999999-9999-4999-8999-999999999999"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	runID := run["run"].(map[string]any)["run_id"].(string)
	stageID := run["stages"].([]any)[0].(map[string]any)["id"].(string)
	confirmationID := run["run"].(map[string]any)["confirmation_id"].(string)
	if _, err = service.Handle(context.Background(), owner, "agent.execution.v2.confirmations.confirm", map[string]any{"confirmation_id": confirmationID, "expected_revision": 1.0, "idempotency_key": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	reconciled, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.reconcile", map[string]any{"run_id": runID, "stage_id": stageID, "expected_revision": 2.0, "idempotency_key": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if reconciled["run"].(map[string]any)["status"] != "succeeded" {
		t.Fatalf("reconcile did not persist provider readback: %v", reconciled)
	}
	replay, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.reconcile", map[string]any{"run_id": runID, "stage_id": stageID, "expected_revision": 2.0, "idempotency_key": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
	if err != nil || replay["run"].(map[string]any)["status"] != "succeeded" {
		t.Fatalf("reconcile replay mismatch: value=%v err=%v", replay, err)
	}
	_, err = service.Handle(context.Background(), owner, "agent.execution.v2.runs.reconcile", map[string]any{"run_id": runID, "stage_id": analysisID, "expected_revision": 2.0, "idempotency_key": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
	if err == nil {
		t.Fatal("reconcile idempotency drift was accepted")
	}
	for _, key := range []string{"analyze", "import", "reserve", "observe", "invoke", "reconcile"} {
		if !called[key] {
			t.Errorf("typed port %s was not called", key)
		}
	}
}

func ConfigProvidersForTest(ports TypedPorts) Providers {
	return AdaptTypedPorts(ports)
}

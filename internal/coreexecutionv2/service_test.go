package coreexecutionv2

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
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
	expected := []string{
		"agent.execution.v2.projects.analyze", "agent.execution.v2.analyses.get",
		"agent.execution.v2.targets.list", "agent.execution.v2.targets.get", "agent.execution.v2.targets.import", "agent.execution.v2.targets.reserve", "agent.execution.v2.targets.observe",
		"agent.execution.v2.plans.create", "agent.execution.v2.plans.revise", "agent.execution.v2.plans.get", "agent.execution.v2.plans.list",
		"agent.execution.v2.deployments.list", "agent.execution.v2.deployments.get", "agent.execution.v2.deployments.events",
		"agent.execution.v2.runs.create", "agent.execution.v2.runs.get", "agent.execution.v2.runs.list", "agent.execution.v2.runs.cancel", "agent.execution.v2.runs.retry", "agent.execution.v2.runs.events",
		"agent.execution.v2.artifacts.get", "agent.execution.v2.artifacts.download", "agent.execution.v2.service_bindings.list", "agent.execution.v2.service_bindings.get", "agent.execution.v2.service_bindings.invoke",
		"agent.execution.v2.secrets.create", "agent.execution.v2.secrets.get", "agent.execution.v2.secrets.list", "agent.execution.v2.secrets.revoke",
	}
	if got := Actions(); !reflect.DeepEqual(got, expected) {
		t.Fatalf("actions=\n%q\nwant=\n%q", got, expected)
	}
	seen := map[string]bool{}
	for _, action := range Actions() {
		if !strings.HasPrefix(action, "agent.execution.v2.") || seen[action] {
			t.Fatalf("invalid or duplicate action %q", action)
		}
		seen[action] = true
	}
	service, _ := newTestService(t, Providers{})
	for _, action := range []string{
		"agent.execution.v2.runs.reconcile",
		"agent.execution.v2.confirmations.get",
		"agent.execution.v2.confirmations.list",
		"agent.execution.v2.confirmations.confirm",
		"agent.execution.v2.confirmations.reject",
	} {
		if seen[action] {
			t.Fatalf("removed action %q is still published", action)
		}
		if _, err := service.Handle(context.Background(), owner, action, map[string]any{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("removed action %q err=%v, want ErrInvalid", action, err)
		}
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

func TestExecutionV2PaginationUsesOnlyCurrentFields(t *testing.T) {
	service, _ := newTestService(t, Providers{})
	if _, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.list", map[string]any{"limit": 1}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "unknown field limit") {
		t.Fatalf("list accepted obsolete limit field: %v", err)
	}
	if _, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.list", map[string]any{"page_size": 1}); err != nil {
		t.Fatalf("list rejected page_size: %v", err)
	}
	if _, err := service.Handle(context.Background(), owner, "agent.execution.v2.runs.events", map[string]any{"run_id": projectID, "limit": 1}); err != nil {
		t.Fatalf("events rejected current limit field: %v", err)
	}
}

func TestExecutionV2PlanCompilesAndRevisionsRemainDurable(t *testing.T) {
	service, _ := newTestService(t, Providers{})
	input := map[string]any{
		"project_id": projectID, "analysis_id": analysisID, "target_id": targetID,
		"target_revision": uint64(1), "intent": "deploy", "recipe_id": "generic-container-service",
		"purpose": "service", "idempotency_key": "12121212-1212-4121-8121-121212121212",
	}
	plan, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.create", input)
	if err != nil {
		t.Fatal(err)
	}
	planView := plan["plan"].(map[string]any)
	if len(planView["command_steps"].([]any)) == 0 || stringParam(planView, "command_steps_digest") == "" || stringParam(planView, "recipe_digest") == "" {
		t.Fatalf("compiled plan is incomplete: %#v", planView)
	}
	replay, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.create", input)
	if err != nil || replay["plan"].(map[string]any)["digest"] != planView["digest"] {
		t.Fatalf("plan replay=%v err=%v", replay, err)
	}
	planID := stringParam(planView, "plan_id")
	revised, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.revise", map[string]any{
		"plan_id": planID, "target_id": targetID, "target_revision": uint64(1), "expected_revision": uint64(1),
		"intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service",
		"idempotency_key": "13131313-1313-4131-8131-131313131313",
	})
	if err != nil {
		t.Fatal(err)
	}
	if revised["plan"].(map[string]any)["revision"].(uint64) != 2 {
		t.Fatalf("revised plan=%v", revised)
	}
	if _, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.get", map[string]any{"plan_id": planID, "revision": uint64(1)}); err != nil {
		t.Fatalf("historical plan read failed after revision: %v", err)
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
	for _, key := range []string{"analyze", "import", "reserve", "observe", "invoke"} {
		if !called[key] {
			t.Errorf("typed port %s was not called", key)
		}
	}
}

func ConfigProvidersForTest(ports TypedPorts) Providers {
	return AdaptTypedPorts(ports)
}

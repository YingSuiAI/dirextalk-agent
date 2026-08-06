package team

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type capabilityService struct {
	ready          bool
	plan           coreteam.PlanRecord
	execution      coreteam.Execution
	page           coreteam.Page
	planScope      coreteam.Scope
	executionScope coreteam.Scope
	query          coreteam.ListQuery
	cancel         coreteam.CancelExecutionRequest
}

func (s *capabilityService) ReadyForPublication() bool { return s != nil && s.ready }
func (s *capabilityService) GetPlan(_ context.Context, scope coreteam.Scope, _ string) (coreteam.PlanRecord, error) {
	s.planScope = scope
	return s.plan, nil
}
func (s *capabilityService) GetExecution(_ context.Context, scope coreteam.Scope, _ string) (coreteam.Execution, error) {
	s.executionScope = scope
	return s.execution, nil
}
func (s *capabilityService) ListExecutions(_ context.Context, query coreteam.ListQuery) (coreteam.Page, error) {
	s.query = query
	return s.page, nil
}
func (s *capabilityService) CancelExecution(_ context.Context, request coreteam.CancelExecutionRequest) (coreteam.Execution, error) {
	s.cancel = request
	return s.execution, nil
}

func TestTeamCapabilityDescriptorIsClosedAndReadinessGated(t *testing.T) {
	service := &capabilityService{}
	capability, err := NewCapability(service)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := capability.Descriptor()
	if descriptor.GetCapabilityId() != CapabilityID || descriptor.GetSemanticVersion() != "1.0.0" || descriptor.GetProtocolVersion() != 1 {
		t.Fatalf("descriptor=%+v", descriptor)
	}
	if descriptor.GetReadiness() || descriptor.GetReadinessReason() == "" {
		t.Fatalf("unready descriptor readiness=%v reason=%q", descriptor.GetReadiness(), descriptor.GetReadinessReason())
	}

	want := []struct {
		id    string
		typ   capv1.OperationType
		risk  capv1.RiskLevel
		scope string
	}{
		{"plans_get", capv1.OperationType_OPERATION_TYPE_READ, capv1.RiskLevel_RISK_LEVEL_SAFE, "agent:team:plans:read"},
		{"executions_list", capv1.OperationType_OPERATION_TYPE_READ, capv1.RiskLevel_RISK_LEVEL_SAFE, "agent:team:executions:read"},
		{"executions_get", capv1.OperationType_OPERATION_TYPE_READ, capv1.RiskLevel_RISK_LEVEL_SAFE, "agent:team:executions:read"},
		{"executions_cancel", capv1.OperationType_OPERATION_TYPE_MUTATION, capv1.RiskLevel_RISK_LEVEL_HIGH, "agent:team:executions:cancel"},
	}
	if len(descriptor.GetOperations()) != len(want) {
		t.Fatalf("operations=%d want=%d", len(descriptor.GetOperations()), len(want))
	}
	for index, expected := range want {
		operation := descriptor.GetOperations()[index]
		if operation.GetOperationId() != expected.id || operation.GetOperationType() != expected.typ || operation.GetRiskLevel() != expected.risk {
			t.Fatalf("operation[%d]=%+v", index, operation)
		}
		if operation.GetMaxRequestSizeBytes() != 1<<20 || len(operation.GetRequiredScopes()) != 1 || operation.GetRequiredScopes()[0] != expected.scope {
			t.Fatalf("operation %s bounds/scopes=%+v", expected.id, operation)
		}
		if len(operation.GetAudience()) != 2 || operation.GetAudience()[0] != capv1.Audience_AUDIENCE_OWNER_CLIENT || operation.GetAudience()[1] != capv1.Audience_AUDIENCE_NATIVE_AGENT {
			t.Fatalf("operation %s audience=%v", expected.id, operation.GetAudience())
		}
		assertClosedSchema(t, operation.GetInputSchemaJson())
		assertClosedSchema(t, operation.GetResultSchemaJson())
		inputDigest := sha256.Sum256([]byte(operation.GetInputSchemaJson()))
		resultDigest := sha256.Sum256([]byte(operation.GetResultSchemaJson()))
		if !bytes.Equal(inputDigest[:], operation.GetInputSchemaDigest()) || !bytes.Equal(resultDigest[:], operation.GetResultSchemaDigest()) {
			t.Fatalf("operation %s schema digest mismatch", expected.id)
		}
		for _, forbidden := range []string{"owner_id", "account_generation", "credential_id", "credential_revision", "image_digest", "ami_id", "adapter", "worker_id", "instance_id", "private_ip", "public_ip"} {
			if strings.Contains(operation.GetResultSchemaJson(), `"`+forbidden+`"`) {
				t.Fatalf("operation %s result schema exposes %q: %s", expected.id, forbidden, operation.GetResultSchemaJson())
			}
		}
	}
	service.ready = true
	if !capability.Descriptor().GetReadiness() {
		t.Fatal("ready Team service was not published as ready")
	}
}

func TestTeamCapabilityDerivesOwnerAndProjectsOnlyPublicFields(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	scope := coreteam.Scope{OwnerID: "@team-owner:example.test", AccountGeneration: 7}
	plan := capabilityTestPlan(t, scope, now)
	execution := coreteam.Execution{
		ExecutionID: "66666666-6666-4666-8666-666666666666", PlanID: plan.PlanID,
		TaskID: plan.TaskID, ConfirmationID: plan.ConfirmationID,
		OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration,
		Status: coreteam.ExecutionQueued, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	service := &capabilityService{
		ready: true, plan: coreteam.PlanRecord{Plan: plan, CreatedAt: now}, execution: execution,
		page: coreteam.Page{Executions: []coreteam.Execution{execution}, NextID: "77777777-7777-4777-8777-777777777777"},
	}
	capability, err := NewCapability(service)
	if err != nil {
		t.Fatal(err)
	}
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, &capv1.PermissionContext{
		AuthenticatedOwnerId: scope.OwnerID, AccountGeneration: scope.AccountGeneration,
	})

	planJSON, err := capability.HandleOperation(ctx, "plans_get", []byte(`{"plan_id":"11111111-1111-4111-8111-111111111111"}`))
	if err != nil || service.planScope != scope {
		t.Fatalf("plans_get scope=%+v err=%v", service.planScope, err)
	}
	assertPublicJSON(t, planJSON)
	for _, want := range []string{`"plan_id"`, `"task_id"`, `"conversation_id"`, `"confirmation_id"`, `"runtime_id"`, `"hard_budget"`} {
		if !bytes.Contains(planJSON, []byte(want)) {
			t.Fatalf("plan projection missing %s: %s", want, planJSON)
		}
	}
	if bytes.Contains(planJSON, []byte(`"depends_on":null`)) || bytes.Contains(planJSON, []byte(`"capabilities":null`)) {
		t.Fatalf("plan projection violates its array schema: %s", planJSON)
	}

	listJSON, err := capability.HandleOperation(ctx, "executions_list", []byte(`{"page_size":20,"page_token":"77777777-7777-4777-8777-777777777777","statuses":["queued","running"]}`))
	if err != nil || service.query.Scope != scope || service.query.Limit != 20 || service.query.AfterID == "" || len(service.query.Statuses) != 2 {
		t.Fatalf("executions_list query=%+v err=%v", service.query, err)
	}
	assertPublicJSON(t, listJSON)

	getJSON, err := capability.HandleOperation(ctx, "executions_get", []byte(`{"execution_id":"66666666-6666-4666-8666-666666666666"}`))
	if err != nil || service.executionScope != scope {
		t.Fatalf("executions_get scope=%+v err=%v", service.executionScope, err)
	}
	assertPublicJSON(t, getJSON)

	cancelJSON, err := capability.HandleOperation(ctx, "executions_cancel", []byte(`{"execution_id":"66666666-6666-4666-8666-666666666666","expected_revision":1,"idempotency_key":"88888888-8888-4888-8888-888888888888"}`))
	if err != nil || service.cancel.Scope != scope || service.cancel.ExecutionID != execution.ExecutionID || service.cancel.ExpectedRevision != 1 {
		t.Fatalf("executions_cancel request=%+v err=%v", service.cancel, err)
	}
	assertPublicJSON(t, cancelJSON)
}

func TestTeamCapabilityRejectsCallerIdentityUnknownFieldsAndInvalidRequests(t *testing.T) {
	service := &capabilityService{ready: true}
	capability, err := NewCapability(service)
	if err != nil {
		t.Fatal(err)
	}
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, &capv1.PermissionContext{
		AuthenticatedOwnerId: "@team-owner:example.test", AccountGeneration: 7,
	})
	tests := []struct {
		name      string
		operation string
		input     []byte
	}{
		{"caller owner", "plans_get", []byte(`{"plan_id":"11111111-1111-4111-8111-111111111111","owner_id":"@other:example.test"}`)},
		{"caller generation", "plans_get", []byte(`{"plan_id":"11111111-1111-4111-8111-111111111111","account_generation":8}`)},
		{"unknown field", "executions_get", []byte(`{"execution_id":"66666666-6666-4666-8666-666666666666","surprise":true}`)},
		{"invalid id", "plans_get", []byte(`{"plan_id":"not-a-uuid"}`)},
		{"duplicate status", "executions_list", []byte(`{"statuses":["queued","queued"]}`)},
		{"unknown status", "executions_list", []byte(`{"statuses":["paused"]}`)},
		{"zero revision", "executions_cancel", []byte(`{"execution_id":"66666666-6666-4666-8666-666666666666","expected_revision":0,"idempotency_key":"88888888-8888-4888-8888-888888888888"}`)},
		{"unknown operation", "workflows_create", []byte(`{}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := capability.HandleOperation(ctx, tt.operation, tt.input); !errors.Is(err, coreteam.ErrInvalid) {
				t.Fatalf("err=%v, want ErrInvalid", err)
			}
		})
	}
	if _, err := capability.HandleOperation(context.Background(), "plans_get", []byte(`{"plan_id":"11111111-1111-4111-8111-111111111111"}`)); !errors.Is(err, coreteam.ErrInvalid) {
		t.Fatalf("ownerless err=%v", err)
	}
	large := append([]byte(`{"plan_id":"11111111-1111-4111-8111-111111111111","padding":"`), bytes.Repeat([]byte("x"), 1<<20)...)
	large = append(large, []byte(`"}`)...)
	if _, err := capability.HandleOperation(ctx, "plans_get", large); !errors.Is(err, coreteam.ErrInvalid) {
		t.Fatalf("oversized err=%v", err)
	}
}

func assertClosedSchema(t *testing.T, raw string) {
	t.Helper()
	var schema map[string]any
	if !json.Valid([]byte(raw)) || json.Unmarshal([]byte(raw), &schema) != nil || schema["additionalProperties"] != false {
		t.Fatalf("schema is not a closed JSON object: %s", raw)
	}
	assertClosedSchemaNode(t, schema, raw)
}

func assertClosedSchemaNode(t *testing.T, node any, raw string) {
	t.Helper()
	switch value := node.(type) {
	case map[string]any:
		if value["type"] == "object" && value["additionalProperties"] != false {
			t.Fatalf("nested object schema is not closed: %s", raw)
		}
		for _, child := range value {
			assertClosedSchemaNode(t, child, raw)
		}
	case []any:
		for _, child := range value {
			assertClosedSchemaNode(t, child, raw)
		}
	}
}

func assertPublicJSON(t *testing.T, raw []byte) {
	t.Helper()
	if !json.Valid(raw) {
		t.Fatalf("invalid public JSON: %s", raw)
	}
	for _, forbidden := range []string{"@team-owner:example.test", "44444444-4444-4444-8444-444444444444", "ami-0123456789abcdef0", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", `"owner_id"`, `"account_generation"`, `"credential_id"`, `"credential_revision"`, `"image_digest"`, `"ami_id"`, `"adapter"`} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("public projection leaked %q: %s", forbidden, raw)
		}
	}
}

func capabilityTestPlan(t *testing.T, scope coreteam.Scope, now time.Time) coreteam.Plan {
	t.Helper()
	plan := coreteam.Plan{
		PlanID: "11111111-1111-4111-8111-111111111111", OwnerID: scope.OwnerID,
		AccountGeneration: scope.AccountGeneration,
		TaskID:            "22222222-2222-4222-8222-222222222222",
		ConversationID:    "33333333-3333-4333-8333-333333333333",
		CredentialID:      "44444444-4444-4444-8444-444444444444",
		ConfirmationID:    "55555555-5555-4555-8555-555555555555",
		Revision:          1, CredentialRevision: 2, Goal: "prepare a release", Status: coreteam.PlanWaitingUser,
		Runtime: coreteam.RuntimeBinding{RuntimeID: coreteam.OfficialRuntimeID, Adapter: coreteam.AdapterPiV1, ImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AMIID: "ami-0123456789abcdef0", OutputTokens: 4096},
		Quote:   coreteam.QuoteBinding{Region: coreteam.OsakaRegion, AvailabilityZone: "ap-northeast-3a", InstanceType: coreteam.MVPInstanceType, Currency: "USD", Amount: "0.10", HardBudget: "1.00", ExpiresAt: now.Add(time.Hour)},
		Roles:   []coreteam.Role{{RoleID: "builder", Goal: "build and test", Capabilities: []coreteam.Capability{coreteam.CapabilityShell, coreteam.CapabilityTest}}},
	}
	var err error
	plan.Digest, err = plan.SemanticDigest()
	if err != nil || plan.Validate() != nil {
		t.Fatalf("fixture Plan invalid: %v", err)
	}
	return plan
}

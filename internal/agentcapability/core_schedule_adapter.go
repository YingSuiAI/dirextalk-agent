package agentcapability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

type coreScheduleCapability struct{ store coretask.ScheduleStore }

func NewScheduleCapability(store coretask.ScheduleStore, ownerID func() string) Capability {
	return &ownerScopedScheduleCapability{inner: &coreScheduleCapability{store: store}, ownerID: ownerID}
}

type ownerScopedScheduleCapability struct {
	inner   Capability
	ownerID func() string
}

func (c *ownerScopedScheduleCapability) Descriptor() *capv1.CapabilityDescriptor {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.Descriptor()
}

func (c *ownerScopedScheduleCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.inner == nil {
		return nil, fmt.Errorf("schedule capability is not configured")
	}
	if c.ownerID != nil {
		permission, ok := capabilityclient.PermissionFromContext(ctx)
		if !ok || permission == nil || permission.GetAuthenticatedOwnerId() != strings.TrimSpace(c.ownerID()) {
			return nil, fmt.Errorf("schedule owner scope mismatch")
		}
	}
	return c.inner.HandleOperation(ctx, operationID, raw)
}

func (c *coreScheduleCapability) Descriptor() *capv1.CapabilityDescriptor {
	value := descriptor("agent.schedules.v1", "Schedules", "Durable task schedules", []opSpec{
		{"create_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"get_schedule", capv1.OperationType_OPERATION_TYPE_READ, "agent:schedules:read"},
		{"list_schedules", capv1.OperationType_OPERATION_TYPE_READ, "agent:schedules:read"},
		{"list_outputs", capv1.OperationType_OPERATION_TYPE_READ, "agent:schedules:read"},
		{"update_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"pause_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"resume_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"trigger_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"delete_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
	})
	for _, operation := range value.GetOperations() {
		input, result := scheduleCapabilitySchemas(operation.GetOperationId())
		operation.InputSchemaJson, operation.ResultSchemaJson = input, result
		inputDigest, resultDigest := sha256.Sum256([]byte(input)), sha256.Sum256([]byte(result))
		operation.InputSchemaDigest, operation.ResultSchemaDigest = inputDigest[:], resultDigest[:]
	}
	return value
}

func (c *coreScheduleCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("schedule store is not configured")
	}
	var in map[string]json.RawMessage
	if json.Unmarshal(raw, &in) != nil || requireCapabilityIdentity(ctx) != nil || hasIdentityOverride(in) {
		return nil, coretask.ErrInvalid
	}
	key := valueOrUUID(in, "idempotency_key")
	switch operationID {
	case "create_schedule":
		schedule, err := scheduleFromCreateInput(ctx, in, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		digest, err := coretask.CanonicalMutationDigest(map[string]any{"operation": operationID, "schedule": schedule})
		if err != nil {
			return nil, err
		}
		out, err := c.store.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: schedule, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
		return marshalResult(scheduleMutationResult(out), err)
	case "get_schedule":
		out, err := c.store.GetSchedule(ctx, stringValue(in, "schedule_id"))
		return marshalResult(map[string]any{"schedule": scheduleProjection(out)}, err)
	case "list_schedules":
		out, next, err := c.store.ListSchedules(ctx, stringValue(in, "page_token"), intValue(in, "page_size", 50))
		items := make([]map[string]any, 0, len(out))
		for _, schedule := range out {
			items = append(items, scheduleProjection(schedule))
		}
		return marshalResult(map[string]any{"schedules": items, "next_page_token": next}, err)
	case "list_outputs":
		scheduleID, pageToken, pageSize, err := parseScheduleOutputInput(in)
		if err != nil {
			return nil, err
		}
		schedule, err := c.store.GetSchedule(ctx, scheduleID)
		if err != nil {
			return nil, err
		}
		if schedule.ID != scheduleID {
			return nil, coretask.ErrConflict
		}
		reader, ok := c.store.(coretask.ScheduleOutputStore)
		if !ok {
			return nil, fmt.Errorf("schedule output store is not configured")
		}
		outputs, next, err := reader.ListScheduleOutputs(ctx, scheduleID, pageToken, pageSize)
		if err != nil {
			return nil, err
		}
		projected := make([]publicScheduleOutput, 0, len(outputs))
		for _, output := range outputs {
			if output.Validate() != nil || output.ScheduleID != scheduleID {
				return nil, coretask.ErrInvalid
			}
			projected = append(projected, projectScheduleOutput(output))
		}
		return marshalResult(map[string]any{"outputs": projected, "next_page_token": next}, nil)
	case "update_schedule":
		expected := uintValue(in, "expected_revision")
		schedule, err := c.store.GetSchedule(ctx, stringValue(in, "schedule_id"))
		if err != nil {
			return nil, err
		}
		if expected == 0 || expected != schedule.Revision {
			return nil, coretask.ErrRevisionConflict
		}
		if value, ok := in["name"]; ok && json.Unmarshal(value, &schedule.Name) != nil {
			return nil, coretask.ErrInvalid
		}
		if value, ok := in["task_template"]; ok {
			var template coretask.TaskTemplate
			if json.Unmarshal(value, &template) != nil || bindScheduleAuthority(ctx, &template) != nil {
				return nil, coretask.ErrInvalid
			}
			schedule.Spec = template
		}
		if value, ok := in["trigger"]; ok {
			if err = applyScheduleTrigger(&schedule, value); err != nil {
				return nil, err
			}
		}
		schedule.UpdatedAt = time.Now().UTC()
		digest, err := coretask.CanonicalMutationDigest(map[string]any{"operation": operationID, "schedule": schedule, "expected_revision": expected})
		if err != nil {
			return nil, err
		}
		out, err := c.store.UpdateSchedule(ctx, coretask.UpdateScheduleCommand{Schedule: schedule, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest, ExpectedRevision: expected}})
		return marshalResult(scheduleMutationResult(out), err)
	case "pause_schedule", "resume_schedule", "delete_schedule":
		scheduleID, revision, at := stringValue(in, "schedule_id"), uintValue(in, "expected_revision"), time.Now().UTC()
		digest, err := coretask.CanonicalMutationDigest(map[string]any{"operation": operationID, "schedule_id": scheduleID, "expected_revision": revision})
		if err != nil {
			return nil, err
		}
		command := coretask.ScheduleMutationCommand{ScheduleID: scheduleID, At: at, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest, ExpectedRevision: revision}}
		var out coretask.Schedule
		switch operationID {
		case "pause_schedule":
			out, err = c.store.PauseSchedule(ctx, command)
		case "resume_schedule":
			out, err = c.store.ResumeSchedule(ctx, command)
		default:
			out, err = c.store.DeleteSchedule(ctx, command)
		}
		if operationID == "delete_schedule" {
			return marshalResult(map[string]any{"deleted": out.Deleted, "schedule_id": out.ID}, err)
		}
		return marshalResult(scheduleMutationResult(out), err)
	case "trigger_schedule":
		scheduleID, at := stringValue(in, "schedule_id"), time.Now().UTC()
		digest, err := coretask.CanonicalMutationDigest(map[string]any{"operation": operationID, "schedule_id": scheduleID})
		if err != nil {
			return nil, err
		}
		schedule, occurrence, task, err := c.store.TriggerNow(ctx, coretask.TriggerScheduleCommand{ScheduleID: scheduleID, At: at, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
		return marshalResult(map[string]any{"schedule": scheduleProjection(schedule), "occurrence": occurrence, "task": task}, err)
	default:
		return nil, fmt.Errorf("unknown schedule operation %q", operationID)
	}
}

func scheduleMutationResult(schedule coretask.Schedule) map[string]any {
	return map[string]any{"schedule": scheduleProjection(schedule)}
}

func hasIdentityOverride(in map[string]json.RawMessage) bool {
	for _, key := range []string{"owner_id", "authenticated_owner_id", "account_generation"} {
		if _, ok := in[key]; ok {
			return true
		}
	}
	return false
}

const scheduleObjectSchema = `{"additionalProperties":false,"properties":{"created_at":{"format":"date-time","type":"string"},"last_scheduled_for":{"format":"date-time","type":"string"},"name":{"type":"string"},"next_run_at":{"format":"date-time","type":"string"},"revision":{"minimum":1,"type":"integer"},"schedule_id":{"format":"uuid","type":"string"},"state":{"enum":["active","paused","deleted"],"type":"string"},"task_template":{"type":"object"},"trigger":{"type":"object"},"updated_at":{"format":"date-time","type":"string"}},"required":["schedule_id","name","task_template","trigger","state","revision","created_at","updated_at"],"type":"object"}`
const scheduleCreateSchema = `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"name":{"type":"string"},"task_template":{"type":"object"},"trigger":{"type":"object"}},"required":["idempotency_key","name","task_template","trigger"],"type":"object"}`
const scheduleGetSchema = `{"additionalProperties":false,"properties":{"schedule_id":{"format":"uuid","type":"string"}},"required":["schedule_id"],"type":"object"}`
const scheduleListSchema = `{"additionalProperties":false,"properties":{"page_size":{"maximum":200,"minimum":1,"type":"integer"},"page_token":{"type":"string"}},"type":"object"}`
const scheduleOutputListSchema = `{"additionalProperties":false,"properties":{"page_size":{"maximum":200,"minimum":1,"type":"integer"},"page_token":{"type":"string"},"schedule_id":{"format":"uuid","type":"string"}},"required":["schedule_id"],"type":"object"}`
const scheduleOutputObjectSchema = `{"additionalProperties":false,"properties":{"created_at":{"format":"date-time","type":"string"},"failure_code":{"type":"string"},"failure_summary":{"type":"string"},"occurrence_id":{"format":"uuid","type":"string"},"result":{"type":"object"},"scheduled_for":{"format":"date-time","type":"string"},"status":{"enum":["queued","running","succeeded","failed","waiting_user","canceled"],"type":"string"},"task_id":{"format":"uuid","type":"string"},"updated_at":{"format":"date-time","type":"string"}},"required":["occurrence_id","task_id","scheduled_for","status","created_at","updated_at"],"type":"object"}`
const scheduleUpdateSchema = `{"additionalProperties":false,"properties":{"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"name":{"type":"string"},"schedule_id":{"format":"uuid","type":"string"},"task_template":{"type":"object"},"trigger":{"type":"object"}},"required":["idempotency_key","schedule_id","expected_revision"],"type":"object"}`
const scheduleMutationSchema = `{"additionalProperties":false,"properties":{"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"schedule_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","schedule_id","expected_revision"],"type":"object"}`
const scheduleTriggerSchema = `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"schedule_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","schedule_id"],"type":"object"}`

func scheduleCapabilitySchemas(operation string) (string, string) {
	object := `{"additionalProperties":false,"properties":{"schedule":` + scheduleObjectSchema + `},"required":["schedule"],"type":"object"}`
	switch operation {
	case "create_schedule":
		return scheduleCreateSchema, object
	case "get_schedule":
		return scheduleGetSchema, object
	case "list_schedules":
		return scheduleListSchema, `{"additionalProperties":false,"properties":{"next_page_token":{"type":"string"},"schedules":{"items":` + scheduleObjectSchema + `,"type":"array"}},"required":["schedules","next_page_token"],"type":"object"}`
	case "list_outputs":
		return scheduleOutputListSchema, `{"additionalProperties":false,"properties":{"next_page_token":{"type":"string"},"outputs":{"items":` + scheduleOutputObjectSchema + `,"type":"array"}},"required":["outputs","next_page_token"],"type":"object"}`
	case "update_schedule":
		return scheduleUpdateSchema, object
	case "pause_schedule", "resume_schedule":
		return scheduleMutationSchema, object
	case "trigger_schedule":
		return scheduleTriggerSchema, `{"additionalProperties":false,"properties":{"occurrence":{"type":"object"},"schedule":` + scheduleObjectSchema + `,"task":{"type":"object"}},"required":["schedule","occurrence","task"],"type":"object"}`
	case "delete_schedule":
		return scheduleMutationSchema, `{"additionalProperties":false,"properties":{"deleted":{"type":"boolean"},"schedule_id":{"format":"uuid","type":"string"}},"required":["deleted","schedule_id"],"type":"object"}`
	default:
		return "", ""
	}
}

type publicScheduleOutput struct {
	OccurrenceID   string          `json:"occurrence_id"`
	TaskID         string          `json:"task_id"`
	ScheduledFor   time.Time       `json:"scheduled_for"`
	Status         coretask.Status `json:"status"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Result         any             `json:"result,omitempty"`
	FailureCode    string          `json:"failure_code,omitempty"`
	FailureSummary string          `json:"failure_summary,omitempty"`
}

func projectScheduleOutput(output coretask.ScheduleOutput) publicScheduleOutput {
	return publicScheduleOutput{
		OccurrenceID: output.OccurrenceID, TaskID: output.TaskID, ScheduledFor: output.ScheduledFor.UTC(), Status: output.Status,
		CreatedAt: output.CreatedAt.UTC(), UpdatedAt: output.UpdatedAt.UTC(), Result: projectTaskResult(output.Result),
		FailureCode: output.FailureCode, FailureSummary: output.FailureSummary,
	}
}

func parseScheduleOutputInput(in map[string]json.RawMessage) (string, string, int, error) {
	for key := range in {
		switch key {
		case "schedule_id", "page_size", "page_token":
		default:
			return "", "", 0, coretask.ErrInvalid
		}
	}
	scheduleID := stringValue(in, "schedule_id")
	if !coretask.ValidUUID(scheduleID) {
		return "", "", 0, coretask.ErrInvalid
	}
	pageSize := 50
	if raw, ok := in["page_size"]; ok {
		var parsed int
		if json.Unmarshal(raw, &parsed) != nil || parsed < 1 || parsed > 200 {
			return "", "", 0, coretask.ErrInvalid
		}
		pageSize = parsed
	}
	pageToken := ""
	if raw, ok := in["page_token"]; ok {
		if strings.TrimSpace(string(raw)) == "null" || json.Unmarshal(raw, &pageToken) != nil || len(pageToken) > 4096 {
			return "", "", 0, coretask.ErrInvalid
		}
	}
	return scheduleID, strings.TrimSpace(pageToken), pageSize, nil
}

func scheduleFromCreateInput(ctx context.Context, in map[string]json.RawMessage, now time.Time) (coretask.Schedule, error) {
	var name string
	var template coretask.TaskTemplate
	if json.Unmarshal(in["name"], &name) != nil || json.Unmarshal(in["task_template"], &template) != nil || bindScheduleAuthority(ctx, &template) != nil {
		return coretask.Schedule{}, coretask.ErrInvalid
	}
	key := valueOrUUID(in, "idempotency_key")
	schedule := coretask.Schedule{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("schedule:"+key)).String(), Name: name, Spec: template, Revision: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC(), Timezone: "UTC"}
	if err := applyScheduleTrigger(&schedule, in["trigger"]); err != nil {
		return coretask.Schedule{}, err
	}
	return schedule.Normalize()
}

func bindScheduleAuthority(ctx context.Context, template *coretask.TaskTemplate) error {
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 || template == nil || template.Payload.Agent != nil {
		return coretask.ErrInvalid
	}
	if template.Kind == "" {
		template.Kind = coretask.TaskKindAgent
	}
	if template.Kind != coretask.TaskKindAgent {
		return coretask.ErrInvalid
	}
	template.Payload.Agent = &coretask.AgentTaskPayload{OwnerID: strings.TrimSpace(permission.GetAuthenticatedOwnerId()), AccountGeneration: uint64(permission.GetAccountGeneration())}
	return nil
}

func applyScheduleTrigger(schedule *coretask.Schedule, raw json.RawMessage) error {
	var trigger struct {
		RunAt string `json:"run_at"`
		Cron  *struct {
			Expression string `json:"expression"`
			Timezone   string `json:"timezone"`
		} `json:"cron"`
	}
	if schedule == nil || json.Unmarshal(raw, &trigger) != nil || (strings.TrimSpace(trigger.RunAt) == "") == (trigger.Cron == nil) {
		return coretask.ErrInvalid
	}
	if trigger.Cron != nil {
		schedule.RunAt, schedule.Cron, schedule.Timezone = nil, strings.TrimSpace(trigger.Cron.Expression), strings.TrimSpace(trigger.Cron.Timezone)
		return nil
	}
	runAt, err := time.Parse(time.RFC3339, strings.TrimSpace(trigger.RunAt))
	if err != nil {
		return coretask.ErrInvalid
	}
	runAt = runAt.UTC()
	schedule.RunAt, schedule.Cron, schedule.Timezone = &runAt, "", "UTC"
	return nil
}

func scheduleProjection(schedule coretask.Schedule) map[string]any {
	state := "active"
	if schedule.Deleted {
		state = "deleted"
	} else if schedule.Paused {
		state = "paused"
	}
	trigger := map[string]any{}
	if schedule.RunAt != nil {
		trigger["run_at"] = schedule.RunAt.UTC()
	} else {
		trigger["cron"] = map[string]any{"expression": schedule.Cron, "timezone": schedule.Timezone}
	}
	result := map[string]any{"schedule_id": schedule.ID, "name": schedule.Name, "task_template": schedule.Spec, "trigger": trigger, "state": state, "revision": schedule.Revision, "created_at": schedule.CreatedAt.UTC(), "updated_at": schedule.UpdatedAt.UTC()}
	if !schedule.NextRunAt.IsZero() {
		result["next_run_at"] = schedule.NextRunAt.UTC()
	}
	if !schedule.LastScheduledFor.IsZero() {
		result["last_scheduled_for"] = schedule.LastScheduledFor.UTC()
	}
	return result
}

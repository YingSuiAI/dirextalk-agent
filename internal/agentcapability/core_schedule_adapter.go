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

// coreScheduleCapability exposes the existing durable ScheduleStore through
// the neutral capability boundary. It intentionally performs no direct SQL
// and uses the store's revision/idempotency contracts for every mutation.
type coreScheduleCapability struct{ store coretask.ScheduleStore }

// NewScheduleCapability exposes the schedule adapter to composition roots
// without coupling them to the unexported implementation type.  A deployment
// may provide an owner identity when one Agent instance is pinned to one
// owner; the neutral server still validates account generation and grant
// scopes before this wrapper runs.
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
		{"update_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"pause_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"resume_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"trigger_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"delete_schedule", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:schedules:write"},
		{"list_runs", capv1.OperationType_OPERATION_TYPE_READ, "agent:schedules:read"},
		{"get_run", capv1.OperationType_OPERATION_TYPE_READ, "agent:schedules:read"},
	})
	for _, operation := range value.GetOperations() {
		var input, result string
		switch operation.GetOperationId() {
		case "list_runs":
			input, result = scheduleRunsListSchema, scheduleRunsListResultSchema
		case "get_run":
			input, result = scheduleRunGetSchema, scheduleRunGetResultSchema
		default:
			continue
		}
		operation.InputSchemaJson = input
		operation.ResultSchemaJson = result
		inputDigest := sha256.Sum256([]byte(input))
		resultDigest := sha256.Sum256([]byte(result))
		operation.InputSchemaDigest = inputDigest[:]
		operation.ResultSchemaDigest = resultDigest[:]
	}
	return value
}

func (c *coreScheduleCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("schedule store is not configured")
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	// Schedule rows live in the Agent-owned database instance.  The signed
	// capability context is the owner/account-generation fence; caller JSON
	// must never be allowed to select another owner.
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	if hasIdentityOverride(in) {
		return nil, fmt.Errorf("owner identity fields are not accepted")
	}
	key := valueOrUUID(in, "idempotency_key")
	switch operationID {
	case "create_schedule":
		schedule, err := scheduleFromInput(in, time.Now().UTC(), false)
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
		return marshalResult(out, err)
	case "list_schedules":
		out, next, err := c.store.ListSchedules(ctx, stringValue(in, "page_token"), intValue(in, "limit", 50))
		return marshalResult(map[string]any{"schedules": out, "next_page_token": next}, err)
	case "update_schedule":
		expected := uintValue(in, "expected_revision")
		schedule, err := scheduleFromInput(in, time.Now().UTC(), false)
		if err != nil {
			return nil, err
		}
		if expected == 0 {
			expected = schedule.Revision
		}
		if schedule.Revision == 0 {
			schedule.Revision = expected
		}
		digest, err := coretask.CanonicalMutationDigest(map[string]any{"operation": operationID, "schedule": schedule, "expected_revision": expected})
		if err != nil {
			return nil, err
		}
		out, err := c.store.UpdateSchedule(ctx, coretask.UpdateScheduleCommand{Schedule: schedule, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest, ExpectedRevision: expected}})
		return marshalResult(scheduleMutationResult(out), err)
	case "pause_schedule", "resume_schedule", "delete_schedule":
		scheduleID := stringValue(in, "schedule_id")
		revision := uintValue(in, "expected_revision")
		at := time.Now().UTC()
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
			return marshalResult(scheduleDeleteResult(out), err)
		}
		return marshalResult(scheduleMutationResult(out), err)
	case "trigger_schedule":
		scheduleID := stringValue(in, "schedule_id")
		at := time.Now().UTC()
		digest, err := coretask.CanonicalMutationDigest(map[string]any{"operation": operationID, "schedule_id": scheduleID})
		if err != nil {
			return nil, err
		}
		schedule, occurrence, task, err := c.store.TriggerNow(ctx, coretask.TriggerScheduleCommand{ScheduleID: scheduleID, At: at, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
		return marshalResult(scheduleTriggerResult(schedule, occurrence, task), err)
	case "list_runs":
		reader, ok := c.store.(interface {
			ListOccurrences(context.Context, string, string, int) ([]coretask.Occurrence, string, error)
		})
		if !ok {
			return nil, fmt.Errorf("schedule occurrence reader is not configured")
		}
		items, next, err := reader.ListOccurrences(ctx, stringValue(in, "schedule_id"), stringValue(in, "page_token"), pageLimit(in, 50))
		return marshalResult(map[string]any{"runs": items, "next_page_token": next}, err)
	case "get_run":
		reader, ok := c.store.(interface {
			GetOccurrence(context.Context, string) (coretask.Occurrence, error)
		})
		if !ok {
			return nil, fmt.Errorf("schedule occurrence reader is not configured")
		}
		item, err := reader.GetOccurrence(ctx, stringValue(in, "run_id"))
		return marshalResult(item, err)
	default:
		return nil, fmt.Errorf("unknown schedule operation %q", operationID)
	}
}

func scheduleMutationResult(schedule coretask.Schedule) map[string]any {
	return map[string]any{"schedule": schedule, "replayed": schedule.Replayed}
}

func scheduleDeleteResult(schedule coretask.Schedule) map[string]any {
	return map[string]any{
		"deleted":     schedule.Deleted,
		"schedule_id": schedule.ID,
		"schedule":    schedule,
		"replayed":    schedule.Replayed,
	}
}

func scheduleTriggerResult(schedule coretask.Schedule, occurrence coretask.Occurrence, task coretask.Task) map[string]any {
	return map[string]any{
		"schedule":      schedule,
		"occurrence":    occurrence,
		"occurrence_id": occurrence.ID,
		"task":          task,
		"task_id":       task.ID,
		"replayed":      schedule.Replayed,
	}
}

func hasIdentityOverride(in map[string]json.RawMessage) bool {
	for _, key := range []string{"owner_id", "authenticated_owner_id", "account_generation"} {
		if _, ok := in[key]; ok {
			return true
		}
	}
	return false
}

const (
	scheduleRunsListSchema       = `{"additionalProperties":false,"properties":{"limit":{"maximum":200,"minimum":1,"type":"integer"},"page_token":{"type":"string"},"schedule_id":{"format":"uuid","type":"string"}},"required":["schedule_id"],"type":"object"}`
	scheduleRunsListResultSchema = `{"additionalProperties":false,"properties":{"next_page_token":{"type":"string"},"runs":{"items":{"additionalProperties":false,"properties":{"created_at":{"format":"date-time","type":"string"},"id":{"format":"uuid","type":"string"},"scheduled_for":{"format":"date-time","type":"string"},"schedule_id":{"format":"uuid","type":"string"},"task_id":{"format":"uuid","type":"string"},"trigger_key":{"format":"uuid","type":"string"}},"required":["id","schedule_id","scheduled_for","task_id","created_at"],"type":"object"},"type":"array"}},"required":["runs","next_page_token"],"type":"object"}`
	scheduleRunGetSchema         = `{"additionalProperties":false,"properties":{"run_id":{"format":"uuid","type":"string"}},"required":["run_id"],"type":"object"}`
	scheduleRunGetResultSchema   = `{"additionalProperties":false,"properties":{"created_at":{"format":"date-time","type":"string"},"id":{"format":"uuid","type":"string"},"scheduled_for":{"format":"date-time","type":"string"},"schedule_id":{"format":"uuid","type":"string"},"task_id":{"format":"uuid","type":"string"},"trigger_key":{"format":"uuid","type":"string"}},"required":["id","schedule_id","scheduled_for","task_id","created_at"],"type":"object"}`
)

func scheduleFromInput(in map[string]json.RawMessage, now time.Time, requireID bool) (coretask.Schedule, error) {
	var schedule coretask.Schedule
	if nested := in["schedule"]; len(nested) > 0 {
		if err := json.Unmarshal(nested, &schedule); err != nil {
			return coretask.Schedule{}, coretask.ErrInvalid
		}
	} else {
		encoded, err := json.Marshal(in)
		if err != nil || json.Unmarshal(encoded, &schedule) != nil {
			return coretask.Schedule{}, coretask.ErrInvalid
		}
	}
	if schedule.ID == "" {
		schedule.ID = stringValue(in, "schedule_id")
	}
	if !coretask.ValidUUID(schedule.ID) {
		if requireID {
			return coretask.Schedule{}, coretask.ErrInvalid
		}
		schedule.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("schedule:"+valueOrUUID(in, "idempotency_key"))).String()
	}
	if schedule.Revision == 0 {
		schedule.Revision = 1
	}
	if schedule.CreatedAt.IsZero() {
		schedule.CreatedAt = now.UTC()
	}
	if schedule.UpdatedAt.IsZero() {
		schedule.UpdatedAt = now.UTC()
	}
	if schedule.Timezone == "" {
		schedule.Timezone = "UTC"
	}
	normalized, err := schedule.Normalize()
	if err != nil {
		return coretask.Schedule{}, err
	}
	return normalized, nil
}

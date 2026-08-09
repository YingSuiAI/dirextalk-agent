package coreconversation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type scheduleIntrinsicArguments struct {
	Name           string `json:"name"`
	Goal           string `json:"goal"`
	RunAt          string `json:"run_at,omitempty"`
	Cron           string `json:"cron,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *Service) resolveIntrinsicTools(ctx context.Context, lease TurnLease) ([]ResolvedIntrinsic, error) {
	tools := make([]ResolvedIntrinsic, 0, 2)
	if schedules, ok := s.turns.(ConversationScheduleStore); ok && strings.TrimSpace(lease.Turn.OwnerID) != "" && lease.Turn.AccountGeneration != 0 {
		tools = append(tools, scheduleIntrinsic(schedules, lease))
	}
	if s.intrinsics != nil {
		external, err := s.intrinsics.ResolveIntrinsicTools(ctx, lease)
		if err != nil {
			return nil, err
		}
		tools = append(tools, external...)
	}
	return tools, nil
}

func scheduleIntrinsic(store ConversationScheduleStore, bound TurnLease) ResolvedIntrinsic {
	return ResolvedIntrinsic{
		Tool: coremodel.Tool{
			Name:        coremodel.IntrinsicScheduleCreateToolName,
			Description: "Create a durable one-time or recurring Agent schedule in this conversation. Identity, conversation, model profile, and account generation are injected by Core and must not be supplied as arguments.",
			InputSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []any{"name", "goal"},
				"properties": map[string]any{
					"name":            map[string]any{"type": "string", "minLength": 1, "maxLength": 512},
					"goal":            map[string]any{"type": "string", "minLength": 1, "maxLength": coretask.MaxGoalBytes},
					"run_at":          map[string]any{"type": "string", "format": "date-time"},
					"cron":            map[string]any{"type": "string"},
					"timezone":        map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
					"timeout_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": coretask.MaxTimeoutSeconds},
				},
				"oneOf": []any{
					map[string]any{"required": []any{"run_at"}, "not": map[string]any{"anyOf": []any{map[string]any{"required": []any{"cron"}}, map[string]any{"required": []any{"timezone"}}}}},
					map[string]any{"required": []any{"cron", "timezone"}, "not": map[string]any{"required": []any{"run_at"}}},
				},
			},
		},
		Execute: func(ctx context.Context, request IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
			return executeScheduleIntrinsic(ctx, store, bound, request)
		},
	}
}

func executeScheduleIntrinsic(ctx context.Context, store ConversationScheduleStore, bound TurnLease, request IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
	if ctx == nil || store == nil || request.Lease.Turn.ID != bound.Turn.ID || request.Lease.Turn.RequestID != bound.Turn.RequestID ||
		request.Lease.LeaseID != bound.LeaseID || request.Lease.Epoch != bound.Epoch || request.Call.Name != coremodel.IntrinsicScheduleCreateToolName || request.Call.Validate() != nil ||
		request.ConversationRevision == 0 || request.ConversationRevision == ^uint64(0) {
		return IntrinsicExecutionResult{}, ErrInvalid
	}
	args, err := parseScheduleIntrinsicArguments(request.CanonicalArguments)
	if err != nil {
		return IntrinsicExecutionResult{}, err
	}
	turn := bound.Turn
	if strings.TrimSpace(turn.OwnerID) == "" || turn.AccountGeneration == 0 || !validUUID(turn.ConversationID) || !validUUID(turn.ProfileID) || turn.CreatedAt.IsZero() {
		return IntrinsicExecutionResult{}, ErrInvalid
	}
	// Turn creation is the immutable time anchor for the same recorded model
	// call across lease recovery. Wall-clock time here would change the replay
	// digest and turn response after an uncertain commit.
	now := turn.CreatedAt.UTC().Truncate(time.Microsecond)
	scheduleID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-schedule:"+turn.ID+":"+turn.RequestID+":"+request.Call.ID)).String()
	idempotencyKey := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-schedule-create:"+turn.ID+":"+turn.RequestID+":"+request.Call.ID)).String()
	schedule := coretask.Schedule{
		ID: scheduleID, Name: args.Name,
		Spec: coretask.TaskTemplate{
			Kind: coretask.TaskKindAgent, Payload: coretask.TaskPayload{Agent: &coretask.AgentTaskPayload{OwnerID: strings.TrimSpace(turn.OwnerID), AccountGeneration: turn.AccountGeneration}},
			Goal: args.Goal, ConversationID: turn.ConversationID, ModelProfileID: turn.ProfileID, TimeoutSeconds: args.TimeoutSeconds,
		},
		Cron: args.Cron, Timezone: args.Timezone, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if args.RunAt != "" {
		runAt, parseErr := time.Parse(time.RFC3339, args.RunAt)
		if parseErr != nil {
			return IntrinsicExecutionResult{}, ErrInvalid
		}
		runAt = runAt.UTC()
		schedule.RunAt, schedule.NextRunAt = &runAt, runAt
	} else {
		schedule.NextRunAt, err = coretask.NextCron(now, schedule.Cron, schedule.Timezone)
		if err != nil {
			return IntrinsicExecutionResult{}, ErrInvalid
		}
	}
	normalized, err := schedule.Normalize()
	if err != nil {
		return IntrinsicExecutionResult{}, ErrInvalid
	}
	schedule = normalized
	digestInput := struct {
		OwnerID           string            `json:"owner_id"`
		AccountGeneration uint64            `json:"account_generation"`
		TurnID            string            `json:"turn_id"`
		RequestID         string            `json:"request_id"`
		CallID            string            `json:"call_id"`
		Schedule          coretask.Schedule `json:"schedule"`
	}{turn.OwnerID, turn.AccountGeneration, turn.ID, turn.RequestID, request.Call.ID, schedule}
	digestRaw, _ := json.Marshal(digestInput)
	digestSum := sha256.Sum256(digestRaw)
	// The client revision is optional for normal chat. Use the exact
	// conversation snapshot that produced this model tool call, so a later
	// concurrent commit still fails the PostgreSQL CAS instead of either
	// guessing revision 2 or appending to context the model did not see.
	revision := request.ConversationRevision + 1
	message := Message{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-schedule-message:"+turn.ID+":"+request.Call.ID)).String(),
		Role: RoleAssistant, Content: fmt.Sprintf("Scheduled %q (schedule_id: %s).", schedule.Name, schedule.ID),
		CreatedAt: now.Add(time.Microsecond), ModelProfileID: turn.ProfileID,
	}
	response := ChatResponse{RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: revision, Message: message, Done: true, ModelProfileID: turn.ProfileID}
	command := ConversationScheduleCommand{
		Lease: bound, Schedule: schedule,
		Mutation: coretask.MutationCommand{IdempotencyKey: idempotencyKey, RequestDigest: hex.EncodeToString(digestSum[:])},
		Response: response,
	}
	if command.Validate() != nil {
		return IntrinsicExecutionResult{}, ErrInvalid
	}
	if _, err = store.CommitConversationSchedule(ctx, command); err != nil {
		return IntrinsicExecutionResult{}, err
	}
	return IntrinsicExecutionResult{TurnCommitted: true}, nil
}

func parseScheduleIntrinsicArguments(raw json.RawMessage) (scheduleIntrinsicArguments, error) {
	if len(raw) == 0 || len(raw) > MaxToolArgumentsBytes {
		return scheduleIntrinsicArguments{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var args scheduleIntrinsicArguments
	if decoder.Decode(&args) != nil || decoder.Decode(&struct{}{}) == nil {
		return scheduleIntrinsicArguments{}, ErrInvalid
	}
	args.Name, args.Goal = strings.TrimSpace(args.Name), strings.TrimSpace(args.Goal)
	args.RunAt, args.Cron, args.Timezone = strings.TrimSpace(args.RunAt), strings.TrimSpace(args.Cron), strings.TrimSpace(args.Timezone)
	if args.Name == "" || args.Goal == "" || !utf8.ValidString(args.Name) || !utf8.ValidString(args.Goal) || len([]byte(args.Name)) > 512 || len([]byte(args.Goal)) > coretask.MaxGoalBytes || args.TimeoutSeconds < 0 || args.TimeoutSeconds > coretask.MaxTimeoutSeconds {
		return scheduleIntrinsicArguments{}, ErrInvalid
	}
	if (args.RunAt == "") == (args.Cron == "") || (args.RunAt != "" && args.Timezone != "") || (args.Cron != "" && args.Timezone == "") {
		return scheduleIntrinsicArguments{}, ErrInvalid
	}
	if args.Cron != "" {
		if coretask.ValidateCron(args.Cron) != nil || len([]byte(args.Timezone)) > 128 {
			return scheduleIntrinsicArguments{}, ErrInvalid
		}
		if _, err := time.LoadLocation(args.Timezone); err != nil {
			return scheduleIntrinsicArguments{}, ErrInvalid
		}
	}
	return args, nil
}

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

const groupAgentCapability = "product.group_agent.v1"

// Group requests are delivered by the authenticated Message Server, not by a
// member's Agent ticket. Never expose these service methods as model tools.
type GroupAgentRequest struct {
	RequestID         string `json:"request_id"`
	RoomID            string `json:"room_id"`
	EventID           string `json:"event_id"`
	SenderMXID        string `json:"sender_mxid"`
	OwnerMXID         string `json:"owner_mxid"`
	AgentMXID         string `json:"agent_mxid"`
	BindingRevision   int64  `json:"binding_revision"`
	AccountGeneration uint64 `json:"account_generation"`
	Body              string `json:"body"`
	// SenderDisplayName is the sender's sanitized in-room name. It labels the
	// message inside the shared group conversation and never authorizes.
	SenderDisplayName string `json:"sender_display_name,omitempty"`
	OriginServerTS    int64  `json:"origin_server_ts"`
}

type GroupAgentPage struct {
	Requests           []GroupAgentRequest `json:"requests"`
	HasMore            bool                `json:"has_more"`
	NextAfterRequestID string              `json:"next_after_request_id,omitempty"`
}

type GroupAgentBindingCheck struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type GroupAgentMessage struct {
	EventID    string `json:"event_id"`
	SenderMXID string `json:"sender_mxid"`
	// SenderDisplayName is the sanitized in-room name so the shared group
	// conversation can attribute what each member said.
	SenderDisplayName string `json:"sender_display_name,omitempty"`
	Body              string `json:"body"`
	OriginServerTS    int64  `json:"origin_server_ts"`
}

type GroupAgentHistory struct {
	Messages   []GroupAgentMessage `json:"messages"`
	HasMore    bool                `json:"has_more"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

// GroupAgentBindingRef is one enabled shared group the Agent may sweep for its
// rolling summary. It carries no member data.
type GroupAgentBindingRef struct {
	RoomID          string `json:"room_id"`
	AgentMXID       string `json:"agent_mxid"`
	BindingRevision int64  `json:"revision"`
}

type GroupAgentBindings struct {
	OwnerMXID string                 `json:"owner_mxid"`
	Bindings  []GroupAgentBindingRef `json:"bindings"`
}

type GroupAgentPublish struct {
	RequestID       string `json:"request_id"`
	BindingRevision int64  `json:"binding_revision"`
	Body            string `json:"body"`
	Kind            string `json:"kind"`
	Status          string `json:"status"`
}

// GroupAgentScheduleMirror is one durable group schedule Product stores so every
// member can read it from the group detail page.
type GroupAgentScheduleMirror struct {
	RoomID, ScheduleID, Name, Capability, Cron, Timezone, CreatedBy string
	RunAt, NextRunAt                                                string
}

// RecordGroupSchedule mirrors one group schedule. It is idempotent per
// (room, schedule), so a retried turn never duplicates the entry.
func (c *Client) RecordGroupSchedule(ctx context.Context, schedule GroupAgentScheduleMirror) error {
	if !validGroupRoomID(schedule.RoomID) || !validGroupRequestID(schedule.ScheduleID) || strings.TrimSpace(schedule.Name) == "" {
		return errors.New("invalid group Agent schedule mirror")
	}
	key := uuid.NewSHA1(uuid.NameSpaceOID, []byte("group-agent:record-schedule:"+schedule.RoomID+":"+schedule.ScheduleID)).String()
	_, err := c.groupAgentMutation(ctx, key, "record_schedule", map[string]any{
		"room_id": schedule.RoomID, "schedule_id": schedule.ScheduleID, "name": schedule.Name,
		"capability": schedule.Capability, "cron": schedule.Cron, "timezone": schedule.Timezone,
		"created_by": schedule.CreatedBy, "run_at": schedule.RunAt, "next_run_at": schedule.NextRunAt,
	})
	return err
}

func (c *Client) RemoveGroupSchedule(ctx context.Context, roomID, scheduleID string) error {
	if !validGroupRoomID(roomID) || !validGroupRequestID(scheduleID) {
		return errors.New("invalid group Agent schedule mirror")
	}
	key := uuid.NewSHA1(uuid.NameSpaceOID, []byte("group-agent:remove-schedule:"+roomID+":"+scheduleID)).String()
	_, err := c.groupAgentMutation(ctx, key, "remove_schedule", map[string]any{"room_id": roomID, "schedule_id": scheduleID})
	return err
}

// GroupAgentScheduledRequest is one due group schedule the Agent asks Product to
// raise as an ordinary request in its own room. The Agent never picks the
// sender: Product re-checks the room, the binding and the actor's membership.
type GroupAgentScheduledRequest struct {
	RequestID string
	RoomID    string
	ActorMXID string
	Body      string
}

type GroupAgentScheduledResult struct {
	Status   string `json:"status"`
	Replayed bool   `json:"replayed"`
}

// EnqueueScheduledGroupRequest is idempotent per occurrence: Product keys the
// request row by the occurrence's own request id, so a retried delivery of the
// same due task never runs the group twice.
func (c *Client) EnqueueScheduledGroupRequest(ctx context.Context, request GroupAgentScheduledRequest) (GroupAgentScheduledResult, error) {
	var result GroupAgentScheduledResult
	if !validGroupRequestID(request.RequestID) || !validGroupRoomID(request.RoomID) ||
		!validGroupMXID(request.ActorMXID) || strings.TrimSpace(request.Body) == "" ||
		len(request.Body) > groupScheduledBodyMaxBytes {
		return result, errors.New("invalid scheduled group request")
	}
	// Raising a request mutates Product's outbox, so it travels the private
	// mutation channel rather than the read-only query one. The occurrence id is
	// stable, so Product still sees one request per occurrence.
	key := uuid.NewSHA1(uuid.NameSpaceOID, []byte("group-agent:enqueue:"+request.RequestID)).String()
	replayed, err := c.groupAgentMutation(ctx, key, "enqueue", map[string]any{
		"request_id": request.RequestID, "room_id": request.RoomID,
		"actor_mxid": request.ActorMXID, "body": request.Body,
	})
	if err != nil {
		return GroupAgentScheduledResult{}, err
	}
	result.Status, result.Replayed = "enqueued", replayed
	return result, nil
}

const groupScheduledBodyMaxBytes = 16000

// boundedGroupAgentError keeps one Product refusal readable in an operator log
// without letting a peer's text grow the line or inject a break.
func boundedGroupAgentError(message string) string {
	trimmed := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, strings.TrimSpace(message))
	if trimmed == "" {
		return "refused without a reason"
	}
	if len(trimmed) > 200 {
		return trimmed[:200]
	}
	return trimmed
}

func (c *Client) PullGroupAgentRequests(ctx context.Context, after string) (GroupAgentPage, error) {
	var result GroupAgentPage
	input := map[string]any{"limit": 10}
	if after != "" {
		if !validGroupRequestID(after) {
			return result, errors.New("invalid group request cursor")
		}
		input["after_request_id"] = after
	}
	err := c.groupAgentQuery(ctx, "pull", input, &result)
	if err == nil && (len(result.Requests) > 10 || result.HasMore && (!validGroupRequestID(result.NextAfterRequestID) || result.NextAfterRequestID <= after)) {
		err = errors.New("invalid group request page")
	}
	return result, err
}

func (c *Client) ValidateGroupAgentRequest(ctx context.Context, requestID string, revision int64) (GroupAgentBindingCheck, error) {
	var result GroupAgentBindingCheck
	if !validGroupRequestID(requestID) || revision <= 0 {
		return result, errors.New("invalid group authorization reference")
	}
	err := c.groupAgentQuery(ctx, "validate", map[string]any{"request_id": requestID, "binding_revision": revision}, &result)
	return result, err
}

func (c *Client) ReadGroupAgentHistory(ctx context.Context, requestID string, revision int64, limit int, cursor string) (GroupAgentHistory, error) {
	var result GroupAgentHistory
	if !validGroupRequestID(requestID) || revision <= 0 || limit < 1 || limit > groupHistoryMaxLimit || !validGroupCursor(cursor) {
		return result, errors.New("invalid group history reference")
	}
	input := map[string]any{"request_id": requestID, "binding_revision": revision, "limit": limit}
	if cursor != "" {
		input["cursor"] = cursor
	}
	err := c.groupAgentQuery(ctx, "history", input, &result)
	return result, err
}

// ListGroupAgentBindings lists the groups the owner shared Ying with. The
// Agent's own summarizer uses it; it is never a model tool.
func (c *Client) ListGroupAgentBindings(ctx context.Context) (GroupAgentBindings, error) {
	var result GroupAgentBindings
	err := c.groupAgentQuery(ctx, "bindings", map[string]any{}, &result)
	if err != nil {
		return result, err
	}
	if len(result.Bindings) > groupBindingsMaxCount || !validGroupMXID(result.OwnerMXID) {
		return GroupAgentBindings{}, errors.New("invalid group binding page")
	}
	for _, binding := range result.Bindings {
		if !validGroupRoomID(binding.RoomID) || !validGroupMXID(binding.AgentMXID) || binding.BindingRevision <= 0 {
			return GroupAgentBindings{}, errors.New("invalid group binding entry")
		}
	}
	return result, nil
}

// ReadGroupAgentTranscript is the Agent's own room read for the rolling group
// summary. It never carries a member ticket and never crosses rooms.
func (c *Client) ReadGroupAgentTranscript(ctx context.Context, roomID string, revision int64, afterTS int64, limit int, cursor string) (GroupAgentHistory, error) {
	var result GroupAgentHistory
	if !validGroupRoomID(roomID) || revision <= 0 || afterTS < 0 || limit < 1 || limit > groupHistoryMaxLimit || !validGroupCursor(cursor) {
		return result, errors.New("invalid group transcript reference")
	}
	input := map[string]any{"room_id": roomID, "binding_revision": revision, "after_ts": afterTS, "limit": limit}
	if cursor != "" {
		input["cursor"] = cursor
	}
	err := c.groupAgentQuery(ctx, "transcript", input, &result)
	return result, err
}

const (
	groupHistoryMaxLimit  = 200
	groupBindingsMaxCount = 50
	groupMembersMaxLimit  = 200
	groupCursorMaxBytes   = 4096
)

func validGroupCursor(cursor string) bool {
	trimmed := strings.TrimSpace(cursor)
	return trimmed == "" || (len(trimmed) <= groupCursorMaxBytes && !strings.ContainsAny(trimmed, "\n\r\t"))
}

func validGroupRoomID(roomID string) bool {
	trimmed := strings.TrimSpace(roomID)
	return len(trimmed) > 1 && len(trimmed) <= 1024 && strings.HasPrefix(trimmed, "!") && !strings.ContainsAny(trimmed, "\n\r\t ")
}

func validGroupMXID(mxid string) bool {
	trimmed := strings.TrimSpace(mxid)
	return len(trimmed) > 1 && len(trimmed) <= 1024 && strings.HasPrefix(trimmed, "@") &&
		strings.Contains(trimmed, ":") && !strings.ContainsAny(trimmed, "\n\r\t ")
}

func (c *Client) PublishGroupAgentReply(ctx context.Context, input GroupAgentPublish) error {
	if !validGroupRequestID(input.RequestID) || input.BindingRevision <= 0 || strings.TrimSpace(input.Body) == "" || len(input.Body) > 64<<10 {
		return errors.New("invalid group reply")
	}
	if input.Kind == "progress" {
		if input.Status != "working" && input.Status != "waiting_owner" {
			return errors.New("invalid group progress status")
		}
	} else if input.Kind != "final" || (input.Status != "completed" && input.Status != "failed") {
		return errors.New("invalid group final status")
	}
	key := uuid.NewSHA1(uuid.NameSpaceOID, []byte("group-agent:publish:"+input.RequestID+":"+input.Kind+":"+input.Status)).String()
	_, err := c.groupAgentMutation(ctx, key, "publish", input)
	return err
}

func (c *Client) CompleteGroupAgentRequest(ctx context.Context, requestID string, revision int64, status string) error {
	if !validGroupRequestID(requestID) || revision <= 0 || (status != "failed" && status != "cancelled") {
		return errors.New("invalid group completion")
	}
	key := uuid.NewSHA1(uuid.NameSpaceOID, []byte("group-agent:complete:"+requestID+":"+status)).String()
	_, err := c.groupAgentMutation(ctx, key, "complete", map[string]any{"request_id": requestID, "binding_revision": revision, "status": status})
	return err
}

func validGroupRequestID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func groupJSON(input any) ([]byte, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return capv1.CanonicalizeJSON(raw)
}

func (c *Client) groupAgentQuery(ctx context.Context, op string, input, result any) error {
	if c == nil || c.client == nil || ctx == nil {
		return errors.New("group Agent Product service is unavailable")
	}
	raw, err := groupJSON(input)
	if err != nil {
		return err
	}
	if err = c.acquireReadSem(ctx); err != nil {
		return err
	}
	defer c.releaseReadSem()
	call, err := freshAgentServiceCallContext(ctx, uuid.NewString())
	if err != nil {
		return err
	}
	release, err := c.enterProductCall(call)
	if err != nil {
		return err
	}
	defer release()
	response, err := c.client.Query(c.authenticatedContext(ctx), &capv1.QueryRequest{CallContext: call, CapabilityId: groupAgentCapability, OperationId: op, RequestJson: raw})
	if err != nil {
		return err
	}
	if response == nil || len(response.ResultJson) > 1<<20 {
		return errors.New("group Agent Product query failed")
	}
	if response.Error != nil {
		// Keep the refusal reason: an operator reading the bounded agent log has
		// no other way to tell a rejected enqueue from a transport failure.
		return fmt.Errorf("group Agent Product query failed: %s", boundedGroupAgentError(response.Error.Message))
	}
	decoder := json.NewDecoder(bytes.NewReader(response.ResultJson))
	if err = decoder.Decode(result); err != nil {
		return fmt.Errorf("invalid group Agent response: %w", err)
	}
	if !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return errors.New("trailing group Agent response")
	}
	return nil
}

func (c *Client) groupAgentMutation(ctx context.Context, id, op string, input any) (bool, error) {
	if c == nil || c.client == nil || ctx == nil {
		return false, errors.New("group Agent Product service is unavailable")
	}
	raw, err := groupJSON(input)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(raw)
	if err = c.acquireMutationSem(ctx); err != nil {
		return false, err
	}
	defer c.releaseMutationSem()
	call, err := freshAgentServiceCallContext(ctx, id)
	if err != nil {
		return false, err
	}
	release, err := c.enterProductCall(call)
	if err != nil {
		return false, err
	}
	defer release()
	response, err := c.client.StartOperation(c.authenticatedContext(ctx), &capv1.StartOperationRequest{CallContext: call, OperationId: id, CapabilityId: groupAgentCapability, Operation: op, RequestJson: raw, RequestDigest: digest[:]})
	if err != nil {
		return false, err
	}
	if response == nil || response.GetOperationId() != id || response.GetState() != capv1.OperationState_OPERATION_STATE_COMPLETED {
		return false, errors.New("group Agent Product mutation failed")
	}
	if response.GetError() != nil {
		return false, fmt.Errorf("group Agent Product mutation failed: %s", boundedGroupAgentError(response.GetError().GetMessage()))
	}
	return response.GetReplayed(), nil
}

// GroupAgentMember is one currently joined group member as the Agent may see it.
type GroupAgentMember struct {
	MXID        string `json:"mxid"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
}

type GroupAgentMembers struct {
	Members []GroupAgentMember `json:"members"`
	Total   int                `json:"total"`
	HasMore bool               `json:"has_more"`
}

// ReadGroupAgentMembers reads the live joined roster of the request's own room.
// It is room-scoped and request-scoped: no other room, contact list or private
// member data is reachable.
func (c *Client) ReadGroupAgentMembers(ctx context.Context, requestID string, revision int64, limit int) (GroupAgentMembers, error) {
	var result GroupAgentMembers
	if !validGroupRequestID(requestID) || revision <= 0 || limit < 1 || limit > groupMembersMaxLimit {
		return result, errors.New("invalid group member reference")
	}
	err := c.groupAgentQuery(ctx, "members", map[string]any{"request_id": requestID, "binding_revision": revision, "limit": limit}, &result)
	if err != nil {
		return result, err
	}
	if result.Total < 0 || len(result.Members) > limit || result.Total < len(result.Members) {
		return GroupAgentMembers{}, errors.New("invalid group member page")
	}
	for _, member := range result.Members {
		if !validGroupMXID(member.MXID) {
			return GroupAgentMembers{}, errors.New("invalid group member entry")
		}
		switch member.Role {
		case "owner", "member", "agent":
		default:
			return GroupAgentMembers{}, errors.New("invalid group member role")
		}
	}
	return result, nil
}

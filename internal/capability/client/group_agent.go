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
	EventID        string `json:"event_id"`
	SenderMXID     string `json:"sender_mxid"`
	Body           string `json:"body"`
	OriginServerTS int64  `json:"origin_server_ts"`
}

type GroupAgentHistory struct {
	Messages []GroupAgentMessage `json:"messages"`
}

type GroupAgentPublish struct {
	RequestID       string `json:"request_id"`
	BindingRevision int64  `json:"binding_revision"`
	Body            string `json:"body"`
	Kind            string `json:"kind"`
	Status          string `json:"status"`
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

func (c *Client) ReadGroupAgentHistory(ctx context.Context, requestID string, revision int64, limit int) (GroupAgentHistory, error) {
	var result GroupAgentHistory
	if !validGroupRequestID(requestID) || revision <= 0 || limit < 1 || limit > 50 {
		return result, errors.New("invalid group history reference")
	}
	err := c.groupAgentQuery(ctx, "history", map[string]any{"request_id": requestID, "binding_revision": revision, "limit": limit}, &result)
	return result, err
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
	return c.groupAgentMutation(ctx, key, "publish", input)
}

func (c *Client) CompleteGroupAgentRequest(ctx context.Context, requestID string, revision int64, status string) error {
	if !validGroupRequestID(requestID) || revision <= 0 || (status != "failed" && status != "cancelled") {
		return errors.New("invalid group completion")
	}
	key := uuid.NewSHA1(uuid.NameSpaceOID, []byte("group-agent:complete:"+requestID+":"+status)).String()
	return c.groupAgentMutation(ctx, key, "complete", map[string]any{"request_id": requestID, "binding_revision": revision, "status": status})
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
	if response == nil || response.Error != nil || len(response.ResultJson) > 1<<20 {
		return errors.New("group Agent Product query failed")
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

func (c *Client) groupAgentMutation(ctx context.Context, id, op string, input any) error {
	if c == nil || c.client == nil || ctx == nil {
		return errors.New("group Agent Product service is unavailable")
	}
	raw, err := groupJSON(input)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if err = c.acquireMutationSem(ctx); err != nil {
		return err
	}
	defer c.releaseMutationSem()
	call, err := freshAgentServiceCallContext(ctx, id)
	if err != nil {
		return err
	}
	release, err := c.enterProductCall(call)
	if err != nil {
		return err
	}
	defer release()
	response, err := c.client.StartOperation(c.authenticatedContext(ctx), &capv1.StartOperationRequest{CallContext: call, OperationId: id, CapabilityId: groupAgentCapability, Operation: op, RequestJson: raw, RequestDigest: digest[:]})
	if err != nil {
		return err
	}
	if response == nil || response.GetOperationId() != id || response.GetError() != nil || response.GetState() != capv1.OperationState_OPERATION_STATE_COMPLETED {
		return errors.New("group Agent Product mutation failed")
	}
	return nil
}

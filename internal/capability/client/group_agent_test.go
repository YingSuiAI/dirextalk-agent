package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type groupProductStub struct {
	capv1.ProductCapabilityServiceClient
	queries []*capv1.QueryRequest
	writes  []*capv1.StartOperationRequest
	result  []byte
	t       *testing.T
}

func (s *groupProductStub) check(ctx context.Context, call *capv1.CallContext, permission *capv1.PermissionContext, capability string) {
	s.t.Helper()
	if permission != nil || capability != groupAgentCapability || call.GetRoute() != capv1.NodeAgent || call.GetHop() != 1 || call.GetParentCallId() != "" || capv1.ValidateStrictCallContext(call) != nil {
		s.t.Fatal("group control leaked owner permission or reused an inbound call chain")
	}
	if md, ok := metadata.FromOutgoingContext(ctx); !ok || len(md) == 0 {
		s.t.Fatal("missing service authentication metadata")
	}
}
func (s *groupProductStub) Query(ctx context.Context, req *capv1.QueryRequest, _ ...grpc.CallOption) (*capv1.QueryResponse, error) {
	s.check(ctx, req.CallContext, req.Permission, req.CapabilityId)
	s.queries = append(s.queries, req)
	return &capv1.QueryResponse{ResultJson: s.result}, nil
}
func (s *groupProductStub) StartOperation(ctx context.Context, req *capv1.StartOperationRequest, _ ...grpc.CallOption) (*capv1.StartOperationResponse, error) {
	s.check(ctx, req.CallContext, req.Permission, req.CapabilityId)
	digest := sha256.Sum256(req.RequestJson)
	canonical, err := capv1.CanonicalizeJSON(req.RequestJson)
	if err != nil || !bytes.Equal(canonical, req.RequestJson) || !bytes.Equal(digest[:], req.RequestDigest) || req.CallContext.RootOperationId != req.OperationId {
		s.t.Fatal("invalid group operation digest/identity")
	}
	s.writes = append(s.writes, req)
	return &capv1.StartOperationResponse{OperationId: req.OperationId, State: capv1.OperationState_OPERATION_STATE_COMPLETED}, nil
}

func TestGroupAgentPrivateClientUsesFixedOperationsAndStableMutationIDs(t *testing.T) {
	token, _ := capv1.EncodeCapabilityToken(bytes.Repeat([]byte{1}, capv1.CapabilityTokenBytes))
	s := &groupProductStub{t: t, result: []byte(`{"requests":[],"has_more":false}`)}
	c := &Client{config: &Config{InstanceID: uuid.NewString(), AccountGeneration: 2}, client: s, token: []byte(token), readSem: make(chan struct{}, 1), mutationSem: make(chan struct{}, 1), chainFence: NewChainFence()}
	ctx := context.Background()
	if _, err := c.PullGroupAgentRequests(ctx, ""); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	s.result = []byte(`{"allowed":true}`)
	if value, err := c.ValidateGroupAgentRequest(ctx, id, 4); err != nil || !value.Allowed {
		t.Fatal(err)
	}
	s.result = []byte(`{"messages":[]}`)
	if _, err := c.ReadGroupAgentHistory(ctx, id, 4, 30); err != nil {
		t.Fatal(err)
	}
	input := GroupAgentPublish{RequestID: id, BindingRevision: 4, Body: "Public group response", Kind: "final", Status: "completed"}
	if err := c.PublishGroupAgentReply(ctx, input); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishGroupAgentReply(ctx, input); err != nil {
		t.Fatal(err)
	}
	if s.writes[0].OperationId != s.writes[1].OperationId || !bytes.Equal(s.writes[0].RequestJson, s.writes[1].RequestJson) {
		t.Fatal("retry changed publication identity")
	}
	if s.writes[0].CallContext.ChainId == s.writes[1].CallContext.ChainId {
		t.Fatal("retry reused call chain")
	}
	for _, q := range s.queries {
		var params map[string]any
		_ = json.Unmarshal(q.RequestJson, &params)
		if _, ok := params["owner_id"]; ok {
			t.Fatal("client supplied owner")
		}
		if _, ok := params["room_id"]; ok {
			t.Fatal("unbounded room selector")
		}
	}
	if err := c.CompleteGroupAgentRequest(ctx, id, 4, "cancelled"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadGroupAgentHistory(ctx, id, 4, 100); err == nil {
		t.Fatal("unbounded history accepted")
	}
}

func TestGroupAgentClientRejectsNonAdvancingPagesAndTrailingJSON(t *testing.T) {
	token, _ := capv1.EncodeCapabilityToken(bytes.Repeat([]byte{1}, capv1.CapabilityTokenBytes))
	s := &groupProductStub{t: t}
	c := &Client{config: &Config{InstanceID: uuid.NewString(), AccountGeneration: 2}, client: s, token: []byte(token), readSem: make(chan struct{}, 1), chainFence: NewChainFence()}
	for _, raw := range []string{`{"requests":[],"has_more":true}`, `{"requests":[],"has_more":false} {}`} {
		s.result = []byte(raw)
		if _, err := c.PullGroupAgentRequests(context.Background(), ""); err == nil {
			t.Fatalf("invalid page accepted: %s", raw)
		}
	}
}

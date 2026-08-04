package server

import (
	"errors"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateOrAdvanceAgentCallContext(t *testing.T) {
	base := capv1.NewCallContext(uuid.NewString(), uuid.NewString(), time.Now().Add(time.Minute).UnixMilli())
	fromMessage, err := capv1.AppendCallNode(base, capv1.NodeMessage)
	if err != nil {
		t.Fatalf("append message-server hop: %v", err)
	}
	advanced, err := validateOrAdvanceAgentCallContext(fromMessage)
	if err != nil {
		t.Fatalf("validate agent boundary: %v", err)
	}
	if advanced.GetRoute() != "ms→agent" || advanced.GetHop() != 2 {
		t.Fatalf("unexpected advanced route: %q/%d", advanced.GetRoute(), advanced.GetHop())
	}

	if _, err := validateOrAdvanceAgentCallContext(base); err == nil {
		t.Fatal("empty peer route was accepted")
	}
	cycle := &capv1.CallContext{ChainId: uuid.NewString(), RootOperationId: uuid.NewString(), Hop: 3, Route: "ms→agent→ms", DeadlineUnixMs: time.Now().Add(time.Minute).UnixMilli()}
	if _, err := validateOrAdvanceAgentCallContext(cycle); !errors.Is(err, capv1.ErrCycleDetected) {
		t.Fatalf("cycle was not rejected: %v", err)
	}
}

func TestValidateCallContextRejectsSameChainReentryAndAllowsAfterCleanup(t *testing.T) {
	fence := capabilityclient.NewChainFence()
	root := capv1.NewCallContext(uuid.NewString(), uuid.NewString(), time.Now().Add(time.Minute).UnixMilli())
	root, _ = capv1.AppendCallNode(root, capv1.NodeMessage)
	active := &capv1.CallContext{ChainId: root.GetChainId(), RootOperationId: root.GetRootOperationId(), Hop: 2, Route: "ms→agent", DeadlineUnixMs: root.GetDeadlineUnixMs()}
	release, err := fence.Enter(active)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{chainFence: fence}
	first := &capv1.QueryRequest{CallContext: root}
	if err := s.validateCallContext(first); status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "CYCLE_DETECTED" {
		t.Fatalf("same-chain reentry err=%v", err)
	}
	release()
	second := &capv1.QueryRequest{CallContext: &capv1.CallContext{ChainId: root.GetChainId(), RootOperationId: root.GetRootOperationId(), Hop: 1, Route: "ms", DeadlineUnixMs: root.GetDeadlineUnixMs()}}
	if err := s.validateCallContext(second); err != nil {
		t.Fatalf("reentry remained blocked after cleanup: %v", err)
	}
	if second.GetCallContext().GetRoute() != "ms→agent" {
		t.Fatalf("route was not advanced after cleanup: %q", second.GetCallContext().GetRoute())
	}
}

package client

import (
	"bytes"
	"testing"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

func TestValidatePermissionRequiresServerIssuedPrincipalAndRootBinding(t *testing.T) {
	valid := &capv1.PermissionContext{
		AuthenticatedOwnerId: "owner",
		AccountGeneration:    1,
		GrantedScopes:        []string{"agent:product:execute"},
		CapabilityGrant:      []byte("signed"),
		RootRequestDigest:    bytes.Repeat([]byte{1}, 32),
	}
	if err := validatePermission(valid); err != nil {
		t.Fatalf("valid permission rejected: %v", err)
	}
	for name, value := range map[string]*capv1.PermissionContext{
		"zero generation":     {AuthenticatedOwnerId: "owner", GrantedScopes: []string{"agent:product:execute"}, CapabilityGrant: []byte("signed"), RootRequestDigest: bytes.Repeat([]byte{1}, 32)},
		"missing root digest": {AuthenticatedOwnerId: "owner", AccountGeneration: 1, GrantedScopes: []string{"agent:product:execute"}, CapabilityGrant: []byte("signed")},
	} {
		if err := validatePermission(value); err == nil {
			t.Fatalf("%s permission accepted", name)
		}
	}
}

func TestAdvanceProductCallContextKeepsPreAdvanceAgentRoute(t *testing.T) {
	parent := capv1.NewCallContext(uuid.NewString(), uuid.NewString(), time.Now().Add(time.Minute).UnixMilli())
	var err error
	parent, err = capv1.AppendCallNode(parent, capv1.NodeMessage)
	if err != nil {
		t.Fatal(err)
	}
	parent, err = capv1.AppendCallNode(parent, capv1.NodeAgent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&Client{}).advanceProductCallContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetRoute() != "ms→agent" || got.GetHop() != 2 {
		t.Fatalf("product call context was advanced by sender: %q/%d", got.GetRoute(), got.GetHop())
	}
	if got == parent {
		t.Fatal("product call context must be an immutable clone")
	}
}

func TestChainFenceTracksNestedChainsAndCleansUp(t *testing.T) {
	fence := NewChainFence()
	call := capv1.NewCallContext(uuid.NewString(), uuid.NewString(), time.Now().Add(time.Minute).UnixMilli())
	call, _ = capv1.AppendCallNode(call, capv1.NodeMessage)
	call, _ = capv1.AppendCallNode(call, capv1.NodeAgent)
	first, err := fence.Enter(call)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fence.Enter(call)
	if err != nil {
		t.Fatal(err)
	}
	if !fence.Active(call.GetChainId()) {
		t.Fatal("nested chain was not marked active")
	}
	first()
	if !fence.Active(call.GetChainId()) {
		t.Fatal("nested chain was released too early")
	}
	second()
	if fence.Active(call.GetChainId()) {
		t.Fatal("chain fence leaked after all releases")
	}
	second() // release is idempotent
}

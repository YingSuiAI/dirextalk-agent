package client

import (
	"testing"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

func TestPermissionWithControlGrantUsesFreshExactActionAndClones(t *testing.T) {
	base := &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 2, CapabilityGrant: []byte("root"), GrantedScopes: []string{"contacts:write"}}
	started := &capv1.StartOperationResponse{ControlGrants: []*capv1.OperationControlGrantEnvelope{
		{Action: "watch", Grant: []byte("watch"), ExpiresAtUnixMs: time.Now().Add(time.Minute).UnixMilli()},
		{Action: "cancel", Grant: []byte("cancel"), ExpiresAtUnixMs: time.Now().Add(time.Minute).UnixMilli()},
	}}
	got, err := PermissionWithControlGrant(base, started, "watch")
	if err != nil || string(got.GetCapabilityGrant()) != "watch" || string(base.GetCapabilityGrant()) != "root" {
		t.Fatalf("grant=%q err=%v base=%q", got.GetCapabilityGrant(), err, base.GetCapabilityGrant())
	}
	started.ControlGrants[0].ExpiresAtUnixMs = time.Now().Add(2 * time.Second).UnixMilli()
	if _, err := PermissionWithControlGrant(base, started, "watch"); err == nil {
		t.Fatal("near-expiry control grant accepted")
	}
}

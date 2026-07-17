package rpcapi

import (
	"reflect"
	"testing"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"google.golang.org/protobuf/proto"
)

func TestCloudVolumeScopeRoundTripsThroughPublicV1Protobuf(t *testing.T) {
	resource := cloudquote.ResourceScopeV1{VolumeScopes: []cloudquote.VolumeScopeV1{{
		SlotID: "knowledge", SizeGiB: 80, VolumeType: "gp3", IOPS: 6_000, ThroughputMiBPS: 250,
		Encrypted: true, KMSKeyID: "alias/dtx-agent-test-foundation", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge",
		Persistent: true, Disposition: cloudquote.VolumeRetainWithManagedService,
	}}}
	protoValue := cloudResourceScopeToProto(resource)
	if len(protoValue.GetVolumeScopes()) != 1 || protoValue.GetVolumeScopes()[0].GetDisposition() != "retain_with_managed_service" {
		t.Fatalf("public CloudResourceScope omitted approval-visible volume data: %+v", protoValue)
	}
	got := cloudResourceScopeFromProto(protoValue)
	if !reflect.DeepEqual(got.VolumeScopes, resource.VolumeScopes) {
		t.Fatalf("volume codec round trip = %+v, want %+v", got.VolumeScopes, resource.VolumeScopes)
	}

	planProjection := approvalResourceScopeToProto(cloudapproval.ResourceScopeV1{VolumeScopes: append([]cloudapproval.VolumeScopeV1(nil), resource.VolumeScopes...)})
	if len(planProjection.GetVolumeScopes()) != 1 || !proto.Equal(planProjection.GetVolumeScopes()[0], protoValue.GetVolumeScopes()[0]) {
		t.Fatalf("CloudPlan and CloudQuote projections diverged: plan=%+v quote=%+v", planProjection.GetVolumeScopes(), protoValue.GetVolumeScopes())
	}
}

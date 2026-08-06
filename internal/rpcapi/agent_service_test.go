package rpcapi

import (
	"context"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
)

func TestAgentServiceProjectsOnlySafeDiscoveryFields(t *testing.T) {
	originalVersion := buildinfo.ReleaseVersion
	buildinfo.ReleaseVersion = "v1.0.0"
	t.Cleanup(func() { buildinfo.ReleaseVersion = originalVersion })

	service, err := NewAgentService("00000000-0000-4000-8000-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := service.GetCapabilities(context.Background(), &agentv1.GetCapabilitiesRequest{})
	if err != nil || capabilities.ApiVersion != CoreAPIVersion || len(capabilities.Capabilities) != 1 {
		t.Fatalf("capabilities=%+v err=%v", capabilities, err)
	}
	if capabilities.Capabilities[0].Name != "agent.info" || !capabilities.Capabilities[0].Enabled {
		t.Fatalf("capability=%+v", capabilities.Capabilities[0])
	}
	info, err := service.GetInstanceInfo(context.Background(), &agentv1.GetInstanceInfoRequest{})
	if err != nil || info.InstanceId != "00000000-0000-4000-8000-000000000000" || info.ApiVersion != CoreAPIVersion || info.ReleaseVersion != "v1.0.0" {
		t.Fatalf("instance info=%+v err=%v", info, err)
	}
}

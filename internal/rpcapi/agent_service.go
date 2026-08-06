package rpcapi

import (
	"context"
	"errors"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
)

const CoreAPIVersion = "v1"

type AgentService struct {
	agentv1.UnimplementedAgentServiceServer
	instanceID   string
	capabilities []*agentv1.AgentCapability
}

func NewAgentService(instanceID string, capabilityNames ...string) (*AgentService, error) {
	if strings.TrimSpace(instanceID) == "" {
		return nil, errors.New("agent instance id is required")
	}
	capabilities := []*agentv1.AgentCapability{{Name: "agent.info", Enabled: true}}
	for _, name := range capabilityNames {
		name = strings.TrimSpace(name)
		if name == "" || name == "agent.info" {
			continue
		}
		capabilities = append(capabilities, &agentv1.AgentCapability{Name: name, Enabled: true})
	}
	return &AgentService{instanceID: instanceID, capabilities: capabilities}, nil
}

func (service *AgentService) GetCapabilities(context.Context, *agentv1.GetCapabilitiesRequest) (*agentv1.GetCapabilitiesResponse, error) {
	return &agentv1.GetCapabilitiesResponse{
		ApiVersion:   CoreAPIVersion,
		Capabilities: service.capabilities,
	}, nil
}

func (service *AgentService) GetInstanceInfo(context.Context, *agentv1.GetInstanceInfoRequest) (*agentv1.GetInstanceInfoResponse, error) {
	return &agentv1.GetInstanceInfoResponse{InstanceId: service.instanceID, ApiVersion: CoreAPIVersion, ReleaseVersion: buildinfo.Version()}, nil
}

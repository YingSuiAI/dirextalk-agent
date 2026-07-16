package rpcapi

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
)

type RuntimeService struct {
	agentv1.UnimplementedRuntimeServiceServer
}

func (RuntimeService) GetCapabilities(context.Context, *agentv1.RuntimeServiceGetCapabilitiesRequest) (*agentv1.RuntimeServiceGetCapabilitiesResponse, error) {
	return &agentv1.RuntimeServiceGetCapabilitiesResponse{Capabilities: &agentv1.RuntimeCapabilities{
		Chat: false, CloudWorker: false, LocalConnector: false,
	}}, nil
}

type CloudControlService struct {
	agentv1.UnimplementedCloudControlServiceServer
}

func (CloudControlService) GetCapabilities(context.Context, *agentv1.CloudControlServiceGetCapabilitiesRequest) (*agentv1.CloudControlServiceGetCapabilitiesResponse, error) {
	return &agentv1.CloudControlServiceGetCapabilitiesResponse{Capabilities: &agentv1.CloudCapabilities{
		Aws: false, DirectSts: false, Worker: false, Reaper: false,
	}}, nil
}

type SecretBootstrapService struct {
	agentv1.UnimplementedSecretBootstrapServiceServer
}
type WorkerControlService struct {
	agentv1.UnimplementedWorkerControlServiceServer
}

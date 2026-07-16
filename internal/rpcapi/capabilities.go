package rpcapi

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
)

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

package rpcapi

import agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"

type WorkerControlService struct {
	agentv1.UnimplementedWorkerControlServiceServer
}

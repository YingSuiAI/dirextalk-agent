package main

import (
	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
)

// coreCloudWorkerComposition contains only the dynamic SSH Worker surfaces
// consumed by the Core server. Worker lifecycle is owned by sshworker.
type coreCloudWorkerComposition struct {
	domain            *cloudworker.Service
	intrinsic         coreconversation.IntrinsicResolver
	executionPort     coreexecutionv2.CloudWorkerExecutionPort
	taskHandler       coreruntime.TaskHandler
	domainTaskHandler coreruntime.TaskHandler
	workerCapability  agentcapability.Capability
}

func (composition *coreCloudWorkerComposition) Cleaners() []coreLifecycleCleaner {
	return nil
}

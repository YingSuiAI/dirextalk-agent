package coreconversation

import (
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const cloudWorkerRoutingGuidance = `Assess the actual execution needs of the user's request against the tools available in this conversation. The local conversation runtime does not provide a general project workspace or shell executor. When a substantial task requires project setup, shell commands, deployment, build, test, durable file delivery, or long-running compute that the available local tools cannot perform, call cloud_worker_propose to create a priced offer for the user's confirmation instead of declining or describing an unverified procedure. The user does not need to mention AWS, cloud, remote execution, or Worker. Keep ordinary conversation and simple reasoning local, and honor any explicit local-only or no-cloud requirement.`

func cloudWorkerSystemPrompt(base string) string {
	if strings.TrimSpace(base) == "" {
		return cloudWorkerRoutingGuidance
	}
	return strings.TrimSpace(base) + "\n\n" + cloudWorkerRoutingGuidance
}

func containsCloudWorkerIntrinsic(tools []ResolvedIntrinsic) bool {
	for _, tool := range tools {
		if tool.Tool.Name == coremodel.IntrinsicCloudWorkerProposeToolName {
			return true
		}
	}
	return false
}

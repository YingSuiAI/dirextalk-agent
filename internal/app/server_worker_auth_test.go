package app

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
)

func TestWorkerSelfAuthenticationAllowlistIsExact(t *testing.T) {
	allowed := []string{
		agentv1.WorkerControlService_CreateIdentityChallenge_FullMethodName,
		agentv1.WorkerControlService_EnrollVerifiedIdentity_FullMethodName,
		agentv1.WorkerControlService_Enroll_FullMethodName,
		agentv1.WorkerControlService_GetCurrentAssignment_FullMethodName,
		agentv1.WorkerControlService_Claim_FullMethodName,
		agentv1.WorkerControlService_Heartbeat_FullMethodName,
		agentv1.WorkerControlService_RecordEvidence_FullMethodName,
		agentv1.WorkerControlService_EmitMilestone_FullMethodName,
		agentv1.WorkerControlService_Complete_FullMethodName,
	}
	for _, method := range allowed {
		if !isWorkerSelfAuthenticatedMethod(method) {
			t.Fatalf("Worker method unexpectedly requires a Service Key: %s", method)
		}
	}
	for _, method := range []string{
		"/dirextalk.agent.v1.WorkerControlService/Unknown",
		agentv1.CloudControlService_GetCloudWorker_FullMethodName,
		agentv1.AdminService_CreateServiceKey_FullMethodName,
		"",
	} {
		if isWorkerSelfAuthenticatedMethod(method) {
			t.Fatalf("non-Worker method bypassed Service Key authentication: %s", method)
		}
	}
}

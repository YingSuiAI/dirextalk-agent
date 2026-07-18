package app

import (
	"reflect"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
)

func TestKnowledgeServiceMethodsUseExactLeastPrivilegeScopes(t *testing.T) {
	want := map[string]string{
		agentv1.KnowledgeService_GetKnowledgeCapabilities_FullMethodName:        "knowledge.read",
		agentv1.KnowledgeService_GetKnowledgeConfig_FullMethodName:              "knowledge.read",
		agentv1.KnowledgeService_PutKnowledgeConfig_FullMethodName:              "knowledge.write",
		agentv1.KnowledgeService_ListKnowledgeSources_FullMethodName:            "knowledge.read",
		agentv1.KnowledgeService_StartKnowledgeAttachmentUpload_FullMethodName:  "knowledge.write",
		agentv1.KnowledgeService_AppendKnowledgeAttachmentChunk_FullMethodName:  "knowledge.write",
		agentv1.KnowledgeService_CommitKnowledgeAttachmentUpload_FullMethodName: "knowledge.write",
		agentv1.KnowledgeService_CreateKnowledgeMemory_FullMethodName:           "knowledge.write",
		agentv1.KnowledgeService_DeleteKnowledgeSource_FullMethodName:           "knowledge.write",
		agentv1.KnowledgeService_SearchKnowledge_FullMethodName:                 "knowledge.search",
		agentv1.KnowledgeService_GetKnowledgeStatus_FullMethodName:              "knowledge.read",
	}
	if got := knowledgeServiceScopes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("knowledge scopes = %#v, want %#v", got, want)
	}
}

func TestKnowledgeWorkerRelayUsesOnlyWorkerSessionAuthentication(t *testing.T) {
	for _, method := range []string{
		agentv1.KnowledgeWorkerControlService_AcquireKnowledgeOperation_FullMethodName,
		agentv1.KnowledgeWorkerControlService_CompleteKnowledgeOperation_FullMethodName,
	} {
		if !isWorkerSelfAuthenticatedMethod(method) {
			t.Fatalf("Knowledge Worker method %q reached Service Key authentication", method)
		}
	}
}

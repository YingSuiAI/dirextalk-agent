package rpcapi

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCoreV1ServiceDescriptorsAndPrivacy(t *testing.T) {
	want := map[string][]string{
		"ModelProfileService": {"Create", "Get", "List", "Update", "Delete", "TestConnection", "Sync"},
		"ConversationService": {"Create", "Get", "List", "Delete", "Chat", "StreamChat", "StartTurn", "GetTurn", "WatchTurnEvents", "CancelTurn"},
		"TaskService":         {"CreateTask", "GetTask", "ListTasks", "CancelTask", "RetryTask", "DeleteTask", "WatchTaskEvents"},
		"ScheduleService":     {"Create", "Get", "List", "Update", "Pause", "Resume", "TriggerNow", "Delete"},
		"WorkloadService":     {"Plan", "Get", "List", "Quote", "RequestApply", "RequestDestroy"},
	}
	files := []protoreflect.FileDescriptor{agentv1.File_dirextalk_agent_v1_core_model_proto, agentv1.File_dirextalk_agent_v1_core_conversation_proto, agentv1.File_dirextalk_agent_v1_core_task_proto, agentv1.File_dirextalk_agent_v1_core_schedule_proto, agentv1.File_dirextalk_agent_v1_core_workload_proto}
	for name, methods := range want {
		var service protoreflect.ServiceDescriptor
		for _, file := range files {
			if candidate := file.Services().ByName(protoreflect.Name(name)); candidate != nil {
				service = candidate
				break
			}
		}
		if service == nil {
			t.Fatalf("missing service %s", name)
		}
		for _, method := range methods {
			if service.Methods().ByName(protoreflect.Name(method)) == nil {
				t.Errorf("%s missing %s", name, method)
			}
		}
	}
	profile := (&agentv1.CoreModelProfile{}).ProtoReflect().Descriptor()
	if profile.Fields().ByName("api_key") != nil {
		t.Fatal("profile response exposes api key")
	}
	if profile.Fields().ByName("client_profile_id") == nil {
		t.Fatal("profile client_profile_id missing")
	}
	if f := profile.Fields().ByName("credential_version"); f == nil || f.Kind() != protoreflect.Int64Kind {
		t.Fatal("profile credential_version missing or wrong type")
	}
	syncEntry := (&agentv1.CoreModelProfileSyncEntry{}).ProtoReflect().Descriptor()
	if f := syncEntry.Fields().ByName("api_key"); f == nil || !f.HasOptionalKeyword() {
		t.Fatal("sync api_key must be optional/write-only")
	}
	if got := (&agentv1.CoreModelProfile{}).ProtoReflect().Descriptor().Fields().ByName("provider").Enum().Values().Len(); got != 4 {
		t.Fatalf("provider values=%d, want 4", got)
	}
	trigger := (&agentv1.ScheduleServiceTriggerNowRequest{}).ProtoReflect().Descriptor()
	if trigger.Fields().ByName("expected_revision") != nil {
		t.Fatal("TriggerNow has revision fence")
	}
	for _, req := range []protoreflect.MessageDescriptor{
		(&agentv1.ConversationServiceChatRequest{}).ProtoReflect().Descriptor(),
		(&agentv1.ConversationServiceStreamChatRequest{}).ProtoReflect().Descriptor(),
		(&agentv1.ConversationServiceStartTurnRequest{}).ProtoReflect().Descriptor(),
	} {
		if f := req.Fields().ByName("expected_revision"); f != nil && !f.HasOptionalKeyword() {
			t.Fatalf("%s expected_revision must be optional when present", req.Name())
		}
		for _, name := range []protoreflect.Name{"model_profile_revision", "credential_version"} {
			if f := req.Fields().ByName(name); f == nil || !f.HasOptionalKeyword() || f.Kind() != protoreflect.Int64Kind {
				t.Fatalf("%s %s must be optional int64", req.Name(), name)
			}
		}
	}
	turn := (&agentv1.CoreConversationTurn{}).ProtoReflect().Descriptor()
	for _, name := range []protoreflect.Name{"model_profile_revision", "credential_version"} {
		if f := turn.Fields().ByName(name); f == nil || !f.HasOptionalKeyword() || f.Kind() != protoreflect.Int64Kind {
			t.Fatalf("turn %s must be optional int64", name)
		}
	}
	update := (&agentv1.ModelProfileServiceUpdateRequest{}).ProtoReflect().Descriptor()
	if update.Oneofs().ByName("api_key_update") == nil {
		t.Fatal("model update api key clear/replace must be oneof")
	}
	watch := (&agentv1.TaskServiceWatchTaskEventsRequest{}).ProtoReflect().Descriptor()
	if watch.Fields().ByName("task_id") == nil || watch.Fields().ByName("after_sequence") == nil {
		t.Fatal("watch cursor fields missing")
	}
	get := (&agentv1.ConversationServiceGetRequest{}).ProtoReflect().Descriptor()
	if get.Fields().ByName("page_token") == nil || get.Fields().ByName("after_sequence") != nil {
		t.Fatal("conversation history must use opaque page_token")
	}
	cloud := agentv1.File_dirextalk_agent_v1_core_aws_proto.Services().ByName("CoreCloudControlService")
	if cloud == nil {
		t.Fatal("missing CoreCloudControlService")
	}
	if cloud.Methods().ByName("TestCredential") != nil {
		t.Fatal("legacy TestCredential alias must not be exposed")
	}
	if cloud.Methods().ByName("TestCredentialIdentity") == nil {
		t.Fatal("TestCredentialIdentity must remain exposed")
	}
	for _, req := range []protoreflect.MessageDescriptor{(&agentv1.ConversationServiceChatRequest{}).ProtoReflect().Descriptor(), (&agentv1.ConversationServiceStreamChatRequest{}).ProtoReflect().Descriptor()} {
		if req.Fields().ByName("extensions") == nil || req.Fields().ByName("mcp_server_ids") != nil || req.Fields().ByName("skill_ids") != nil {
			t.Fatalf("%s has parallel extension fields", req.Name())
		}
	}
}

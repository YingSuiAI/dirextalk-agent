package rpcapi

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestMutationRequestsExposeIdempotencyAndRevisionFences(t *testing.T) {
	tests := []struct {
		message       proto.Message
		revisionField protoreflect.Name
	}{
		{message: &agentv1.CreateTaskRequest{}},
		{message: &agentv1.CancelTaskRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.PutRuntimeConfigRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.ChatRequest{}, revisionField: "expected_conversation_revision"},
		{message: &agentv1.StreamChatRequest{}, revisionField: "expected_conversation_revision"},
		{message: &agentv1.CreateSessionRequest{}},
		{message: &agentv1.UploadEncryptedRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.CompleteRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.CreateCloudGoalRequest{}},
		{message: &agentv1.CreateCloudQuoteRequest{}},
		{message: &agentv1.CreateCloudPlanRequest{}},
		{message: &agentv1.CreateApprovalChallengeRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.ApproveCloudPlanRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.CreateServiceKeyRequest{}},
		{message: &agentv1.RevokeServiceKeyRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.EnrollRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.CreateIdentityChallengeRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.EnrollVerifiedIdentityRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.WorkerControlServiceClaimRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.HeartbeatRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.WorkerControlServiceRecordEvidenceRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.WorkerControlServiceCompleteRequest{}, revisionField: "expected_revision"},
	}
	for _, test := range tests {
		descriptor := test.message.ProtoReflect().Descriptor()
		t.Run(string(descriptor.Name()), func(t *testing.T) {
			assertFieldKind(t, descriptor, "idempotency_key", protoreflect.StringKind)
			if test.revisionField != "" {
				assertFieldKind(t, descriptor, test.revisionField, protoreflect.Int64Kind)
			}
		})
	}
}

func TestFoundationEstablishmentFencesBothPlanAndBootstrapSession(t *testing.T) {
	descriptor := (&agentv1.EstablishAwsConnectionRequest{}).ProtoReflect().Descriptor()
	assertFieldKind(t, descriptor, "idempotency_key", protoreflect.StringKind)
	assertFieldKind(t, descriptor, "expected_plan_revision", protoreflect.Int64Kind)
	assertFieldKind(t, descriptor, "expected_session_revision", protoreflect.Int64Kind)
	approval := descriptor.Fields().ByName("approval")
	if approval == nil || approval.Kind() != protoreflect.MessageKind || approval.Message().Name() != "DeviceApprovalSignature" {
		t.Fatal("EstablishAwsConnectionRequest must require a typed device approval")
	}
}

func TestStreamChatUsesTypedEventsWithoutLegacyFinalFlag(t *testing.T) {
	descriptor := (&agentv1.StreamChatResponse{}).ProtoReflect().Descriptor()
	if descriptor.Fields().ByName("final") != nil || descriptor.Oneofs().ByName("event") == nil {
		t.Fatal("StreamChatResponse must use the typed event oneof without a final flag")
	}
	for _, fieldName := range []protoreflect.Name{"delta", "tool", "done"} {
		field := descriptor.Fields().ByName(fieldName)
		if field == nil || field.ContainingOneof() == nil || field.ContainingOneof().Name() != "event" {
			t.Fatalf("StreamChatResponse.%s is not part of event oneof", fieldName)
		}
	}
	if descriptor.Fields().ByName("reasoning") != nil {
		t.Fatal("StreamChatResponse must not expose raw model reasoning")
	}
}

func TestChatCloudDialogueUsesVersionedTypedScope(t *testing.T) {
	for _, request := range []proto.Message{&agentv1.ChatRequest{}, &agentv1.StreamChatRequest{}} {
		descriptor := request.ProtoReflect().Descriptor()
		field := descriptor.Fields().ByName("cloud_dialogue_scope")
		if field == nil || field.Kind() != protoreflect.MessageKind || field.Message().Name() != "CloudDialogueScopeV1" {
			t.Fatalf("%s.cloud_dialogue_scope is not a versioned typed scope", descriptor.Name())
		}
		scopeFields := field.Message().Fields()
		if scopeFields.Len() != 1 || scopeFields.ByName("cloud_connection_id") == nil || scopeFields.ByName("cloud_connection_id").Kind() != protoreflect.StringKind {
			t.Fatalf("CloudDialogueScopeV1 contains caller-controlled fields beyond cloud_connection_id: %v", scopeFields)
		}
	}
}

func TestCreateServiceKeyContractHasEncryptedDeliveryOnly(t *testing.T) {
	descriptor := (&agentv1.CreateServiceKeyResponse{}).ProtoReflect().Descriptor()
	if descriptor.Fields().ByName("secret") != nil {
		t.Fatal("CreateServiceKeyResponse must never expose a plaintext secret field")
	}
	field := descriptor.Fields().ByName("delivery")
	if field == nil || field.Kind() != protoreflect.MessageKind || field.Message().Name() != "ServiceKeyDelivery" {
		t.Fatal("CreateServiceKeyResponse must contain ServiceKeyDelivery")
	}
	request := (&agentv1.CreateServiceKeyRequest{}).ProtoReflect().Descriptor()
	assertFieldKind(t, request, "recipient_public_key", protoreflect.StringKind)
}

func TestSecretBootstrapSessionExposesServerAuthoritativeAADInputs(t *testing.T) {
	descriptor := (&agentv1.SecretBootstrapSession{}).ProtoReflect().Descriptor()
	for _, field := range []struct {
		name   protoreflect.Name
		number protoreflect.FieldNumber
	}{
		{name: "agent_instance_id", number: 10},
		{name: "session_schema_version", number: 11},
		{name: "envelope_schema_version", number: 12},
	} {
		assertFieldKind(t, descriptor, field.name, protoreflect.StringKind)
		if got := descriptor.Fields().ByName(field.name).Number(); got != field.number {
			t.Fatalf("SecretBootstrapSession.%s number = %d, want %d", field.name, got, field.number)
		}
	}
}

func TestCloudStatusContractSeparatesAxesAndRequiresOwnerFilters(t *testing.T) {
	connection := (&agentv1.CloudConnection{}).ProtoReflect().Descriptor()
	for _, name := range []protoreflect.Name{"revision", "credential_generation"} {
		assertFieldKind(t, connection, name, protoreflect.Int64Kind)
	}
	for _, name := range []protoreflect.Name{"created_at", "updated_at"} {
		field := connection.Fields().ByName(name)
		if field == nil || field.Kind() != protoreflect.MessageKind || field.Message().FullName() != "google.protobuf.Timestamp" {
			t.Fatalf("CloudConnection.%s must be a protobuf Timestamp", name)
		}
	}
	deployment := (&agentv1.CloudDeployment{}).ProtoReflect().Descriptor()
	assertFieldKind(t, deployment, "revision", protoreflect.Int64Kind)
	for _, name := range []protoreflect.Name{"execution_status", "outcome_status", "resources"} {
		if deployment.Fields().ByName(name) == nil {
			t.Fatalf("CloudDeployment.%s is required", name)
		}
	}
	resource := (&agentv1.CloudResource{}).ProtoReflect().Descriptor()
	assertFieldKind(t, resource, "revision", protoreflect.Int64Kind)
	if resource.Fields().ByName("read_back") == nil {
		t.Fatal("CloudResource.read_back is required")
	}
	worker := (&agentv1.CloudWorker{}).ProtoReflect().Descriptor()
	assertFieldKind(t, worker, "revision", protoreflect.Int64Kind)
	for _, request := range []proto.Message{
		&agentv1.ListCloudPlansRequest{},
		&agentv1.GetCloudConnectionRequest{}, &agentv1.ListCloudConnectionsRequest{},
		&agentv1.GetCloudDeploymentRequest{}, &agentv1.ListCloudDeploymentsRequest{},
		&agentv1.GetCloudResourceRequest{}, &agentv1.ListCloudResourcesRequest{},
		&agentv1.GetCloudWorkerRequest{}, &agentv1.ListCloudWorkersRequest{},
	} {
		assertFieldKind(t, request.ProtoReflect().Descriptor(), "owner_id", protoreflect.StringKind)
	}
}

func assertFieldKind(t *testing.T, descriptor protoreflect.MessageDescriptor, name protoreflect.Name, kind protoreflect.Kind) {
	t.Helper()
	field := descriptor.Fields().ByName(name)
	if field == nil || field.Kind() != kind {
		t.Fatalf("%s.%s kind = %v, want %v", descriptor.Name(), name, fieldKind(field), kind)
	}
}

func fieldKind(field protoreflect.FieldDescriptor) protoreflect.Kind {
	if field == nil {
		return 0
	}
	return field.Kind()
}

package rpcapi

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestMutationRequestsExposeIdempotencyAndRevisionFences(t *testing.T) {
	tests := []struct {
		message          proto.Message
		requiresRevision bool
	}{
		{message: &agentv1.CreateTaskRequest{}},
		{message: &agentv1.CancelTaskRequest{}, requiresRevision: true},
		{message: &agentv1.ChatRequest{}},
		{message: &agentv1.StreamChatRequest{}},
		{message: &agentv1.CreateSessionRequest{}},
		{message: &agentv1.UploadEncryptedRequest{}, requiresRevision: true},
		{message: &agentv1.CompleteRequest{}, requiresRevision: true},
		{message: &agentv1.CreateServiceKeyRequest{}},
		{message: &agentv1.RevokeServiceKeyRequest{}, requiresRevision: true},
		{message: &agentv1.EnrollRequest{}},
		{message: &agentv1.HeartbeatRequest{}, requiresRevision: true},
	}
	for _, test := range tests {
		descriptor := test.message.ProtoReflect().Descriptor()
		t.Run(string(descriptor.Name()), func(t *testing.T) {
			assertFieldKind(t, descriptor, "idempotency_key", protoreflect.StringKind)
			if test.requiresRevision {
				assertFieldKind(t, descriptor, "expected_revision", protoreflect.Int64Kind)
			}
		})
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

package rpcapi

import (
	"strings"
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
		{message: &agentv1.CreateAwsFoundationOperationChallengeRequest{}, revisionField: "expected_bootstrap_revision"},
		{message: &agentv1.ApproveAwsFoundationOperationRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.CreateServiceKeyRequest{}},
		{message: &agentv1.RevokeServiceKeyRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.EnrollRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.CreateIdentityChallengeRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.EnrollVerifiedIdentityRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.WorkerControlServiceClaimRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.HeartbeatRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.WorkerControlServiceRecordEvidenceRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.WorkerControlServiceCompleteRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.CreateCloudDeploymentEntryPlanRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.CreateCloudDeploymentEntryChallengeRequest{}, revisionField: "expected_revision"},
		{message: &agentv1.ApproveCloudDeploymentEntryRequest{}, revisionField: "expected_revision"},
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

func TestWorkerMilestoneRelayContractIsClosedAndAtLeastOnce(t *testing.T) {
	descriptor := (&agentv1.WorkerControlServiceEmitMilestoneRequest{}).ProtoReflect().Descriptor()
	for name, number := range map[protoreflect.Name]struct {
		number protoreflect.FieldNumber
		kind   protoreflect.Kind
	}{
		"deployment_id": {1, protoreflect.StringKind},
		"worker_id":     {2, protoreflect.StringKind},
		"lease_epoch":   {3, protoreflect.Int64Kind},
		"event_id":      {4, protoreflect.StringKind},
		"kind":          {5, protoreflect.EnumKind},
		"action_id":     {6, protoreflect.StringKind},
		"outcome":       {7, protoreflect.EnumKind},
	} {
		field := descriptor.Fields().ByName(name)
		if field == nil || field.Number() != number.number || field.Kind() != number.kind {
			t.Fatalf("Worker milestone field %s = %v, want number=%d kind=%s", name, field, number.number, number.kind)
		}
	}
	if descriptor.Fields().Len() != 7 {
		t.Fatalf("Worker milestone relay accepts %d fields, want only 7 closed fields", descriptor.Fields().Len())
	}
	if outcome := descriptor.Fields().ByName("outcome"); outcome == nil || outcome.Enum().Name() != "WorkerOutcome" {
		t.Fatalf("Worker milestone outcome must reuse the canonical WorkerOutcome enum: %v", outcome)
	}
	for index := 0; index < descriptor.Fields().Len(); index++ {
		name := string(descriptor.Fields().Get(index).Name())
		for _, forbidden := range []string{"log_group", "log_prefix", "stream", "timestamp", "message", "error", "path", "url", "output", "secret", "credential"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Worker milestone relay must not accept %q field %q", forbidden, name)
			}
		}
	}
	if agentv1.File_dirextalk_agent_v1_agent_proto.Services().ByName("WorkerControlService").Methods().ByName("EmitMilestone") == nil {
		t.Fatal("WorkerControlService must expose the closed Agent relay")
	}
}

func TestFoundationApprovalContractIsIndependentAndFullyFenced(t *testing.T) {
	scope := (&agentv1.AwsFoundationOperationScope{}).ProtoReflect().Descriptor()
	for _, required := range []protoreflect.Name{"agent_instance_id", "owner_id", "action", "connection_id", "expected_connection_revision", "account_id", "region",
		"bootstrap_session_id", "expected_bootstrap_revision", "expected_credential_generation", "identity_observed_at", "identity_expires_at",
		"foundation_template_digest", "reaper_image_uri", "release_environment"} {
		if scope.Fields().ByName(required) == nil {
			t.Fatalf("Foundation scope is missing %s", required)
		}
	}
	for _, forbidden := range []protoreflect.Name{"plan_id", "quote_id", "recipe_id", "instance_type", "operator_credentials", "argv", "environment"} {
		if scope.Fields().ByName(forbidden) != nil {
			t.Fatalf("Foundation scope must not contain %s", forbidden)
		}
	}
	approve := (&agentv1.ApproveAwsFoundationOperationRequest{}).ProtoReflect().Descriptor()
	for _, required := range []protoreflect.Name{"operation_id", "expected_revision", "connection_id", "action", "scope_digest", "approval"} {
		if approve.Fields().ByName(required) == nil {
			t.Fatalf("Foundation approval request is missing %s", required)
		}
	}
}

func TestCloudEntryContractFencesUntrustedWorkerInputsAndBindsApproval(t *testing.T) {
	draft := (&agentv1.CloudEntryPlanDraft{}).ProtoReflect().Descriptor()
	for name, number := range map[protoreflect.Name]protoreflect.FieldNumber{
		"hostname":                      1,
		"certificate_arn":               2,
		"public_subnet_ids":             3,
		"target_port":                   4,
		"health_path":                   5,
		"expected_health_status_code":   6,
		"recipe_health_contract_digest": 7,
		"recipe_authentication_digest":  8,
		"cost":                          9,
	} {
		field := draft.Fields().ByName(name)
		if field == nil || field.Number() != number {
			t.Fatalf("CloudEntryPlanDraft.%s field = %v, want number %d", name, field, number)
		}
	}
	if draft.Fields().Len() != 9 {
		t.Fatalf("CloudEntryPlanDraft must have exactly the server-fenced input fields, got %d", draft.Fields().Len())
	}
	for _, forbidden := range []protoreflect.Name{
		"worker_url", "worker_public_ip", "public_ip", "eip", "vpc_endpoint", "endpoint", "security_group_id", "retention",
	} {
		if draft.Fields().ByName(forbidden) != nil {
			t.Fatalf("CloudEntryPlanDraft must not accept caller-controlled %s", forbidden)
		}
	}

	create := (&agentv1.CreateCloudDeploymentEntryPlanRequest{}).ProtoReflect().Descriptor()
	assertFieldKind(t, create, "idempotency_key", protoreflect.StringKind)
	assertFieldKind(t, create, "expected_revision", protoreflect.Int64Kind)
	if field := create.Fields().ByName("draft"); field == nil || field.Kind() != protoreflect.MessageKind || field.Message().Name() != "CloudEntryPlanDraft" {
		t.Fatalf("CreateCloudDeploymentEntryPlanRequest.draft must be CloudEntryPlanDraft: %v", field)
	}

	challenge := (&agentv1.CloudEntryApprovalChallenge{}).ProtoReflect().Descriptor()
	signature := (&agentv1.CloudEntryApprovalSignature{}).ProtoReflect().Descriptor()
	for _, descriptor := range []protoreflect.MessageDescriptor{challenge, signature} {
		for _, name := range []protoreflect.Name{"approval_id", "challenge_id", "entry_plan_id", "entry_plan_revision", "plan_hash", "scope_digest", "signer_key_id", "expires_at"} {
			if descriptor.Fields().ByName(name) == nil {
				t.Fatalf("%s must bind %s", descriptor.Name(), name)
			}
		}
	}
	if field := challenge.Fields().ByName("scope"); field == nil || field.Kind() != protoreflect.MessageKind || field.Message().Name() != "CloudEntryApprovalScope" {
		t.Fatalf("CloudEntryApprovalChallenge.scope must expose the complete signed scope: %v", field)
	}
	if field := (&agentv1.CloudEntryPlan{}).ProtoReflect().Descriptor().Fields().ByName("scope"); field == nil || field.Message().Name() != "CloudEntryApprovalScope" {
		t.Fatalf("CloudEntryPlan.scope must expose the device-visible entry scope: %v", field)
	}
	if field := (&agentv1.CloudEntryApprovalScope{}).ProtoReflect().Descriptor().Fields().ByName("kind"); field == nil || field.Kind() != protoreflect.EnumKind || field.Enum().Name() != "CloudEntryKind" {
		t.Fatalf("CloudEntryApprovalScope.kind must be a typed entry kind: %v", field)
	}

	targetSource := agentv1.File_dirextalk_agent_v1_agent_proto.Enums().ByName("CloudEntryTargetSource")
	if targetSource == nil || targetSource.Values().Len() != 2 || targetSource.Values().ByName("CLOUD_ENTRY_TARGET_SOURCE_APPROVED_WORKER_READ_BACK") == nil {
		t.Fatal("CloudEntryTargetSource must only permit approved Worker AWS read-back")
	}
}

func TestCloudEntryProjectionsCannotCarrySensitiveTransportMaterial(t *testing.T) {
	for _, message := range []proto.Message{
		&agentv1.CloudEntryPlanDraft{},
		&agentv1.CloudEntryAWSReadBack{},
		&agentv1.CloudEntryWorkerReadBackScope{},
		&agentv1.CloudEntryRecipeHealthBinding{},
		&agentv1.CloudEntryCertificateScope{},
		&agentv1.CloudEntryPublicSubnetScope{},
		&agentv1.CloudEntryALBScope{},
		&agentv1.CloudEntryHealthRouteScope{},
		&agentv1.CloudEntryAuthenticationScope{},
		&agentv1.CloudEntryRetentionScope{},
		&agentv1.CloudEntryApprovalScope{},
		&agentv1.CloudEntryPlan{},
		&agentv1.CloudEntryApprovalChallenge{},
		&agentv1.CloudEntryApprovalSignature{},
		&agentv1.CloudEntryOperation{},
	} {
		descriptor := message.ProtoReflect().Descriptor()
		for index := 0; index < descriptor.Fields().Len(); index++ {
			name := string(descriptor.Fields().Get(index).Name())
			for _, forbidden := range []string{"url", "headers", "body", "secret", "worker_public_ip", "public_ip", "eip", "endpoint"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s must not expose %q field %q", descriptor.Name(), forbidden, name)
				}
			}
		}
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
	healthField := deployment.Fields().ByName("health")
	if healthField == nil || healthField.Number() != 14 || healthField.Kind() != protoreflect.MessageKind || healthField.Message().Name() != "CloudHealthSummary" {
		t.Fatalf("CloudDeployment.health must remain the additive field 14: %v", healthField)
	}
	health := (&agentv1.CloudHealthSummary{}).ProtoReflect().Descriptor()
	for name, number := range map[protoreflect.Name]protoreflect.FieldNumber{
		"status": 1, "revision": 2, "observed_at": 3, "next_due_at": 4,
		"probe_count": 5, "probe_counts": 6, "external_evidence_digest": 7, "evidence_type": 8,
	} {
		field := health.Fields().ByName(name)
		if field == nil || field.Number() != number {
			t.Fatalf("CloudHealthSummary.%s number = %v, want %d", name, field, number)
		}
	}
	for _, forbidden := range []protoreflect.Name{"url", "target", "body", "headers", "pairing", "secret", "secret_ref"} {
		if health.Fields().ByName(forbidden) != nil {
			t.Fatalf("CloudHealthSummary must not expose %s", forbidden)
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

func TestCloudManagedServiceReadContractIsOwnerScopedAndClosed(t *testing.T) {
	get := (&agentv1.GetCloudManagedServiceRequest{}).ProtoReflect().Descriptor()
	if get.Fields().Len() != 2 {
		t.Fatalf("GetCloudManagedServiceRequest accepts %d fields, want only owner and service IDs", get.Fields().Len())
	}
	for name, number := range map[protoreflect.Name]protoreflect.FieldNumber{
		"owner_id":   1,
		"service_id": 2,
	} {
		field := get.Fields().ByName(name)
		if field == nil || field.Number() != number || field.Kind() != protoreflect.StringKind {
			t.Fatalf("GetCloudManagedServiceRequest.%s=%v, want string field %d", name, field, number)
		}
	}
	for _, forbidden := range []protoreflect.Name{"deployment_id", "operation_id", "approval_id", "contract", "provider_id", "secret_ref"} {
		if get.Fields().ByName(forbidden) != nil {
			t.Fatalf("GetCloudManagedServiceRequest must not accept %s", forbidden)
		}
	}
	list := (&agentv1.ListCloudManagedServicesRequest{}).ProtoReflect().Descriptor()
	if list.Fields().Len() != 3 {
		t.Fatalf("ListCloudManagedServicesRequest accepts %d fields, want only owner and cursor pagination", list.Fields().Len())
	}
	for name, number := range map[protoreflect.Name]protoreflect.FieldNumber{
		"owner_id":   1,
		"page_size":  2,
		"page_token": 3,
	} {
		field := list.Fields().ByName(name)
		if field == nil || field.Number() != number {
			t.Fatalf("ListCloudManagedServicesRequest.%s=%v, want field %d", name, field, number)
		}
	}
	assertFieldKind(t, list, "owner_id", protoreflect.StringKind)
	assertFieldKind(t, list, "page_size", protoreflect.Int32Kind)
	assertFieldKind(t, list, "page_token", protoreflect.StringKind)
	for _, forbidden := range []protoreflect.Name{"deployment_id", "operation_id", "approval_id", "contract", "provider_id", "secret_ref"} {
		if list.Fields().ByName(forbidden) != nil {
			t.Fatalf("ListCloudManagedServicesRequest must not accept %s", forbidden)
		}
	}
	response := (&agentv1.ListCloudManagedServicesResponse{}).ProtoReflect().Descriptor()
	service := response.Fields().ByName("services")
	if service == nil || !service.IsList() || service.Kind() != protoreflect.MessageKind || service.Message().Name() != "CloudManagedCompatibilityService" {
		t.Fatalf("ListCloudManagedServicesResponse.services must reuse CloudManagedCompatibilityService: %v", service)
	}
	if next := response.Fields().ByName("next_page_token"); next == nil || next.Number() != 2 || next.Kind() != protoreflect.StringKind {
		t.Fatalf("ListCloudManagedServicesResponse.next_page_token=%v", next)
	}
	control := agentv1.File_dirextalk_agent_v1_agent_proto.Services().ByName("CloudControlService")
	for _, name := range []protoreflect.Name{"GetCloudManagedService", "ListCloudManagedServices"} {
		if control == nil || control.Methods().ByName(name) == nil {
			t.Fatalf("CloudControlService must expose %s", name)
		}
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

package agentcapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

func TestCoreAWSCapabilityUsesLowerSnakeRedactedCredentialDTO(t *testing.T) {
	service := coreaws.NewService(coreaws.NewMemoryRepository(), nil, nil, nil, nil, nil)
	capability := NewCoreAWSCapability(service)
	permission := &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1, GrantedScopes: []string{"agent:aws:credentials:write"}}
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, permission)
	key := uuid.NewString()
	result, err := capability.HandleOperation(ctx, "create_credential", []byte(`{"idempotency_key":"`+key+`","name":"prod","region":"us-east-1","access_key_id":"AKIA-SECRET","secret_access_key":"SECRET-BYTES","session_token":"TOKEN"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result), "AKIA-SECRET") || strings.Contains(string(result), "SECRET-BYTES") || strings.Contains(string(result), "TOKEN") {
		t.Fatalf("credential secret leaked: %s", result)
	}
	var envelope map[string]any
	if err := json.Unmarshal(result, &envelope); err != nil {
		t.Fatal(err)
	}
	credential, ok := envelope["credential"].(map[string]any)
	if !ok || credential["credential_id"] == nil || credential["revision"] != float64(1) || credential["access_key_configured"] != true {
		t.Fatalf("unexpected lower_snake credential DTO: %s", result)
	}
	if _, ok := credential["ID"]; ok {
		t.Fatalf("default Go field name leaked into DTO: %s", result)
	}
}

func TestCoreAWSCapabilityDescriptorBindsAWSInputSchemas(t *testing.T) {
	descriptor := (&coreAWSCapability{}).Descriptor()
	if descriptor.GetCapabilityId() != "agent.aws.v1" || len(descriptor.GetOperations()) < 10 {
		t.Fatalf("unexpected AWS descriptor: %+v", descriptor)
	}
	for _, op := range descriptor.GetOperations() {
		if op.GetInputSchemaJson() == "" || !json.Valid([]byte(op.GetInputSchemaJson())) || len(op.GetInputSchemaDigest()) != 32 {
			t.Fatalf("invalid AWS operation schema %s", op.GetOperationId())
		}
		resultDigest := sha256.Sum256([]byte(op.GetResultSchemaJson()))
		if op.GetResultSchemaJson() == "" || !json.Valid([]byte(op.GetResultSchemaJson())) || !bytes.Equal(resultDigest[:], op.GetResultSchemaDigest()) {
			t.Fatalf("invalid AWS result schema %s", op.GetOperationId())
		}
	}
}

func TestCoreAWSCapabilityCredentialResponseSchemaIncludesVerificationFields(t *testing.T) {
	descriptor := (&coreAWSCapability{}).Descriptor()
	for _, operationID := range []string{"create_credential", "get_credential", "update_credential", "list_credentials"} {
		var operation *capv1.OperationDescriptor
		for _, candidate := range descriptor.GetOperations() {
			if candidate.GetOperationId() == operationID {
				operation = candidate
				break
			}
		}
		if operation == nil {
			t.Fatalf("missing operation %s", operationID)
		}
		var schema map[string]any
		if err := json.Unmarshal([]byte(operation.GetResultSchemaJson()), &schema); err != nil {
			t.Fatalf("decode %s result schema: %v", operationID, err)
		}
		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s result schema has no properties", operationID)
		}
		credential := properties["credential"]
		if operationID == "list_credentials" {
			items := properties["credentials"].(map[string]any)
			credential = items["items"]
		}
		credentialObject, ok := credential.(map[string]any)
		if !ok {
			t.Fatalf("%s result schema has no credential object", operationID)
		}
		credentialProperties := credentialObject["properties"].(map[string]any)
		if _, ok := credentialProperties["verified_revision"]; !ok {
			t.Fatalf("%s credential schema omits verified_revision", operationID)
		}
		if _, ok := credentialProperties["tested_at"]; !ok {
			t.Fatalf("%s credential schema omits optional tested_at", operationID)
		}
		required := credentialObject["required"].([]any)
		verifiedRequired := false
		testedRequired := false
		for _, field := range required {
			if field == "verified_revision" {
				verifiedRequired = true
			}
			if field == "tested_at" {
				testedRequired = true
			}
		}
		if !verifiedRequired || testedRequired {
			t.Fatalf("%s credential required fields do not enforce optional tested_at and required verified_revision", operationID)
		}
	}
}

func TestAWSCredentialDTOIncludesTestedAtOnlyWhenPresent(t *testing.T) {
	testedAt := time.Date(2026, time.July, 1, 12, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	view := awsCredentialView(coreaws.CredentialView{ID: uuid.NewString(), VerifiedRevision: 2, Revision: 2, TestedAt: testedAt})
	if view["verified_revision"] != int64(2) {
		t.Fatalf("verified_revision missing from DTO: %#v", view)
	}
	if _, ok := view["tested_at"]; !ok {
		t.Fatalf("tested_at missing from verified DTO: %#v", view)
	}
	unverified := awsCredentialView(coreaws.CredentialView{ID: uuid.NewString(), VerifiedRevision: 0, Revision: 1})
	if _, ok := unverified["tested_at"]; ok {
		t.Fatalf("stale tested_at must be omitted: %#v", unverified)
	}
}

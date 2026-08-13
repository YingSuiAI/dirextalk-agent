package agentcapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
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

func TestCoreAWSCapabilityRejectsSecondActiveCredential(t *testing.T) {
	service := coreaws.NewService(coreaws.NewMemoryRepository(), nil, nil, nil, nil, nil)
	capability := &errorClassifyingCapability{inner: NewCoreAWSCapability(service)}
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1})
	request := func(key, name string) []byte {
		return []byte(`{"idempotency_key":"` + key + `","name":"` + name + `","region":"us-east-1","access_key_id":"access","secret_access_key":"secret"}`)
	}
	if _, err := capability.HandleOperation(ctx, "create_credential", request(uuid.NewString(), "first")); err != nil {
		t.Fatal(err)
	}
	_, err := capability.HandleOperation(ctx, "create_credential", request(uuid.NewString(), "second"))
	code, message, classified := capabilityoperation.FailureDetails(err)
	if !classified || code != "PRECONDITION_FAILED" || message != "Delete the active AWS credential before adding another" || !errors.Is(err, coreaws.ErrActiveCredentialExists) {
		t.Fatalf("second active credential error=%v code=%q message=%q classified=%v", err, code, message, classified)
	}
}

func TestCoreAWSCapabilityTestCredentialIsDurablyIdempotent(t *testing.T) {
	const credentialID = "11111111-1111-4111-8111-111111111111"
	const firstKey = "22222222-2222-4222-8222-222222222222"
	const concurrentKey = "33333333-3333-4333-8333-333333333333"
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1, GrantedScopes: []string{"agent:aws:credentials:write"}})
	sts := &coreaws.FakeSTSProvider{Identity: coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/test", PrincipalID: "principal"}}
	now := time.Date(2026, time.August, 6, 1, 2, 3, 0, time.UTC)
	service := coreaws.NewService(coreaws.NewMemoryRepository(), nil, nil, sts, nil, func() time.Time { return now })
	if _, err := service.SaveCredential(ctx, coreaws.CredentialInput{ID: credentialID, Name: "prod", Region: "us-east-1", AccessKeyID: "access", SecretAccessKey: "secret", IdempotencyKey: "44444444-4444-4444-8444-444444444444"}); err != nil {
		t.Fatal(err)
	}
	capability := NewCoreAWSCapability(service)
	raw := []byte(`{"credential_id":"` + credentialID + `","expected_revision":1,"idempotency_key":"` + firstKey + `"}`)
	first, err := capability.HandleOperation(ctx, "test_credential", raw)
	if err != nil {
		t.Fatalf("first neutral test: %v", err)
	}
	second, err := capability.HandleOperation(ctx, "test_credential", raw)
	if err != nil {
		t.Fatalf("replayed neutral test: %v", err)
	}
	if !bytes.Equal(first, second) || sts.Calls != 1 {
		t.Fatalf("replay=%s/%s sts_calls=%d", first, second, sts.Calls)
	}
	if _, err := capability.HandleOperation(ctx, "test_credential", []byte(`{"credential_id":"`+credentialID+`","expected_revision":2,"idempotency_key":"`+firstKey+`"}`)); !errors.Is(err, coreaws.ErrIdempotencyConflict) {
		t.Fatalf("changed binding error=%v, want idempotency conflict", err)
	}
	for _, request := range []string{
		`{"credential_id":"` + credentialID + `","expected_revision":1}`,
		`{"credential_id":"` + credentialID + `","expected_revision":1,"idempotency_key":"not-a-uuid"}`,
	} {
		if _, err := capability.HandleOperation(ctx, "test_credential", []byte(request)); !errors.Is(err, coreaws.ErrInvalid) {
			t.Fatalf("invalid neutral key request=%s err=%v", request, err)
		}
	}
	concurrentRaw := []byte(`{"credential_id":"` + credentialID + `","expected_revision":1,"idempotency_key":"` + concurrentKey + `"}`)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	results := make([][]byte, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = capability.HandleOperation(ctx, "test_credential", concurrentRaw)
		}(i)
	}
	wg.Wait()
	successes := 0
	var concurrentResult []byte
	for i := range errs {
		if errs[i] == nil {
			successes++
			if concurrentResult == nil {
				concurrentResult = results[i]
			} else if !bytes.Equal(results[i], concurrentResult) {
				t.Fatalf("concurrent replay[%d]=%s differs from successful result=%s", i, results[i], concurrentResult)
			}
			continue
		}
		t.Fatalf("concurrent replay[%d]=%s err=%v", i, results[i], errs[i])
	}
	if successes != len(errs) {
		t.Fatalf("concurrent claim outcomes successes=%d want=%d", successes, len(errs))
	}
	if sts.Calls != 2 {
		t.Fatalf("same-key concurrent provider calls=%d, want 2 total provider calls", sts.Calls)
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

func TestAWSCredentialTestResultSchemaAndDTOAreBidirectionallyClosed(t *testing.T) {
	descriptor := (&coreAWSCapability{}).Descriptor()
	var schemaJSON string
	for _, operation := range descriptor.GetOperations() {
		if operation.GetOperationId() == "test_credential" {
			schemaJSON = operation.GetResultSchemaJson()
			break
		}
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	required := schema["required"].([]any)
	want := map[string]struct{}{"credential_id": {}, "credential_revision": {}, "account_id": {}, "user_arn": {}, "principal_id": {}, "tested_at": {}}
	if len(required) != len(want) {
		t.Fatalf("required fields=%#v, want six fields", required)
	}
	for _, raw := range required {
		name, ok := raw.(string)
		if !ok {
			t.Fatalf("non-string required field=%#v", raw)
		}
		if _, ok := want[name]; !ok {
			t.Fatalf("unexpected required field %q", name)
		}
	}
	dto := awsCredentialTest(coreaws.CredentialTest{CredentialID: uuid.NewString(), Identity: coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/test", PrincipalID: "principal"}, CredentialRevision: 3, TestedAt: time.Date(2026, 8, 6, 1, 2, 3, 0, time.UTC)})
	for field := range want {
		if _, ok := dto[field]; !ok {
			t.Fatalf("DTO omitted schema-required field %q: %#v", field, dto)
		}
		if _, ok := properties[field]; !ok {
			t.Fatalf("schema omitted DTO field %q: %s", field, schemaJSON)
		}
	}
	for field := range dto {
		if _, ok := properties[field]; !ok {
			t.Fatalf("DTO field %q is absent from result schema: %s", field, schemaJSON)
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

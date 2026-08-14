package agentcapability

// The neutral agent.aws.v1 capability is the only public adapter for the
// Agent-owned AWS credential store. It never returns credential bytes or
// permits arbitrary provider calls.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type coreAWSCapability struct{ service *coreaws.Service }

func NewCoreAWSCapability(service *coreaws.Service) Capability {
	if service == nil {
		return nil
	}
	return &coreAWSCapability{service: service}
}

func (c *coreAWSCapability) Descriptor() *capv1.CapabilityDescriptor {
	d := descriptor("agent.aws.v1", "AWS Credentials", "Owner-scoped AWS credentials and identity verification", []opSpec{
		{"create_credential", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:credentials:write"},
		{"get_credential", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:credentials:read"},
		{"list_credentials", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:credentials:read"},
		{"update_credential", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:credentials:write"},
		{"delete_credential", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:credentials:write"},
		{"test_credential", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:credentials:write"},
	})
	for _, operation := range d.GetOperations() {
		resultSchema := awsResultSchema(operation.GetOperationId())
		resultDigest := sha256.Sum256([]byte(resultSchema))
		operation.ResultSchemaJson = resultSchema
		operation.ResultSchemaDigest = resultDigest[:]
	}
	return d
}

// awsResultSchema keeps the public adapter's response contract explicit.  In
// particular, verified_revision is always present while tested_at is only
// present when the credential was tested at its current revision.
func awsResultSchema(operation string) string {
	const credential = `{"additionalProperties":false,"properties":{"access_key_configured":{"type":"boolean"},"account_id":{"type":"string"},"created_at":{"format":"date-time","type":"string"},"credential_id":{"format":"uuid","type":"string"},"name":{"type":"string"},"region":{"type":"string"},"revision":{"minimum":1,"type":"integer"},"secret_access_key_configured":{"type":"boolean"},"session_token_configured":{"type":"boolean"},"tested_at":{"format":"date-time","type":"string"},"updated_at":{"format":"date-time","type":"string"},"user_arn":{"type":"string"},"verified_revision":{"minimum":0,"type":"integer"}},"required":["credential_id","name","region","account_id","user_arn","access_key_configured","secret_access_key_configured","session_token_configured","revision","verified_revision","created_at","updated_at"],"type":"object"}`
	switch operation {
	case "create_credential", "get_credential", "update_credential":
		return `{"additionalProperties":false,"properties":{"credential":` + credential + `},"required":["credential"],"type":"object"}`
	case "list_credentials":
		return `{"additionalProperties":false,"properties":{"credentials":{"items":` + credential + `,"type":"array"},"next_page_token":{"type":"string"}},"required":["credentials"],"type":"object"}`
	case "delete_credential":
		return `{"additionalProperties":false,"properties":{"credential_id":{"format":"uuid","type":"string"},"deleted":{"type":"boolean"}},"type":"object"}`
	case "test_credential":
		return `{"additionalProperties":false,"properties":{"account_id":{"type":"string"},"credential_id":{"format":"uuid","type":"string"},"credential_revision":{"minimum":1,"type":"integer"},"principal_id":{"type":"string"},"tested_at":{"format":"date-time","type":"string"},"user_arn":{"type":"string"}},"required":["credential_id","credential_revision","account_id","user_arn","principal_id","tested_at"],"type":"object"}`
	default:
		return `{"type":"object"}`
	}
}

func (c *coreAWSCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, coreaws.ErrInvalid
	}
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	in, err := decodeAWSInput(raw, awsFields(operationID))
	if err != nil {
		return nil, err
	}
	if c.service == nil {
		return nil, coreaws.ErrInvalid
	}
	switch operationID {
	case "create_credential":
		key, err := requiredAWSUUID(in, "idempotency_key")
		if err != nil {
			return nil, err
		}
		access, err := requiredAWSString(in, "access_key_id")
		if err != nil {
			return nil, err
		}
		secret, err := requiredAWSString(in, "secret_access_key")
		if err != nil {
			return nil, err
		}
		view, err := c.service.SaveCredential(ctx, coreaws.CredentialInput{IdempotencyKey: key, Name: stringValue(in, "name"), Region: stringValue(in, "region"), AccessKeyID: access, SecretAccessKey: secret, SessionToken: stringValue(in, "session_token")})
		return marshalResult(map[string]any{"credential": awsCredentialView(view)}, err)
	case "get_credential":
		id, err := requiredAWSUUID(in, "credential_id")
		if err != nil {
			return nil, err
		}
		view, err := c.service.GetCredential(ctx, id)
		return marshalResult(map[string]any{"credential": awsCredentialView(view)}, err)
	case "list_credentials":
		page, err := c.service.ListCredentials(ctx, awsPageLimit(in), stringValue(in, "page_token"))
		if err != nil {
			return nil, err
		}
		items := make([]map[string]any, 0, len(page.Items))
		for _, view := range page.Items {
			items = append(items, awsCredentialView(view))
		}
		return marshalResult(map[string]any{"credentials": items, "next_page_token": page.NextPageToken}, nil)
	case "update_credential":
		id, err := requiredAWSUUID(in, "credential_id")
		if err != nil {
			return nil, err
		}
		key, err := requiredAWSUUID(in, "idempotency_key")
		if err != nil {
			return nil, err
		}
		expected := int64Value(in, "expected_revision")
		if expected < 1 {
			return nil, coreaws.ErrInvalid
		}
		current, err := c.service.GetCredential(ctx, id)
		if err != nil {
			return nil, err
		}
		name, region := stringValue(in, "name"), stringValue(in, "region")
		if name == "" {
			name = current.Name
		}
		if region == "" {
			region = current.Region
		}
		view, err := c.service.ReplaceCredential(ctx, coreaws.CredentialInput{ID: id, Name: name, Region: region, AccessKeyID: unmaskAWSString(in, "access_key_id"), SecretAccessKey: unmaskAWSString(in, "secret_access_key"), SessionToken: unmaskAWSString(in, "session_token")}, expected, key)
		return marshalResult(map[string]any{"credential": awsCredentialView(view)}, err)
	case "delete_credential":
		id, err := requiredAWSUUID(in, "credential_id")
		if err != nil {
			return nil, err
		}
		key, err := requiredAWSUUID(in, "idempotency_key")
		if err != nil {
			return nil, err
		}
		expected := int64Value(in, "expected_revision")
		if expected < 1 {
			return nil, coreaws.ErrInvalid
		}
		if err := c.service.DeleteCredential(ctx, id, expected, key); err != nil {
			return nil, err
		}
		return marshalResult(map[string]any{"credential_id": id, "deleted": true}, nil)
	case "test_credential":
		id, err := requiredAWSUUID(in, "credential_id")
		if err != nil {
			return nil, err
		}
		key, err := requiredAWSUUID(in, "idempotency_key")
		if err != nil {
			return nil, err
		}
		expected := int64Value(in, "expected_revision")
		if expected < 1 {
			return nil, coreaws.ErrInvalid
		}
		test, err := c.service.TestCredentialIdempotent(ctx, id, expected, key)
		return marshalResult(awsCredentialTest(test), err)
	default:
		return nil, coreaws.ErrInvalid
	}
}

func decodeAWSInput(raw []byte, allowed map[string]struct{}) (map[string]json.RawMessage, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil || in == nil {
		return nil, coreaws.ErrInvalid
	}
	for key := range in {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("%w: unknown field %s", coreaws.ErrInvalid, key)
		}
	}
	return in, nil
}

func awsFields(operation string) map[string]struct{} {
	values := map[string][]string{
		"create_credential": {"idempotency_key", "name", "region", "access_key_id", "secret_access_key", "session_token"},
		"get_credential":    {"credential_id"}, "list_credentials": {"page_size", "page_token"},
		"update_credential": {"idempotency_key", "credential_id", "expected_revision", "name", "region", "access_key_id", "secret_access_key", "session_token"},
		"delete_credential": {"idempotency_key", "credential_id", "expected_revision"}, "test_credential": {"credential_id", "expected_revision", "idempotency_key"},
	}
	out := map[string]struct{}{}
	for _, key := range values[operation] {
		out[key] = struct{}{}
	}
	return out
}

func requiredAWSUUID(in map[string]json.RawMessage, key string) (string, error) {
	value := stringValue(in, key)
	if !coretask.ValidUUID(value) {
		return "", coreaws.ErrInvalid
	}
	return value, nil
}

func requiredAWSString(in map[string]json.RawMessage, key string) (string, error) {
	value := stringValue(in, key)
	if value == "" {
		return "", coreaws.ErrInvalid
	}
	return value, nil
}

func unmaskAWSString(in map[string]json.RawMessage, key string) string {
	value := stringValue(in, key)
	if strings.Contains(value, "****") || strings.Contains(value, "••••") {
		return ""
	}
	return value
}

func awsPageLimit(in map[string]json.RawMessage) int {
	limit := intValue(in, "page_size", 50)
	if limit < 1 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return limit
}

func awsCredentialView(value coreaws.CredentialView) map[string]any {
	view := map[string]any{"credential_id": value.ID, "name": value.Name, "region": value.Region, "account_id": value.AccountID, "user_arn": value.UserARN, "access_key_configured": value.HasAccessKey, "secret_access_key_configured": value.HasSecretKey, "session_token_configured": value.HasSessionToken, "revision": value.Revision, "verified_revision": value.VerifiedRevision, "created_at": value.CreatedAt.UTC(), "updated_at": value.UpdatedAt.UTC()}
	if !value.TestedAt.IsZero() {
		view["tested_at"] = value.TestedAt.UTC()
	}
	return view
}

func awsCredentialTest(value coreaws.CredentialTest) map[string]any {
	return map[string]any{"credential_id": value.CredentialID, "account_id": value.Identity.AccountID, "user_arn": value.Identity.UserARN, "principal_id": value.Identity.PrincipalID, "credential_revision": value.CredentialRevision, "tested_at": value.TestedAt.UTC()}
}

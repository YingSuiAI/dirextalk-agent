package agentcapability

// The neutral agent.aws.v1 capability is the only public adapter for the
// Agent-owned Core AWS graph.  It exposes the existing typed credential,
// immutable-plan and confirmation/change read surfaces without returning
// credential bytes or allowing arbitrary CloudFormation requests.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
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
	d := descriptor("agent.aws.v1", "AWS Cloud Control", "Owner-scoped typed AWS credentials, immutable plans and confirmation-bound changes", []opSpec{
		{"create_credential", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:credentials:write"},
		{"get_credential", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:credentials:read"},
		{"list_credentials", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:credentials:read"},
		{"update_credential", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:credentials:write"},
		{"delete_credential", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:credentials:write"},
		{"test_credential", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:credentials:write"},
		{"create_plan", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:plans:write"},
		{"get_plan", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:plans:read"},
		{"list_plans", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:plans:read"},
		{"quote_plan", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:plans:read"},
		{"request_change", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:aws:changes:write"},
		{"get_change", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:changes:read"},
		{"list_changes", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:changes:read"},
		{"get_change_status", capv1.OperationType_OPERATION_TYPE_READ, "agent:aws:changes:read"},
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
		return `{"additionalProperties":false,"properties":{"account_id":{"type":"string"},"credential_id":{"format":"uuid","type":"string"},"credential_revision":{"minimum":1,"type":"integer"},"principal_id":{"type":"string"},"tested_at":{"format":"date-time","type":"string"},"user_arn":{"type":"string"}},"type":"object"}`
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
		if _, err := requiredAWSUUID(in, "idempotency_key"); err != nil {
			return nil, err
		}
		if int64Value(in, "expected_revision") < 1 {
			return nil, coreaws.ErrInvalid
		}
		current, err := c.service.GetCredential(ctx, id)
		if err != nil || current.Revision != int64Value(in, "expected_revision") {
			if err != nil {
				return nil, err
			}
			return nil, coreaws.ErrRevisionConflict
		}
		test, err := c.service.TestCredential(ctx, id)
		return marshalResult(awsCredentialTest(test), err)
	case "create_plan":
		key, err := requiredAWSUUID(in, "idempotency_key")
		if err != nil {
			return nil, err
		}
		credentialID, err := requiredAWSUUID(in, "credential_id")
		if err != nil {
			return nil, err
		}
		template, err := awsBytes(in, "template")
		if err != nil {
			return nil, err
		}
		op, ok := awsOperation(stringValue(in, "operation"))
		if !ok {
			return nil, coreaws.ErrInvalid
		}
		view, err := c.service.CreatePlan(ctx, coreaws.PlanInput{IdempotencyKey: key, CredentialID: credentialID, Region: stringValue(in, "region"), StackName: stringValue(in, "stack_name"), Operation: op, Template: template, Parameters: awsStringMap(in, "parameters"), Tags: awsStringMap(in, "tags"), Capabilities: awsStringSlice(in, "capabilities")})
		return marshalResult(map[string]any{"plan": awsPlanView(view)}, err)
	case "get_plan":
		id, err := requiredAWSUUID(in, "plan_id")
		if err != nil {
			return nil, err
		}
		view, err := c.service.GetPlan(ctx, id)
		return marshalResult(map[string]any{"plan": awsPlanView(view)}, err)
	case "list_plans":
		page, err := c.service.ListPlans(ctx, awsPageLimit(in), stringValue(in, "page_token"))
		if err != nil {
			return nil, err
		}
		items := make([]map[string]any, 0, len(page.Items))
		for _, view := range page.Items {
			items = append(items, awsPlanView(view))
		}
		return marshalResult(map[string]any{"plans": items, "next_page_token": page.NextPageToken}, nil)
	case "quote_plan":
		id, err := requiredAWSUUID(in, "plan_id")
		if err != nil {
			return nil, err
		}
		quote, err := c.service.Quote(ctx, id)
		return marshalResult(map[string]any{"quote": awsQuoteView(quote)}, err)
	case "request_change":
		key, err := requiredAWSUUID(in, "idempotency_key")
		if err != nil {
			return nil, err
		}
		planID, err := requiredAWSUUID(in, "plan_id")
		if err != nil {
			return nil, err
		}
		result, err := c.service.RequestChange(ctx, coreaws.RequestChangeInput{PlanID: planID, IdempotencyKey: key})
		return marshalResult(map[string]any{"change": awsChangeView(result.Change), "task_id": result.Task.ID, "confirmation": awsConfirmationView(result.Confirmation)}, err)
	case "get_change":
		id, err := requiredAWSUUID(in, "change_id")
		if err != nil {
			return nil, err
		}
		change, err := c.service.GetChange(ctx, id)
		return marshalResult(map[string]any{"change": awsChangeView(change)}, err)
	case "list_changes":
		planID := stringValue(in, "plan_id")
		if planID != "" && !coretask.ValidUUID(planID) {
			return nil, coreaws.ErrInvalid
		}
		page, err := c.service.ListChanges(ctx, awsPageLimit(in), planID, stringValue(in, "page_token"))
		if err != nil {
			return nil, err
		}
		items := make([]map[string]any, 0, len(page.Items))
		for _, change := range page.Items {
			items = append(items, awsChangeView(change))
		}
		return marshalResult(map[string]any{"changes": items, "next_page_token": page.NextPageToken}, nil)
	case "get_change_status":
		id, err := requiredAWSUUID(in, "change_id")
		if err != nil {
			return nil, err
		}
		change, err := c.service.GetChange(ctx, id)
		return marshalResult(map[string]any{"change": awsChangeView(change), "status": string(change.Status), "stage": string(change.Stage)}, err)
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
		"create_plan": {"idempotency_key", "credential_id", "region", "stack_name", "operation", "template", "parameters", "tags", "capabilities"},
		"get_plan":    {"plan_id"}, "list_plans": {"page_size", "page_token"}, "quote_plan": {"plan_id"},
		"request_change": {"idempotency_key", "plan_id"}, "get_change": {"change_id"}, "list_changes": {"page_size", "page_token", "plan_id"}, "get_change_status": {"change_id"},
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

func awsBytes(in map[string]json.RawMessage, key string) ([]byte, error) {
	var value []byte
	if json.Unmarshal(in[key], &value) != nil || len(value) == 0 || len(value) > 51200 {
		return nil, coreaws.ErrInvalid
	}
	var document map[string]any
	if !json.Valid(value) || json.Unmarshal(value, &document) != nil || document == nil {
		return nil, coreaws.ErrInvalid
	}
	return value, nil
}

func awsStringMap(in map[string]json.RawMessage, key string) map[string]string {
	var value map[string]string
	_ = json.Unmarshal(in[key], &value)
	return value
}

func awsStringSlice(in map[string]json.RawMessage, key string) []string {
	var value []string
	_ = json.Unmarshal(in[key], &value)
	return value
}

func awsOperation(value string) (coreaws.Operation, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "create":
		return coreaws.OperationCreate, true
	case "update":
		return coreaws.OperationUpdate, true
	case "delete":
		return coreaws.OperationDelete, true
	default:
		return "", false
	}
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

func awsPlanView(value coreaws.PlanView) map[string]any {
	return map[string]any{"plan_id": value.ID, "credential_id": value.CredentialID, "region": value.Region, "stack_name": value.StackName, "operation": string(value.Operation), "template_sha256": value.TemplateSHA256, "parameters": value.Parameters, "tags": value.Tags, "capabilities": value.Capabilities, "revision": value.Revision, "created_at": value.CreatedAt.UTC()}
}

func awsQuoteView(value coreaws.Quote) map[string]any {
	return map[string]any{"plan_id": value.PlanID, "operation": string(value.Operation), "region": value.Region, "stack_name": value.StackName, "resource_count": value.ResourceCount, "parameter_count": value.ParameterCount, "tag_count": value.TagCount, "estimated_monthly_usd": value.EstimatedMonthlyUSD, "summary": value.Summary, "plan_digest": value.PlanDigest}
}

func awsChangeView(value coreaws.Change) map[string]any {
	return map[string]any{"change_id": value.ID, "plan_id": value.PlanID, "credential_id": value.CredentialID, "task_id": value.TaskID, "confirmation_id": value.ConfirmationID, "operation": string(value.Operation), "status": string(value.Status), "stage": string(value.Stage), "change_set_id": value.ChangeSetID, "provider_request_digest": value.ProviderRequestDigest, "revision": value.Revision, "error_code": value.ErrorCode, "error_summary": value.ErrorSummary, "created_at": value.CreatedAt.UTC(), "updated_at": value.UpdatedAt.UTC()}
}

func awsConfirmationView(value coreconfirmation.Confirmation) map[string]any {
	return map[string]any{"confirmation_id": value.ConfirmationID, "task_id": value.TaskID, "state": string(value.State), "revision": value.Revision, "binding": awsBindingView(value.Binding), "created_at": value.CreatedAt.UTC(), "updated_at": value.UpdatedAt.UTC(), "expires_at": value.ExpiresAt.UTC(), "terminal_code": value.TerminalCode, "terminal_note": value.TerminalNote, "terminal_reason": value.TerminalReason}
}

func awsBindingView(value coreconfirmation.Binding) map[string]any {
	grants := make([]map[string]any, 0, len(value.SecretGrants))
	for _, grant := range value.SecretGrants {
		grants = append(grants, map[string]any{"reference_id": grant.ReferenceID, "purpose": string(grant.Purpose), "binding_digest": string(grant.BindingDigest)})
	}
	return map[string]any{"operation_domain": value.OperationDomain, "target_id": value.TargetID, "target_revision": value.TargetRevision, "target_kind": value.TargetKind, "source_version": value.SourceVersion, "source_commit": value.SourceCommit, "content_digest": string(value.ContentDigest), "manifest_digest": string(value.ManifestDigest), "execution_digest": string(value.ExecutionDigest), "permission_digest": string(value.PermissionDigest), "parameter_digest": string(value.ParameterDigest), "network_digest": string(value.NetworkDigest), "secret_grant_digest": string(value.SecretGrantDigest), "selected_tool": value.SelectedTool, "selected_command": append([]string(nil), value.SelectedCommand...), "network_grants": append([]string(nil), value.NetworkGrants...), "secret_grants": grants}
}

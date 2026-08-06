// Package team publishes the owner-scoped public control surface for bounded
// Central Agent plans and official Pi Worker executions.
package team

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

const (
	CapabilityID    = "agent.team.v1"
	maxRequestSize  = 1 << 20
	defaultPageSize = 50
)

type Service interface {
	ReadyForPublication() bool
	GetPlan(context.Context, coreteam.Scope, string) (coreteam.PlanRecord, error)
	GetExecution(context.Context, coreteam.Scope, string) (coreteam.Execution, error)
	ListExecutions(context.Context, coreteam.ListQuery) (coreteam.Page, error)
	CancelExecution(context.Context, coreteam.CancelExecutionRequest) (coreteam.Execution, error)
}

type Capability struct{ service Service }

func NewCapability(service Service) (*Capability, error) {
	if service == nil {
		return nil, coreteam.ErrInvalid
	}
	return &Capability{service: service}, nil
}

type operationSpec struct {
	id, name, description, scope string
	typ                          capv1.OperationType
	risk                         capv1.RiskLevel
	input, result                string
}

var operations = []operationSpec{
	{id: "plans_get", name: "Get Team plan", description: "Read one owner-scoped immutable Team plan.", scope: "agent:team:plans:read", typ: capv1.OperationType_OPERATION_TYPE_READ, risk: capv1.RiskLevel_RISK_LEVEL_SAFE, input: planGetSchema, result: planGetResultSchema},
	{id: "executions_list", name: "List Team executions", description: "List owner-scoped Team execution summaries.", scope: "agent:team:executions:read", typ: capv1.OperationType_OPERATION_TYPE_READ, risk: capv1.RiskLevel_RISK_LEVEL_SAFE, input: executionListSchema, result: executionListResultSchema},
	{id: "executions_get", name: "Get Team execution", description: "Read one owner-scoped Team execution summary.", scope: "agent:team:executions:read", typ: capv1.OperationType_OPERATION_TYPE_READ, risk: capv1.RiskLevel_RISK_LEVEL_SAFE, input: executionGetSchema, result: executionGetResultSchema},
	{id: "executions_cancel", name: "Cancel Team execution", description: "Request idempotent cancellation through the Team controller.", scope: "agent:team:executions:cancel", typ: capv1.OperationType_OPERATION_TYPE_MUTATION, risk: capv1.RiskLevel_RISK_LEVEL_HIGH, input: executionCancelSchema, result: executionGetResultSchema},
}

func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	ready := c != nil && c.service != nil && c.service.ReadyForPublication()
	reason := "Team repository and cancellation controller are not ready"
	if ready {
		reason = "Team repository and cancellation controller are ready"
	}
	descriptor := &capv1.CapabilityDescriptor{
		CapabilityId: CapabilityID, SemanticVersion: "1.0.0", ProtocolVersion: 1,
		DisplayName: "Agent Team", Description: "Owner-scoped bounded Pi Worker plans and execution control",
		Readiness: ready, ReadinessReason: reason,
	}
	for _, spec := range operations {
		inputDigest := sha256.Sum256([]byte(spec.input))
		resultDigest := sha256.Sum256([]byte(spec.result))
		descriptor.Operations = append(descriptor.Operations, &capv1.OperationDescriptor{
			OperationId: spec.id, DisplayName: spec.name, Description: spec.description,
			OperationType: spec.typ, Audience: []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT, capv1.Audience_AUDIENCE_NATIVE_AGENT},
			RiskLevel: spec.risk, RequiredScopes: []string{spec.scope}, InputSchemaJson: spec.input,
			InputSchemaDigest: inputDigest[:], ResultSchemaJson: spec.result, ResultSchemaDigest: resultDigest[:],
			MaxRequestSizeBytes: maxRequestSize, TimeoutClass: "medium",
		})
	}
	return descriptor
}

func (c *Capability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil || !c.service.ReadyForPublication() || len(raw) > maxRequestSize {
		return nil, coreteam.ErrInvalid
	}
	scope, err := scopeFromContext(ctx)
	if err != nil {
		return nil, err
	}
	switch operationID {
	case "plans_get":
		var input idRequest
		if decodeStrict(raw, &input) != nil || !validUUID(input.PlanID) {
			return nil, coreteam.ErrInvalid
		}
		record, err := c.service.GetPlan(ctx, scope, input.PlanID)
		return marshal(map[string]any{"plan": projectPlan(record)}, err)
	case "executions_list":
		var input listRequest
		if decodeStrict(raw, &input) != nil {
			return nil, coreteam.ErrInvalid
		}
		query, err := input.query(scope)
		if err != nil {
			return nil, err
		}
		page, err := c.service.ListExecutions(ctx, query)
		if err != nil {
			return nil, err
		}
		items := make([]publicExecution, 0, len(page.Executions))
		for _, execution := range page.Executions {
			items = append(items, projectExecution(execution))
		}
		return json.Marshal(map[string]any{"executions": items, "next_page_token": page.NextID})
	case "executions_get":
		var input executionIDRequest
		if decodeStrict(raw, &input) != nil || !validUUID(input.ExecutionID) {
			return nil, coreteam.ErrInvalid
		}
		execution, err := c.service.GetExecution(ctx, scope, input.ExecutionID)
		return marshal(map[string]any{"execution": projectExecution(execution)}, err)
	case "executions_cancel":
		var input cancelRequest
		if decodeStrict(raw, &input) != nil || !validUUID(input.ExecutionID) || input.ExpectedRevision == 0 || !validUUID(input.IdempotencyKey) {
			return nil, coreteam.ErrInvalid
		}
		execution, err := c.service.CancelExecution(ctx, coreteam.CancelExecutionRequest{
			Scope: scope, ExecutionID: input.ExecutionID, ExpectedRevision: input.ExpectedRevision, IdempotencyKey: input.IdempotencyKey,
		})
		return marshal(map[string]any{"execution": projectExecution(execution)}, err)
	default:
		return nil, coreteam.ErrInvalid
	}
}

type idRequest struct {
	PlanID string `json:"plan_id"`
}

type executionIDRequest struct {
	ExecutionID string `json:"execution_id"`
}

type listRequest struct {
	PageSize  *uint32                    `json:"page_size"`
	PageToken string                     `json:"page_token"`
	Statuses  []coreteam.ExecutionStatus `json:"statuses"`
}

func (r listRequest) query(scope coreteam.Scope) (coreteam.ListQuery, error) {
	limit := uint32(defaultPageSize)
	if r.PageSize != nil {
		limit = *r.PageSize
	}
	if limit == 0 || limit > coreteam.MaxExecutionPageSize || (r.PageToken != "" && !validUUID(r.PageToken)) {
		return coreteam.ListQuery{}, coreteam.ErrInvalid
	}
	seen := make(map[coreteam.ExecutionStatus]struct{}, len(r.Statuses))
	for _, status := range r.Statuses {
		switch status {
		case coreteam.ExecutionQueued, coreteam.ExecutionRunning, coreteam.ExecutionCleaningUp, coreteam.ExecutionCompleted, coreteam.ExecutionFailed, coreteam.ExecutionCanceled, coreteam.ExecutionTimedOut:
		default:
			return coreteam.ListQuery{}, coreteam.ErrInvalid
		}
		if _, duplicate := seen[status]; duplicate {
			return coreteam.ListQuery{}, coreteam.ErrInvalid
		}
		seen[status] = struct{}{}
	}
	return coreteam.ListQuery{Scope: scope, AfterID: r.PageToken, Limit: limit, Statuses: append([]coreteam.ExecutionStatus(nil), r.Statuses...)}, nil
}

type cancelRequest struct {
	ExecutionID      string `json:"execution_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
	IdempotencyKey   string `json:"idempotency_key"`
}

type publicPlan struct {
	PlanID         string              `json:"plan_id"`
	TaskID         string              `json:"task_id"`
	ConversationID string              `json:"conversation_id"`
	ConfirmationID string              `json:"confirmation_id"`
	Revision       uint64              `json:"revision"`
	Goal           string              `json:"goal"`
	Runtime        publicRuntime       `json:"runtime"`
	Quote          publicQuote         `json:"quote"`
	Roles          []publicRole        `json:"roles"`
	Status         coreteam.PlanStatus `json:"status"`
	CreatedAt      time.Time           `json:"created_at"`
}

type publicRuntime struct {
	RuntimeID    string `json:"runtime_id"`
	OutputTokens uint32 `json:"output_tokens"`
}

type publicQuote struct {
	Region           string    `json:"region"`
	AvailabilityZone string    `json:"availability_zone"`
	InstanceType     string    `json:"instance_type"`
	Currency         string    `json:"currency"`
	Amount           string    `json:"amount"`
	HardBudget       string    `json:"hard_budget"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type publicRole struct {
	RoleID       string                `json:"role_id"`
	Goal         string                `json:"goal"`
	DependsOn    []string              `json:"depends_on"`
	Capabilities []coreteam.Capability `json:"capabilities"`
}

type publicExecution struct {
	ExecutionID     string                   `json:"execution_id"`
	PlanID          string                   `json:"plan_id"`
	TaskID          string                   `json:"task_id"`
	ConfirmationID  string                   `json:"confirmation_id"`
	Status          coreteam.ExecutionStatus `json:"status"`
	Revision        uint64                   `json:"revision"`
	CleanupVerified bool                     `json:"cleanup_verified"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

func projectPlan(record coreteam.PlanRecord) publicPlan {
	plan := record.Plan
	roles := make([]publicRole, 0, len(plan.Roles))
	for _, role := range plan.Roles {
		roles = append(roles, publicRole{
			RoleID: role.RoleID, Goal: role.Goal, DependsOn: append([]string{}, role.DependsOn...),
			Capabilities: append([]coreteam.Capability{}, role.Capabilities...),
		})
	}
	return publicPlan{
		PlanID: plan.PlanID, TaskID: plan.TaskID, ConversationID: plan.ConversationID, ConfirmationID: plan.ConfirmationID,
		Revision: plan.Revision, Goal: plan.Goal,
		Runtime: publicRuntime{RuntimeID: plan.Runtime.RuntimeID, OutputTokens: plan.Runtime.OutputTokens},
		Quote:   publicQuote{Region: plan.Quote.Region, AvailabilityZone: plan.Quote.AvailabilityZone, InstanceType: plan.Quote.InstanceType, Currency: plan.Quote.Currency, Amount: plan.Quote.Amount, HardBudget: plan.Quote.HardBudget, ExpiresAt: plan.Quote.ExpiresAt.UTC()},
		Roles:   roles, Status: plan.Status, CreatedAt: record.CreatedAt.UTC(),
	}
}

func projectExecution(execution coreteam.Execution) publicExecution {
	return publicExecution{
		ExecutionID: execution.ExecutionID, PlanID: execution.PlanID, TaskID: execution.TaskID,
		ConfirmationID: execution.ConfirmationID, Status: execution.Status, Revision: execution.Revision,
		CleanupVerified: !execution.CleanupVerifiedAt.IsZero(), CreatedAt: execution.CreatedAt.UTC(), UpdatedAt: execution.UpdatedAt.UTC(),
	}
}

func scopeFromContext(ctx context.Context) (coreteam.Scope, error) {
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil {
		return coreteam.Scope{}, coreteam.ErrInvalid
	}
	scope := coreteam.Scope{OwnerID: permission.GetAuthenticatedOwnerId(), AccountGeneration: permission.GetAccountGeneration()}
	if scope.Validate() != nil {
		return coreteam.Scope{}, coreteam.ErrInvalid
	}
	return scope, nil
}

func decodeStrict(raw []byte, value any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return coreteam.ErrInvalid
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return coreteam.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return coreteam.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return coreteam.ErrInvalid
	}
	return nil
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed.String() == value
}

func marshal(value any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

const (
	planGetSchema             = `{"additionalProperties":false,"properties":{"plan_id":{"format":"uuid","type":"string"}},"required":["plan_id"],"type":"object"}`
	executionListSchema       = `{"additionalProperties":false,"properties":{"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"format":"uuid","type":"string"},"statuses":{"items":{"enum":["queued","running","cleaning_up","completed","failed","canceled","timed_out"],"type":"string"},"maxItems":7,"uniqueItems":true,"type":"array"}},"type":"object"}`
	executionGetSchema        = `{"additionalProperties":false,"properties":{"execution_id":{"format":"uuid","type":"string"}},"required":["execution_id"],"type":"object"}`
	executionCancelSchema     = `{"additionalProperties":false,"properties":{"execution_id":{"format":"uuid","type":"string"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["execution_id","expected_revision","idempotency_key"],"type":"object"}`
	roleSchema                = `{"additionalProperties":false,"properties":{"capabilities":{"items":{"enum":["repository.read","repository.write","code.review","shell","git","test","web.research","browser","mcp.client","result.structured"],"type":"string"},"type":"array"},"depends_on":{"items":{"type":"string"},"type":"array"},"goal":{"type":"string"},"role_id":{"type":"string"}},"required":["role_id","goal","depends_on","capabilities"],"type":"object"}`
	runtimeSchema             = `{"additionalProperties":false,"properties":{"output_tokens":{"minimum":1,"type":"integer"},"runtime_id":{"type":"string"}},"required":["runtime_id","output_tokens"],"type":"object"}`
	quoteSchema               = `{"additionalProperties":false,"properties":{"amount":{"type":"string"},"availability_zone":{"type":"string"},"currency":{"type":"string"},"expires_at":{"format":"date-time","type":"string"},"hard_budget":{"type":"string"},"instance_type":{"type":"string"},"region":{"type":"string"}},"required":["region","availability_zone","instance_type","currency","amount","hard_budget","expires_at"],"type":"object"}`
	planSchema                = `{"additionalProperties":false,"properties":{"confirmation_id":{"format":"uuid","type":"string"},"conversation_id":{"format":"uuid","type":"string"},"created_at":{"format":"date-time","type":"string"},"goal":{"type":"string"},"plan_id":{"format":"uuid","type":"string"},"quote":` + quoteSchema + `,"revision":{"minimum":1,"type":"integer"},"roles":{"items":` + roleSchema + `,"type":"array"},"runtime":` + runtimeSchema + `,"status":{"enum":["waiting_user","approved","expired"],"type":"string"},"task_id":{"format":"uuid","type":"string"}},"required":["plan_id","task_id","conversation_id","confirmation_id","revision","goal","runtime","quote","roles","status","created_at"],"type":"object"}`
	executionSchema           = `{"additionalProperties":false,"properties":{"cleanup_verified":{"type":"boolean"},"confirmation_id":{"format":"uuid","type":"string"},"created_at":{"format":"date-time","type":"string"},"execution_id":{"format":"uuid","type":"string"},"plan_id":{"format":"uuid","type":"string"},"revision":{"minimum":1,"type":"integer"},"status":{"enum":["queued","running","cleaning_up","completed","failed","canceled","timed_out"],"type":"string"},"task_id":{"format":"uuid","type":"string"},"updated_at":{"format":"date-time","type":"string"}},"required":["execution_id","plan_id","task_id","confirmation_id","status","revision","cleanup_verified","created_at","updated_at"],"type":"object"}`
	planGetResultSchema       = `{"additionalProperties":false,"properties":{"plan":` + planSchema + `},"required":["plan"],"type":"object"}`
	executionGetResultSchema  = `{"additionalProperties":false,"properties":{"execution":` + executionSchema + `},"required":["execution"],"type":"object"}`
	executionListResultSchema = `{"additionalProperties":false,"properties":{"executions":{"items":` + executionSchema + `,"type":"array"},"next_page_token":{"type":"string"}},"required":["executions","next_page_token"],"type":"object"}`
)

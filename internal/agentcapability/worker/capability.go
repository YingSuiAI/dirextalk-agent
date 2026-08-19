// Package worker adapts the persistent SSH Worker provider to the neutral
// owner-facing Capability API. It owns no Worker, workload, DNS, or AWS state.
package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

const (
	CapabilityID    = "agent.worker.v1"
	SemanticVersion = "1.0.0"

	identitySchema = `{"additionalProperties":false,"properties":{"account_id":{"type":"string"},"credential_id":{"type":"string"},"credential_revision":{"minimum":1,"type":"integer"},"instance_id":{"type":"string"},"key_pair_id":{"type":"string"},"region":{"type":"string"},"security_group_id":{"type":"string"},"worker_id":{"type":"string"}},"required":["worker_id","instance_id","key_pair_id","security_group_id","credential_id","credential_revision","account_id","region"],"type":"object"}`
	domainSchema   = `{"additionalProperties":false,"properties":{"hostname":{"type":"string"},"mode":{"const":"route53_same_account","type":"string"},"record_status":{"enum":["pending","current","drifted","error"],"type":"string"},"target_ipv4":{"type":"string"},"ttl":{"type":"integer"},"zone_id":{"type":"string"}},"required":["mode","zone_id","hostname","target_ipv4","ttl","record_status"],"type":"object"}`
	workloadSchema = `{"additionalProperties":false,"properties":{"active_state":{"type":"string"},"domain":` + domainSchema + `,"health":{"type":"string"},"hostname":{"type":"string"},"kind":{"enum":["job","service"],"type":"string"},"phase":{"type":"string"},"port":{"type":"integer"},"workload_id":{"type":"string"}},"required":["workload_id","kind","phase","active_state","health"],"type":"object"}`
	statusSchema   = `{"additionalProperties":false,"properties":{"availability":{"enum":["available","unavailable"],"type":"string"},"created_at":{"format":"date-time","type":"string"},"current_task":{"additionalProperties":false,"properties":{"execution_id":{"type":"string"},"phase":{"type":"string"}},"required":["execution_id","phase"],"type":"object"},"display_name":{"type":"string"},"ec2_state":{"type":"string"},"error":{"type":"string"},"hourly_quote":{"additionalProperties":false,"properties":{"currency":{"type":"string"},"expires_at":{"format":"date-time","type":"string"},"micros_per_hour":{"minimum":0,"type":"integer"},"observed_at":{"format":"date-time","type":"string"}},"required":["currency","micros_per_hour","observed_at","expires_at"],"type":"object"},"identity":` + identitySchema + `,"observed_at":{"format":"date-time","type":"string"},"public_ipv4":{"type":"string"},"server":{"additionalProperties":false,"properties":{"last_seen":{"format":"date-time","type":"string"},"load_1":{"type":"number"},"load_15":{"type":"number"},"load_5":{"type":"number"}},"required":["last_seen","load_1","load_5","load_15"],"type":"object"},"worker_phase":{"type":"string"},"workloads":{"items":` + workloadSchema + `,"type":"array"}},"required":["identity","display_name","created_at","availability","ec2_state","worker_phase","observed_at"],"type":"object"}`

	listInputSchema     = `{"additionalProperties":false,"properties":{},"type":"object"}`
	listResultSchema    = `{"additionalProperties":false,"properties":{"workers":{"items":` + statusSchema + `,"type":"array"}},"required":["workers"],"type":"object"}`
	getInputSchema      = `{"additionalProperties":false,"properties":{"identity":` + identitySchema + `},"required":["identity"],"type":"object"}`
	getResultSchema     = `{"additionalProperties":false,"properties":{"worker":` + statusSchema + `},"required":["worker"],"type":"object"}`
	destroyInputSchema  = `{"additionalProperties":false,"properties":{"confirmation":{"const":"destroy_worker","type":"string"},"identity":` + identitySchema + `},"required":["identity","confirmation"],"type":"object"}`
	destroyResultSchema = `{"additionalProperties":false,"properties":{"destroyed":{"const":true,"type":"boolean"},"identity":` + identitySchema + `},"required":["identity","destroyed"],"type":"object"}`
)

// CredentialSource returns the one current verified AWS credential. The
// implementation owns the exact verification and secret-handling policy.
type CredentialSource interface {
	HasCurrentVerifiedCredential(context.Context) bool
}

// Manager routes retained Workers through their exact credential revision.
type Manager interface {
	HasManagedWorkers(context.Context) bool
	ListWorkers(context.Context, sshworker.OwnerAuthority) ([]sshworker.WorkerStatus, error)
	ObserveWorker(context.Context, sshworker.OwnerAuthority, sshworker.WorkerIdentity) (sshworker.WorkerStatus, error)
	DestroyWorker(context.Context, sshworker.OwnerAuthority, sshworker.DestroyRequest) error
}

type DomainStatus struct {
	Mode         string `json:"mode"`
	ZoneID       string `json:"zone_id"`
	Hostname     string `json:"hostname"`
	TargetIPv4   string `json:"target_ipv4"`
	TTL          uint32 `json:"ttl"`
	RecordStatus string `json:"record_status"`
}

type WorkloadStatus struct {
	WorkloadID  string        `json:"workload_id"`
	Kind        string        `json:"kind"`
	Phase       string        `json:"phase"`
	ActiveState string        `json:"active_state"`
	Health      string        `json:"health"`
	Port        uint16        `json:"port,omitempty"`
	Hostname    string        `json:"hostname,omitempty"`
	Domain      *DomainStatus `json:"domain,omitempty"`
}

// WorkloadSource is an optional live projection for workload/service status.
type WorkloadSource interface {
	ListWorkerWorkloads(context.Context, sshworker.WorkerStatus) ([]WorkloadStatus, error)
}

type Bindings struct {
	Credentials CredentialSource
	Workers     Manager
	Workloads   WorkloadSource
}

type Capability struct{ bindings Bindings }

func NewCapability(bindings Bindings) (*Capability, error) {
	if bindings.Credentials == nil || bindings.Workers == nil {
		return nil, errors.New("worker capability dependencies are incomplete")
	}
	return &Capability{bindings: bindings}, nil
}

func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	ready := c != nil && c.bindings.Credentials != nil && c.bindings.Workers != nil
	reason := ""
	if ready && !c.bindings.Credentials.HasCurrentVerifiedCredential(context.Background()) && !c.bindings.Workers.HasManagedWorkers(context.Background()) {
		ready = false
		reason = "a verified AWS credential or retained Worker is required"
	}
	descriptor := &capv1.CapabilityDescriptor{CapabilityId: CapabilityID, SemanticVersion: SemanticVersion, ProtocolVersion: 1, DisplayName: "Workers", Description: "Persistent SSH Worker management", Readiness: ready, ReadinessReason: reason}
	specs := []operationSpec{
		{"list_workers", "List Workers", capv1.OperationType_OPERATION_TYPE_READ, capv1.RiskLevel_RISK_LEVEL_SAFE, "agent:worker:read", listInputSchema, listResultSchema},
		{"get_worker", "Get Worker", capv1.OperationType_OPERATION_TYPE_READ, capv1.RiskLevel_RISK_LEVEL_SAFE, "agent:worker:read", getInputSchema, getResultSchema},
		{"destroy_worker", "Destroy Worker", capv1.OperationType_OPERATION_TYPE_MUTATION, capv1.RiskLevel_RISK_LEVEL_HIGH, "agent:worker:destroy", destroyInputSchema, destroyResultSchema},
	}
	for _, spec := range specs {
		inputDigest, resultDigest := sha256.Sum256([]byte(spec.input)), sha256.Sum256([]byte(spec.result))
		descriptor.Operations = append(descriptor.Operations, &capv1.OperationDescriptor{OperationId: spec.id, DisplayName: spec.name, OperationType: spec.typ, Audience: []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT}, RiskLevel: spec.risk, RequiredScopes: []string{spec.scope}, InputSchemaJson: spec.input, InputSchemaDigest: inputDigest[:], ResultSchemaJson: spec.result, ResultSchemaDigest: resultDigest[:], MaxRequestSizeBytes: 16 << 10, TimeoutClass: "long"})
	}
	return descriptor
}

type operationSpec struct {
	id, name string
	typ      capv1.OperationType
	risk     capv1.RiskLevel
	scope    string
	input    string
	result   string
}

func (c *Capability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.bindings.Credentials == nil || c.bindings.Workers == nil {
		return nil, capabilityoperation.NewFailure("PRECONDITION_FAILED", "Worker management is not ready", errors.New("worker capability dependencies are incomplete"))
	}
	authority, err := ownerAuthority(ctx)
	if err != nil {
		return nil, err
	}
	switch operationID {
	case "list_workers":
		var request struct{}
		if err := decodeStrict(raw, &request); err != nil {
			return nil, invalid(err)
		}
		statuses, err := c.bindings.Workers.ListWorkers(ctx, authority)
		if err != nil {
			return nil, managerFailure(err)
		}
		workers := make([]map[string]any, 0, len(statuses))
		for _, status := range statuses {
			worker, err := c.projectStatus(ctx, status)
			if err != nil {
				return nil, err
			}
			workers = append(workers, worker)
		}
		return json.Marshal(map[string]any{"workers": workers})
	case "get_worker":
		var request identityRequest
		if err := decodeStrict(raw, &request); err != nil {
			return nil, invalid(err)
		}
		identity, err := request.Identity.workerIdentity()
		if err != nil {
			return nil, managerFailure(err)
		}
		identity.OwnerID, identity.AccountGeneration = authority.OwnerID, authority.AccountGeneration
		status, err := c.bindings.Workers.ObserveWorker(ctx, authority, identity)
		if err != nil {
			return nil, managerFailure(err)
		}
		worker, err := c.projectStatus(ctx, status)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"worker": worker})
	case "destroy_worker":
		var request destroyRequest
		if err := decodeStrict(raw, &request); err != nil || request.Confirmation != "destroy_worker" {
			return nil, invalid(errors.Join(err, errors.New("explicit destroy authorization is required")))
		}
		identity, err := request.Identity.workerIdentity()
		if err != nil {
			return nil, managerFailure(err)
		}
		identity.OwnerID, identity.AccountGeneration = authority.OwnerID, authority.AccountGeneration
		authorization := sshworker.DestroyAuthorization{Authorized: true, Proof: "capability:destroy_worker"}
		if err := c.bindings.Workers.DestroyWorker(ctx, authority, sshworker.DestroyRequest{Identity: identity, Authorization: authorization}); err != nil {
			return nil, managerFailure(err)
		}
		return json.Marshal(map[string]any{"identity": projectIdentity(identity), "destroyed": true})
	default:
		return nil, invalid(errors.New("unknown worker operation"))
	}
}

type identityRequest struct {
	Identity identityInput `json:"identity"`
}
type destroyRequest struct {
	Identity     identityInput `json:"identity"`
	Confirmation string        `json:"confirmation"`
}
type identityInput struct {
	WorkerID           string `json:"worker_id"`
	InstanceID         string `json:"instance_id"`
	KeyPairID          string `json:"key_pair_id"`
	SecurityGroupID    string `json:"security_group_id"`
	CredentialID       string `json:"credential_id"`
	CredentialRevision uint64 `json:"credential_revision"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
}

func (input identityInput) workerIdentity() (sshworker.WorkerIdentity, error) {
	credential := sshworker.CredentialIdentity{CredentialID: input.CredentialID, CredentialRevision: input.CredentialRevision, AccountID: input.AccountID, Region: input.Region}
	if strings.TrimSpace(input.WorkerID) == "" || strings.TrimSpace(credential.CredentialID) == "" || credential.CredentialRevision == 0 ||
		!validAccountID(credential.AccountID) || strings.TrimSpace(credential.Region) == "" {
		return sshworker.WorkerIdentity{}, sshworker.ErrIdentity
	}
	return sshworker.WorkerIdentity{WorkerID: input.WorkerID, InstanceID: input.InstanceID, KeyPairID: input.KeyPairID, SecurityGroupID: input.SecurityGroupID, Credential: credential}, nil
}

func validAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func (c *Capability) projectStatus(ctx context.Context, status sshworker.WorkerStatus) (map[string]any, error) {
	name := strings.TrimSpace(status.DisplayName)
	if name == "" {
		name = status.PublicIP
	}
	if name == "" {
		name = "Worker " + shortWorkerID(status.Identity.WorkerID)
	}
	createdAt := status.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = status.ObservedAt.UTC()
	}
	value := map[string]any{"identity": projectIdentity(status.Identity), "display_name": name, "created_at": createdAt, "availability": status.Availability, "ec2_state": status.EC2State, "worker_phase": status.WorkerPhase, "observed_at": status.ObservedAt.UTC()}
	if status.Error != "" {
		value["error"] = status.Error
	}
	if status.PublicIP != "" {
		value["public_ipv4"] = status.PublicIP
	}
	if status.CurrentExecutionID != "" {
		value["current_task"] = map[string]any{"execution_id": status.CurrentExecutionID, "phase": status.TaskPhase}
	}
	if !status.Runner.LastSeen.IsZero() {
		value["server"] = map[string]any{"last_seen": status.Runner.LastSeen.UTC(), "load_1": status.Runner.Load1, "load_5": status.Runner.Load5, "load_15": status.Runner.Load15}
	}
	if status.Quote.Currency != "" && !status.Quote.ExpiresAt.IsZero() {
		value["hourly_quote"] = map[string]any{"currency": status.Quote.Currency, "micros_per_hour": status.Quote.MicrosPerHour, "observed_at": status.Quote.ObservedAt.UTC(), "expires_at": status.Quote.ExpiresAt.UTC()}
	}
	if c.bindings.Workloads != nil && status.Availability == sshworker.WorkerAvailable {
		workloads, err := c.bindings.Workloads.ListWorkerWorkloads(ctx, status)
		if err != nil {
			return nil, capabilityoperation.NewFailure("UNAVAILABLE", "Worker workload status is unavailable", err)
		}
		if workloads == nil {
			workloads = make([]WorkloadStatus, 0)
		}
		value["workloads"] = workloads
	}
	return value, nil
}

func shortWorkerID(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}

func projectIdentity(identity sshworker.WorkerIdentity) map[string]any {
	return map[string]any{"worker_id": identity.WorkerID, "instance_id": identity.InstanceID, "key_pair_id": identity.KeyPairID, "security_group_id": identity.SecurityGroupID, "credential_id": identity.Credential.CredentialID, "credential_revision": identity.Credential.CredentialRevision, "account_id": identity.Credential.AccountID, "region": identity.Credential.Region}
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("request JSON is required")
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return errors.New("request must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func ownerAuthority(ctx context.Context) (sshworker.OwnerAuthority, error) {
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
		return sshworker.OwnerAuthority{}, capabilityoperation.NewFailure("PERMISSION_DENIED", "Authenticated owner context is required", errors.New("owner permission context is missing"))
	}
	return sshworker.OwnerAuthority{OwnerID: permission.GetAuthenticatedOwnerId(), AccountGeneration: uint64(permission.GetAccountGeneration())}, nil
}

func invalid(err error) error {
	return capabilityoperation.NewFailure("INVALID_ARGUMENT", "Worker request is invalid", err)
}

func managerFailure(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, sshworker.ErrInvalid):
		return invalid(err)
	case errors.Is(err, sshworker.ErrNotAuthorized):
		return capabilityoperation.NewFailure("PERMISSION_DENIED", "Worker mutation is not authorized", err)
	case errors.Is(err, sshworker.ErrIdentity):
		return capabilityoperation.NewFailure("NOT_FOUND", "Exact Worker identity was not found", err)
	case errors.Is(err, sshworker.ErrBusy):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Worker is running a task", err)
	default:
		return capabilityoperation.NewFailure("UNAVAILABLE", "Worker provider is unavailable", err)
	}
}

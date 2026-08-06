// Package coreexecutionv2 owns the execution-plan/v2 domain that used to live
// in Message Server.  The package is deliberately transport independent: the
// Neutral Capability adapter and the Core gRPC adapter both call Service.
//
// A single Agent instance owns one execution history.  The owner is supplied
// by the authenticated capability context and is never accepted from the
// business request body.
package coreexecutionv2

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

const (
	CapabilityID    = "agent.execution.v2"
	SemanticVersion = "2.0.0"
	SchemaVersion   = "execution-plan/v2"
)

var (
	ErrInvalid          = errors.New("execution.v2: invalid request")
	ErrNotFound         = errors.New("execution.v2: record not found")
	ErrConflict         = errors.New("execution.v2: revision or idempotency conflict")
	ErrNotReady         = errors.New("execution.v2: capability is not ready")
	ErrUnsafeOutput     = errors.New("execution.v2: unsafe provider output")
	ErrSecretNotFound   = errors.New("execution.v2: secret not found")
	ErrUnsupported      = errors.New("execution.v2: unsupported action")
	ErrMissingPort      = errors.New("execution.v2: provider port is not configured")
	ErrReplayInProgress = errors.New("execution.v2: idempotent request is in progress")
)

// Record is a durable owner-scoped immutable snapshot.  A new revision is a
// new snapshot; callers never mutate a previously returned map in place.
type Record struct {
	OwnerID           string         `json:"owner_id"`
	AccountGeneration int64          `json:"account_generation"`
	Kind              string         `json:"kind"`
	ID                string         `json:"id"`
	Revision          uint64         `json:"revision"`
	Status            string         `json:"status"`
	Digest            string         `json:"digest"`
	Payload           map[string]any `json:"payload"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	MutationAction    string         `json:"-"`
	MutationKey       string         `json:"-"`
	MutationDigest    []byte         `json:"-"`
}

type Event struct {
	OwnerID           string         `json:"owner_id"`
	AccountGeneration int64          `json:"account_generation"`
	Kind              string         `json:"kind"`
	ResourceID        string         `json:"resource_id"`
	Sequence          uint64         `json:"sequence"`
	EventID           string         `json:"event_id"`
	Type              string         `json:"type"`
	Payload           map[string]any `json:"payload"`
	CreatedAt         time.Time      `json:"created_at"`
}

type ReplayClaim struct {
	Token            string
	Response         []byte
	ProviderResponse []byte
	Completed        bool
	Dispatched       bool
}

// Store is the only persistence dependency of the domain.  The repository
// includes a PostgreSQL implementation and a deterministic in-memory
// implementation for boundary tests.
type Store interface {
	Read(context.Context, coretask.OwnerScope, string, string, uint64) (Record, error)
	List(context.Context, coretask.OwnerScope, string, map[string]string, string, int) ([]Record, string, error)
	Create(context.Context, Record) (Record, error)
	Update(context.Context, Record, uint64) (Record, error)
	BeginReplay(context.Context, coretask.OwnerScope, string, string, []byte, time.Time, time.Duration) (ReplayClaim, error)
	MarkReplayDispatched(context.Context, coretask.OwnerScope, string, string, []byte, string, time.Time) error
	StoreReplayProviderResponse(context.Context, coretask.OwnerScope, string, string, []byte, string, []byte, time.Time) error
	CompleteReplay(context.Context, coretask.OwnerScope, string, string, []byte, string, []byte, time.Time) error
	AbortReplay(context.Context, coretask.OwnerScope, string, string, []byte, string) error
	AppendEvent(context.Context, Event) (Event, error)
	Events(context.Context, coretask.OwnerScope, string, string, uint64, int) ([]Event, uint64, error)
	SaveSecret(context.Context, Secret) (Secret, error)
	ReadSecret(context.Context, coretask.OwnerScope, string, uint64) (Secret, error)
	ListSecrets(context.Context, coretask.OwnerScope, string, int) ([]Secret, string, error)
	RevokeSecret(context.Context, Secret, uint64) (Secret, error)
}

type Secret struct {
	OwnerID           string    `json:"owner_id"`
	AccountGeneration int64     `json:"account_generation"`
	Ref               string    `json:"secret_ref"`
	Revision          uint64    `json:"revision"`
	Provider          string    `json:"provider"`
	Purpose           string    `json:"purpose"`
	Value             string    `json:"-"`
	BindingDigest     string    `json:"binding_digest"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	MutationAction    string    `json:"-"`
	MutationKey       string    `json:"-"`
	MutationDigest    []byte    `json:"-"`
}

type Providers struct {
	Analyze       func(context.Context, coretask.OwnerScope, map[string]any) (map[string]any, error)
	ImportTarget  func(context.Context, coretask.OwnerScope, map[string]any) (map[string]any, error)
	ReserveTarget func(context.Context, coretask.OwnerScope, map[string]any) (map[string]any, error)
	Observe       func(context.Context, coretask.OwnerScope, map[string]any) (map[string]any, error)
	Invoke        func(context.Context, coretask.OwnerScope, map[string]any) (map[string]any, error)
	Reconcile     func(context.Context, coretask.OwnerScope, map[string]any) (map[string]any, error)
}

// Source is the immutable source pin supplied to an analyzer.  Keeping this
// type separate from map[string]any makes the provider boundary explicit: a
// provider receives validated, owner-scoped fields and never a caller-owned
// JSON object that it could interpret as an arbitrary AWS/SSM request.
type Source struct {
	Kind               string
	Location           string
	Commit             string
	ArtifactID         string
	CredentialRef      string
	CredentialRevision uint64
	Immutable          bool
}

type AnalyzeRequest struct {
	ProjectID      string
	Source         Source
	IdempotencyKey string
}

type TargetImportRequest struct {
	CredentialID       string
	CredentialRevision uint64
	InstanceID         string
	IdempotencyKey     string
}

type TargetReserveRequest struct {
	CredentialID       string
	CredentialRevision uint64
	InstanceType       string
	VolumeGiB          uint64
	IdempotencyKey     string
}

type TargetObserveRequest struct {
	TargetID       string
	TargetRevision uint64
	IdempotencyKey string
}

type ReconcileRequest struct {
	RunID            string
	StageID          string
	ExpectedRevision uint64
	IdempotencyKey   string
}

type InvokeRequest struct {
	BindingID        string
	Operation        string
	ExpectedRevision uint64
	IdempotencyKey   string
	Input            map[string]any
}

// TypedPorts are the only provider extension points used by execution.v2.
// The functions intentionally use request structs above rather than accepting
// an arbitrary action name, URL, SDK request, shell command, or credential.
// Composition code can adapt the existing Core Workload/AWS SSM/ECS services
// to these ports after it has proved the corresponding readiness gate.
type TypedPorts struct {
	Analyze       func(context.Context, coretask.OwnerScope, AnalyzeRequest) (map[string]any, error)
	ImportTarget  func(context.Context, coretask.OwnerScope, TargetImportRequest) (map[string]any, error)
	ReserveTarget func(context.Context, coretask.OwnerScope, TargetReserveRequest) (map[string]any, error)
	Observe       func(context.Context, coretask.OwnerScope, TargetObserveRequest) (map[string]any, error)
	Invoke        func(context.Context, coretask.OwnerScope, InvokeRequest) (map[string]any, error)
	Reconcile     func(context.Context, coretask.OwnerScope, ReconcileRequest) (map[string]any, error)
	// Ready is a composition proof, not a liveness hint. It should only return
	// true after the exact configured provider route has passed its typed
	// startup probe (for example the existing Workload AWS SSM/ECS Probe).
	Ready func() bool
}

// The interface form is convenient for existing Core providers (Workload
// AWS SSM/ECS and Cloud Control adapters) that already expose methods rather
// than callbacks. Each interface is intentionally one operation wide so a
// deployment can prove and bind only the route it actually configured.
type AnalyzeProvider interface {
	Analyze(context.Context, coretask.OwnerScope, AnalyzeRequest) (map[string]any, error)
}
type TargetImportProvider interface {
	ImportTarget(context.Context, coretask.OwnerScope, TargetImportRequest) (map[string]any, error)
}
type TargetReserveProvider interface {
	ReserveTarget(context.Context, coretask.OwnerScope, TargetReserveRequest) (map[string]any, error)
}
type TargetObserveProvider interface {
	Observe(context.Context, coretask.OwnerScope, TargetObserveRequest) (map[string]any, error)
}
type BindingInvokeProvider interface {
	Invoke(context.Context, coretask.OwnerScope, InvokeRequest) (map[string]any, error)
}
type RunReconcileProvider interface {
	Reconcile(context.Context, coretask.OwnerScope, ReconcileRequest) (map[string]any, error)
}

type ProviderInterfaces struct {
	Analyze       AnalyzeProvider
	ImportTarget  TargetImportProvider
	ReserveTarget TargetReserveProvider
	Observe       TargetObserveProvider
	Invoke        BindingInvokeProvider
	Reconcile     RunReconcileProvider
	Ready         func() bool
}

func AdaptProviderInterfaces(in ProviderInterfaces) TypedPorts {
	var out TypedPorts
	if in.Analyze != nil {
		out.Analyze = func(ctx context.Context, scope coretask.OwnerScope, req AnalyzeRequest) (map[string]any, error) {
			if in.Analyze == nil {
				return nil, ErrMissingPort
			}
			return in.Analyze.Analyze(ctx, scope, req)
		}
	}
	if in.ImportTarget != nil {
		out.ImportTarget = func(ctx context.Context, scope coretask.OwnerScope, req TargetImportRequest) (map[string]any, error) {
			if in.ImportTarget == nil {
				return nil, ErrMissingPort
			}
			return in.ImportTarget.ImportTarget(ctx, scope, req)
		}
	}
	if in.ReserveTarget != nil {
		out.ReserveTarget = func(ctx context.Context, scope coretask.OwnerScope, req TargetReserveRequest) (map[string]any, error) {
			if in.ReserveTarget == nil {
				return nil, ErrMissingPort
			}
			return in.ReserveTarget.ReserveTarget(ctx, scope, req)
		}
	}
	if in.Observe != nil {
		out.Observe = func(ctx context.Context, scope coretask.OwnerScope, req TargetObserveRequest) (map[string]any, error) {
			if in.Observe == nil {
				return nil, ErrMissingPort
			}
			return in.Observe.Observe(ctx, scope, req)
		}
	}
	if in.Invoke != nil {
		out.Invoke = func(ctx context.Context, scope coretask.OwnerScope, req InvokeRequest) (map[string]any, error) {
			if in.Invoke == nil {
				return nil, ErrMissingPort
			}
			return in.Invoke.Invoke(ctx, scope, req)
		}
	}
	if in.Reconcile != nil {
		out.Reconcile = func(ctx context.Context, scope coretask.OwnerScope, req ReconcileRequest) (map[string]any, error) {
			if in.Reconcile == nil {
				return nil, ErrMissingPort
			}
			return in.Reconcile.Reconcile(ctx, scope, req)
		}
	}
	out.Ready = in.Ready
	return out
}

// AdaptTypedPorts converts the typed provider boundary to the internal
// callback representation. It is intentionally small and lossless; all
// validation remains in Service before these callbacks are reached.
func AdaptTypedPorts(ports TypedPorts) Providers {
	var out Providers
	if ports.Analyze != nil {
		out.Analyze = func(ctx context.Context, scope coretask.OwnerScope, in map[string]any) (map[string]any, error) {
			if ports.Analyze == nil {
				return nil, ErrMissingPort
			}
			return ports.Analyze(ctx, scope, AnalyzeRequest{
				ProjectID: stringParam(in, "project_id"), Source: sourceFromInput(in["source"]), IdempotencyKey: stringParam(in, "idempotency_key"),
			})
		}
	}
	if ports.ImportTarget != nil {
		out.ImportTarget = func(ctx context.Context, scope coretask.OwnerScope, in map[string]any) (map[string]any, error) {
			if ports.ImportTarget == nil {
				return nil, ErrMissingPort
			}
			return ports.ImportTarget(ctx, scope, TargetImportRequest{
				CredentialID: stringParam(in, "credential_id"), CredentialRevision: uintParam(in, "credential_revision"), InstanceID: stringParam(in, "instance_id"), IdempotencyKey: stringParam(in, "idempotency_key"),
			})
		}
	}
	if ports.ReserveTarget != nil {
		out.ReserveTarget = func(ctx context.Context, scope coretask.OwnerScope, in map[string]any) (map[string]any, error) {
			if ports.ReserveTarget == nil {
				return nil, ErrMissingPort
			}
			return ports.ReserveTarget(ctx, scope, TargetReserveRequest{
				CredentialID: stringParam(in, "credential_id"), CredentialRevision: uintParam(in, "credential_revision"), InstanceType: stringParam(in, "instance_type"), VolumeGiB: uintParam(in, "volume_gib"), IdempotencyKey: stringParam(in, "idempotency_key"),
			})
		}
	}
	if ports.Observe != nil {
		out.Observe = func(ctx context.Context, scope coretask.OwnerScope, in map[string]any) (map[string]any, error) {
			if ports.Observe == nil {
				return nil, ErrMissingPort
			}
			return ports.Observe(ctx, scope, TargetObserveRequest{
				TargetID: stringParam(in, "target_id"), TargetRevision: uintParam(in, "target_revision"), IdempotencyKey: stringParam(in, "idempotency_key"),
			})
		}
	}
	if ports.Invoke != nil {
		out.Invoke = func(ctx context.Context, scope coretask.OwnerScope, in map[string]any) (map[string]any, error) {
			if ports.Invoke == nil {
				return nil, ErrMissingPort
			}
			return ports.Invoke(ctx, scope, InvokeRequest{
				BindingID: stringParam(in, "binding_id"), Operation: stringParam(in, "operation"), ExpectedRevision: uintParam(in, "expected_revision"), IdempotencyKey: stringParam(in, "idempotency_key"), Input: cloneMap(in["input"].(map[string]any)),
			})
		}
	}
	if ports.Reconcile != nil {
		out.Reconcile = func(ctx context.Context, scope coretask.OwnerScope, in map[string]any) (map[string]any, error) {
			if ports.Reconcile == nil {
				return nil, ErrMissingPort
			}
			return ports.Reconcile(ctx, scope, ReconcileRequest{
				RunID: stringParam(in, "run_id"), StageID: stringParam(in, "stage_id"), ExpectedRevision: uintParam(in, "expected_revision"), IdempotencyKey: stringParam(in, "idempotency_key"),
			})
		}
	}
	return out
}

func sourceFromInput(raw any) Source {
	in, _ := raw.(map[string]any)
	return Source{Kind: stringParam(in, "kind"), Location: stringParam(in, "location"), Commit: stringParam(in, "commit"), ArtifactID: stringParam(in, "artifact_id"), CredentialRef: stringParam(in, "credential_ref"), CredentialRevision: uintParam(in, "credential_revision"), Immutable: boolValue(in, "immutable")}
}

type Config struct {
	Store     Store
	Providers Providers
	Typed     TypedPorts
	Ready     func() bool
	Now       func() time.Time
}

// ActionPort is useful to composition code that wants to expose execution.v2
// without importing the concrete service implementation.
type ActionPort interface {
	Handle(context.Context, coretask.OwnerScope, string, map[string]any) (map[string]any, error)
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil || out == nil {
		return map[string]any{}
	}
	return out
}

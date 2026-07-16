// Package healthprobe runs independent, control-plane-side health probes for
// one approved deployment. It exposes no header, body, shell, credential, or
// arbitrary transport configuration surface.
package healthprobe

import (
	"context"
	"errors"
	"time"
)

const (
	SchemaV1      = "dirextalk.agent.external-health-probe/v1"
	SuiteSchemaV1 = "dirextalk.agent.external-health-suite/v1"
	EvidenceV1    = "dirextalk.agent.external-health-evidence/v1"
)

var (
	ErrInvalidSpec      = errors.New("invalid external health probe specification")
	ErrInvalidTransport = errors.New("invalid external health probe transport")
)

type Purpose string

const (
	PurposeLiveness  Purpose = "liveness"
	PurposeReadiness Purpose = "readiness"
	PurposeSemantic  Purpose = "semantic"
)

type Protocol string

const (
	ProtocolHTTPS Protocol = "https"
	ProtocolTCP   Protocol = "tcp"
)

type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusCanceled  Status = "canceled"
)

type AggregateStatus string

const (
	AggregateHealthy   AggregateStatus = "healthy"
	AggregateDegraded  AggregateStatus = "degraded"
	AggregateUnhealthy AggregateStatus = "unhealthy"
	AggregateCanceled  AggregateStatus = "canceled"
)

type FailureCode string

const (
	FailureNone             FailureCode = ""
	FailureCanceled         FailureCode = "canceled"
	FailureTimeout          FailureCode = "timeout"
	FailureTargetRejected   FailureCode = "target_rejected"
	FailureResolve          FailureCode = "resolve_failed"
	FailureConnect          FailureCode = "connect_failed"
	FailureTLS              FailureCode = "tls_failed"
	FailureHTTPStatus       FailureCode = "http_status_unhealthy"
	FailureResponseTooLarge FailureCode = "response_too_large"
	FailureSemanticMismatch FailureCode = "semantic_mismatch"
	FailureTransport        FailureCode = "transport_failed"
)

// BindingV1 is repeated in every evidence item. ProbeDigest is computed over
// this deployment/plan/Recipe binding and every executable probe field.
type BindingV1 struct {
	DeploymentID string `json:"deployment_id"`
	PlanHash     string `json:"plan_hash"`
	RecipeDigest string `json:"recipe_digest"`
	ProbeDigest  string `json:"probe_digest"`
}

// SpecV1 deliberately has no method, headers, request body, credentials,
// redirects, TLS override, proxy, shell, or generic options map.
type SpecV1 struct {
	SchemaVersion         string    `json:"schema_version"`
	Binding               BindingV1 `json:"binding"`
	Purpose               Purpose   `json:"purpose"`
	Protocol              Protocol  `json:"protocol"`
	Target                string    `json:"target"`
	TimeoutMillis         uint32    `json:"timeout_millis"`
	MaxAttempts           uint32    `json:"max_attempts"`
	RetryDelayMillis      uint32    `json:"retry_delay_millis"`
	ExpectedSummaryDigest string    `json:"expected_summary_digest,omitempty"`
}

type SuiteV1 struct {
	SchemaVersion string   `json:"schema_version"`
	Probes        []SpecV1 `json:"probes"`
}

// Request is the only transport input. A production transport always emits a
// credential-free HTTPS GET with no caller headers/body, or a TCP connect with
// no bytes written.
type Request struct {
	Protocol Protocol
	Target   string
	Timeout  time.Duration
}

// Observation contains no response bytes or remote error string. HTTP bodies
// are bounded and represented only by SummaryDigest.
type Observation struct {
	StatusCode    int
	SummaryDigest string
	Latency       time.Duration
}

type Transport interface {
	Probe(context.Context, Request) (Observation, error)
}

type AttemptEvidence struct {
	Attempt       uint32      `json:"attempt"`
	Status        Status      `json:"status"`
	FailureCode   FailureCode `json:"failure_code,omitempty"`
	StatusCode    int         `json:"status_code,omitempty"`
	SummaryDigest string      `json:"summary_digest,omitempty"`
	LatencyMillis int64       `json:"latency_millis"`
	ObservedAt    time.Time   `json:"observed_at"`
}

type ProbeEvidence struct {
	SchemaVersion string            `json:"schema_version"`
	Binding       BindingV1         `json:"binding"`
	Purpose       Purpose           `json:"purpose"`
	Protocol      Protocol          `json:"protocol"`
	Target        string            `json:"target"`
	Status        Status            `json:"status"`
	Healthy       bool              `json:"healthy"`
	Attempts      []AttemptEvidence `json:"attempts"`
	ObservedAt    time.Time         `json:"observed_at"`
}

type SuiteEvidence struct {
	SchemaVersion string          `json:"schema_version"`
	DeploymentID  string          `json:"deployment_id"`
	PlanHash      string          `json:"plan_hash"`
	RecipeDigest  string          `json:"recipe_digest"`
	Status        AggregateStatus `json:"status"`
	Healthy       bool            `json:"healthy"`
	Probes        []ProbeEvidence `json:"probes"`
	ObservedAt    time.Time       `json:"observed_at"`
}

// TransportError exposes only a stable de-sensitive code. Cause is retained
// for errors.Is/cancellation decisions but its text is never copied to evidence.
type TransportError struct {
	Code  FailureCode
	Cause error
}

func (err *TransportError) Error() string { return string(err.Code) }
func (err *TransportError) Unwrap() error { return err.Cause }

type clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

// Package entrypoint defines the device-approved public-entry contract.
//
// It is intentionally a pure domain package. It neither discovers provider
// state nor creates a load balancer: callers must obtain the independent AWS
// read-backs represented here before an entry plan can be signed. In
// particular, a Worker URL, Worker log, EIP, or VPC endpoint is never a valid
// public-health target source.
package entrypoint

import (
	"errors"
	"time"
)

const (
	// ScopeSchemaV1 names the immutable, device-visible entry scope.
	ScopeSchemaV1 = "dirextalk.agent.cloud.entrypoint.scope/v1"
	// PlanSchemaV1 names a separately approved entry plan. It is deliberately
	// distinct from the original Worker deployment plan.
	PlanSchemaV1 = "dirextalk.agent.cloud.entrypoint.plan/v1"
	// PlanHashSchemaV1 identifies the canonical projection used for PlanHash.
	PlanHashSchemaV1 = "dirextalk.agent.cloud.entrypoint.plan-hash/v1"
	// SigningPayloadV1 identifies the canonical challenge payload signed by a
	// registered user device.
	SigningPayloadV1 = "dirextalk.agent.cloud.entrypoint.approval/v1"

	ChallengeValidity = 5 * time.Minute
	HTTPSPort         = uint32(443)
)

var (
	ErrInvalid             = errors.New("invalid cloud entrypoint request")
	ErrNotFound            = errors.New("cloud entrypoint operation not found")
	ErrRevisionConflict    = errors.New("cloud entrypoint revision conflict")
	ErrIdempotencyConflict = errors.New("cloud entrypoint idempotency conflict")
	ErrApprovalRequired    = errors.New("valid cloud entrypoint device approval is required")
	ErrApprovalExpired     = errors.New("cloud entrypoint approval is expired")
	ErrWorkerNotReady      = errors.New("successful independently read-back worker is required")
	ErrReadBackRequired    = errors.New("independent AWS read-back is required")
	ErrUnsupportedEntry    = errors.New("unsupported cloud entrypoint")
	ErrUnavailable         = errors.New("cloud entrypoint persistence is unavailable")
)

type EntryKind string

const (
	// EntryKindALB is the only first-release public entry. It terminates TLS at
	// a public Application Load Balancer and forwards only to the approved
	// Worker private target port.
	EntryKindALB EntryKind = "alb"
)

type PlanStatus string

const (
	PlanDraft            PlanStatus = "draft"
	PlanReadyForApproval PlanStatus = "ready_for_approval"
	PlanApproved         PlanStatus = "approved"
	PlanExpired          PlanStatus = "expired"
	PlanSuperseded       PlanStatus = "superseded"
)

type Status string

const (
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusApproved         Status = "approved"
	StatusProvisioning     Status = "provisioning"
	StatusVerifying        Status = "verifying"
	StatusActive           Status = "active"
	StatusFailed           Status = "failed"
	StatusDestroying       Status = "destroying"
	StatusDestroyed        Status = "destroyed"
	StatusDestroyBlocked   Status = "destroy_blocked"
)

type ErrorCode string

const (
	ErrorCodeNone               ErrorCode = ""
	ErrorCodeWorkerNotReady     ErrorCode = "worker_not_ready"
	ErrorCodeReadBackMismatch   ErrorCode = "read_back_mismatch"
	ErrorCodeCertificateInvalid ErrorCode = "certificate_invalid"
	ErrorCodeQuoteExpired       ErrorCode = "quote_expired"
	ErrorCodeProvisioningFailed ErrorCode = "provisioning_failed"
	ErrorCodeVerificationFailed ErrorCode = "verification_failed"
	ErrorCodeDestroyBlocked     ErrorCode = "destroy_blocked"
)

type WorkerOutcome string

const (
	WorkerOutcomeSucceeded WorkerOutcome = "succeeded"
	WorkerOutcomeFailed    WorkerOutcome = "failed"
	WorkerOutcomeCanceled  WorkerOutcome = "canceled"
	WorkerOutcomeTimedOut  WorkerOutcome = "timed_out"
)

type EC2InstanceState string

const (
	EC2InstanceRunning EC2InstanceState = "running"
)

type CertificateStatus string

const (
	CertificateStatusIssued            CertificateStatus = "ISSUED"
	CertificateStatusPendingValidation CertificateStatus = "PENDING_VALIDATION"
)

type ALBScheme string

const (
	ALBSchemeInternetFacing ALBScheme = "internet-facing"
)

type ListenerProtocol string

const (
	ListenerProtocolHTTPS ListenerProtocol = "HTTPS"
)

// TLSPolicyTLS13_2021_06 is deliberately explicit in every device approval.
// A later compatibility change requires a new scope/approval, not a provider
// default silently changing beneath an existing public endpoint.
const TLSPolicyTLS13_2021_06 = "ELBSecurityPolicy-TLS13-1-2-2021-06"

type TargetProtocol string

const (
	TargetProtocolHTTP  TargetProtocol = "HTTP"
	TargetProtocolHTTPS TargetProtocol = "HTTPS"
)

type TargetSource string

const (
	// TargetSourceApprovedWorkerReadBack is the sole accepted source. Its
	// concrete EC2 identity and read-back evidence are signed in Worker.
	TargetSourceApprovedWorkerReadBack TargetSource = "approved_worker_read_back"
	// The following values exist solely so callers cannot accidentally turn an
	// unsafe derivation into a future accepted default. Validation rejects all
	// of them; no provider implementation may treat them as aliases.
	TargetSourceEIP         TargetSource = "eip"
	TargetSourceVPCEndpoint TargetSource = "vpc_endpoint"
	TargetSourceWorkerURL   TargetSource = "worker_url"
	TargetSourceWorkerLog   TargetSource = "worker_log"
)

type RetentionClass string

const (
	RetentionEphemeral RetentionClass = "ephemeral"
	RetentionManaged   RetentionClass = "managed"
)

// AWSReadBackV1 is only AWS-side evidence. It intentionally has no worker URL
// or Worker-provided endpoint field because such claims are untrusted for a
// public entrypoint.
type AWSReadBackV1 struct {
	Observed   bool             `json:"observed"`
	Exists     bool             `json:"exists"`
	State      EC2InstanceState `json:"state"`
	ObservedAt time.Time        `json:"observed_at"`
	TagDigest  string           `json:"tag_digest"`
}

// RetentionScopeV1 is copied into the entry scope and must exactly match the
// underlying Worker lifecycle. A public entry cannot quietly outlive the
// resource it exposes.
type RetentionScopeV1 struct {
	Class           RetentionClass `json:"class"`
	AutoDestroy     bool           `json:"auto_destroy"`
	DestroyDeadline time.Time      `json:"destroy_deadline,omitempty"`
}

// WorkerReadBackScopeV1 binds a public entry to an already successful Worker
// deployment. It is not an instruction to create or mutate an EC2 instance.
type WorkerReadBackScopeV1 struct {
	DeploymentID           string           `json:"deployment_id"`
	DeploymentRevision     int64            `json:"deployment_revision"`
	TaskID                 string           `json:"task_id"`
	OriginalPlanID         string           `json:"original_plan_id"`
	OriginalPlanHash       string           `json:"original_plan_hash"`
	OriginalApprovalID     string           `json:"original_approval_id"`
	WorkerResourceID       string           `json:"worker_resource_id"`
	WorkerResourceRevision int64            `json:"worker_resource_revision"`
	WorkerSpecDigest       string           `json:"worker_spec_digest"`
	InstanceID             string           `json:"instance_id"`
	VPCID                  string           `json:"vpc_id"`
	SubnetID               string           `json:"subnet_id"`
	SecurityGroupID        string           `json:"security_group_id"`
	ExecutionOutcome       WorkerOutcome    `json:"execution_outcome"`
	SucceededAt            time.Time        `json:"succeeded_at"`
	ReadBack               AWSReadBackV1    `json:"read_back"`
	Retention              RetentionScopeV1 `json:"retention"`
}

// RecipeHealthBindingV1 holds only digests. Recipe text, service credentials,
// and any user data remain outside public entry contracts.
type RecipeHealthBindingV1 struct {
	RecipeDigest                 string `json:"recipe_digest"`
	HealthContractDigest         string `json:"health_contract_digest"`
	AuthenticationContractDigest string `json:"authentication_contract_digest"`
}

// CertificateScopeV1 describes an existing, same-region ACM certificate. This
// first contract intentionally does not create certificates or mutate Route53.
type CertificateScopeV1 struct {
	CertificateARN          string            `json:"certificate_arn"`
	Region                  string            `json:"region"`
	Hostname                string            `json:"hostname"`
	SubjectAlternativeNames []string          `json:"subject_alternative_names"`
	Status                  CertificateStatus `json:"status"`
	ReadBackDigest          string            `json:"read_back_digest"`
	ObservedAt              time.Time         `json:"observed_at"`
}

type PublicSubnetScopeV1 struct {
	SubnetID         string    `json:"subnet_id"`
	VPCID            string    `json:"vpc_id"`
	AvailabilityZone string    `json:"availability_zone"`
	Public           bool      `json:"public"`
	ReadBackDigest   string    `json:"read_back_digest"`
	ObservedAt       time.Time `json:"observed_at"`
}

// ALBScopeV1 contains the complete first-release load-balancer intent. An ALB
// itself may use AWS-managed addresses, but a Worker must never receive a
// public IPv4 address or an EIP as part of this public-entry plan.
type ALBScopeV1 struct {
	Scheme           ALBScheme             `json:"scheme"`
	ListenerPort     uint32                `json:"listener_port"`
	ListenerProtocol ListenerProtocol      `json:"listener_protocol"`
	TLSPolicy        string                `json:"tls_policy"`
	IngressCIDRs     []string              `json:"ingress_cidrs"`
	TargetProtocol   TargetProtocol        `json:"target_protocol"`
	TargetPort       uint32                `json:"target_port"`
	TargetSource     TargetSource          `json:"target_source"`
	WorkerPublicIPv4 bool                  `json:"worker_public_ipv4"`
	EIPRequested     bool                  `json:"eip_requested"`
	PublicSubnets    []PublicSubnetScopeV1 `json:"public_subnets"`
}

// HealthRouteScopeV1 declares an intentionally unauthenticated, non-sensitive
// service health route. It cannot be inferred from a Worker report and the
// expected evidence digest must exactly match Recipe.HealthContractDigest.
type HealthRouteScopeV1 struct {
	Path               string `json:"path"`
	ExpectedStatusCode uint32 `json:"expected_status_code"`
	EvidenceDigest     string `json:"evidence_digest"`
	NoCredentialRoute  bool   `json:"no_credential_route"`
}

// AuthenticationScopeV1 confirms that normal service traffic is authenticated
// even though the declared health route is deliberately credential-free.
type AuthenticationScopeV1 struct {
	Required       bool   `json:"required"`
	ContractDigest string `json:"contract_digest"`
}

// EntryCostScopeV1 binds every first-release ALB/LCU/traffic price assumption
// into device approval. All money values are integer micro-units of Currency.
type EntryCostScopeV1 struct {
	QuoteID                   string    `json:"quote_id"`
	QuoteDigest               string    `json:"quote_digest"`
	Currency                  string    `json:"currency"`
	QuotedAt                  time.Time `json:"quoted_at"`
	ValidUntil                time.Time `json:"valid_until"`
	ALBHourlyEstimateMicros   uint64    `json:"alb_hourly_estimate_micros"`
	LCUHourlyEstimateMicros   uint64    `json:"lcu_hourly_estimate_micros"`
	EstimatedLCUMilliUnits    uint32    `json:"estimated_lcu_milli_units"`
	EstimatedEgressMiB        uint64    `json:"estimated_egress_mib"`
	TrafficEstimateMicros     uint64    `json:"traffic_estimate_micros"`
	MaximumLaunchAmountMicros uint64    `json:"maximum_launch_amount_micros"`
	AssumptionsDigest         string    `json:"assumptions_digest"`
}

// ScopeV1 is the complete separate device-approval scope for a public entry.
// It binds an existing Worker, ACM certificate, two public ALB subnets, TLS,
// ingress, external health contract, price assumptions, and lifecycle.
type ScopeV1 struct {
	SchemaVersion   string                `json:"schema_version"`
	Kind            EntryKind             `json:"kind"`
	AgentInstanceID string                `json:"agent_instance_id"`
	OwnerID         string                `json:"owner_id"`
	ConnectionID    string                `json:"connection_id"`
	Region          string                `json:"region"`
	Worker          WorkerReadBackScopeV1 `json:"worker"`
	Recipe          RecipeHealthBindingV1 `json:"recipe"`
	Certificate     CertificateScopeV1    `json:"certificate"`
	ALB             ALBScopeV1            `json:"alb"`
	Health          HealthRouteScopeV1    `json:"health"`
	Authentication  AuthenticationScopeV1 `json:"authentication"`
	Cost            EntryCostScopeV1      `json:"cost"`
	Retention       RetentionScopeV1      `json:"retention"`
}

// PlanV1 carries the immutable scope and its digest. Its status is deliberately
// outside PlanHash so a lifecycle status update cannot change what the device
// approved.
type PlanV1 struct {
	SchemaVersion string     `json:"schema_version"`
	EntryPlanID   string     `json:"entry_plan_id"`
	Revision      uint64     `json:"revision"`
	Status        PlanStatus `json:"status"`
	Scope         ScopeV1    `json:"scope"`
	ScopeDigest   string     `json:"scope_digest"`
}

// ChallengeV1 is the one-time device-signing request. SigningCBOR is a cached
// copy of SigningPayload for persistence adapters; it is excluded from JSON
// and verification always recomputes the canonical payload.
type ChallengeV1 struct {
	OperationID       string    `json:"operation_id"`
	ChallengeID       string    `json:"challenge_id"`
	ApprovalID        string    `json:"approval_id"`
	EntryPlanID       string    `json:"entry_plan_id"`
	EntryPlanRevision uint64    `json:"entry_plan_revision"`
	PlanHash          string    `json:"plan_hash"`
	ScopeDigest       string    `json:"scope_digest"`
	SignerKeyID       string    `json:"signer_key_id"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	SigningCBOR       []byte    `json:"-"`
	Revision          int64     `json:"revision"`
}

// SignatureV1 mirrors every challenge binding so a persistence adapter can
// reject a stale or cross-plan signature before cryptographic verification.
type SignatureV1 struct {
	ApprovalID        string    `json:"approval_id"`
	ChallengeID       string    `json:"challenge_id"`
	EntryPlanID       string    `json:"entry_plan_id"`
	EntryPlanRevision uint64    `json:"entry_plan_revision"`
	PlanHash          string    `json:"plan_hash"`
	ScopeDigest       string    `json:"scope_digest"`
	SignerKeyID       string    `json:"signer_key_id"`
	ExpiresAt         time.Time `json:"expires_at"`
	Signature         []byte    `json:"-"`
}

// OperationV1 is durable state only; AWS mutation/read-back is deliberately
// outside this package. ErrorSummary must stay a de-sensitized fixed summary.
type OperationV1 struct {
	Challenge    ChallengeV1  `json:"challenge"`
	Status       Status       `json:"status"`
	Signature    *SignatureV1 `json:"-"`
	ErrorCode    ErrorCode    `json:"error_code,omitempty"`
	ErrorSummary string       `json:"error_summary,omitempty"`
	Revision     int64        `json:"revision"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	ApprovedAt   *time.Time   `json:"approved_at,omitempty"`
}

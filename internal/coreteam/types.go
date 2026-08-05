// Package coreteam owns the bounded Central Agent plan for official Pi Workers.
// It stores references to credentials and cloud facts, never secret bytes or
// free-form provider requests.
package coreteam

import "time"

const (
	MaxRoles          = 3
	MaxOwnerIDBytes   = 256
	MaxGoalBytes      = 65_536
	MaxRoleGoalBytes  = 16_384
	MaxOutputTokens   = 131_072
	OfficialRuntimeID = "official-pi-0.83.0"
	AdapterPiV1       = "pi-v1"
	OsakaRegion       = "ap-northeast-3"
	MVPInstanceType   = "t3.small"
)

type PlanStatus string

const (
	PlanWaitingUser PlanStatus = "waiting_user"
	PlanApproved    PlanStatus = "approved"
	PlanExpired     PlanStatus = "expired"
)

type ExecutionStatus string

const (
	ExecutionQueued     ExecutionStatus = "queued"
	ExecutionRunning    ExecutionStatus = "running"
	ExecutionCleaningUp ExecutionStatus = "cleaning_up"
	ExecutionCompleted  ExecutionStatus = "completed"
	ExecutionFailed     ExecutionStatus = "failed"
	ExecutionCanceled   ExecutionStatus = "canceled"
	ExecutionTimedOut   ExecutionStatus = "timed_out"
)

type Capability string

const (
	CapabilityRepositoryRead   Capability = "repository.read"
	CapabilityRepositoryWrite  Capability = "repository.write"
	CapabilityCodeReview       Capability = "code.review"
	CapabilityShell            Capability = "shell"
	CapabilityGit              Capability = "git"
	CapabilityTest             Capability = "test"
	CapabilityWebResearch      Capability = "web.research"
	CapabilityBrowser          Capability = "browser"
	CapabilityMCPClient        Capability = "mcp.client"
	CapabilityStructuredResult Capability = "result.structured"
)

type RuntimeBinding struct {
	RuntimeID    string `json:"runtime_id"`
	Adapter      string `json:"adapter"`
	ImageDigest  string `json:"image_digest"`
	AMIID        string `json:"ami_id"`
	OutputTokens uint32 `json:"output_tokens"`
}

type QuoteBinding struct {
	Region           string    `json:"region"`
	AvailabilityZone string    `json:"availability_zone"`
	InstanceType     string    `json:"instance_type"`
	Currency         string    `json:"currency"`
	Amount           string    `json:"amount"`
	HardBudget       string    `json:"hard_budget"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type RoleProposal struct {
	RoleID       string       `json:"role_id"`
	Goal         string       `json:"goal"`
	DependsOn    []string     `json:"depends_on,omitempty"`
	Capabilities []Capability `json:"capabilities"`
}

type Role struct {
	RoleID       string       `json:"role_id"`
	Goal         string       `json:"goal"`
	DependsOn    []string     `json:"depends_on,omitempty"`
	Capabilities []Capability `json:"capabilities"`
}

type CompileCommand struct {
	OwnerID            string         `json:"owner_id"`
	AccountGeneration  int64          `json:"account_generation"`
	Goal               string         `json:"goal"`
	ConversationID     string         `json:"conversation_id"`
	CredentialID       string         `json:"credential_id"`
	CredentialRevision uint64         `json:"credential_revision"`
	RuntimeID          string         `json:"runtime_id,omitempty"`
	Roles              []RoleProposal `json:"roles"`
}

type QuoteRequest struct {
	RuntimeID    string `json:"runtime_id"`
	Region       string `json:"region"`
	InstanceType string `json:"instance_type"`
	RoleCount    uint32 `json:"role_count"`
}

// Plan is immutable except for Status. Generated identity fields and Status do
// not enter Digest; all owner, generation, credential, runtime, quote and role
// facts do.
type Plan struct {
	PlanID             string         `json:"plan_id"`
	OwnerID            string         `json:"owner_id"`
	AccountGeneration  int64          `json:"account_generation"`
	TaskID             string         `json:"task_id"`
	ConversationID     string         `json:"conversation_id"`
	CredentialID       string         `json:"credential_id"`
	ConfirmationID     string         `json:"confirmation_id"`
	Revision           uint64         `json:"revision"`
	CredentialRevision uint64         `json:"credential_revision"`
	Goal               string         `json:"goal"`
	Digest             string         `json:"digest"`
	Runtime            RuntimeBinding `json:"runtime"`
	Quote              QuoteBinding   `json:"quote"`
	Roles              []Role         `json:"roles"`
	Status             PlanStatus     `json:"status"`
}

func (p Plan) Clone() Plan {
	p.Roles = cloneRoles(p.Roles)
	return p
}

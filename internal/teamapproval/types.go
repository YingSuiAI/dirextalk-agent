// Package teamapproval defines the device-signed approval contract for a
// multi-Worker Team Plan. It does not persist challenges, resolve device keys,
// launch Workers, or mutate cloud resources.
package teamapproval

import (
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

const (
	ChallengeSchemaV1      = "dirextalk.agent.team-plan-challenge/v1"
	ChallengeSchemaV2      = "dirextalk.agent.team-plan-challenge/v2"
	SignatureSchemaV1      = "dirextalk.agent.team-plan-signature/v1"
	SignatureSchemaV2      = "dirextalk.agent.team-plan-signature/v2"
	SigningPayloadSchemaV1 = "dirextalk.agent.team-plan-signing-payload/v1"
	SigningPayloadSchemaV2 = "dirextalk.agent.team-plan-signing-payload/v2"
	ChallengeValidity      = 5 * time.Minute
)

type ChallengeV1 struct {
	SchemaVersion             string                 `json:"schema_version"`
	Revision                  uint64                 `json:"revision"`
	ApprovalID                string                 `json:"approval_id"`
	ChallengeID               string                 `json:"challenge_id"`
	AgentInstanceID           string                 `json:"agent_instance_id"`
	OwnerID                   string                 `json:"owner_id"`
	PlanID                    string                 `json:"plan_id"`
	PlanRevision              uint64                 `json:"plan_revision"`
	PlanDigest                string                 `json:"plan_digest"`
	GoalDigest                string                 `json:"goal_digest"`
	ProviderScope             teamplan.ProviderScope `json:"provider_scope"`
	CatalogRevision           string                 `json:"catalog_revision"`
	PolicyRevision            string                 `json:"policy_revision"`
	PricingSnapshotID         string                 `json:"pricing_snapshot_id"`
	PricingSnapshotDigest     string                 `json:"pricing_snapshot_digest"`
	QuotedAt                  time.Time              `json:"quoted_at"`
	QuoteValidUntil           time.Time              `json:"quote_valid_until"`
	WorkerCount               uint32                 `json:"worker_count"`
	MaxConcurrentWorkers      uint32                 `json:"max_concurrent_workers"`
	Currency                  string                 `json:"currency"`
	MinimumCostMicros         uint64                 `json:"minimum_cost_micros"`
	ExpectedCostMicros        uint64                 `json:"expected_cost_micros"`
	MaximumCostMicros         uint64                 `json:"maximum_cost_micros"`
	HardBudgetMicros          uint64                 `json:"hard_budget_micros"`
	MinimumWallSeconds        uint64                 `json:"minimum_wall_seconds"`
	ExpectedWallSeconds       uint64                 `json:"expected_wall_seconds"`
	MaximumWallSeconds        uint64                 `json:"maximum_wall_seconds"`
	LaunchAuthorizationID     string                 `json:"launch_authorization_id,omitempty"`
	LaunchAuthorizationDigest string                 `json:"launch_authorization_digest,omitempty"`
	SignerKeyID               string                 `json:"signer_key_id"`
	IssuedAt                  time.Time              `json:"issued_at"`
	ExpiresAt                 time.Time              `json:"expires_at"`
}

type SignatureV1 struct {
	SchemaVersion             string `json:"schema_version"`
	ApprovalID                string `json:"approval_id"`
	ChallengeID               string `json:"challenge_id"`
	PlanID                    string `json:"plan_id"`
	PlanRevision              uint64 `json:"plan_revision"`
	PlanDigest                string `json:"plan_digest"`
	LaunchAuthorizationID     string `json:"launch_authorization_id,omitempty"`
	LaunchAuthorizationDigest string `json:"launch_authorization_digest,omitempty"`
	SignerKeyID               string `json:"signer_key_id"`
	SignatureBase64URL        string `json:"signature_base64url"`
}

// LaunchApprovalV2 keeps the complete signed launch facts beside the compact
// challenge. The authorization itself is persisted and returned to the device
// for inspection; only its deterministic digest is duplicated in the
// challenge signing payload.
type LaunchApprovalV2 struct {
	Challenge     ChallengeV1
	Authorization teamlaunch.AuthorizationV1
}

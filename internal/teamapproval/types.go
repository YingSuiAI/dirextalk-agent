// Package teamapproval defines the device-signed approval contract for a
// multi-Worker Team Plan. It does not persist challenges, resolve device keys,
// launch Workers, or mutate cloud resources.
package teamapproval

import (
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

const (
	ChallengeSchemaV1      = "dirextalk.agent.team-plan-challenge/v1"
	SignatureSchemaV1      = "dirextalk.agent.team-plan-signature/v1"
	SigningPayloadSchemaV1 = "dirextalk.agent.team-plan-signing-payload/v1"
	ChallengeValidity      = 5 * time.Minute
)

type ChallengeV1 struct {
	SchemaVersion         string                 `json:"schema_version"`
	Revision              uint64                 `json:"revision"`
	ApprovalID            string                 `json:"approval_id"`
	ChallengeID           string                 `json:"challenge_id"`
	AgentInstanceID       string                 `json:"agent_instance_id"`
	OwnerID               string                 `json:"owner_id"`
	PlanID                string                 `json:"plan_id"`
	PlanRevision          uint64                 `json:"plan_revision"`
	PlanDigest            string                 `json:"plan_digest"`
	GoalDigest            string                 `json:"goal_digest"`
	ProviderScope         teamplan.ProviderScope `json:"provider_scope"`
	CatalogRevision       string                 `json:"catalog_revision"`
	PolicyRevision        string                 `json:"policy_revision"`
	PricingSnapshotID     string                 `json:"pricing_snapshot_id"`
	PricingSnapshotDigest string                 `json:"pricing_snapshot_digest"`
	QuotedAt              time.Time              `json:"quoted_at"`
	QuoteValidUntil       time.Time              `json:"quote_valid_until"`
	WorkerCount           uint32                 `json:"worker_count"`
	MaxConcurrentWorkers  uint32                 `json:"max_concurrent_workers"`
	Currency              string                 `json:"currency"`
	MinimumCostMicros     uint64                 `json:"minimum_cost_micros"`
	ExpectedCostMicros    uint64                 `json:"expected_cost_micros"`
	MaximumCostMicros     uint64                 `json:"maximum_cost_micros"`
	HardBudgetMicros      uint64                 `json:"hard_budget_micros"`
	MinimumWallSeconds    uint64                 `json:"minimum_wall_seconds"`
	ExpectedWallSeconds   uint64                 `json:"expected_wall_seconds"`
	MaximumWallSeconds    uint64                 `json:"maximum_wall_seconds"`
	SignerKeyID           string                 `json:"signer_key_id"`
	IssuedAt              time.Time              `json:"issued_at"`
	ExpiresAt             time.Time              `json:"expires_at"`
}

type SignatureV1 struct {
	SchemaVersion      string `json:"schema_version"`
	ApprovalID         string `json:"approval_id"`
	ChallengeID        string `json:"challenge_id"`
	PlanID             string `json:"plan_id"`
	PlanRevision       uint64 `json:"plan_revision"`
	PlanDigest         string `json:"plan_digest"`
	SignerKeyID        string `json:"signer_key_id"`
	SignatureBase64URL string `json:"signature_base64url"`
}

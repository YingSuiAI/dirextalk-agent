package cloudworker

import (
	"sort"
	"strings"
	"time"
)

// PublicSecretGrant deliberately exposes only why a secret is needed. Secret
// reference IDs and per-reference binding digests remain private; the sealed
// aggregate digest on the plan/confirmation is the public drift fence.
type PublicSecretGrant struct {
	Purpose string `json:"purpose"`
}

// ProjectPublicSecretGrants removes duplicate purposes and sorts the result.
// This avoids leaking either private reference ordering or the number of
// credentials that happen to satisfy one approved purpose.
func ProjectPublicSecretGrants(values []SecretGrant) []PublicSecretGrant {
	seen := make(map[string]struct{}, len(values))
	purposes := make([]string, 0, len(values))
	for _, value := range values {
		purpose := strings.TrimSpace(value.Purpose)
		if purpose == "" {
			continue
		}
		if _, duplicate := seen[purpose]; duplicate {
			continue
		}
		seen[purpose] = struct{}{}
		purposes = append(purposes, purpose)
	}
	sort.Strings(purposes)
	result := make([]PublicSecretGrant, 0, len(purposes))
	for _, purpose := range purposes {
		result = append(result, PublicSecretGrant{Purpose: purpose})
	}
	return result
}

// PublicPlan is the sole Execution V2 projection for a Cloud Worker plan.
// Keep this explicit allow-list: the private Plan contains credential IDs,
// exact S3 locations, placement, bootstrap, relay and policy material.
type PublicPlan struct {
	OwnerID                  string              `json:"owner_id"`
	AccountGeneration        uint64              `json:"account_generation"`
	PlanID                   string              `json:"plan_id"`
	Revision                 uint64              `json:"revision"`
	Status                   string              `json:"status"`
	ExecutionID              string              `json:"execution_id"`
	TaskID                   string              `json:"task_id"`
	ConfirmationID           string              `json:"confirmation_id"`
	ConversationID           string              `json:"conversation_id"`
	TurnID                   string              `json:"turn_id"`
	ObjectiveSummary         string              `json:"objective_summary"`
	ProposalReason           ProposalReason      `json:"proposal_reason"`
	PersistentWorkerReuse    bool                `json:"persistent_worker_reuse"`
	WorkspaceMode            WorkspaceMode       `json:"workspace_mode"`
	AWS                      PublicAWSBinding    `json:"aws"`
	Compute                  PublicCompute       `json:"compute"`
	Limits                   PublicLimits        `json:"limits"`
	NetworkGrants            []string            `json:"network_grants"`
	SecretGrants             []PublicSecretGrant `json:"secret_grants"`
	ArtifactRetentionSeconds uint64              `json:"artifact_retention_seconds"`
	Quote                    PublicQuote         `json:"quote"`
	CreatedAt                time.Time           `json:"created_at"`
	UpdatedAt                time.Time           `json:"updated_at"`
}

type PublicAWSBinding struct {
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}

type PublicCompute struct {
	InstanceType        string `json:"instance_type"`
	VolumeGiB           uint64 `json:"volume_gib"`
	VolumeType          string `json:"volume_type"`
	VolumeIOPS          uint64 `json:"volume_iops"`
	VolumeThroughputMiB uint64 `json:"volume_throughput_mib"`
}

type PublicLimits struct {
	MaxRuntimeSeconds uint64 `json:"max_runtime_seconds"`
}

// PublicQuote exposes only the values needed to show the current price and
// confirmation window. Internal quote and pricing identities stay private.
type PublicQuote struct {
	AmountMicros                int64     `json:"amount_micros"`
	Currency                    string    `json:"currency"`
	SourceTime                  time.Time `json:"source_time"`
	ExpiresAt                   time.Time `json:"expires_at"`
	MaximumAuthorizedCostMicros int64     `json:"maximum_authorized_cost_micros"`
}

func (p Plan) Public() (PublicPlan, error) {
	if err := p.Seal(); err != nil {
		return PublicPlan{}, err
	}
	return PublicPlan{
		OwnerID: p.OwnerID, AccountGeneration: p.AccountGeneration, PlanID: p.PlanID,
		Revision: p.Revision, Status: p.Status, ExecutionID: p.ExecutionID,
		TaskID: p.TaskID, ConfirmationID: p.ConfirmationID, ConversationID: p.ConversationID,
		TurnID:           p.TurnID,
		ObjectiveSummary: p.ObjectiveSummary, ProposalReason: p.ProposalReason,
		PersistentWorkerReuse: p.PersistentWorkerReuse, WorkspaceMode: p.WorkspaceMode,
		AWS: PublicAWSBinding{AccountID: p.AWS.AccountID, Region: p.AWS.Region},
		Compute: PublicCompute{InstanceType: p.Compute.InstanceType, VolumeGiB: p.Compute.VolumeGiB,
			VolumeType: p.Compute.VolumeType, VolumeIOPS: p.Compute.VolumeIOPS, VolumeThroughputMiB: p.Compute.VolumeThroughputMiB},
		Limits:                   PublicLimits{MaxRuntimeSeconds: p.Limits.MaxRuntimeSeconds},
		NetworkGrants:            append(make([]string, 0, len(p.NetworkGrants)), p.NetworkGrants...),
		SecretGrants:             ProjectPublicSecretGrants(p.SecretGrants),
		ArtifactRetentionSeconds: p.ArtifactRetentionSeconds,
		Quote: PublicQuote{AmountMicros: p.Quote.AmountMicros, Currency: p.Quote.Currency,
			SourceTime: p.Quote.SourceTime, ExpiresAt: p.Quote.ExpiresAt,
			MaximumAuthorizedCostMicros: p.Quote.MaximumAuthorizedCostMicros},
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}, nil
}

type PublicExecution struct {
	OwnerID               string         `json:"owner_id"`
	AccountGeneration     uint64         `json:"account_generation"`
	RunID                 string         `json:"run_id"`
	ExecutionID           string         `json:"execution_id"`
	PlanID                string         `json:"plan_id"`
	PlanRevision          uint64         `json:"plan_revision"`
	TaskID                string         `json:"task_id"`
	ConfirmationID        string         `json:"confirmation_id"`
	ConversationID        string         `json:"conversation_id"`
	TurnID                string         `json:"turn_id"`
	Status                ExecutionState `json:"status"`
	Revision              uint64         `json:"revision"`
	WorkerID              string         `json:"worker_id"`
	PersistentWorker      bool           `json:"persistent_worker"`
	Cleanup               CleanupSummary `json:"cleanup"`
	ArtifactIDs           []string       `json:"artifact_ids"`
	FailureCode           string         `json:"failure_code"`
	FailureSummary        string         `json:"failure_summary"`
	CancellationRequested bool           `json:"cancellation_requested"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

func (e Execution) Public() (PublicExecution, error) {
	if err := e.Seal(); err != nil {
		return PublicExecution{}, err
	}
	return PublicExecution{
		OwnerID: e.OwnerID, AccountGeneration: e.AccountGeneration, RunID: e.RunID, ExecutionID: e.ExecutionID,
		PlanID: e.PlanID, PlanRevision: e.PlanRevision, TaskID: e.TaskID,
		ConfirmationID: e.ConfirmationID, ConversationID: e.ConversationID, TurnID: e.TurnID,
		Status: e.State, Revision: e.Revision, WorkerID: e.WorkerID, PersistentWorker: e.PersistentWorker, Cleanup: e.Cleanup,
		ArtifactIDs: append(make([]string, 0, len(e.ArtifactIDs)), e.ArtifactIDs...), FailureCode: e.FailureCode,
		FailureSummary: e.FailureSummary, CancellationRequested: e.TerminalIntent == string(StateCanceled),
		CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt,
	}, nil
}

type PublicArtifact struct {
	OwnerID           string         `json:"owner_id"`
	AccountGeneration uint64         `json:"account_generation"`
	ArtifactID        string         `json:"artifact_id"`
	ExecutionID       string         `json:"execution_id"`
	Kind              string         `json:"kind"`
	Name              string         `json:"name"`
	MediaType         string         `json:"media_type"`
	SizeBytes         uint64         `json:"size_bytes"`
	SHA256            string         `json:"sha256"`
	Status            ArtifactStatus `json:"status"`
	CreatedAt         time.Time      `json:"created_at"`
}

func (a Artifact) Public(ownerID string, accountGeneration uint64) (PublicArtifact, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" || accountGeneration == 0 || !validUUID(a.ArtifactID) || !validUUID(a.ExecutionID) ||
		strings.TrimSpace(a.Kind) == "" || strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.MediaType) == "" ||
		!validDigest(a.SHA256) || a.Status != ArtifactVerified || a.CreatedAt.IsZero() {
		return PublicArtifact{}, ErrInvalid
	}
	return PublicArtifact{OwnerID: ownerID, AccountGeneration: accountGeneration,
		ArtifactID: a.ArtifactID, ExecutionID: a.ExecutionID, Kind: a.Kind, Name: a.Name,
		MediaType: a.MediaType, SizeBytes: a.SizeBytes, SHA256: a.SHA256, Status: a.Status,
		CreatedAt: a.CreatedAt.UTC()}, nil
}

type PublicEvent struct {
	EventID           string         `json:"event_id"`
	RunID             string         `json:"run_id"`
	OwnerID           string         `json:"owner_id"`
	AccountGeneration uint64         `json:"account_generation"`
	Revision          uint64         `json:"revision"`
	Sequence          uint64         `json:"sequence"`
	Type              string         `json:"type"`
	At                time.Time      `json:"at"`
	PayloadDigest     string         `json:"payload_digest"`
	Status            ExecutionState `json:"status,omitempty"`
}

func (e Event) Public() (PublicEvent, error) {
	if !validUUID(e.EventID) || !validUUID(e.RunID) || e.RunID != e.ExecutionID || e.OwnerID == "" || e.AccountGeneration == 0 || e.Revision == 0 || e.Sequence == 0 || e.Type == "" || e.CreatedAt.IsZero() || !validDigest(e.PayloadDigest) || (e.State != "" && !validExecutionState(e.State)) {
		return PublicEvent{}, ErrInvalid
	}
	return PublicEvent{EventID: e.EventID, RunID: e.RunID, OwnerID: e.OwnerID, AccountGeneration: e.AccountGeneration, Revision: e.Revision, Sequence: e.Sequence, Type: e.Type, At: e.CreatedAt.UTC(), PayloadDigest: e.PayloadDigest, Status: e.State}, nil
}

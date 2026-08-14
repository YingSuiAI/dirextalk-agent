package coreexecutionv2

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
)

const RecordKindCloudWorker = "cloud_worker"

// Authority is derived from the signed Capability permission. Cloud Worker
// lookups must bind both fields so a deleted/recreated owner account cannot
// read or mutate records from an earlier account generation.
type Authority struct {
	OwnerID           string
	AccountGeneration uint64
}

type CloudWorkerPlanGetRequest struct {
	Authority
	PlanID   string
	Revision uint64
}

type CloudWorkerListRequest struct {
	Authority
	PageToken string
	PageSize  int
}

type CloudWorkerRunGetRequest struct {
	Authority
	RunID string
}

type CloudWorkerRunCancelRequest struct {
	Authority
	RunID            string
	ExpectedRevision uint64
	IdempotencyKey   string
}

type CloudWorkerRunEventsRequest struct {
	Authority
	RunID         string
	AfterSequence uint64
	Limit         int
}

type CloudWorkerArtifactGetRequest struct {
	Authority
	ArtifactID string
}

const MaxCloudWorkerArtifactDownloadChunkBytes uint64 = 512 << 10
const MaxCloudWorkerArtifactDownloadOffsetBytes = cloudworker.MaxCloudWorkerOutputBytes - 1

type CloudWorkerArtifactDownloadRequest struct {
	Authority
	ArtifactID    string
	OffsetBytes   uint64
	MaxChunkBytes uint64
}

type CloudWorkerArtifactChunk struct {
	Authority
	ArtifactID      string
	ExecutionID     string
	OffsetBytes     uint64
	Data            []byte
	ChunkSHA256     string
	ArtifactSHA256  string
	SizeBytes       uint64
	NextOffsetBytes uint64
	EOF             bool
}

// CloudWorkerObject is an already-redacted public projection. The Service
// still normalizes and validates owner, account generation and immutable IDs
// before returning it to a caller.
type CloudWorkerObject map[string]any

type CloudWorkerPage struct {
	Items         []CloudWorkerObject
	NextPageToken string
}

type CloudWorkerEventPage struct {
	Events           []CloudWorkerObject
	NextSequence     uint64
	HistoryTruncated bool
}

// CloudWorkerExecutionPort is the only bridge from public Execution V2 to
// the strongly typed Cloud Worker authority. Implementations must query the
// Cloud Worker tables directly; they must not project through or dual-write
// core_execution_v2_records.
type CloudWorkerExecutionPort interface {
	GetPlan(context.Context, CloudWorkerPlanGetRequest) (CloudWorkerObject, error)
	ListPlans(context.Context, CloudWorkerListRequest) (CloudWorkerPage, error)
	GetRun(context.Context, CloudWorkerRunGetRequest) (CloudWorkerObject, error)
	ListRuns(context.Context, CloudWorkerListRequest) (CloudWorkerPage, error)
	CancelRun(context.Context, CloudWorkerRunCancelRequest) (CloudWorkerObject, error)
	RunEvents(context.Context, CloudWorkerRunEventsRequest) (CloudWorkerEventPage, error)
	GetArtifact(context.Context, CloudWorkerArtifactGetRequest) (CloudWorkerObject, error)
	DownloadArtifact(context.Context, CloudWorkerArtifactDownloadRequest) (CloudWorkerArtifactChunk, error)
}

// CloudWorkerAuthorityStore is the persistence boundary used by the public
// adapter. Every read carries account_generation into the database predicate;
// checking the generation only after loading a same-owner row would leak an
// earlier account incarnation and is therefore insufficient.
type CloudWorkerAuthorityStore interface {
	GetPlanForAuthority(context.Context, string, uint64, string, uint64) (cloudworker.Plan, error)
	ListPlansForAuthority(context.Context, string, uint64, string, int) ([]cloudworker.Plan, string, error)
	GetExecutionForAuthority(context.Context, string, uint64, string) (cloudworker.Execution, error)
	ListExecutionsForAuthority(context.Context, string, uint64, string, int) ([]cloudworker.Execution, string, error)
	RequestCancel(context.Context, string, uint64, string, uint64, string) (cloudworker.Execution, error)
	EventsForAuthority(context.Context, string, uint64, string, uint64, int) ([]cloudworker.Event, uint64, bool, error)
}

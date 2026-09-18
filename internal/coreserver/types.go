package coreserver

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalid  = errors.New("invalid server inventory request")
	ErrNotFound = errors.New("server or artifact not found")
	ErrConflict = errors.New("server inventory conflict")
	ErrPrimary  = errors.New("primary server cannot be destroyed")
	ErrBusy     = errors.New("server is busy")
)

const (
	ServerPrimary = "primary"
	ServerWorker  = "worker"

	ArtifactSystemService   = "system_service"
	ArtifactStaticPage      = "static_page"
	ArtifactExecutionFile   = "execution_file"
	ArtifactDeployedService = "deployed_service"
)

type Authority struct {
	OwnerID           string
	AccountGeneration uint64
}

// DestroyNotice records one resource a destroy deliberately left in place.
// The owner sees exactly which resource was not touched and why, instead of a
// destroy that silently reports success.
type DestroyNotice struct {
	Resource string `json:"resource"`
	Name     string `json:"name"`
	Detail   string `json:"detail"`
}

type destroyNoticeKey struct{}

// WithDestroyNotices attaches a collector so a destroy can report resources it
// intentionally left untouched, such as a DNS record that no longer belongs to
// the Worker. Callers read the slice after the destroy returns.
func WithDestroyNotices(ctx context.Context) (context.Context, *[]DestroyNotice) {
	notices := make([]DestroyNotice, 0, 1)
	return context.WithValue(ctx, destroyNoticeKey{}, &notices), &notices
}

// AppendDestroyNotice records one skipped resource when a collector is
// attached; it is a no-op otherwise.
func AppendDestroyNotice(ctx context.Context, notice DestroyNotice) {
	if ctx == nil || strings.TrimSpace(notice.Resource) == "" {
		return
	}
	collector, ok := ctx.Value(destroyNoticeKey{}).(*[]DestroyNotice)
	if !ok || collector == nil {
		return
	}
	*collector = append(*collector, notice)
}

func (a Authority) Valid() bool {
	return strings.TrimSpace(a.OwnerID) == a.OwnerID && a.OwnerID != "" && len(a.OwnerID) <= 512 && a.AccountGeneration > 0
}

type Instance struct {
	ID        string
	CreatedAt time.Time
}

type Server struct {
	ServerID      string    `json:"server_id"`
	ServerKind    string    `json:"server_kind"`
	Name          string    `json:"name"`
	Status        string    `json:"status"`
	Address       string    `json:"address,omitempty"`
	Region        string    `json:"region,omitempty"`
	ArtifactCount int64     `json:"artifact_count"`
	CanDestroy    bool      `json:"can_destroy"`
	Busy          bool      `json:"busy"`
	BusyReason    string    `json:"busy_reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	Identity      any       `json:"identity,omitempty"`
}

type Artifact struct {
	ArtifactID        string         `json:"artifact_id"`
	AccountGeneration uint64         `json:"account_generation"`
	ServerID          string         `json:"server_id"`
	ServerKind        string         `json:"server_kind"`
	ArtifactKind      string         `json:"artifact_kind"`
	SourceKind        string         `json:"source_kind"`
	SourceID          string         `json:"source_id"`
	Name              string         `json:"name"`
	Status            string         `json:"status"`
	PublicURL         string         `json:"public_url,omitempty"`
	Domain            string         `json:"domain,omitempty"`
	PublicIPv4        string         `json:"public_ipv4,omitempty"`
	Port              uint16         `json:"port,omitempty"`
	Health            string         `json:"health,omitempty"`
	RecordKind        string         `json:"record_kind,omitempty"`
	ExecutionID       string         `json:"execution_id,omitempty"`
	MediaType         string         `json:"media_type,omitempty"`
	SizeBytes         int64          `json:"size_bytes,omitempty"`
	Metadata          map[string]any `json:"metadata"`
	DeletionState     string         `json:"deletion_state"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

func (a Artifact) Valid() bool {
	return uuid.Validate(a.ArtifactID) == nil && uuid.Validate(a.ServerID) == nil &&
		(a.ServerKind == ServerPrimary || a.ServerKind == ServerWorker) && strings.TrimSpace(a.SourceID) != "" &&
		strings.TrimSpace(a.Name) != "" && !a.CreatedAt.IsZero()
}

type Page struct {
	Artifacts     []Artifact `json:"artifacts"`
	NextPageToken string     `json:"next_page_token,omitempty"`
}

type Repository interface {
	Instance(context.Context) (Instance, error)
	EnsurePrimaryArtifact(context.Context, Authority, Instance, string) error
	Upsert(context.Context, Authority, Artifact) error
	GetArtifact(context.Context, Authority, string) (Artifact, error)
	ListArtifacts(context.Context, Authority, string, int, string) (Page, error)
	ListServerArtifactsForCleanup(context.Context, Authority, string) ([]Artifact, error)
	CountByServer(context.Context, Authority) (map[string]int64, error)
	DeleteBySource(context.Context, Authority, string, string) error
	MarkServerDeleting(context.Context, Authority, string) error
	DeleteServer(context.Context, Authority, string) error
}

type WorkerInventory interface {
	List(context.Context, Authority) ([]Server, error)
	Get(context.Context, Authority, string) (Server, error)
	Destroy(context.Context, Authority, string, string) error
	FinalizeDestroy(context.Context, Authority, string, string) error
}

type ArtifactDeleter interface {
	DeleteArtifact(context.Context, Authority, Artifact, string) error
}

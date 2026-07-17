package resource

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ManagedPreparationSwapRequest is the narrow authorization hand-off from the
// service-operation executor into the authoritative resource ledger. The
// attachment observation is evidence only; the repository must independently
// bind every identifier to the signed operation scope before changing the
// EC2 dependency graph.
type ManagedPreparationSwapRequest struct {
	OperationID              string
	OwnerID                  string
	DeploymentID             string
	EC2ResourceID            string
	SourceResourceID         string
	SnapshotResourceID       string
	ReplacementResourceID    string
	InstanceID               string
	ReplacementVolumeID      string
	DeviceName               string
	AttachmentEvidenceDigest string
	AttachmentObservedAt     time.Time
}

func (request ManagedPreparationSwapRequest) Validate() error {
	for _, value := range []string{
		request.OperationID, request.DeploymentID, request.EC2ResourceID, request.SourceResourceID,
		request.SnapshotResourceID, request.ReplacementResourceID,
	} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || parsed.String() != value {
			return ErrInvalid
		}
	}
	if request.OwnerID == "" || strings.TrimSpace(request.OwnerID) != request.OwnerID ||
		request.InstanceID == "" || request.ReplacementVolumeID == "" ||
		!sha256Pattern.MatchString(request.AttachmentEvidenceDigest) || request.AttachmentObservedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type ManagedPreparationSwapRecord struct {
	OperationID              string
	AgentInstanceID          string
	OwnerID                  string
	DeploymentID             string
	EC2ResourceID            string
	SourceResourceID         string
	SnapshotResourceID       string
	ReplacementResourceID    string
	DeviceName               string
	AttachmentEvidenceDigest string
	AttachmentObservedAt     time.Time
	Status                   string
	Revision                 int64
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

type ManagedPreparationRetireRequest struct {
	OperationID  string
	OwnerID      string
	DeploymentID string
	ResourceID   string
}

func (request ManagedPreparationRetireRequest) Validate() error {
	for _, value := range []string{request.OperationID, request.DeploymentID, request.ResourceID} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || parsed.String() != value {
			return ErrInvalid
		}
	}
	if request.OwnerID == "" || strings.TrimSpace(request.OwnerID) != request.OwnerID {
		return ErrInvalid
	}
	return nil
}

// ManagedPreparationRepository is intentionally smaller than the
// service-operation domain. It exposes only the two resource-ledger mutations
// whose authorization depends on a persisted managed-preparation operation.
type ManagedPreparationRepository interface {
	CommitManagedPreparationSwap(context.Context, ManagedPreparationSwapRequest, time.Time) (ManagedPreparationSwapRecord, ResourceV1, error)
	BeginManagedPreparationRetire(context.Context, ManagedPreparationRetireRequest, time.Time) (ResourceV1, error)
	CompleteManagedPreparationRetire(context.Context, ManagedPreparationRetireRequest, ReadBackEvidence, time.Time) (ResourceV1, error)
}

type ManagedPreparationLifecycle interface {
	CommitManagedPreparationSwap(context.Context, ManagedPreparationSwapRequest) (ManagedPreparationSwapRecord, ResourceV1, error)
	RetireManagedPreparationOriginal(context.Context, ManagedPreparationRetireRequest) (ResourceV1, error)
}

func (service *Service) CommitManagedPreparationSwap(
	ctx context.Context,
	request ManagedPreparationSwapRequest,
) (ManagedPreparationSwapRecord, ResourceV1, error) {
	repository, ok := service.repository.(ManagedPreparationRepository)
	if !ok || request.Validate() != nil {
		return ManagedPreparationSwapRecord{}, ResourceV1{}, ErrInvalid
	}
	var record ManagedPreparationSwapRecord
	var ec2 ResourceV1
	err := service.withDeploymentFence(ctx, request.DeploymentID, func(fenced context.Context) error {
		var commitErr error
		record, ec2, commitErr = repository.CommitManagedPreparationSwap(fenced, request, service.now().UTC())
		if commitErr != nil {
			return commitErr
		}
		resources, listErr := service.repository.ListDeployment(fenced, request.DeploymentID)
		if listErr != nil {
			return listErr
		}
		return service.putManifest(fenced, resources, false)
	})
	return record, ec2.clone(), err
}

func (service *Service) RetireManagedPreparationOriginal(
	ctx context.Context,
	request ManagedPreparationRetireRequest,
) (ResourceV1, error) {
	repository, ok := service.repository.(ManagedPreparationRepository)
	if !ok || request.Validate() != nil {
		return ResourceV1{}, ErrInvalid
	}
	var retired ResourceV1
	err := service.withDeploymentFence(ctx, request.DeploymentID, func(fenced context.Context) error {
		item, beginErr := repository.BeginManagedPreparationRetire(fenced, request, service.now().UTC())
		if beginErr != nil {
			return beginErr
		}
		if item.State == StateVerifiedDestroyed {
			retired = item
			resources, listErr := service.repository.ListDeployment(fenced, request.DeploymentID)
			if listErr != nil {
				return listErr
			}
			return service.putManifest(fenced, resources, false)
		}
		resources, listErr := service.repository.ListDeployment(fenced, request.DeploymentID)
		if listErr != nil {
			return listErr
		}
		if manifestErr := service.putManifest(fenced, resources, false); manifestErr != nil {
			return manifestErr
		}
		evidence, verified, deleteErr := deleteAndVerifyProviderIDs(fenced, service.provider, item)
		if !verified {
			if deleteErr != nil {
				return deleteErr
			}
			return ErrReadBack
		}
		retired, beginErr = repository.CompleteManagedPreparationRetire(fenced, request, evidence, service.now().UTC())
		if beginErr != nil {
			return beginErr
		}
		resources, listErr = service.repository.ListDeployment(fenced, request.DeploymentID)
		if listErr != nil {
			return listErr
		}
		return service.putManifest(fenced, resources, false)
	})
	return retired.clone(), err
}

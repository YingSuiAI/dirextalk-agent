package rpcapi

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
)

// GetCloudManagedService exposes the completed, owner-scoped managed-service
// compatibility projection. The reader is deliberately read-only and returns
// an already de-secreted model rather than an approval or resource snapshot.
func (service *CloudControlService) GetCloudManagedService(ctx context.Context, request *agentv1.GetCloudManagedServiceRequest) (*agentv1.GetCloudManagedServiceResponse, error) {
	if service.managedServiceReader == nil {
		return nil, cloudStatusUnavailable()
	}
	item, err := service.managedServiceReader.GetManagedService(ctx, request.GetOwnerId(), request.GetServiceId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudManagedServiceResponse{Service: cloudManagedServiceToProto(item)}, nil
}

// ListCloudManagedServices uses the reader's owner-bound cursor. The request
// never accepts a deployment, provider, contract, or approval identifier as a
// filtering bypass.
func (service *CloudControlService) ListCloudManagedServices(ctx context.Context, request *agentv1.ListCloudManagedServicesRequest) (*agentv1.ListCloudManagedServicesResponse, error) {
	if service.managedServiceReader == nil {
		return nil, cloudStatusUnavailable()
	}
	page, err := service.managedServiceReader.ListManagedServices(ctx, cloudstatus.ListQuery{
		OwnerID: request.GetOwnerId(), PageSize: int(request.GetPageSize()), PageToken: request.GetPageToken(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.ListCloudManagedServicesResponse{
		Services: make([]*agentv1.CloudManagedCompatibilityService, 0, len(page.Services)), NextPageToken: page.NextPageToken,
	}
	for _, item := range page.Services {
		response.Services = append(response.Services, cloudManagedServiceToProto(item))
	}
	return response, nil
}

func cloudManagedServiceToProto(item cloudstatus.ManagedService) *agentv1.CloudManagedCompatibilityService {
	result := &agentv1.CloudManagedCompatibilityService{
		ServiceId: item.ServiceID, DeploymentId: item.DeploymentID, RecipeId: item.RecipeID, Name: item.Name,
		ServiceStatus: item.ServiceStatus, IntegrationStatus: item.IntegrationStatus, Revision: item.Revision,
		CreatedAtUnixMs: item.CreatedAt.UnixMilli(), UpdatedAtUnixMs: item.UpdatedAt.UnixMilli(),
		Backups:  make([]*agentv1.CloudManagedCompatibilityBackup, 0, len(item.Backups)),
		Restores: make([]*agentv1.CloudManagedCompatibilityRestore, 0, len(item.Restores)),
	}
	for _, backup := range item.Backups {
		// ImageID and SnapshotIDs deliberately stay unset: they are provider
		// identifiers, not compatibility façade facts.
		result.Backups = append(result.Backups, &agentv1.CloudManagedCompatibilityBackup{
			BackupId: backup.BackupID, ServiceId: backup.ServiceID, DeploymentId: backup.DeploymentID,
			Status: backup.Status, RetentionPolicy: backup.RetentionPolicy, Revision: backup.Revision,
			CreatedAtUnixMs: backup.CreatedAt.UnixMilli(), UpdatedAtUnixMs: backup.UpdatedAt.UnixMilli(),
		})
	}
	for _, restore := range item.Restores {
		// OriginalVolumeIDs and ReplacementVolumeIDs deliberately stay unset:
		// they are provider identifiers, not compatibility façade facts.
		result.Restores = append(result.Restores, &agentv1.CloudManagedCompatibilityRestore{
			RestoreId: restore.RestoreID, RestorePlanId: restore.RestorePlanID, ServiceId: restore.ServiceID,
			DeploymentId: restore.DeploymentID, BackupId: restore.BackupID, Status: restore.Status,
			Revision: restore.Revision, CreatedAtUnixMs: restore.CreatedAt.UnixMilli(), UpdatedAtUnixMs: restore.UpdatedAt.UnixMilli(),
		})
	}
	return result
}

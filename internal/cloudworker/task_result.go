package cloudworker

import (
	"slices"
	"strings"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
)

// TaskResultSnapshot is the durable, display-oriented Cloud Worker result
// retained by CoreTask after the ephemeral AWS graph has been destroyed. It
// deliberately excludes account generations, provider instance IDs and other
// authority fences; those remain in the typed Plan, Execution and resource
// ledgers and are not prerequisites for rendering this snapshot.
type TaskResultSnapshot struct {
	ExecutionID    string         `json:"execution_id"`
	ArtifactIDs    []string       `json:"artifact_ids"`
	ServerSnapshot ServerSnapshot `json:"server_snapshot"`
}

type ServerSnapshot struct {
	Name         string               `json:"name"`
	Region       string               `json:"region"`
	PrivateIP    string               `json:"private_ip,omitempty"`
	PublicIP     string               `json:"public_ip,omitempty"`
	WorkerConfig WorkerConfigSnapshot `json:"worker_config"`
}

type WorkerConfigSnapshot struct {
	ComputeSpec
	WorkspaceMode WorkspaceMode `json:"workspace_mode"`
	Limits        Limits        `json:"limits"`
}

func NewTaskResultSnapshot(plan Plan, resources []Resource, artifactIDs []string) (TaskResultSnapshot, error) {
	copy := plan
	if copy.Seal() != nil {
		return TaskResultSnapshot{}, ErrInvalid
	}
	snapshot := TaskResultSnapshot{
		ExecutionID: copy.ExecutionID,
		ArtifactIDs: slices.Clone(artifactIDs),
		ServerSnapshot: ServerSnapshot{
			Name: cloudaws.WorkerServerName(copy.ExecutionID, copy.Revision), Region: copy.AWS.Region,
			WorkerConfig: WorkerConfigSnapshot{ComputeSpec: copy.Compute, WorkspaceMode: copy.WorkspaceMode, Limits: copy.Limits},
		},
	}
	if snapshot.ServerSnapshot.Name == "" || strings.TrimSpace(snapshot.ServerSnapshot.Region) == "" {
		return TaskResultSnapshot{}, ErrInvalid
	}
	for _, artifactID := range snapshot.ArtifactIDs {
		if !validUUID(artifactID) {
			return TaskResultSnapshot{}, ErrInvalid
		}
	}
	seen := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if resource.ExecutionID != copy.ExecutionID || resource.AccountGeneration != copy.AccountGeneration ||
			(resource.Provider != "aws" && resource.Provider != "fake") ||
			!slices.Contains(cloudaws.AllResourceKinds(), cloudaws.ResourceKind(resource.Kind)) ||
			resource.AccountID != copy.AWS.AccountID || resource.Region != copy.AWS.Region || resource.ValidateObservedAddresses() != nil {
			return TaskResultSnapshot{}, ErrInvalid
		}
		if _, duplicate := seen[resource.Kind]; duplicate {
			return TaskResultSnapshot{}, ErrInvalid
		}
		seen[resource.Kind] = struct{}{}
		switch resource.Kind {
		case string(cloudaws.ResourceEC2):
			snapshot.ServerSnapshot.PrivateIP = resource.PrivateIP
		case string(cloudaws.ResourceEIP):
			snapshot.ServerSnapshot.PublicIP = resource.PublicIP
		}
	}
	return snapshot, nil
}

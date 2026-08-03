package workerprotocol

import "slices"

const WorkerManifestSchemaV1 = "dirextalk.worker.manifest/v1"

// WorkerManifestV1 is supplied by a publisher and reviewed before a release
// can enter a trusted registry. It cannot declare an arbitrary entrypoint,
// transport, network host, filesystem path, or cloud credential.
type WorkerManifestV1 struct {
	SchemaVersion        string             `json:"schema_version"`
	ProtocolVersion      string             `json:"protocol_version"`
	WorkerTypeID         string             `json:"worker_type_id"`
	Name                 string             `json:"name"`
	Description          string             `json:"description"`
	Entrypoint           string             `json:"entrypoint"`
	ControlTransport     string             `json:"control_transport"`
	Capabilities         []string           `json:"capabilities"`
	ModelInterfaces      []string           `json:"model_interfaces"`
	WorkspaceModes       []WorkspaceMode    `json:"workspace_modes"`
	RequestedPermissions PermissionSetV1    `json:"requested_permissions"`
	MinimumResources     ResourceEnvelopeV1 `json:"minimum_resources"`
	RecommendedResources ResourceEnvelopeV1 `json:"recommended_resources"`
	MaxTaskSeconds       uint64             `json:"max_task_seconds"`
	TaskConcurrency      uint32             `json:"task_concurrency"`
}

func (value WorkerManifestV1) Validate() error {
	if value.SchemaVersion != WorkerManifestSchemaV1 ||
		value.ProtocolVersion != ProtocolVersion ||
		!canonicalUUID(value.WorkerTypeID) ||
		!validText(value.Name, 128) ||
		!validText(value.Description, 2048) ||
		value.Entrypoint != FixedEntrypoint ||
		value.ControlTransport != FixedControlTransport ||
		len(value.Capabilities) == 0 ||
		len(value.Capabilities) > 64 ||
		!slices.IsSorted(value.Capabilities) ||
		hasDuplicate(value.Capabilities) ||
		len(value.ModelInterfaces) == 0 ||
		len(value.ModelInterfaces) > 16 ||
		!slices.IsSorted(value.ModelInterfaces) ||
		hasDuplicate(value.ModelInterfaces) ||
		len(value.WorkspaceModes) == 0 ||
		len(value.WorkspaceModes) > 3 ||
		!slices.IsSorted(value.WorkspaceModes) ||
		hasDuplicate(value.WorkspaceModes) ||
		value.RequestedPermissions.Validate() != nil ||
		value.MinimumResources.Validate() != nil ||
		value.RecommendedResources.Validate() != nil ||
		value.MinimumResources.Architecture !=
			value.RecommendedResources.Architecture ||
		value.RecommendedResources.VCPU <
			value.MinimumResources.VCPU ||
		value.RecommendedResources.MemoryMiB <
			value.MinimumResources.MemoryMiB ||
		value.RecommendedResources.DiskGiB <
			value.MinimumResources.DiskGiB ||
		value.MaxTaskSeconds == 0 ||
		value.MaxTaskSeconds > 7*24*60*60 ||
		value.TaskConcurrency != 1 {
		return ErrInvalid
	}
	for _, capability := range value.Capabilities {
		if !validToken(capability, 128) {
			return ErrInvalid
		}
	}
	for _, modelInterface := range value.ModelInterfaces {
		if !validToken(modelInterface, 128) {
			return ErrInvalid
		}
	}
	for _, mode := range value.WorkspaceModes {
		if mode != WorkspaceNone &&
			mode != WorkspaceReadOnly &&
			mode != WorkspaceIsolated {
			return ErrInvalid
		}
	}
	if !slices.Contains(
		value.WorkspaceModes,
		value.RequestedPermissions.Workspace,
	) {
		return ErrInvalid
	}
	return nil
}

func (value WorkerManifestV1) Digest() (string, error) {
	return digestValidated(value, value.Validate)
}

package cloudworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

// RuntimeTaskFence is the fresh CoreTask/WorkerControl fence required when
// building claim material. Attempt and lease epoch are validated here and
// carried separately by WorkerControl; they deliberately do not enter the
// immutable runtime task digest so a reclaim of the same EC2 dispatch cannot
// create a different authorized task.
type RuntimeTaskFence struct {
	ExecutionID       string
	TaskID            string
	AccountGeneration uint64
	Attempt           uint32
	LeaseEpoch        uint64
}

// RuntimeQualification is image-owned release evidence. It is resolved from
// the exact AMI qualification record, never from user input or the model.
type RuntimeQualification struct {
	WorkerProtocolVersion  string
	RuntimeContractVersion string
	PiRuntimeDigest        string
	PiVersion              string
	PiExecutableSHA256     string
	ResultExtensionSHA256  string
}

func (value RuntimeQualification) protocolVersions() cloudprotocol.Versions {
	return cloudprotocol.Versions{
		WorkerProtocolVersion:  value.WorkerProtocolVersion,
		RuntimeContractVersion: value.RuntimeContractVersion,
	}
}

type RuntimeTaskMaterial struct {
	ProtocolVersions     cloudprotocol.Versions
	Task                 cloudruntime.Task
	RuntimeTaskJSON      []byte
	RuntimeTaskSHA256    string
	InputManifestJSON    []byte
	InputManifestSHA256  string
	SourceManifestSHA256 string
	StagedManifestSHA256 string
	Fence                RuntimeTaskFence
}

func (material *RuntimeTaskMaterial) Destroy() {
	if material == nil {
		return
	}
	clear(material.RuntimeTaskJSON)
	clear(material.InputManifestJSON)
	*material = RuntimeTaskMaterial{}
}

// CloneForFence rebinds immutable claim material to the current CoreTask
// attempt/lease without changing the canonical Pi task or either content
// digest. Attempt and lease epoch deliberately live outside RuntimeTaskJSON;
// a lease reclaim must not invent a second authorized task or AWS dispatch.
func (material RuntimeTaskMaterial) CloneForFence(fence RuntimeTaskFence) (RuntimeTaskMaterial, error) {
	if validateRuntimeTaskFenceForMaterial(fence, material) != nil {
		return RuntimeTaskMaterial{}, ErrStaleAuthorization
	}
	task, err := cloudruntime.ParseTask(material.RuntimeTaskJSON)
	if err != nil || task != material.Task {
		return RuntimeTaskMaterial{}, ErrConflict
	}
	taskDigest, err := task.Digest()
	inputDigest := sha256.Sum256(material.InputManifestJSON)
	if err != nil || taskDigest != material.RuntimeTaskSHA256 ||
		!material.ProtocolVersions.IsCurrent() ||
		hex.EncodeToString(inputDigest[:]) != material.InputManifestSHA256 ||
		cloudruntime.ValidateInputManifestJSON(material.InputManifestJSON, material.InputManifestSHA256) != nil ||
		!validDigest(material.SourceManifestSHA256) || !validDigest(material.StagedManifestSHA256) {
		return RuntimeTaskMaterial{}, ErrConflict
	}
	clone := material
	clone.RuntimeTaskJSON = bytes.Clone(material.RuntimeTaskJSON)
	clone.InputManifestJSON = bytes.Clone(material.InputManifestJSON)
	clone.Fence = fence
	return clone, nil
}

func validateRuntimeTaskFenceForMaterial(fence RuntimeTaskFence, material RuntimeTaskMaterial) error {
	if fence.ExecutionID == "" || fence.TaskID == "" || fence.AccountGeneration == 0 || fence.Attempt == 0 || fence.LeaseEpoch == 0 ||
		fence.ExecutionID != material.Task.ExecutionID || fence.TaskID != material.Task.TaskID ||
		material.Fence.ExecutionID != fence.ExecutionID || material.Fence.TaskID != fence.TaskID ||
		material.Fence.AccountGeneration != fence.AccountGeneration || material.Fence.Attempt == 0 || material.Fence.LeaseEpoch == 0 {
		return ErrStaleAuthorization
	}
	return nil
}

// BuildRuntimeTask is the sole Plan -> Pi task compiler. It verifies the
// sealed plan/execution, exact staged S3 versions, current session fence, AMI
// qualification and relay mapping before returning canonical private claim
// material.
func BuildRuntimeTask(
	plan Plan,
	execution Execution,
	staged StagedInputManifest,
	fence RuntimeTaskFence,
	qualification RuntimeQualification,
) (RuntimeTaskMaterial, error) {
	sealedPlan := plan
	if sealedPlan.Seal() != nil || execution.Seal() != nil ||
		sealedPlan.ExecutionID != execution.ExecutionID ||
		sealedPlan.TaskID != execution.TaskID || sealedPlan.Digest != execution.PlanDigest ||
		sealedPlan.ExecutionDigest != execution.ExecutionDigest ||
		sealedPlan.AccountGeneration != execution.AccountGeneration ||
		!runtimeBuildState(execution.State) ||
		validateRuntimeTaskFence(fence, sealedPlan) != nil ||
		validateRuntimeQualification(qualification, sealedPlan) != nil {
		return RuntimeTaskMaterial{}, ErrStaleAuthorization
	}
	stagedCopy := staged
	stagedDigest, err := stagedCopy.Seal(sealedPlan.InputManifest)
	if err != nil || stagedCopy.ExecutionID != sealedPlan.ExecutionID {
		return RuntimeTaskMaterial{}, ErrInvalid
	}
	inputJSON, inputDigest, err := sanitizedRuntimeInputManifest(
		sealedPlan.InputManifest, stagedCopy,
	)
	if err != nil {
		return RuntimeTaskMaterial{}, err
	}
	piProvider, piInterface, err := PiRelayModel(sealedPlan.ModelAuthorization)
	if err != nil {
		clear(inputJSON)
		return RuntimeTaskMaterial{}, err
	}
	relayDigest := sha256.Sum256([]byte(sealedPlan.ModelRelay.Endpoint))
	task := cloudruntime.Task{
		SchemaVersion: cloudruntime.TaskSchemaV1,
		Recipe:        cloudruntime.RecipeEphemeralPiTask, Adapter: cloudruntime.AdapterPiJSONTaskV1,
		TaskID: sealedPlan.TaskID, ExecutionID: sealedPlan.ExecutionID,
		Objective: sealedPlan.Objective, InputManifestSHA256: inputDigest,
		WorkspaceMode:         cloudruntime.WorkspaceMode(sealedPlan.WorkspaceMode),
		PiVersion:             qualification.PiVersion,
		PiExecutableSHA256:    qualification.PiExecutableSHA256,
		ResultExtensionSHA256: qualification.ResultExtensionSHA256,
		ModelProfileID:        sealedPlan.ModelAuthorization.ModelProfileID,
		ModelProfileRevision:  sealedPlan.ModelAuthorization.ModelProfileRevision,
		ModelProvider:         piProvider, Model: sealedPlan.ModelAuthorization.Model,
		ModelInterface:           piInterface,
		CredentialVersion:        sealedPlan.ModelAuthorization.CredentialVersion,
		ModelBindingSHA256:       sealedPlan.ModelAuthorization.BindingDigest,
		ModelGrantAudienceSHA256: RuntimeGrantAudienceDigest(sealedPlan, fence),
		ModelGrantLimitSHA256:    digestValue(sealedPlan.Limits),
		ModelRelayBaseURL:        sealedPlan.ModelRelay.Endpoint,
		ModelRelayEndpointSHA256: hex.EncodeToString(relayDigest[:]),
		ModelRelayBindingSHA256:  sealedPlan.ModelRelay.BindingDigest,
		MaxOutputTokens:          sealedPlan.Limits.MaxTokens,
		MaxOutputBytes:           sealedPlan.Limits.MaxOutputBytes,
	}
	if sealedPlan.WorkspaceMode != WorkspaceNone {
		task.WorkspaceSHA256 = inputDigest
	}
	runtimeJSON, err := json.Marshal(task)
	if err != nil {
		clear(inputJSON)
		return RuntimeTaskMaterial{}, ErrInvalid
	}
	parsed, err := cloudruntime.ParseTask(runtimeJSON)
	if err != nil || parsed != task {
		clear(inputJSON)
		clear(runtimeJSON)
		return RuntimeTaskMaterial{}, ErrInvalid
	}
	taskDigest, err := task.Digest()
	if err != nil {
		clear(inputJSON)
		clear(runtimeJSON)
		return RuntimeTaskMaterial{}, ErrInvalid
	}
	return RuntimeTaskMaterial{
		ProtocolVersions: qualification.protocolVersions(),
		Task:             task, RuntimeTaskJSON: runtimeJSON, RuntimeTaskSHA256: taskDigest,
		InputManifestJSON: inputJSON, InputManifestSHA256: inputDigest,
		SourceManifestSHA256: sealedPlan.InputManifestDigest,
		StagedManifestSHA256: stagedDigest, Fence: fence,
	}, nil
}

func PiRelayModel(
	authorization ModelAuthorization,
) (string, cloudruntime.ModelInterface, error) {
	copy := authorization
	if copy.Seal() != nil {
		return "", "", ErrInvalid
	}
	switch {
	case copy.Provider == "openai" && copy.Interface == "openai_responses":
		return "openai", cloudruntime.ModelOpenAIResponses, nil
	case copy.Provider == "openai_compatible" && copy.Interface == "openai_compatible":
		// Pi's closed compatible adapter is named deepseek, but the model call
		// still terminates at the Agent relay and never at api.deepseek.com.
		return "deepseek", cloudruntime.ModelOpenAICompatible, nil
	default:
		return "", "", ErrInvalid
	}
}

func RuntimeGrantAudienceDigest(plan Plan, fence RuntimeTaskFence) string {
	return digestValue(struct {
		OwnerID           string `json:"owner_id"`
		AccountGeneration uint64 `json:"account_generation"`
		ExecutionID       string `json:"execution_id"`
		TaskID            string `json:"task_id"`
		PlanDigest        string `json:"plan_digest"`
		ExecutionDigest   string `json:"execution_digest"`
		ModelBinding      string `json:"model_binding_digest"`
	}{
		plan.OwnerID, plan.AccountGeneration, plan.ExecutionID, plan.TaskID,
		plan.Digest, plan.ExecutionDigest, plan.ModelAuthorization.BindingDigest,
	})
}

func sanitizedRuntimeInputManifest(
	source InputManifest,
	staged StagedInputManifest,
) ([]byte, string, error) {
	sourceCopy := source
	sourceDigest, err := sourceCopy.Seal()
	if err != nil {
		return nil, "", err
	}
	stagedCopy := staged
	if _, err := stagedCopy.Seal(sourceCopy); err != nil ||
		stagedCopy.SourceManifestDigest != sourceDigest {
		return nil, "", ErrInvalid
	}
	sources := make(map[string]InputManifestItem, len(sourceCopy.Items))
	for _, item := range sourceCopy.Items {
		sources[item.InputID] = item
	}
	type runtimeItem struct {
		InputID     string `json:"input_id"`
		Kind        string `json:"kind"`
		MediaType   string `json:"media_type"`
		MountPath   string `json:"mount_path"`
		Name        string `json:"name"`
		S3Bucket    string `json:"s3_bucket"`
		S3Key       string `json:"s3_key"`
		S3VersionID string `json:"s3_version_id"`
		SHA256      string `json:"sha256"`
		SizeBytes   uint64 `json:"size_bytes"`
	}
	manifest := struct {
		Items  []runtimeItem `json:"items"`
		Schema string        `json:"schema"`
	}{Items: make([]runtimeItem, 0, len(stagedCopy.Items)), Schema: InputManifestSchema}
	for _, item := range stagedCopy.Items {
		origin, ok := sources[item.InputID]
		if !ok {
			return nil, "", ErrInvalid
		}
		manifest.Items = append(manifest.Items, runtimeItem{
			InputID: item.InputID, Kind: origin.Kind, Name: origin.Name,
			MountPath: item.MountPath, MediaType: item.MediaType,
			SizeBytes: item.SizeBytes, SHA256: item.SHA256,
			S3Bucket: item.S3Bucket, S3Key: item.S3Key, S3VersionID: item.S3VersionID,
		})
	}
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) == 0 || len(raw) > cloudruntime.MaxInputManifestBytes ||
		strings.Contains(string(raw), "source_ref") ||
		strings.Contains(string(raw), "source_revision") {
		clear(raw)
		return nil, "", ErrInvalid
	}
	digest := sha256.Sum256(raw)
	digestText := hex.EncodeToString(digest[:])
	if cloudruntime.ValidateInputManifestJSON(raw, digestText) != nil {
		clear(raw)
		return nil, "", ErrInvalid
	}
	return raw, digestText, nil
}

func validateRuntimeTaskFence(fence RuntimeTaskFence, plan Plan) error {
	if fence.ExecutionID != plan.ExecutionID || fence.TaskID != plan.TaskID ||
		fence.AccountGeneration != plan.AccountGeneration || fence.Attempt == 0 ||
		fence.LeaseEpoch == 0 {
		return ErrStaleAuthorization
	}
	return nil
}

func validateRuntimeQualification(value RuntimeQualification, plan Plan) error {
	if !value.protocolVersions().IsCurrent() || !validDigest(value.PiRuntimeDigest) ||
		value.PiRuntimeDigest != plan.Compute.PiRuntimeDigest ||
		strings.TrimSpace(value.PiVersion) == "" ||
		!validDigest(value.PiExecutableSHA256) ||
		!validDigest(value.ResultExtensionSHA256) {
		return ErrInvalid
	}
	return nil
}

func runtimeBuildState(state ExecutionState) bool {
	switch state {
	case StateQueued, StateProvisioning, StateAwaitingWorker, StateRunning:
		return true
	default:
		return false
	}
}

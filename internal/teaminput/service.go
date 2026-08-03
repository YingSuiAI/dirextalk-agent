package teaminput

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

const MaterializationSchemaV1 = "dirextalk.agent.team-worker-input-materialization/v1"

var (
	ErrNotReady     = errors.New("Team Worker input is not ready")
	ErrFactMismatch = errors.New("Team Worker input fact mismatch")
)

type Status string

const (
	StatusMaterialized    Status = "materialized"
	StatusPublished       Status = "published"
	StatusCredentialReady Status = "credential_ready"
	StatusLaunchReady     Status = "launch_ready"
)

type MaterializationV1 struct {
	SchemaVersion         string                 `json:"schema_version"`
	InputID               string                 `json:"input_id"`
	OwnerID               string                 `json:"owner_id"`
	ExecutionID           string                 `json:"execution_id"`
	ExecutionDigest       string                 `json:"execution_digest"`
	RoleID                string                 `json:"role_id"`
	RoleDigest            string                 `json:"role_digest"`
	TaskID                string                 `json:"task_id"`
	TaskStepID            string                 `json:"task_step_id"`
	DeploymentID          string                 `json:"deployment_id"`
	ExpectedWorkerID      string                 `json:"expected_worker_id"`
	ContextSnapshotID     string                 `json:"context_snapshot_id"`
	ContextDigest         string                 `json:"context_digest"`
	WorkspaceSnapshotID   string                 `json:"workspace_snapshot_id"`
	WorkspaceDigest       string                 `json:"workspace_digest"`
	Manifest              ManifestV1             `json:"manifest"`
	ManifestDigest        string                 `json:"manifest_digest"`
	RuntimeTask           workerruntime.TaskV1   `json:"runtime_task"`
	RuntimeTaskDigest     string                 `json:"runtime_task_digest"`
	ExecutionBundleDigest string                 `json:"execution_bundle_digest"`
	CredentialGrant       CredentialGrantRequest `json:"credential_grant"`
	CredentialGrantDigest string                 `json:"credential_grant_digest"`
	ContextTargetPath     string                 `json:"context_target_path"`
	WorkspaceTargetPath   string                 `json:"workspace_target_path"`
	CredentialTargetPath  string                 `json:"credential_target_path"`
}

type Fact struct {
	Materialization MaterializationV1 `json:"materialization"`
	Status          Status            `json:"status"`
	RecordRevision  uint64            `json:"record_revision"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type MaterializeRequest struct {
	IdempotencyKey string
	OwnerID        string
	ExecutionID    string
	RoleID         string
}

// PersistCommand intentionally omits ContextBytes. The durable context source
// owns those encrypted bytes; PostgreSQL receives only their identity/digest
// plus the secret-free manifest and execution bundle.
type PersistCommand struct {
	IdempotencyKey      string
	Materialization     MaterializationV1
	ManifestJSON        []byte
	ExecutionBundleJSON []byte
}

type PreparedInput struct {
	Fact     Fact
	Compiled CompiledInput
}

func (prepared *PreparedInput) Destroy() {
	if prepared == nil {
		return
	}
	prepared.Compiled.Destroy()
	*prepared = PreparedInput{}
}

type ExecutionReader interface {
	GetTeamExecution(
		context.Context,
		string,
		string,
	) (teamexecution.Fact, error)
}

type ContextSource interface {
	LoadRoleContext(
		context.Context,
		teamexecution.ExecutionV1,
		teamexecution.RoleV1,
	) (ContextInput, error)
}

type WorkspaceSource interface {
	LoadRoleWorkspace(
		context.Context,
		teamexecution.ExecutionV1,
		teamexecution.RoleV1,
	) (WorkspaceSnapshot, error)
}

type Repository interface {
	FindMaterializedInput(
		context.Context,
		task.MutationScope,
		MaterializeRequest,
	) (Fact, bool, error)
	PersistMaterializedInput(
		context.Context,
		task.MutationScope,
		PersistCommand,
	) (Fact, error)
}

type Service struct {
	executions ExecutionReader
	contexts   ContextSource
	workspaces WorkspaceSource
	repository Repository
}

func NewService(
	executions ExecutionReader,
	contexts ContextSource,
	workspaces WorkspaceSource,
	repository Repository,
) (*Service, error) {
	if executions == nil ||
		contexts == nil ||
		workspaces == nil ||
		repository == nil {
		return nil, ErrInvalid
	}
	return &Service{
		executions: executions,
		contexts:   contexts,
		workspaces: workspaces,
		repository: repository,
	}, nil
}

func (service *Service) Materialize(
	ctx context.Context,
	scope task.MutationScope,
	request MaterializeRequest,
) (PreparedInput, error) {
	if service == nil ||
		service.executions == nil ||
		service.contexts == nil ||
		service.workspaces == nil ||
		service.repository == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		!validMaterializeRequest(request) {
		return PreparedInput{}, ErrInvalid
	}
	replayed, found, err := service.repository.FindMaterializedInput(
		ctx,
		scope,
		request,
	)
	if err != nil {
		return PreparedInput{}, err
	}
	executionFact, err := service.executions.GetTeamExecution(
		ctx,
		request.OwnerID,
		request.ExecutionID,
	)
	if err != nil {
		return PreparedInput{}, err
	}
	if !validExecutionFactForInput(executionFact) ||
		executionFact.Execution.OwnerID != request.OwnerID ||
		executionFact.Execution.ExecutionID != request.ExecutionID {
		return PreparedInput{}, ErrFactMismatch
	}
	if !found && !materializableExecutionStatus(executionFact.Status) {
		return PreparedInput{}, ErrNotReady
	}
	if found && !replayableExecutionStatus(executionFact.Status) {
		return PreparedInput{}, ErrFactMismatch
	}
	role, foundRole := findRole(
		executionFact.Execution.Roles,
		request.RoleID,
	)
	if !foundRole {
		return PreparedInput{}, ErrFactMismatch
	}
	contextInput, err := service.contexts.LoadRoleContext(
		ctx,
		executionFact.Execution,
		role,
	)
	if err != nil {
		return PreparedInput{}, err
	}
	workspace, err := service.workspaces.LoadRoleWorkspace(
		ctx,
		executionFact.Execution,
		role,
	)
	if err != nil {
		return PreparedInput{}, err
	}
	compiled, err := Compile(CompileRequest{
		Execution:       executionFact.Execution,
		ExecutionDigest: executionFact.ExecutionDigest,
		RoleID:          request.RoleID,
		Context:         contextInput,
		Workspace:       workspace,
	})
	if err != nil {
		return PreparedInput{}, err
	}
	materialization, err := materializationFromCompiled(
		executionFact.Execution,
		role,
		compiled,
	)
	if err != nil {
		compiled.Destroy()
		return PreparedInput{}, err
	}
	if found {
		if !sameMaterialization(
			replayed.Materialization,
			materialization,
		) ||
			!validFact(replayed) {
			compiled.Destroy()
			return PreparedInput{}, ErrFactMismatch
		}
		return PreparedInput{
			Fact: replayed, Compiled: compiled,
		}, nil
	}
	fact, err := service.repository.PersistMaterializedInput(
		ctx,
		scope,
		PersistCommand{
			IdempotencyKey:      request.IdempotencyKey,
			Materialization:     materialization,
			ManifestJSON:        bytes.Clone(compiled.ManifestBytes),
			ExecutionBundleJSON: bytes.Clone(compiled.ExecutionBytes),
		},
	)
	if err != nil {
		compiled.Destroy()
		return PreparedInput{}, err
	}
	if !validFact(fact) ||
		!sameMaterialization(fact.Materialization, materialization) {
		compiled.Destroy()
		return PreparedInput{}, ErrFactMismatch
	}
	return PreparedInput{Fact: fact, Compiled: compiled}, nil
}

func InputID(executionID, roleID string) (string, error) {
	parsed, err := uuid.Parse(executionID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != executionID ||
		!validRoleID(roleID) {
		return "", ErrInvalid
	}
	return uuid.NewSHA1(
		parsed,
		[]byte("team-worker-input/v1\x00"+roleID),
	).String(), nil
}

func materializationFromCompiled(
	execution teamexecution.ExecutionV1,
	role teamexecution.RoleV1,
	compiled CompiledInput,
) (MaterializationV1, error) {
	inputID, err := InputID(execution.ExecutionID, role.RoleID)
	if err != nil {
		return MaterializationV1{}, err
	}
	roleDigest, err := role.Digest()
	if err != nil {
		return MaterializationV1{}, ErrInvalid
	}
	value := MaterializationV1{
		SchemaVersion:         MaterializationSchemaV1,
		InputID:               inputID,
		OwnerID:               execution.OwnerID,
		ExecutionID:           execution.ExecutionID,
		ExecutionDigest:       compiled.Manifest.ExecutionDigest,
		RoleID:                role.RoleID,
		RoleDigest:            roleDigest,
		TaskID:                execution.TaskID,
		TaskStepID:            role.TaskStepID,
		DeploymentID:          role.DeploymentID,
		ExpectedWorkerID:      role.ExpectedWorkerID,
		ContextSnapshotID:     compiled.Manifest.ContextSnapshotID,
		ContextDigest:         compiled.Manifest.ContextDigest,
		WorkspaceSnapshotID:   compiled.Manifest.WorkspaceSnapshotID,
		WorkspaceDigest:       compiled.Manifest.WorkspaceDigest,
		Manifest:              compiled.Manifest,
		ManifestDigest:        compiled.ManifestDigest,
		RuntimeTask:           compiled.RuntimeTask,
		RuntimeTaskDigest:     compiled.Manifest.RuntimeTaskDigest,
		ExecutionBundleDigest: compiled.ExecutionBundleDigest,
		CredentialGrant:       compiled.CredentialGrant,
		CredentialGrantDigest: compiled.CredentialGrantDigest,
		ContextTargetPath:     compiled.ContextTargetPath,
		WorkspaceTargetPath:   compiled.WorkspaceTargetPath,
		CredentialTargetPath:  compiled.CredentialTargetPath,
	}
	if value.Validate() != nil {
		return MaterializationV1{}, ErrInvalid
	}
	return value, nil
}

func (value MaterializationV1) Validate() error {
	expectedInputID, err := InputID(value.ExecutionID, value.RoleID)
	if err != nil ||
		value.SchemaVersion != MaterializationSchemaV1 ||
		value.InputID != expectedInputID ||
		!validSafeText(value.OwnerID, 255) ||
		!canonicalUUID(value.TaskID) ||
		!canonicalUUID(value.TaskStepID) ||
		!canonicalUUID(value.DeploymentID) ||
		!canonicalUUID(value.ExpectedWorkerID) ||
		!canonicalUUID(value.ContextSnapshotID) ||
		!digestPattern.MatchString(value.ExecutionDigest) ||
		!digestPattern.MatchString(value.RoleDigest) ||
		!digestPattern.MatchString(value.ContextDigest) ||
		!canonicalUUID(value.WorkspaceSnapshotID) ||
		!digestPattern.MatchString(value.WorkspaceDigest) ||
		!digestPattern.MatchString(value.ManifestDigest) ||
		!digestPattern.MatchString(value.RuntimeTaskDigest) ||
		!digestPattern.MatchString(value.ExecutionBundleDigest) ||
		!digestPattern.MatchString(value.CredentialGrantDigest) ||
		value.RuntimeTask.Validate() != nil ||
		validateCredentialGrant(value.CredentialGrant) != nil {
		return ErrInvalid
	}
	runtimeTaskDigest, err := value.RuntimeTask.Digest()
	if err != nil || runtimeTaskDigest != value.RuntimeTaskDigest {
		return ErrInvalid
	}
	manifestBytes, err := json.Marshal(value.Manifest)
	if err != nil || digestBytes(manifestBytes) != value.ManifestDigest {
		clear(manifestBytes)
		return ErrInvalid
	}
	clear(manifestBytes)
	credentialBytes, err := json.Marshal(value.CredentialGrant)
	if err != nil ||
		digestBytes(credentialBytes) != value.CredentialGrantDigest {
		clear(credentialBytes)
		return ErrInvalid
	}
	clear(credentialBytes)
	if value.Manifest.ExecutionID != value.ExecutionID ||
		value.Manifest.ExecutionDigest != value.ExecutionDigest ||
		value.Manifest.TaskID != value.TaskID ||
		value.Manifest.TaskStepID != value.TaskStepID ||
		value.Manifest.RoleID != value.RoleID ||
		value.Manifest.RoleDigest != value.RoleDigest ||
		value.Manifest.DeploymentID != value.DeploymentID ||
		value.Manifest.ExpectedWorkerID != value.ExpectedWorkerID ||
		value.Manifest.ContextSnapshotID != value.ContextSnapshotID ||
		value.Manifest.ContextDigest != value.ContextDigest ||
		value.Manifest.WorkspaceSnapshotID != value.WorkspaceSnapshotID ||
		value.Manifest.WorkspaceDigest != value.WorkspaceDigest ||
		value.Manifest.RuntimeTaskDigest != value.RuntimeTaskDigest ||
		value.RuntimeTask.TaskID != value.TaskID ||
		value.RuntimeTask.RoleID != value.RoleID ||
		value.RuntimeTask.ContextDigest != value.ContextDigest ||
		value.RuntimeTask.WorkspaceDigest != value.WorkspaceDigest ||
		value.RuntimeTask.CredentialSlot !=
			value.CredentialGrant.CredentialSlot ||
		value.CredentialGrant.ExecutionID != value.ExecutionID ||
		value.CredentialGrant.RoleID != value.RoleID ||
		value.CredentialGrant.DeploymentID != value.DeploymentID ||
		value.CredentialGrant.ExpectedWorkerID !=
			value.ExpectedWorkerID ||
		value.ContextTargetPath != path.Join(
			workerruntime.DefaultContextRoot,
			strings.TrimPrefix(value.ContextDigest, "sha256:")+
				".json",
		) ||
		value.WorkspaceTargetPath != path.Join(
			workerruntime.DefaultWorkspaceRoot,
			strings.TrimPrefix(value.WorkspaceDigest, "sha256:"),
		) ||
		value.CredentialTargetPath != path.Join(
			workerruntime.DefaultCredentialRoot,
			value.CredentialGrant.CredentialSlot,
		) {
		return ErrInvalid
	}
	return nil
}

func (command PersistCommand) Validate() error {
	if !canonicalUUID(command.IdempotencyKey) ||
		command.Materialization.Validate() != nil ||
		len(command.ManifestJSON) == 0 ||
		len(command.ExecutionBundleJSON) == 0 ||
		!json.Valid(command.ManifestJSON) ||
		!json.Valid(command.ExecutionBundleJSON) ||
		digestBytes(command.ManifestJSON) !=
			command.Materialization.ManifestDigest ||
		digestBytes(command.ExecutionBundleJSON) !=
			command.Materialization.ExecutionBundleDigest {
		return ErrInvalid
	}
	expectedManifest, err := json.Marshal(command.Materialization.Manifest)
	if err != nil || !bytes.Equal(command.ManifestJSON, expectedManifest) {
		clear(expectedManifest)
		return ErrInvalid
	}
	clear(expectedManifest)
	return nil
}

func validFact(fact Fact) bool {
	if fact.Materialization.Validate() != nil ||
		fact.RecordRevision == 0 ||
		fact.CreatedAt.IsZero() ||
		fact.UpdatedAt.IsZero() {
		return false
	}
	switch fact.Status {
	case StatusMaterialized,
		StatusPublished,
		StatusCredentialReady,
		StatusLaunchReady:
		return true
	default:
		return false
	}
}

func validMaterializeRequest(request MaterializeRequest) bool {
	return canonicalUUID(request.IdempotencyKey) &&
		validSafeText(request.OwnerID, 255) &&
		canonicalUUID(request.ExecutionID) &&
		validRoleID(request.RoleID)
}

func replayableExecutionStatus(status teamexecution.Status) bool {
	switch status {
	case teamexecution.StatusDispatching,
		teamexecution.StatusRunning,
		teamexecution.StatusVerifying,
		teamexecution.StatusCompleted,
		teamexecution.StatusFailed,
		teamexecution.StatusCanceled:
		return true
	default:
		return false
	}
}

func materializableExecutionStatus(status teamexecution.Status) bool {
	return status == teamexecution.StatusDispatching ||
		status == teamexecution.StatusRunning
}

func validExecutionFactForInput(fact teamexecution.Fact) bool {
	digest, err := fact.Execution.Digest()
	return err == nil &&
		digest == fact.ExecutionDigest &&
		fact.RecordRevision > 0 &&
		!fact.CreatedAt.IsZero() &&
		!fact.UpdatedAt.IsZero()
}

func sameMaterialization(
	left,
	right MaterializationV1,
) bool {
	return reflect.DeepEqual(left, right)
}

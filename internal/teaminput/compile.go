package teaminput

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func Compile(request CompileRequest) (CompiledInput, error) {
	execution := request.Execution
	if execution.Validate() != nil ||
		!digestPattern.MatchString(request.ExecutionDigest) {
		return CompiledInput{}, ErrInvalid
	}
	actualExecutionDigest, err := execution.Digest()
	if err != nil || actualExecutionDigest != request.ExecutionDigest {
		return CompiledInput{}, ErrInvalid
	}
	role, found := findRole(execution.Roles, request.RoleID)
	if !found {
		return CompiledInput{}, ErrInvalid
	}
	roleDigest, err := role.Digest()
	if err != nil {
		return CompiledInput{}, ErrInvalid
	}
	expectedContextID, err := ContextSnapshotID(
		execution.ExecutionID,
		role.RoleID,
	)
	if err != nil || request.Context.SnapshotID != expectedContextID {
		return CompiledInput{}, ErrInvalid
	}
	contextDocument, err := compileContext(
		execution,
		request.ExecutionDigest,
		role,
		request.Context,
	)
	if err != nil {
		return CompiledInput{}, err
	}
	contextBytes, err := json.Marshal(contextDocument)
	if err != nil ||
		len(contextBytes) == 0 ||
		len(contextBytes) > workerruntime.MaxContextBytes ||
		security.ContainsLikelySecret(string(contextBytes)) {
		clear(contextBytes)
		return CompiledInput{}, ErrInvalid
	}
	contextDigest := digestBytes(contextBytes)

	workspaceMode, includePatch, err := runtimeWorkspace(role.Workspace)
	if err == nil &&
		execution.SchemaVersion == teamexecution.SchemaV3 &&
		taskinput.IsEmptyInput(execution.TaskInput) {
		includePatch = false
	}
	expectedWorkspaceID, workspaceIDErr := WorkspaceSnapshotID(
		execution.ExecutionID,
		role.RoleID,
	)
	if err != nil ||
		workspaceIDErr != nil ||
		request.Workspace.SnapshotID != expectedWorkspaceID ||
		!digestPattern.MatchString(request.Workspace.Digest) ||
		request.Workspace.SizeBytes < 1 ||
		request.Workspace.SizeBytes >
			workerrunner.MaxWorkspaceArchiveBytes {
		clear(contextBytes)
		return CompiledInput{}, ErrInvalid
	}
	adapter, err := runtimeAdapter(role.RuntimeAdapter)
	if err != nil {
		clear(contextBytes)
		return CompiledInput{}, err
	}
	modelInterface, err := runtimeModelInterface(role.ModelInterface)
	if err != nil {
		clear(contextBytes)
		return CompiledInput{}, err
	}
	runtimeTask := workerruntime.TaskV1{
		SchemaVersion:      workerruntime.TaskSchemaV1,
		TaskID:             execution.TaskID,
		RoleID:             role.RoleID,
		Adapter:            adapter,
		RuntimeReleaseID:   role.RuntimeReleaseID,
		RuntimeVersion:     role.RuntimeVersion,
		RuntimeImageDigest: role.RuntimeImageDigest,
		ContextDigest:      contextDigest,
		WorkspaceMode:      workspaceMode,
		WorkspaceDigest:    request.Workspace.Digest,
		Objective:          role.Objective,
		ModelProfileID:     role.ModelProfileID,
		ModelProvider:      role.ModelProvider,
		Model:              role.Model,
		ModelInterface:     modelInterface,
		MaxOutputTokens:    role.Tokens.OutputMaximum,
		CredentialSlot:     role.ModelCredentialSlot,
		IncludePatch:       includePatch,
	}
	runtimeTaskDigest, err := runtimeTask.Digest()
	if err != nil {
		clear(contextBytes)
		return CompiledInput{}, ErrInvalid
	}
	manifest := ManifestV1{
		SchemaVersion:       ManifestSchemaV1,
		ExecutionID:         execution.ExecutionID,
		ExecutionDigest:     request.ExecutionDigest,
		PlanID:              execution.PlanID,
		PlanDigest:          execution.PlanDigest,
		TaskID:              execution.TaskID,
		TaskStepID:          role.TaskStepID,
		RoleID:              role.RoleID,
		RoleDigest:          roleDigest,
		DeploymentID:        role.DeploymentID,
		ExpectedWorkerID:    role.ExpectedWorkerID,
		ContextSnapshotID:   request.Context.SnapshotID,
		ContextDigest:       contextDigest,
		WorkspaceMode:       workspaceMode,
		WorkspaceSnapshotID: request.Workspace.SnapshotID,
		WorkspaceDigest:     request.Workspace.Digest,
		CredentialSlot:      role.ModelCredentialSlot,
		RuntimeTaskDigest:   runtimeTaskDigest,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil ||
		len(manifestBytes) == 0 ||
		security.ContainsLikelySecret(string(manifestBytes)) {
		clear(contextBytes)
		clear(manifestBytes)
		return CompiledInput{}, ErrInvalid
	}
	manifestDigest := digestBytes(manifestBytes)
	if role.Duration.MaximumSeconds > uint64(math.MaxUint32) {
		clear(contextBytes)
		clear(manifestBytes)
		return CompiledInput{}, ErrInvalid
	}
	contextObject := workerrunner.MaterializeObjectV1{
		ObjectName: teamInputObjectName(
			"context",
			contextDigest,
			".json",
		),
		SHA256:      contextDigest,
		SizeBytes:   int64(len(contextBytes)),
		ContentType: "application/json",
	}
	workspaceObject := workerrunner.MaterializeObjectV1{
		ObjectName: teamInputObjectName(
			"workspace",
			request.Workspace.Digest,
			".tar",
		),
		SHA256:      request.Workspace.Digest,
		SizeBytes:   request.Workspace.SizeBytes,
		ContentType: "application/x-tar",
	}
	executionBundle := workerrunner.ExecutionBundleV1{
		SchemaVersion: 1,
		RecipeSHA256: strings.TrimPrefix(
			manifestDigest,
			"sha256:",
		),
		Actions: []workerrunner.ActionV1{
			{
				ID:             "materialize-input",
				Kind:           workerrunner.InputMaterializeActionKind,
				TimeoutSeconds: uint32(role.Duration.MaximumSeconds),
				Input: &workerrunner.InputMaterializeInputV1{
					Context:   contextObject,
					Workspace: &workspaceObject,
				},
			},
			{
				ID:             "execute-role",
				Kind:           workerrunner.RuntimeExecuteActionKind,
				TimeoutSeconds: uint32(role.Duration.MaximumSeconds),
				Runtime: &workerrunner.RuntimeExecuteInputV1{
					Task: runtimeTask,
				},
			},
		},
	}
	executionBytes, err := json.Marshal(executionBundle)
	if err != nil ||
		len(executionBytes) == 0 ||
		security.ContainsLikelySecret(string(executionBytes)) {
		clear(contextBytes)
		clear(manifestBytes)
		clear(executionBytes)
		return CompiledInput{}, ErrInvalid
	}
	bundleDigest := digestBytes(executionBytes)
	credentialGrant := CredentialGrantRequest{
		ExecutionID:            execution.ExecutionID,
		RoleID:                 role.RoleID,
		DeploymentID:           role.DeploymentID,
		ExpectedWorkerID:       role.ExpectedWorkerID,
		CredentialSlot:         role.ModelCredentialSlot,
		ModelProfileID:         role.ModelProfileID,
		ModelProvider:          role.ModelProvider,
		Model:                  role.Model,
		ModelInterface:         modelInterface,
		MaximumInputTokens:     role.Tokens.InputMaximum,
		MaximumOutputTokens:    role.Tokens.OutputMaximum,
		MaximumDurationSeconds: role.Duration.MaximumSeconds,
	}
	if validateCredentialGrant(credentialGrant) != nil {
		clear(contextBytes)
		clear(manifestBytes)
		clear(executionBytes)
		return CompiledInput{}, ErrInvalid
	}
	credentialGrantBytes, err := json.Marshal(credentialGrant)
	if err != nil ||
		security.ContainsLikelySecret(string(credentialGrantBytes)) {
		clear(contextBytes)
		clear(manifestBytes)
		clear(executionBytes)
		clear(credentialGrantBytes)
		return CompiledInput{}, ErrInvalid
	}
	credentialGrantDigest := digestBytes(credentialGrantBytes)
	clear(credentialGrantBytes)
	return CompiledInput{
		Manifest:              manifest,
		ManifestBytes:         manifestBytes,
		ManifestDigest:        manifestDigest,
		Context:               contextDocument,
		ContextBytes:          contextBytes,
		RuntimeTask:           runtimeTask,
		ExecutionBytes:        executionBytes,
		ExecutionBundleDigest: bundleDigest,
		ContextObject:         contextObject,
		WorkspaceObject:       workspaceObject,
		CredentialGrant:       credentialGrant,
		CredentialGrantDigest: credentialGrantDigest,
		ContextTargetPath: path.Join(
			workerruntime.DefaultContextRoot,
			strings.TrimPrefix(contextDigest, "sha256:")+".json",
		),
		WorkspaceTargetPath: path.Join(
			workerruntime.DefaultWorkspaceRoot,
			strings.TrimPrefix(request.Workspace.Digest, "sha256:"),
		),
		CredentialTargetPath: path.Join(
			workerruntime.DefaultCredentialRoot,
			role.ModelCredentialSlot,
		),
	}, nil
}

func teamInputObjectName(
	kind string,
	digest string,
	suffix string,
) string {
	return "team-" + kind + "-" +
		strings.TrimPrefix(digest, "sha256:") + suffix
}

// ContextSnapshotID is the stable lookup identity for the transient,
// encrypted context payload of one Execution role.
func ContextSnapshotID(executionID, roleID string) (string, error) {
	parsed, err := uuid.Parse(executionID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != executionID ||
		!validRoleID(roleID) {
		return "", ErrInvalid
	}
	return uuid.NewSHA1(
		parsed,
		[]byte("team-worker-context/v1\x00"+roleID),
	).String(), nil
}

// WorkspaceSnapshotID is stable for one Execution role. A trusted snapshot
// service may produce the bytes, but it cannot rebind them to another role.
func WorkspaceSnapshotID(executionID, roleID string) (string, error) {
	parsed, err := uuid.Parse(executionID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != executionID ||
		!validRoleID(roleID) {
		return "", ErrInvalid
	}
	return uuid.NewSHA1(
		parsed,
		[]byte("team-worker-workspace/v1\x00"+roleID),
	).String(), nil
}

func compileContext(
	execution teamexecution.ExecutionV1,
	executionDigest string,
	role teamexecution.RoleV1,
	input ContextInput,
) (ContextDocumentV1, error) {
	if input.GoalDigest != execution.GoalDigest ||
		!validSafeText(input.GoalSummary, MaxGoalSummaryBytes) ||
		len(input.Constraints) > MaxConstraints ||
		len(input.Artifacts) > MaxArtifacts {
		return ContextDocumentV1{}, ErrInvalid
	}
	constraints := append([]string(nil), input.Constraints...)
	slices.Sort(constraints)
	for index, constraint := range constraints {
		if !validSafeText(constraint, MaxConstraintBytes) ||
			index > 0 && constraints[index-1] == constraint {
			return ContextDocumentV1{}, ErrInvalid
		}
	}
	dependencies := append(
		[]DependencyResultV1(nil),
		input.Dependencies...,
	)
	slices.SortFunc(
		dependencies,
		func(left, right DependencyResultV1) int {
			return strings.Compare(left.RoleID, right.RoleID)
		},
	)
	if len(dependencies) != len(role.DependsOnRoleIDs) {
		return ContextDocumentV1{}, ErrInvalid
	}
	for index, dependencyRoleID := range role.DependsOnRoleIDs {
		dependency := dependencies[index]
		dependencyRole, found := findRole(
			execution.Roles,
			dependencyRoleID,
		)
		if !found ||
			dependency.RoleID != dependencyRoleID ||
			dependency.TaskStepID != dependencyRole.TaskStepID ||
			!digestPattern.MatchString(dependency.ResultDigest) ||
			!validSafeText(
				dependency.Summary,
				MaxDependencySummaryBytes,
			) {
			return ContextDocumentV1{}, ErrInvalid
		}
	}
	artifacts := append([]ArtifactRefV1(nil), input.Artifacts...)
	slices.SortFunc(
		artifacts,
		func(left, right ArtifactRefV1) int {
			return strings.Compare(left.ArtifactID, right.ArtifactID)
		},
	)
	for index, artifact := range artifacts {
		if !canonicalUUID(artifact.ArtifactID) ||
			!digestPattern.MatchString(artifact.Digest) ||
			!validArtifactMediaType(artifact.MediaType) ||
			!validSafeText(artifact.Purpose, 512) ||
			index > 0 &&
				artifacts[index-1].ArtifactID == artifact.ArtifactID {
			return ContextDocumentV1{}, ErrInvalid
		}
	}
	return ContextDocumentV1{
		SchemaVersion:     ContextSchemaV1,
		ExecutionID:       execution.ExecutionID,
		ExecutionDigest:   executionDigest,
		PlanID:            execution.PlanID,
		PlanDigest:        execution.PlanDigest,
		TaskID:            execution.TaskID,
		TaskStepID:        role.TaskStepID,
		RoleID:            role.RoleID,
		ContextSnapshotID: input.SnapshotID,
		GoalDigest:        execution.GoalDigest,
		GoalSummary:       input.GoalSummary,
		Objective:         role.Objective,
		Constraints:       constraints,
		Dependencies:      dependencies,
		Artifacts:         artifacts,
	}, nil
}

func validateCredentialGrant(value CredentialGrantRequest) error {
	if !canonicalUUID(value.ExecutionID) ||
		!validRoleID(value.RoleID) ||
		!canonicalUUID(value.DeploymentID) ||
		!canonicalUUID(value.ExpectedWorkerID) ||
		!validIdentifier(value.CredentialSlot, 64) ||
		!validIdentifier(value.ModelProfileID, 160) ||
		!validIdentifier(value.ModelProvider, 128) ||
		!validIdentifier(value.Model, 256) ||
		value.MaximumInputTokens == 0 ||
		value.MaximumOutputTokens == 0 ||
		value.MaximumDurationSeconds == 0 ||
		value.MaximumDurationSeconds > 7*24*60*60 {
		return ErrInvalid
	}
	switch value.ModelInterface {
	case workerruntime.ModelAnthropicAPI,
		workerruntime.ModelOpenAIResponses,
		workerruntime.ModelOpenAICompatible:
	default:
		return ErrInvalid
	}
	return nil
}

func runtimeAdapter(
	value teamplan.RuntimeAdapter,
) (workerruntime.Adapter, error) {
	switch value {
	case teamplan.AdapterClaudeCodeV1,
		teamplan.AdapterCodexV1,
		teamplan.AdapterOpenClawV1,
		teamplan.AdapterHermesV1,
		teamplan.AdapterOpenCodeV1,
		teamplan.AdapterPiV1:
		return workerruntime.Adapter(value), nil
	default:
		return "", ErrInvalid
	}
}

func runtimeModelInterface(
	value teamplan.ModelInterface,
) (workerruntime.ModelInterface, error) {
	switch value {
	case teamplan.ModelAnthropicAPI,
		teamplan.ModelOpenAIResponses,
		teamplan.ModelOpenAICompatible:
		return workerruntime.ModelInterface(value), nil
	default:
		return "", ErrInvalid
	}
}

func runtimeWorkspace(
	value teamplan.WorkspaceMode,
) (workerruntime.WorkspaceMode, bool, error) {
	switch value {
	case teamplan.WorkspaceReadOnly:
		return workerruntime.WorkspaceReadOnly, false, nil
	case teamplan.WorkspaceIsolated:
		return workerruntime.WorkspaceIsolated, true, nil
	case teamplan.WorkspaceExclusive:
		return workerruntime.WorkspaceExclusive, true, nil
	default:
		return "", false, ErrInvalid
	}
}

func findRole(
	roles []teamexecution.RoleV1,
	roleID string,
) (teamexecution.RoleV1, bool) {
	index, found := slices.BinarySearchFunc(
		roles,
		roleID,
		func(role teamexecution.RoleV1, target string) int {
			return strings.Compare(role.RoleID, target)
		},
	)
	if !found {
		return teamexecution.RoleV1{}, false
	}
	return roles[index], true
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == value
}

func validSafeText(value string, maximum int) bool {
	if value == "" ||
		value != strings.TrimSpace(value) ||
		len(value) > maximum ||
		!utf8.ValidString(value) ||
		strings.IndexByte(value, 0) >= 0 ||
		security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) &&
			character != '\n' &&
			character != '\r' &&
			character != '\t' {
			return false
		}
	}
	return true
}

func validArtifactMediaType(value string) bool {
	switch value {
	case "application/json",
		"application/octet-stream",
		"text/plain; charset=utf-8",
		"application/x-tar":
		return true
	default:
		return false
	}
}

func validRoleID(value string) bool {
	if len(value) == 0 || len(value) > 64 ||
		value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' {
					return false
				}
			}
		}
	}
	return true
}

func validIdentifier(value string, maximum int) bool {
	return value != "" &&
		value == strings.TrimSpace(value) &&
		len(value) <= maximum &&
		!security.ContainsLikelySecret(value) &&
		strings.IndexByte(value, 0) < 0
}

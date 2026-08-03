package app

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamresult"
	"github.com/google/uuid"
)

type teamTaskReader interface {
	Get(context.Context, string) (task.Task, error)
}

type durableTeamContextSource struct {
	tasks      teamTaskReader
	dispatches teamdispatch.Repository
}

func newDurableTeamContextSource(
	tasks teamTaskReader,
	dispatches teamdispatch.Repository,
) (*durableTeamContextSource, error) {
	if tasks == nil || dispatches == nil {
		return nil, teaminput.ErrInvalid
	}
	return &durableTeamContextSource{
		tasks:      tasks,
		dispatches: dispatches,
	}, nil
}

func (source *durableTeamContextSource) LoadRoleContext(
	ctx context.Context,
	execution teamexecution.ExecutionV1,
	role teamexecution.RoleV1,
) (teaminput.ContextInput, error) {
	if source == nil ||
		source.tasks == nil ||
		source.dispatches == nil ||
		ctx == nil ||
		execution.Validate() != nil {
		return teaminput.ContextInput{}, teaminput.ErrInvalid
	}
	currentTask, err := source.tasks.Get(ctx, execution.TaskID)
	if err != nil {
		return teaminput.ContextInput{}, err
	}
	goal := strings.TrimSpace(currentTask.Goal)
	if currentTask.OwnerID != execution.OwnerID ||
		currentTask.TaskID != execution.TaskID ||
		goal == "" ||
		len(goal) > teaminput.MaxGoalSummaryBytes {
		return teaminput.ContextInput{}, teaminput.ErrNotReady
	}
	snapshotID, err := teaminput.ContextSnapshotID(
		execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		return teaminput.ContextInput{}, teaminput.ErrInvalid
	}
	operations, err := source.dispatches.ListExecutionOperations(
		ctx,
		execution.OwnerID,
		execution.ExecutionID,
	)
	if err != nil {
		return teaminput.ContextInput{}, err
	}
	byRole := make(
		map[string]teamdispatch.Fact,
		len(operations),
	)
	for _, operation := range operations {
		if operation.Validate() != nil {
			return teaminput.ContextInput{},
				teaminput.ErrFactMismatch
		}
		byRole[operation.Intent.RoleID] = operation
	}
	dependencies := make(
		[]teaminput.DependencyResultV1,
		0,
		len(role.DependsOnRoleIDs),
	)
	artifacts := make(
		[]teaminput.ArtifactRefV1,
		0,
		len(role.DependsOnRoleIDs),
	)
	for _, dependencyRoleID := range role.DependsOnRoleIDs {
		dependencyRole, found := executionRole(
			execution.Roles,
			dependencyRoleID,
		)
		operation, operationFound := byRole[dependencyRoleID]
		if !found ||
			!operationFound ||
			operation.Phase != teamdispatch.PhaseCompleted ||
			operation.Outcome != task.OutcomeSucceeded ||
			operation.ResultEvidence == nil ||
			operation.ResultEvidenceDigest == "" {
			return teaminput.ContextInput{},
				teaminput.ErrNotReady
		}
		summary, err := teamDependencySummary(
			*operation.ResultEvidence,
		)
		if err != nil {
			return teaminput.ContextInput{}, err
		}
		dependencies = append(
			dependencies,
			teaminput.DependencyResultV1{
				RoleID:       dependencyRoleID,
				TaskStepID:   dependencyRole.TaskStepID,
				ResultDigest: operation.ResultEvidenceDigest,
				Summary:      summary,
			},
		)
		for _, final := range operation.ResultEvidence.Finals {
			artifacts = append(
				artifacts,
				teaminput.ArtifactRefV1{
					ArtifactID: uuid.NewSHA1(
						uuid.MustParse(
							operation.Intent.OperationID,
						),
						[]byte(
							"team-result-artifact/v1\x00"+
								final.ActionID,
						),
					).String(),
					Digest:    final.ArtifactSHA256,
					MediaType: final.ArtifactMediaType,
					Purpose: "Validated final output from role " +
						dependencyRoleID + ".",
				},
			)
		}
	}
	return teaminput.ContextInput{
		SnapshotID:  snapshotID,
		GoalDigest:  execution.GoalDigest,
		GoalSummary: goal,
		Constraints: []string{
			"Do not expose credentials or inspect credential locations.",
			teamSourceConstraint(execution),
			"Return only evidence supported by this role's inputs and tools.",
		},
		Dependencies: dependencies,
		Artifacts:    artifacts,
	}, nil
}

func teamSourceConstraint(execution teamexecution.ExecutionV1) string {
	if execution.SchemaVersion != teamexecution.SchemaV3 {
		return "No source workspace was supplied; do not claim that existing files were inspected."
	}
	switch execution.TaskInput.SourceKind {
	case taskinput.SourceGitHubRepository:
		return "Use only the supplied immutable snapshot of the approved GitHub commit; do not fetch another revision or request repository credentials."
	case taskinput.SourceWorkspaceArchive:
		return "Use only the supplied immutable workspace archive; do not fetch replacement source."
	default:
		return "No source workspace was supplied; do not claim that existing files were inspected."
	}
}

func teamDependencySummary(
	evidence teamresult.EvidenceV1,
) (string, error) {
	if evidence.Validate() != nil {
		return "", teaminput.ErrFactMismatch
	}
	summaries := make([]string, 0, len(evidence.Finals))
	for _, final := range evidence.Finals {
		summaries = append(summaries, final.Summary)
	}
	summary := strings.Join(summaries, "\n")
	if summary != "" &&
		len(summary) <= teaminput.MaxDependencySummaryBytes {
		return summary, nil
	}
	return "", teaminput.ErrFactMismatch
}

type emptyTeamWorkspaceProvider struct {
	content []byte
	digest  string
}

func newEmptyTeamWorkspaceProvider() (*emptyTeamWorkspaceProvider, error) {
	content, digest := taskinput.EmptyWorkspace()
	if len(content) == 0 || digest == "" {
		return nil, teaminput.ErrInvalid
	}
	return &emptyTeamWorkspaceProvider{
		content: content,
		digest:  digest,
	}, nil
}

func (provider *emptyTeamWorkspaceProvider) LoadRoleWorkspace(
	_ context.Context,
	execution teamexecution.ExecutionV1,
	role teamexecution.RoleV1,
) (teaminput.WorkspaceSnapshot, error) {
	if provider == nil ||
		len(provider.content) == 0 ||
		execution.Validate() != nil ||
		!taskinput.IsEmptyInput(execution.TaskInput) ||
		execution.TaskInput.Workspace.WorkspaceDigest != provider.digest ||
		execution.TaskInput.Workspace.WorkspaceSizeBytes !=
			int64(len(provider.content)) {
		return teaminput.WorkspaceSnapshot{}, teaminput.ErrInvalid
	}
	if _, found := executionRole(
		execution.Roles,
		role.RoleID,
	); !found {
		return teaminput.WorkspaceSnapshot{},
			teaminput.ErrFactMismatch
	}
	snapshotID, err := teaminput.WorkspaceSnapshotID(
		execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		return teaminput.WorkspaceSnapshot{},
			teaminput.ErrInvalid
	}
	return teaminput.WorkspaceSnapshot{
		SnapshotID: snapshotID,
		Digest:     provider.digest,
		SizeBytes:  int64(len(provider.content)),
	}, nil
}

func (provider *emptyTeamWorkspaceProvider) LoadRoleWorkspaceContent(
	_ context.Context,
	intent teamdispatch.IntentV1,
	materialization teaminput.MaterializationV1,
) (awsartifact.TeamWorkspaceContent, error) {
	if provider == nil ||
		len(provider.content) == 0 ||
		intent.Validate() != nil ||
		materialization.Validate() != nil ||
		materialization.OwnerID != intent.OwnerID ||
		materialization.ExecutionID != intent.ExecutionID ||
		materialization.RoleID != intent.RoleID ||
		materialization.DeploymentID != intent.DeploymentID ||
		materialization.WorkspaceDigest != provider.digest {
		return nil, teaminput.ErrFactMismatch
	}
	return emptyTeamWorkspaceContent{
		content: provider.content,
	}, nil
}

type emptyTeamWorkspaceContent struct {
	content []byte
}

func (content emptyTeamWorkspaceContent) Open(
	ctx context.Context,
) (io.ReadSeekCloser, error) {
	if ctx == nil || len(content.content) == 0 {
		return nil, teaminput.ErrInvalid
	}
	return &memoryReadSeekCloser{
		Reader: bytes.NewReader(content.content),
	}, nil
}

type memoryReadSeekCloser struct {
	*bytes.Reader
}

func (*memoryReadSeekCloser) Close() error { return nil }

type githubTeamSourceSnapshotter interface {
	Prepare(
		context.Context,
		taskinput.BindingV2,
	) (githubsource.Prepared, error)
}

type githubTeamSourcePublisher interface {
	PublishGitHubSourceSnapshot(
		context.Context,
		cloudapp.Connection,
		githubsource.SnapshotV1,
		awsartifact.TeamWorkspaceContent,
	) (githubsource.ArtifactV1, error)
}

type teamSourceConnectionReader interface {
	LoadConnection(
		context.Context,
		string,
		string,
	) (cloudapp.Connection, error)
}

type durableTeamWorkspaceProvider struct {
	empty       *emptyTeamWorkspaceProvider
	executions  teaminput.ExecutionReader
	connections teamSourceConnectionReader
	snapshots   githubsource.Repository
	snapshotter githubTeamSourceSnapshotter
	publisher   githubTeamSourcePublisher
}

func newDurableTeamWorkspaceProvider(
	empty *emptyTeamWorkspaceProvider,
	executions teaminput.ExecutionReader,
	connections teamSourceConnectionReader,
	snapshots githubsource.Repository,
	snapshotter githubTeamSourceSnapshotter,
	publisher githubTeamSourcePublisher,
) (*durableTeamWorkspaceProvider, error) {
	if empty == nil || executions == nil {
		return nil, teaminput.ErrInvalid
	}
	githubDependencyCount := 0
	for _, available := range []bool{
		connections != nil,
		snapshots != nil,
		snapshotter != nil,
		publisher != nil,
	} {
		if available {
			githubDependencyCount++
		}
	}
	if githubDependencyCount != 0 && githubDependencyCount != 4 {
		return nil, teaminput.ErrInvalid
	}
	return &durableTeamWorkspaceProvider{
		empty:       empty,
		executions:  executions,
		connections: connections,
		snapshots:   snapshots,
		snapshotter: snapshotter,
		publisher:   publisher,
	}, nil
}

func (provider *durableTeamWorkspaceProvider) LoadRoleWorkspace(
	ctx context.Context,
	execution teamexecution.ExecutionV1,
	role teamexecution.RoleV1,
) (teaminput.WorkspaceSnapshot, error) {
	if provider == nil ||
		provider.empty == nil ||
		provider.executions == nil ||
		ctx == nil ||
		execution.Validate() != nil {
		return teaminput.WorkspaceSnapshot{}, teaminput.ErrInvalid
	}
	exactRole, found := executionRole(execution.Roles, role.RoleID)
	if !found || !reflect.DeepEqual(exactRole, role) {
		return teaminput.WorkspaceSnapshot{},
			teaminput.ErrFactMismatch
	}
	switch execution.TaskInput.SourceKind {
	case taskinput.SourceEmpty:
		return provider.empty.LoadRoleWorkspace(ctx, execution, role)
	case taskinput.SourceGitHubRepository:
		if !provider.githubEnabled() {
			return teaminput.WorkspaceSnapshot{},
				teaminput.ErrNotReady
		}
	default:
		return teaminput.WorkspaceSnapshot{}, teaminput.ErrNotReady
	}
	connection, err := provider.loadExactConnection(ctx, execution)
	if err != nil {
		return teaminput.WorkspaceSnapshot{}, err
	}
	stored, err := provider.loadOrCreateGitHubSource(
		ctx,
		execution,
		connection,
	)
	if err != nil {
		return teaminput.WorkspaceSnapshot{}, err
	}
	snapshotID, err := teaminput.WorkspaceSnapshotID(
		execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		return teaminput.WorkspaceSnapshot{},
			teaminput.ErrInvalid
	}
	return teaminput.WorkspaceSnapshot{
		SnapshotID: snapshotID,
		Digest:     stored.Fact.Snapshot.WorkspaceDigest,
		SizeBytes:  stored.Fact.Snapshot.SizeBytes,
	}, nil
}

func (provider *durableTeamWorkspaceProvider) LoadRoleWorkspaceContent(
	ctx context.Context,
	intent teamdispatch.IntentV1,
	materialization teaminput.MaterializationV1,
) (awsartifact.TeamWorkspaceContent, error) {
	if provider == nil ||
		provider.empty == nil ||
		provider.executions == nil ||
		ctx == nil ||
		intent.Validate() != nil ||
		materialization.Validate() != nil {
		return nil, teaminput.ErrInvalid
	}
	fact, err := provider.executions.GetTeamExecution(
		ctx,
		intent.OwnerID,
		intent.ExecutionID,
	)
	if err != nil {
		return nil, err
	}
	execution, err := exactWorkspaceExecution(
		fact,
		intent,
		materialization,
	)
	if err != nil {
		return nil, err
	}
	switch execution.TaskInput.SourceKind {
	case taskinput.SourceEmpty:
		return provider.empty.LoadRoleWorkspaceContent(
			ctx,
			intent,
			materialization,
		)
	case taskinput.SourceGitHubRepository:
		if !provider.githubEnabled() {
			return nil, teaminput.ErrNotReady
		}
	default:
		return nil, teaminput.ErrNotReady
	}
	stored, found, err := provider.snapshots.FindGitHubSourceSnapshot(
		ctx,
		githubsource.LookupKey{
			InputID:      execution.TaskInput.InputID,
			InputDigest:  execution.TaskInput.InputDigest,
			ConnectionID: execution.ProviderScope.ConnectionID,
		},
	)
	if err != nil {
		return nil, err
	}
	if !found ||
		validateGitHubSourceFact(
			stored,
			execution.TaskInput,
			execution.ProviderScope.ConnectionID,
		) != nil ||
		stored.Fact.Snapshot.WorkspaceDigest !=
			materialization.WorkspaceDigest {
		return nil, teaminput.ErrFactMismatch
	}
	return awsartifact.NewGitHubSourceWorkspace(stored.Fact.Artifact)
}

func (provider *durableTeamWorkspaceProvider) githubEnabled() bool {
	return provider != nil &&
		provider.connections != nil &&
		provider.snapshots != nil &&
		provider.snapshotter != nil &&
		provider.publisher != nil
}

func (provider *durableTeamWorkspaceProvider) loadExactConnection(
	ctx context.Context,
	execution teamexecution.ExecutionV1,
) (cloudapp.Connection, error) {
	connection, err := provider.connections.LoadConnection(
		ctx,
		execution.OwnerID,
		execution.ProviderScope.ConnectionID,
	)
	if err != nil {
		return cloudapp.Connection{}, err
	}
	if connection.Status != "active" ||
		connection.OwnerID != execution.OwnerID ||
		connection.ConnectionID !=
			execution.ProviderScope.ConnectionID ||
		connection.Revision <= 0 ||
		uint64(connection.Revision) !=
			execution.ProviderScope.ConnectionRevision ||
		connection.AccountID != execution.ProviderScope.AccountID ||
		connection.Region != execution.Region {
		return cloudapp.Connection{}, teaminput.ErrFactMismatch
	}
	return connection, nil
}

func (provider *durableTeamWorkspaceProvider) loadOrCreateGitHubSource(
	ctx context.Context,
	execution teamexecution.ExecutionV1,
	connection cloudapp.Connection,
) (githubsource.StoredFact, error) {
	key := githubsource.LookupKey{
		InputID:      execution.TaskInput.InputID,
		InputDigest:  execution.TaskInput.InputDigest,
		ConnectionID: connection.ConnectionID,
	}
	stored, found, err := provider.snapshots.FindGitHubSourceSnapshot(
		ctx,
		key,
	)
	if err != nil {
		return githubsource.StoredFact{}, err
	}
	if found {
		if validateGitHubSourceFact(
			stored,
			execution.TaskInput,
			connection.ConnectionID,
		) != nil {
			return githubsource.StoredFact{},
				teaminput.ErrFactMismatch
		}
		return stored, nil
	}
	prepared, err := provider.snapshotter.Prepare(
		ctx,
		execution.TaskInput,
	)
	if err != nil {
		return githubsource.StoredFact{}, err
	}
	defer prepared.Destroy()
	artifact, err := provider.publisher.PublishGitHubSourceSnapshot(
		ctx,
		connection,
		prepared.Snapshot,
		&prepared,
	)
	if err != nil {
		return githubsource.StoredFact{}, err
	}
	fact, err := githubsource.NewFactV1(
		prepared.Snapshot,
		artifact,
	)
	if err != nil {
		return githubsource.StoredFact{}, teaminput.ErrFactMismatch
	}
	stored, err = provider.snapshots.PersistGitHubSourceSnapshot(
		ctx,
		fact,
	)
	if err != nil {
		return githubsource.StoredFact{}, err
	}
	if validateGitHubSourceFact(
		stored,
		execution.TaskInput,
		connection.ConnectionID,
	) != nil ||
		stored.Fact != fact {
		return githubsource.StoredFact{},
			teaminput.ErrFactMismatch
	}
	return stored, nil
}

func validateGitHubSourceFact(
	stored githubsource.StoredFact,
	binding taskinput.BindingV2,
	connectionID string,
) error {
	bindingDigest, err := binding.Digest()
	if err != nil ||
		stored.Validate() != nil ||
		stored.Fact.ConnectionID != connectionID ||
		stored.Fact.Snapshot.InputID != binding.InputID ||
		stored.Fact.Snapshot.InputDigest != binding.InputDigest ||
		stored.Fact.Snapshot.InputBindingDigest != bindingDigest ||
		stored.Fact.Snapshot.SourceDigest != binding.SourceDigest ||
		stored.Fact.Snapshot.Repository != binding.Repository {
		return teaminput.ErrFactMismatch
	}
	return nil
}

func exactWorkspaceExecution(
	fact teamexecution.Fact,
	intent teamdispatch.IntentV1,
	materialization teaminput.MaterializationV1,
) (teamexecution.ExecutionV1, error) {
	execution := fact.Execution
	executionDigest, err := execution.Digest()
	role, found := executionRole(execution.Roles, intent.RoleID)
	roleDigest, roleErr := role.Digest()
	expectedInputID, inputErr := teaminput.InputID(
		intent.ExecutionID,
		intent.RoleID,
	)
	expectedSnapshotID, snapshotErr :=
		teaminput.WorkspaceSnapshotID(
			intent.ExecutionID,
			intent.RoleID,
		)
	if err != nil ||
		roleErr != nil ||
		inputErr != nil ||
		snapshotErr != nil ||
		!found ||
		fact.ExecutionDigest != executionDigest ||
		fact.RecordRevision == 0 ||
		fact.CreatedAt.IsZero() ||
		fact.UpdatedAt.IsZero() ||
		fact.UpdatedAt.Before(fact.CreatedAt) ||
		(execution.SchemaVersion != teamexecution.SchemaV3) ||
		execution.OwnerID != intent.OwnerID ||
		execution.ExecutionID != intent.ExecutionID ||
		executionDigest != intent.ExecutionDigest ||
		execution.PlanID != intent.PlanID ||
		execution.PlanRevision != intent.PlanRevision ||
		execution.PlanDigest != intent.PlanDigest ||
		execution.ApprovalID != intent.ApprovalID ||
		execution.TaskID != intent.TaskID ||
		role.RoleID != intent.RoleID ||
		roleDigest != intent.RoleDigest ||
		role.TaskStepID != intent.TaskStepID ||
		role.DeploymentID != intent.DeploymentID ||
		role.ExpectedWorkerID != intent.ExpectedWorkerID ||
		materialization.InputID != expectedInputID ||
		materialization.OwnerID != intent.OwnerID ||
		materialization.ExecutionID != intent.ExecutionID ||
		materialization.ExecutionDigest != intent.ExecutionDigest ||
		materialization.RoleID != intent.RoleID ||
		materialization.RoleDigest != intent.RoleDigest ||
		materialization.TaskID != intent.TaskID ||
		materialization.TaskStepID != intent.TaskStepID ||
		materialization.DeploymentID != intent.DeploymentID ||
		materialization.ExpectedWorkerID != intent.ExpectedWorkerID ||
		materialization.WorkspaceSnapshotID != expectedSnapshotID {
		return teamexecution.ExecutionV1{},
			teaminput.ErrFactMismatch
	}
	return execution, nil
}

func executionRole(
	roles []teamexecution.RoleV1,
	roleID string,
) (teamexecution.RoleV1, bool) {
	for _, role := range roles {
		if role.RoleID == roleID {
			return role, true
		}
	}
	return teamexecution.RoleV1{}, false
}

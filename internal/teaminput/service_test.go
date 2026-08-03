package teaminput

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/google/uuid"
)

func TestServiceMaterializesDispatchingRoleAndReplaysAfterAdvance(
	t *testing.T,
) {
	t.Parallel()
	fixture := newTeamInputServiceFixture(t)
	first, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		fixture.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	if first.Fact.Status != StatusMaterialized ||
		first.Fact.RecordRevision != 1 ||
		first.Fact.Materialization.ExecutionID !=
			fixture.execution.Execution.ExecutionID ||
		first.Fact.Materialization.RoleID != fixture.request.RoleID ||
		fixture.repository.persistCalls != 1 {
		t.Fatalf("materialized input = %#v", first.Fact)
	}
	persisted := fixture.repository.lastCommand
	if persisted.Validate() != nil ||
		bytes.Contains(
			persisted.ManifestJSON,
			[]byte(fixture.context.GoalSummary),
		) ||
		bytes.Contains(
			persisted.ExecutionBundleJSON,
			[]byte(fixture.context.GoalSummary),
		) {
		t.Fatal("PostgreSQL command contained transient context content")
	}

	fixture.executions.fact.Status = teamexecution.StatusRunning
	replayed, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		fixture.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Destroy()
	if fixture.repository.persistCalls != 1 ||
		replayed.Fact.Materialization.InputID !=
			first.Fact.Materialization.InputID ||
		!bytes.Equal(
			replayed.Compiled.ContextBytes,
			first.Compiled.ContextBytes,
		) {
		t.Fatalf("replayed input = %#v", replayed.Fact)
	}
}

func TestServiceConvergesAnotherIdempotencyKeyOnOneRoleInput(
	t *testing.T,
) {
	t.Parallel()
	fixture := newTeamInputServiceFixture(t)
	first, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		fixture.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	first.Destroy()
	fixture.executions.fact.Status = teamexecution.StatusRunning
	another := fixture.request
	another.IdempotencyKey = uuid.NewString()
	second, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		another,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if fixture.repository.persistCalls != 1 ||
		len(fixture.repository.byKey) != 2 ||
		second.Fact.Materialization.InputID == "" {
		t.Fatalf(
			"cross-key convergence persisted=%d keys=%d fact=%#v",
			fixture.repository.persistCalls,
			len(fixture.repository.byKey),
			second.Fact,
		)
	}
}

func TestServiceRejectsFreshInputBeforeSpendGate(t *testing.T) {
	t.Parallel()
	fixture := newTeamInputServiceFixture(t)
	fixture.executions.fact.Status = teamexecution.StatusMaterialized
	prepared, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		fixture.request,
	)
	prepared.Destroy()
	if !errors.Is(err, ErrNotReady) ||
		fixture.contexts.calls != 0 ||
		fixture.workspaces.calls != 0 ||
		fixture.repository.persistCalls != 0 {
		t.Fatalf(
			"pre-spend input error=%v context=%d workspace=%d persist=%d",
			err,
			fixture.contexts.calls,
			fixture.workspaces.calls,
			fixture.repository.persistCalls,
		)
	}
}

func TestServiceFailsClosedWhenDurableContextDrifts(t *testing.T) {
	t.Parallel()
	fixture := newTeamInputServiceFixture(t)
	first, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		fixture.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	first.Destroy()
	fixture.executions.fact.Status = teamexecution.StatusRunning
	fixture.contexts.value.GoalSummary =
		"Different but otherwise valid context for the same snapshot."
	replayed, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		fixture.request,
	)
	replayed.Destroy()
	if !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("context drift error = %v", err)
	}
}

func TestServiceRejectsCorruptExecutionFactBeforeContextRead(t *testing.T) {
	t.Parallel()
	fixture := newTeamInputServiceFixture(t)
	fixture.executions.fact.ExecutionDigest = testDigest("9")
	prepared, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		fixture.request,
	)
	prepared.Destroy()
	if !errors.Is(err, ErrFactMismatch) ||
		fixture.contexts.calls != 0 ||
		fixture.workspaces.calls != 0 {
		t.Fatalf(
			"corrupt Execution error=%v context=%d workspace=%d",
			err,
			fixture.contexts.calls,
			fixture.workspaces.calls,
		)
	}
}

func TestServiceMaterializesDependentRoleWhileExecutionIsRunning(
	t *testing.T,
) {
	t.Parallel()
	fixture := newTeamInputServiceFixture(t)
	fixture.executions.fact.Status = teamexecution.StatusRunning
	prepared, err := fixture.service.Materialize(
		context.Background(),
		fixture.scope,
		fixture.request,
	)
	defer prepared.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Fact.Materialization.RoleID != fixture.request.RoleID ||
		prepared.Fact.Status != StatusMaterialized {
		t.Fatalf("unexpected running materialization: %#v", prepared.Fact)
	}
}

type teamInputServiceFixture struct {
	service    *Service
	execution  teamexecution.Fact
	executions *teamInputExecutionReader
	context    ContextInput
	contexts   *teamInputContextSource
	workspaces *teamInputWorkspaceSource
	repository *teamInputRepository
	scope      task.MutationScope
	request    MaterializeRequest
}

func newTeamInputServiceFixture(t *testing.T) teamInputServiceFixture {
	t.Helper()
	execution, executionDigest := teamInputExecutionFixture(t)
	now := time.Date(2026, time.July, 30, 9, 0, 0, 0, time.UTC)
	executionFact := teamexecution.Fact{
		Execution:       execution,
		ExecutionDigest: executionDigest,
		Status:          teamexecution.StatusDispatching,
		RecordRevision:  2,
		CreatedAt:       now.Add(-time.Minute),
		UpdatedAt:       now,
	}
	compiledRequest := teamInputCompileRequest(
		execution,
		executionDigest,
	)
	executions := &teamInputExecutionReader{fact: executionFact}
	contexts := &teamInputContextSource{value: compiledRequest.Context}
	workspaces := &teamInputWorkspaceSource{
		value: compiledRequest.Workspace,
	}
	repository := &teamInputRepository{
		now:         now,
		byKey:       make(map[string]Fact),
		byAggregate: make(map[string]Fact),
	}
	service, err := NewService(
		executions,
		contexts,
		workspaces,
		repository,
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := task.MutationScope{
		ClientID:     "internal-team-dispatcher",
		CredentialID: uuid.NewString(),
	}
	request := MaterializeRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        execution.OwnerID,
		ExecutionID:    execution.ExecutionID,
		RoleID:         compiledRequest.RoleID,
	}
	return teamInputServiceFixture{
		service: service, execution: executionFact,
		executions: executions, context: compiledRequest.Context,
		contexts: contexts, workspaces: workspaces,
		repository: repository, scope: scope, request: request,
	}
}

type teamInputExecutionReader struct {
	fact teamexecution.Fact
	err  error
}

func (reader *teamInputExecutionReader) GetTeamExecution(
	_ context.Context,
	ownerID,
	executionID string,
) (teamexecution.Fact, error) {
	if reader.err != nil {
		return teamexecution.Fact{}, reader.err
	}
	if reader.fact.Execution.OwnerID != ownerID ||
		reader.fact.Execution.ExecutionID != executionID {
		return teamexecution.Fact{}, ErrFactMismatch
	}
	return reader.fact, nil
}

type teamInputContextSource struct {
	value ContextInput
	err   error
	calls int
}

func (source *teamInputContextSource) LoadRoleContext(
	_ context.Context,
	_ teamexecution.ExecutionV1,
	_ teamexecution.RoleV1,
) (ContextInput, error) {
	source.calls++
	if source.err != nil {
		return ContextInput{}, source.err
	}
	result := source.value
	result.Constraints = append([]string(nil), source.value.Constraints...)
	result.Dependencies = append(
		[]DependencyResultV1(nil),
		source.value.Dependencies...,
	)
	result.Artifacts = append(
		[]ArtifactRefV1(nil),
		source.value.Artifacts...,
	)
	return result, nil
}

type teamInputWorkspaceSource struct {
	value WorkspaceSnapshot
	err   error
	calls int
}

func (source *teamInputWorkspaceSource) LoadRoleWorkspace(
	_ context.Context,
	_ teamexecution.ExecutionV1,
	_ teamexecution.RoleV1,
) (WorkspaceSnapshot, error) {
	source.calls++
	if source.err != nil {
		return WorkspaceSnapshot{}, source.err
	}
	return source.value, nil
}

type teamInputRepository struct {
	now          time.Time
	byKey        map[string]Fact
	byAggregate  map[string]Fact
	persistCalls int
	lastCommand  PersistCommand
}

func (repository *teamInputRepository) FindMaterializedInput(
	_ context.Context,
	scope task.MutationScope,
	request MaterializeRequest,
) (Fact, bool, error) {
	key := teamInputReplayKey(scope, request.IdempotencyKey)
	if fact, found := repository.byKey[key]; found {
		return fact, true, nil
	}
	inputID, err := InputID(request.ExecutionID, request.RoleID)
	if err != nil {
		return Fact{}, false, err
	}
	fact, found := repository.byAggregate[inputID]
	if found {
		repository.byKey[key] = fact
	}
	return fact, found, nil
}

func (repository *teamInputRepository) PersistMaterializedInput(
	_ context.Context,
	scope task.MutationScope,
	command PersistCommand,
) (Fact, error) {
	if err := command.Validate(); err != nil {
		return Fact{}, err
	}
	repository.persistCalls++
	repository.lastCommand = PersistCommand{
		IdempotencyKey:      command.IdempotencyKey,
		Materialization:     command.Materialization,
		ManifestJSON:        bytes.Clone(command.ManifestJSON),
		ExecutionBundleJSON: bytes.Clone(command.ExecutionBundleJSON),
	}
	if existing, found := repository.byAggregate[command.Materialization.InputID]; found {
		key := teamInputReplayKey(scope, command.IdempotencyKey)
		repository.byKey[key] = existing
		return existing, nil
	}
	fact := Fact{
		Materialization: command.Materialization,
		Status:          StatusMaterialized,
		RecordRevision:  1,
		CreatedAt:       repository.now,
		UpdatedAt:       repository.now,
	}
	repository.byAggregate[command.Materialization.InputID] = fact
	key := teamInputReplayKey(scope, command.IdempotencyKey)
	repository.byKey[key] = fact
	return fact, nil
}

func teamInputReplayKey(
	scope task.MutationScope,
	idempotencyKey string,
) string {
	return strings.Join(
		[]string{
			scope.ClientID,
			scope.CredentialID,
			idempotencyKey,
		},
		"/",
	)
}

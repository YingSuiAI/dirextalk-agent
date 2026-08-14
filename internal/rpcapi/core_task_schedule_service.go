package rpcapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ agentv1.TaskServiceServer = (*CoreTaskService)(nil)
var _ agentv1.ScheduleServiceServer = (*CoreScheduleService)(nil)

type CoreTaskService struct {
	agentv1.UnimplementedTaskServiceServer
	store taskServiceStore
}

type taskServiceStore interface {
	CreateTask(context.Context, coretask.CreateTaskCommand) (coretask.Task, error)
	GetTask(context.Context, string) (coretask.Task, error)
	ListTasks(context.Context, coretask.TaskListQuery) ([]coretask.Task, string, error)
	CancelTask(context.Context, coretask.CancelCommand) (coretask.Task, error)
	RetryTask(context.Context, coretask.RetryCommand) (coretask.Task, error)
	DeleteTask(context.Context, coretask.DeleteTaskCommand) (coretask.DeletedTaskResponse, error)
	ListProgress(context.Context, string, uint64, int) ([]coretask.Progress, string, error)
	WatchProgress(context.Context, string, uint64) (<-chan coretask.Progress, error)
}

type taskProgressErrorStore interface {
	WatchProgressWithErrors(context.Context, string, uint64) (<-chan coretask.ProgressStreamEvent, error)
}

func NewCoreTaskService(store taskServiceStore) *CoreTaskService {
	return &CoreTaskService{store: store}
}
func NewTaskService(store taskServiceStore) *CoreTaskService { return NewCoreTaskService(store) }

func (s *CoreTaskService) CreateTask(ctx context.Context, r *agentv1.TaskServiceCreateTaskRequest) (*agentv1.TaskServiceCreateTaskResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if !validCoreUUID(r.GetIdempotencyKey()) {
		return nil, status.Error(codes.InvalidArgument, "idempotency_key is invalid")
	}
	spec, err := taskSpecFromProto(r.GetIdempotencyKey(), r.GetGoal(), r.GetConversationId(), r.GetModelProfileId(), r.GetAttachmentRefs(), r.GetExtensions(), r.GetKnowledgeRefs(), r.GetTimeoutSeconds())
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	digestSpec := spec
	digestSpec.IdempotencyKey = "00000000-0000-4000-8000-000000000001"
	digest, err := digestSpec.MutationDigest()
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	t, err := s.store.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: r.GetIdempotencyKey(), RequestDigest: digest}})
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	return &agentv1.TaskServiceCreateTaskResponse{Task: coreTaskProto(t)}, nil
}

func (s *CoreTaskService) GetTask(ctx context.Context, r *agentv1.TaskServiceGetTaskRequest) (*agentv1.TaskServiceGetTaskResponse, error) {
	if r == nil || !validCoreUUID(r.GetTaskId()) {
		return nil, status.Error(codes.InvalidArgument, "task_id is invalid")
	}
	t, err := s.store.GetTask(ctx, r.GetTaskId())
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	return &agentv1.TaskServiceGetTaskResponse{Task: coreTaskProto(t)}, nil
}

func (s *CoreTaskService) ListTasks(ctx context.Context, r *agentv1.TaskServiceListTasksRequest) (*agentv1.TaskServiceListTasksResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	limit, err := pageLimit(r.GetPageSize())
	if err != nil {
		return nil, err
	}
	q := coretask.TaskListQuery{Cursor: r.GetPageToken(), Limit: limit}
	if r.GetStatus() != agentv1.CoreTaskStatus_CORE_TASK_STATUS_UNSPECIFIED {
		st, ok := statusFromProto(r.GetStatus())
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "status is invalid")
		}
		q.Status = &st
	}
	items, next, err := s.store.ListTasks(ctx, q)
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	out := &agentv1.TaskServiceListTasksResponse{NextPageToken: next, Tasks: make([]*agentv1.CoreTask, 0, len(items))}
	for _, t := range items {
		out.Tasks = append(out.Tasks, coreTaskProto(t))
	}
	return out, nil
}

func (s *CoreTaskService) CancelTask(ctx context.Context, r *agentv1.TaskServiceCancelTaskRequest) (*agentv1.TaskServiceCancelTaskResponse, error) {
	if r == nil || !validCoreUUID(r.GetTaskId()) || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpectedRevision() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid cancellation request")
	}
	digest, err := mutationDigest("cancel", r.GetTaskId(), r.GetExpectedRevision(), r.GetReason())
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	t, err := s.store.CancelTask(ctx, coretask.CancelCommand{TaskID: r.GetTaskId(), Reason: r.GetReason(), At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: r.GetIdempotencyKey(), RequestDigest: digest, ExpectedRevision: uint64(r.GetExpectedRevision())}})
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	return &agentv1.TaskServiceCancelTaskResponse{Task: coreTaskProto(t)}, nil
}

func (s *CoreTaskService) RetryTask(ctx context.Context, r *agentv1.TaskServiceRetryTaskRequest) (*agentv1.TaskServiceRetryTaskResponse, error) {
	if r == nil || !validCoreUUID(r.GetTaskId()) || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpectedRevision() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid retry request")
	}
	digest, err := mutationDigest("retry", r.GetTaskId(), r.GetExpectedRevision())
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	t, err := s.store.RetryTask(ctx, coretask.RetryCommand{TaskID: r.GetTaskId(), At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: r.GetIdempotencyKey(), RequestDigest: digest, ExpectedRevision: uint64(r.GetExpectedRevision())}})
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	return &agentv1.TaskServiceRetryTaskResponse{Task: coreTaskProto(t)}, nil
}

func (s *CoreTaskService) DeleteTask(ctx context.Context, r *agentv1.TaskServiceDeleteTaskRequest) (*agentv1.TaskServiceDeleteTaskResponse, error) {
	if r == nil || !validCoreUUID(r.GetTaskId()) || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpectedRevision() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid deletion request")
	}
	digest, err := mutationDigest("delete", r.GetTaskId(), r.GetExpectedRevision())
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	_, err = s.store.DeleteTask(ctx, coretask.DeleteTaskCommand{TaskID: r.GetTaskId(), At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: r.GetIdempotencyKey(), RequestDigest: digest, ExpectedRevision: uint64(r.GetExpectedRevision())}})
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	return &agentv1.TaskServiceDeleteTaskResponse{}, nil
}

func (s *CoreTaskService) WatchTaskEvents(r *agentv1.TaskServiceWatchTaskEventsRequest, stream agentv1.TaskService_WatchTaskEventsServer) error {
	if r == nil || !validCoreUUID(r.GetTaskId()) || r.GetAfterSequence() < 0 {
		return status.Error(codes.InvalidArgument, "invalid event cursor")
	}
	ctx := stream.Context()
	after := uint64(r.GetAfterSequence())
	items, _, err := s.store.ListProgress(ctx, r.GetTaskId(), after, 200)
	if err != nil {
		return coreTaskRPCError(err)
	}
	for _, p := range items {
		if err := stream.Send(&agentv1.TaskServiceWatchTaskEventsResponse{Event: progressProto(p)}); err != nil {
			return err
		}
		after = p.Sequence
	}
	var ch <-chan coretask.Progress
	var errCh <-chan coretask.ProgressStreamEvent
	if errorStore, ok := s.store.(taskProgressErrorStore); ok {
		errCh, err = errorStore.WatchProgressWithErrors(ctx, r.GetTaskId(), after)
	} else {
		ch, err = s.store.WatchProgress(ctx, r.GetTaskId(), after)
	}
	if err != nil {
		return coreTaskRPCError(err)
	}
	for {
		if errCh != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case event, ok := <-errCh:
				if !ok {
					return status.Error(codes.Unavailable, "progress stream ended")
				}
				if event.Err != nil {
					return coreTaskRPCError(event.Err)
				}
				if event.Progress == nil {
					return status.Error(codes.Unavailable, "progress stream returned empty event")
				}
				p := *event.Progress
				if p.Sequence <= after {
					continue
				}
				if err := stream.Send(&agentv1.TaskServiceWatchTaskEventsResponse{Event: progressProto(p)}); err != nil {
					return err
				}
				after = p.Sequence
			}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p, ok := <-ch:
			if !ok {
				return nil
			}
			if p.Sequence <= after {
				continue
			}
			if err := stream.Send(&agentv1.TaskServiceWatchTaskEventsResponse{Event: progressProto(p)}); err != nil {
				return err
			}
			after = p.Sequence
		}
	}
}

func pageLimit(v int32) (int, error) {
	if v == 0 {
		return 50, nil
	}
	if v < 0 || v > 200 {
		return 0, status.Error(codes.InvalidArgument, "page_size is invalid")
	}
	return int(v), nil
}
func validCoreUUID(v string) bool {
	u, err := uuid.Parse(v)
	return err == nil && u != uuid.Nil && u.String() == v
}
func mutationDigest(op string, v ...any) (string, error) {
	return coretask.CanonicalMutationDigest(struct {
		Operation string
		Value     []any
	}{op, v})
}
func taskSpecFromProto(key, goal, conv, model string, att []string, ext []*agentv1.CoreExtensionSelection, know []string, timeout int64) (coretask.TaskSpec, error) {
	if !validCoreUUID(key) || !validCoreUUID(model) || (conv != "" && !validCoreUUID(conv)) {
		return coretask.TaskSpec{}, coretask.ErrInvalid
	}
	x := make([]coretask.ExtensionSelection, 0, len(ext))
	for _, e := range ext {
		if e == nil {
			continue
		}
		if !validCoreUUID(e.GetId()) {
			return coretask.TaskSpec{}, coretask.ErrInvalid
		}
		x = append(x, coretask.ExtensionSelection{Kind: coretask.ExtensionKind(e.GetKind()), ID: e.GetId(), Version: e.GetPinnedVersion(), Digest: e.GetDigest(), AllowedTools: e.GetAllowedTools()})
	}
	return (coretask.TaskSpec{Goal: goal, ConversationID: conv, ModelProfileID: model, AttachmentRefs: att, Extensions: x, KnowledgeRefs: know, TimeoutSeconds: timeout, IdempotencyKey: key}).Normalize()
}
func templateFromProto(t *agentv1.CoreTaskTemplate) (coretask.TaskTemplate, error) {
	if t == nil {
		return coretask.TaskTemplate{}, coretask.ErrInvalid
	}
	s, e := taskSpecFromProto("00000000-0000-4000-8000-000000000001", t.GetGoal(), t.GetConversationId(), t.GetModelProfileId(), t.GetAttachmentRefs(), t.GetExtensions(), t.GetKnowledgeRefs(), t.GetTimeoutSeconds())
	if e != nil {
		return coretask.TaskTemplate{}, e
	}
	return coretask.TaskTemplate{Goal: s.Goal, ConversationID: s.ConversationID, ModelProfileID: s.ModelProfileID, AttachmentRefs: s.AttachmentRefs, Extensions: s.Extensions, KnowledgeRefs: s.KnowledgeRefs, TimeoutSeconds: s.TimeoutSeconds}, nil
}
func triggerFromProto(t *agentv1.CoreScheduleTrigger) (*time.Time, string, string, error) {
	if t == nil {
		return nil, "", "", coretask.ErrInvalid
	}
	switch x := t.GetTrigger().(type) {
	case *agentv1.CoreScheduleTrigger_RunAt:
		if x.RunAt == nil || !x.RunAt.IsValid() {
			return nil, "", "", coretask.ErrInvalid
		}
		v := x.RunAt.AsTime().UTC()
		return &v, "", "UTC", nil
	case *agentv1.CoreScheduleTrigger_Cron:
		if x.Cron == nil || strings.TrimSpace(x.Cron.GetExpression()) == "" {
			return nil, "", "", coretask.ErrInvalid
		}
		tz := x.Cron.GetTimezone()
		if tz == "" {
			tz = "UTC"
		}
		return nil, x.Cron.GetExpression(), tz, nil
	default:
		return nil, "", "", coretask.ErrInvalid
	}
}
func scheduleFromProto(id, name string, t *agentv1.CoreTaskTemplate, tr *agentv1.CoreScheduleTrigger, now time.Time) (coretask.Schedule, error) {
	tpl, e := templateFromProto(t)
	if e != nil {
		return coretask.Schedule{}, e
	}
	run, cron, tz, e := triggerFromProto(tr)
	if e != nil {
		return coretask.Schedule{}, e
	}
	return coretask.Schedule{ID: id, Name: name, Spec: tpl, RunAt: run, Cron: cron, Timezone: tz, Revision: 1, CreatedAt: now, UpdatedAt: now, NextRunAt: func() time.Time {
		if run != nil {
			return *run
		}
		return time.Time{}
	}()}, nil
}
func coreTaskProto(t coretask.Task) *agentv1.CoreTask {
	var workload *agentv1.CoreWorkloadTaskPayload
	if p := t.Spec.Payload.Workload; p != nil {
		workload = &agentv1.CoreWorkloadTaskPayload{WorkloadId: p.WorkloadID, PlanId: p.PlanID, OperationId: p.OperationID, PlanRevision: int64(p.PlanRevision), PlanDigest: p.PlanDigest, TargetKind: p.TargetKind, ConfirmationId: p.ConfirmationID, ExecutionSnapshot: rawJSONStruct(p.ExecutionSnapshot)}
	}
	var conversationTool *agentv1.CoreConversationToolTaskPayload
	if p := t.Spec.Payload.ConversationTool; p != nil {
		conversationTool = &agentv1.CoreConversationToolTaskPayload{TurnId: p.TurnID, AttemptId: p.AttemptID, Round: p.Round, CallId: p.CallID, ExtensionSnapshotDigest: p.ExtensionSnapshotDigest, InstallationId: p.InstallationID, VersionId: p.VersionID, InstallationRevision: p.InstallationRevision, ToolName: p.ToolName, ToolSchemaDigest: p.ToolSchemaDigest, ArgumentsDigest: p.ArgumentsDigest, ConfirmationId: p.ConfirmationID, SafeSummary: p.SafeSummary}
	}
	var cloudWorker *agentv1.CoreCloudWorkerTaskPayload
	if p := t.Spec.Payload.CloudWorker; p != nil {
		cloudWorker = &agentv1.CoreCloudWorkerTaskPayload{ExecutionId: p.ExecutionID, AccountGeneration: p.AccountGeneration, PlanId: p.PlanID, PlanRevision: p.PlanRevision, PlanDigest: p.PlanDigest, ConfirmationId: p.ConfirmationID, TurnId: p.TurnID, ConversationId: p.ConversationID, QuoteDigest: p.QuoteDigest, ExecutionDigest: p.ExecutionDigest}
	}
	return &agentv1.CoreTask{TaskId: t.ID, Goal: t.Spec.Goal, ConversationId: t.Spec.ConversationID, ModelProfileId: t.Spec.ModelProfileID, AttachmentRefs: t.Spec.AttachmentRefs, Extensions: extensionsProto(t.Spec.Extensions), KnowledgeRefs: t.Spec.KnowledgeRefs, TimeoutSeconds: t.Spec.TimeoutSeconds, Status: statusProto(t.Status), Attempt: t.Attempt, LeaseEpoch: t.LeaseEpoch, AvailableAt: timestampOrNil(t.AvailableAt), RetryOfTaskId: t.RetryOfTaskID, Result: resultStruct(t.Result), FailureCode: t.FailureCode, FailureSummary: t.FailureSummary, Revision: int64(t.Revision), CreatedAt: timestampOrNil(t.CreatedAt), UpdatedAt: timestampOrNil(t.UpdatedAt), Kind: taskKindProto(t.Spec.Kind), Workload: workload, ConversationTool: conversationTool, CloudWorker: cloudWorker}
}
func taskKindProto(k coretask.TaskKind) agentv1.CoreTaskKind {
	switch k {
	case coretask.TaskKindExtension:
		return agentv1.CoreTaskKind_CORE_TASK_KIND_EXTENSION
	case coretask.TaskKindKnowledgeIndex:
		return agentv1.CoreTaskKind_CORE_TASK_KIND_KNOWLEDGE_INDEX
	case coretask.TaskKindWorkload:
		return agentv1.CoreTaskKind_CORE_TASK_KIND_WORKLOAD
	case coretask.TaskKindConversationTool:
		return agentv1.CoreTaskKind_CORE_TASK_KIND_CONVERSATION_TOOL
	case coretask.TaskKindCloudWorker:
		return agentv1.CoreTaskKind_CORE_TASK_KIND_CLOUD_WORKER
	case coretask.TaskKindAgent, "":
		return agentv1.CoreTaskKind_CORE_TASK_KIND_AGENT
	default:
		return agentv1.CoreTaskKind_CORE_TASK_KIND_UNSPECIFIED
	}
}
func progressProto(p coretask.Progress) *agentv1.CoreTaskEvent {
	return &agentv1.CoreTaskEvent{TaskId: p.TaskID, Sequence: int64(p.Sequence), EventId: p.EventID, Attempt: p.Attempt, Status: statusProto(p.Status), Phase: p.Phase, ProgressMessage: p.Message, Percent: p.Percent, Result: progressResultStruct(p), ErrorCode: p.ErrorCode, ErrorSummary: p.ErrorSummary, OccurredAt: timestampOrNil(p.At)}
}
func progressResultStruct(p coretask.Progress) *structpb.Struct {
	if len(p.ResultJSON) > 0 {
		return rawJSONStruct(p.ResultJSON)
	}
	if p.ResultSummary == "" {
		return nil
	}
	v, _ := structpb.NewStruct(map[string]any{"summary": p.ResultSummary})
	return v
}
func rawJSONStruct(raw []byte) *structpb.Struct {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	v, _ := structpb.NewStruct(m)
	return v
}
func resultStruct(r *coretask.Result) *structpb.Struct {
	if r == nil {
		return nil
	}
	if len(r.JSON) > 0 {
		var m map[string]any
		if json.Unmarshal(r.JSON, &m) == nil {
			v, _ := structpb.NewStruct(m)
			return v
		}
	}
	m := map[string]any{}
	if r.Text != "" {
		m["text"] = r.Text
	}
	if r.Summary != "" {
		m["summary"] = r.Summary
	}
	if len(r.Files) > 0 {
		files := make([]any, 0, len(r.Files))
		for _, f := range r.Files {
			files = append(files, map[string]any{"path": f.Path, "digest": f.Digest, "size": f.Size})
		}
		m["files"] = files
	}
	v, _ := structpb.NewStruct(m)
	return v
}
func extensionsProto(in []coretask.ExtensionSelection) []*agentv1.CoreExtensionSelection {
	o := make([]*agentv1.CoreExtensionSelection, 0, len(in))
	for _, e := range in {
		o = append(o, &agentv1.CoreExtensionSelection{Kind: string(e.Kind), Id: e.ID, PinnedVersion: e.Version, Digest: e.Digest, AllowedTools: e.AllowedTools})
	}
	return o
}
func statusProto(s coretask.Status) agentv1.CoreTaskStatus {
	switch s {
	case coretask.StatusQueued:
		return agentv1.CoreTaskStatus_CORE_TASK_STATUS_QUEUED
	case coretask.StatusRunning:
		return agentv1.CoreTaskStatus_CORE_TASK_STATUS_RUNNING
	case coretask.StatusWaitingUser:
		return agentv1.CoreTaskStatus_CORE_TASK_STATUS_WAITING_USER
	case coretask.StatusSucceeded:
		return agentv1.CoreTaskStatus_CORE_TASK_STATUS_SUCCEEDED
	case coretask.StatusFailed:
		return agentv1.CoreTaskStatus_CORE_TASK_STATUS_FAILED
	case coretask.StatusCanceled:
		return agentv1.CoreTaskStatus_CORE_TASK_STATUS_CANCELED
	}
	return agentv1.CoreTaskStatus_CORE_TASK_STATUS_UNSPECIFIED
}
func statusFromProto(s agentv1.CoreTaskStatus) (coretask.Status, bool) {
	switch s {
	case agentv1.CoreTaskStatus_CORE_TASK_STATUS_QUEUED:
		return coretask.StatusQueued, true
	case agentv1.CoreTaskStatus_CORE_TASK_STATUS_RUNNING:
		return coretask.StatusRunning, true
	case agentv1.CoreTaskStatus_CORE_TASK_STATUS_WAITING_USER:
		return coretask.StatusWaitingUser, true
	case agentv1.CoreTaskStatus_CORE_TASK_STATUS_SUCCEEDED:
		return coretask.StatusSucceeded, true
	case agentv1.CoreTaskStatus_CORE_TASK_STATUS_FAILED:
		return coretask.StatusFailed, true
	case agentv1.CoreTaskStatus_CORE_TASK_STATUS_CANCELED:
		return coretask.StatusCanceled, true
	}
	return "", false
}
func scheduleProto(s coretask.Schedule) *agentv1.CoreSchedule {
	tr := &agentv1.CoreScheduleTrigger{}
	if s.RunAt != nil {
		tr.Trigger = &agentv1.CoreScheduleTrigger_RunAt{RunAt: timestamppb.New(*s.RunAt)}
	} else {
		tr.Trigger = &agentv1.CoreScheduleTrigger_Cron{Cron: &agentv1.CoreCronTrigger{Expression: s.Cron, Timezone: s.Timezone}}
	}
	state := agentv1.CoreScheduleState_CORE_SCHEDULE_STATE_ACTIVE
	if s.Paused {
		state = agentv1.CoreScheduleState_CORE_SCHEDULE_STATE_PAUSED
	}
	if s.Deleted {
		state = agentv1.CoreScheduleState_CORE_SCHEDULE_STATE_DELETED
	}
	return &agentv1.CoreSchedule{ScheduleId: s.ID, Name: s.Name, TaskTemplate: &agentv1.CoreTaskTemplate{Goal: s.Spec.Goal, ConversationId: s.Spec.ConversationID, ModelProfileId: s.Spec.ModelProfileID, AttachmentRefs: s.Spec.AttachmentRefs, Extensions: extensionsProto(s.Spec.Extensions), KnowledgeRefs: s.Spec.KnowledgeRefs, TimeoutSeconds: s.Spec.TimeoutSeconds}, Trigger: tr, State: state, NextRunAt: timestampOrNil(s.NextRunAt), LastScheduledFor: timestampOrNil(s.LastScheduledFor), Revision: int64(s.Revision), CreatedAt: timestampOrNil(s.CreatedAt), UpdatedAt: timestampOrNil(s.UpdatedAt)}
}
func timestampOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
func validateSchedulePageToken(token string) error {
	if token == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || !validCoreUUID(string(raw)) {
		return status.Error(codes.InvalidArgument, "page_token is invalid")
	}
	return nil
}
func coreTaskRPCError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, coretask.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid task or schedule request")
	case errors.Is(err, coretask.ErrNotFound):
		return status.Error(codes.NotFound, "requested task or schedule was not found")
	case errors.Is(err, coretask.ErrRevisionConflict), errors.Is(err, coretask.ErrLeaseConflict), errors.Is(err, coretask.ErrConflict):
		return status.Error(codes.Aborted, "task or schedule revision conflict")
	case errors.Is(err, coretask.ErrTerminal), errors.Is(err, coretask.ErrTimedOut):
		return status.Error(codes.FailedPrecondition, "task cannot be mutated in its current state")
	default:
		return status.Error(codes.Unavailable, "task or schedule persistence is unavailable")
	}
}

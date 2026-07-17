package workerrunner

import (
	"context"
	"errors"
	"sync"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
)

// GRPCMilestoneSink relays the closed Worker telemetry vocabulary through the
// authenticated Agent session. It never constructs an AWS client or receives
// a CloudWatch destination from the Worker runtime.
type GRPCMilestoneSink struct {
	control ControlClient

	mu    sync.Mutex
	token []byte
}

func NewGRPCMilestoneSink(control ControlClient) (*GRPCMilestoneSink, error) {
	if control == nil {
		return nil, errors.New("Worker milestone control is unavailable")
	}
	return &GRPCMilestoneSink{control: control}, nil
}

func (sink *GRPCMilestoneSink) BindSession(token []byte) error {
	if sink == nil || len(token) < 32 {
		return errors.New("Worker milestone session is invalid")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	wipe(sink.token)
	sink.token = append(sink.token[:0], token...)
	return nil
}

func (sink *GRPCMilestoneSink) Close() {
	if sink == nil {
		return
	}
	sink.mu.Lock()
	wipe(sink.token)
	sink.token = nil
	sink.mu.Unlock()
}

func (sink *GRPCMilestoneSink) Emit(ctx context.Context, event LogEventV1) error {
	if sink == nil || ctx == nil {
		return errors.New("Worker milestone relay is unavailable")
	}
	kind, ok := workerMilestoneKindToProto(event.Kind)
	if !ok {
		return errors.New("Worker milestone is invalid")
	}
	outcome, ok := workerMilestoneOutcomeToProto(event.Outcome)
	if !ok {
		return errors.New("Worker milestone is invalid")
	}
	sink.mu.Lock()
	token := append([]byte(nil), sink.token...)
	sink.mu.Unlock()
	defer wipe(token)
	if len(token) < 32 {
		return errors.New("Worker milestone session is unavailable")
	}
	_, err := sink.control.EmitMilestone(ctx, token, &agentv1.WorkerControlServiceEmitMilestoneRequest{
		DeploymentId: event.DeploymentID, WorkerId: event.WorkerID, LeaseEpoch: event.LeaseEpoch,
		EventId: event.EventID, Kind: kind, ActionId: event.ActionID, Outcome: outcome,
	})
	return err
}

func workerMilestoneKindToProto(value LogKind) (agentv1.WorkerMilestoneKind, bool) {
	switch value {
	case LogExecutionStarted:
		return agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_EXECUTION_STARTED, true
	case LogActionStarted:
		return agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_ACTION_STARTED, true
	case LogActionSucceeded:
		return agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_ACTION_SUCCEEDED, true
	case LogActionFailed:
		return agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_ACTION_FAILED, true
	case LogExecutionFinished:
		return agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_EXECUTION_FINISHED, true
	default:
		return agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_UNSPECIFIED, false
	}
}

func workerMilestoneOutcomeToProto(value LogOutcome) (agentv1.WorkerOutcome, bool) {
	switch value {
	case "":
		return agentv1.WorkerOutcome_WORKER_OUTCOME_UNSPECIFIED, true
	case LogOutcomeSucceeded:
		return agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED, true
	case LogOutcomeFailed:
		return agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED, true
	case LogOutcomeCanceled:
		return agentv1.WorkerOutcome_WORKER_OUTCOME_CANCELED, true
	case LogOutcomeTimedOut:
		return agentv1.WorkerOutcome_WORKER_OUTCOME_TIMED_OUT, true
	case LogOutcomeInterrupted:
		return agentv1.WorkerOutcome_WORKER_OUTCOME_INTERRUPTED, true
	default:
		return agentv1.WorkerOutcome_WORKER_OUTCOME_UNSPECIFIED, false
	}
}

var _ sessionBoundLogSink = (*GRPCMilestoneSink)(nil)

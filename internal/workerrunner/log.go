package workerrunner

import (
	"context"
	"time"
)

const WorkerLogSchemaV1 = "dirextalk.agent.worker-log-event/v1"

type LogKind string

const (
	LogExecutionStarted  LogKind = "execution_started"
	LogActionStarted     LogKind = "action_started"
	LogActionSucceeded   LogKind = "action_succeeded"
	LogActionFailed      LogKind = "action_failed"
	LogExecutionFinished LogKind = "execution_finished"
)

type LogOutcome string

const (
	LogOutcomeSucceeded   LogOutcome = "succeeded"
	LogOutcomeFailed      LogOutcome = "failed"
	LogOutcomeCanceled    LogOutcome = "canceled"
	LogOutcomeTimedOut    LogOutcome = "timed_out"
	LogOutcomeInterrupted LogOutcome = "interrupted"
)

// LogEventV1 deliberately contains only control-plane identifiers and fixed
// enums. It has no free-form message, command, path, URL, output, or error.
type LogEventV1 struct {
	SchemaVersion string     `json:"schema_version"`
	EventID       string     `json:"event_id"`
	DeploymentID  string     `json:"deployment_id"`
	WorkerID      string     `json:"worker_id"`
	Attempt       int32      `json:"attempt"`
	LeaseEpoch    int64      `json:"lease_epoch"`
	Kind          LogKind    `json:"kind"`
	ActionID      string     `json:"action_id,omitempty"`
	Outcome       LogOutcome `json:"outcome,omitempty"`
	OccurredAt    time.Time  `json:"occurred_at"`
}

type LogSink interface {
	Emit(context.Context, LogEventV1) error
}

// sessionBoundLogSink receives the short-lived Worker session only after
// enrollment/identity verification. It is internal so direct test sinks never
// gain a credential channel.
type sessionBoundLogSink interface {
	LogSink
	BindSession([]byte) error
	Close()
}

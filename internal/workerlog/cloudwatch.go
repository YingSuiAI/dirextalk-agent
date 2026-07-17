// Package workerlog writes a deliberately small, secret-free Worker milestone
// schema to the deployment's CloudWatch Logs stream. Worker logs remain
// untrusted claims; readiness is established by independent probes.
package workerlog

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

const SchemaV1 = workerrunner.WorkerLogSchemaV1

const maxMessageBytes = 16 << 10

var (
	// Foundation deliberately uses its DNS-safe stack name as the log group,
	// which is also carried as the cloudwatch:// authority in Worker scope.
	logGroupPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$`)
	logPrefixPattern = regexp.MustCompile(`^AROA[A-Z0-9]{12,124}/i-[0-9a-f]{8,17}$`)
	logStreamPattern = regexp.MustCompile(`^AROA[A-Z0-9]{12,124}/i-[0-9a-f]{8,17}/milestones-a[1-9][0-9]*-e[1-9][0-9]*$`)
	actionIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

type Kind = workerrunner.LogKind

const (
	KindExecutionStarted  = workerrunner.LogExecutionStarted
	KindActionStarted     = workerrunner.LogActionStarted
	KindActionSucceeded   = workerrunner.LogActionSucceeded
	KindActionFailed      = workerrunner.LogActionFailed
	KindExecutionFinished = workerrunner.LogExecutionFinished
)

type Outcome = workerrunner.LogOutcome

const (
	OutcomeSucceeded   = workerrunner.LogOutcomeSucceeded
	OutcomeFailed      = workerrunner.LogOutcomeFailed
	OutcomeCanceled    = workerrunner.LogOutcomeCanceled
	OutcomeTimedOut    = workerrunner.LogOutcomeTimedOut
	OutcomeInterrupted = workerrunner.LogOutcomeInterrupted
)

// EventV1 intentionally has no free-form message, error, argv, path, URL,
// secret reference, or output field. The root-capable Worker cannot use this
// transport to exfiltrate deployment secrets through normal log messages.
type EventV1 = workerrunner.LogEventV1

type LogsAPI interface {
	CreateLogStream(context.Context, *cloudwatchlogs.CreateLogStreamInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error)
	PutLogEvents(context.Context, *cloudwatchlogs.PutLogEventsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error)
}

type Sink struct {
	client LogsAPI
	group  string
	prefix string

	mu      sync.Mutex
	streams map[string]struct{}
}

func NewCloudWatchSink(client LogsAPI, group, prefix string) (*Sink, error) {
	group = strings.TrimSpace(group)
	prefix = strings.TrimSpace(prefix)
	if client == nil || !logGroupPattern.MatchString(group) || !logPrefixPattern.MatchString(prefix) ||
		security.ContainsLikelySecret(group) || security.ContainsLikelySecret(prefix) {
		return nil, errors.New("invalid Worker CloudWatch scope")
	}
	return &Sink{client: client, group: group, prefix: prefix, streams: make(map[string]struct{})}, nil
}

func (sink *Sink) Emit(ctx context.Context, event EventV1) error {
	if sink == nil || ctx == nil {
		return errors.New("Worker CloudWatch sink is unavailable")
	}
	normalized, err := normalizeEvent(event)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(normalized)
	if err != nil || len(payload) == 0 || len(payload) > maxMessageBytes || security.ContainsLikelySecret(string(payload)) {
		return errors.New("invalid Worker log event")
	}
	stream := sink.prefix + "/milestones-a" + strconv.FormatInt(int64(normalized.Attempt), 10) + "-e" + strconv.FormatInt(normalized.LeaseEpoch, 10)
	if !logStreamPattern.MatchString(stream) {
		return errors.New("invalid Worker log stream")
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if _, ready := sink.streams[stream]; !ready {
		_, err = sink.client.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
			LogGroupName:  &sink.group,
			LogStreamName: &stream,
		})
		if err != nil && !alreadyExists(err) {
			return errors.New("create Worker log stream")
		}
		sink.streams[stream] = struct{}{}
	}
	millis := normalized.OccurredAt.UnixMilli()
	message := string(payload)
	_, err = sink.client.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &sink.group,
		LogStreamName: &stream,
		LogEvents:     []cloudwatchtypes.InputLogEvent{{Message: &message, Timestamp: &millis}},
	})
	if err != nil {
		return errors.New("write Worker log event")
	}
	return nil
}

func normalizeEvent(event EventV1) (EventV1, error) {
	if event.SchemaVersion == "" {
		event.SchemaVersion = SchemaV1
	}
	if event.SchemaVersion != SchemaV1 || !validUUID(event.EventID) || !validUUID(event.DeploymentID) || !validUUID(event.WorkerID) ||
		event.Attempt < 1 || event.LeaseEpoch < 1 || event.OccurredAt.IsZero() {
		return EventV1{}, errors.New("invalid Worker log event")
	}
	switch event.Kind {
	case KindExecutionStarted:
		if event.ActionID != "" || event.Outcome != "" {
			return EventV1{}, errors.New("invalid execution-started log event")
		}
	case KindActionStarted, KindActionSucceeded:
		if !actionIDPattern.MatchString(event.ActionID) || event.Outcome != "" {
			return EventV1{}, errors.New("invalid action log event")
		}
	case KindActionFailed:
		if !actionIDPattern.MatchString(event.ActionID) || event.Outcome != OutcomeFailed {
			return EventV1{}, errors.New("invalid failed-action log event")
		}
	case KindExecutionFinished:
		if event.ActionID != "" || !validOutcome(event.Outcome) {
			return EventV1{}, errors.New("invalid execution-finished log event")
		}
	default:
		return EventV1{}, errors.New("invalid Worker log event kind")
	}
	event.OccurredAt = event.OccurredAt.UTC()
	return event, nil
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validOutcome(value Outcome) bool {
	switch value {
	case OutcomeSucceeded, OutcomeFailed, OutcomeCanceled, OutcomeTimedOut, OutcomeInterrupted:
		return true
	default:
		return false
	}
}

func alreadyExists(err error) bool {
	var api smithy.APIError
	return errors.As(err, &api) && api.ErrorCode() == "ResourceAlreadyExistsException"
}

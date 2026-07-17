package workerlog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

func TestCloudWatchSinkCreatesExactStreamAndWritesTypedMilestone(t *testing.T) {
	client := &logsFake{createErr: &smithy.GenericAPIError{Code: "ResourceAlreadyExistsException", Message: "already exists"}}
	sink, err := NewCloudWatchSink(client, "dtx-agent-a-foundation", "AROAABCDEFGHIJKLMNOP/i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	event := EventV1{
		EventID: uuid.NewString(), DeploymentID: uuid.NewString(), WorkerID: uuid.NewString(), Attempt: 2, LeaseEpoch: 7,
		Kind: KindActionSucceeded, ActionID: "install.openclaw", OccurredAt: time.Date(2026, 7, 17, 12, 0, 0, 0, time.FixedZone("CST", 8*60*60)),
	}
	if err := sink.Emit(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if client.createCalls != 1 || client.putCalls != 2 || client.createGroup != "dtx-agent-a-foundation" ||
		client.createStream != "AROAABCDEFGHIJKLMNOP/i-0123456789abcdef0/milestones-a2-e7" || client.putGroup != client.createGroup || client.putStream != client.createStream {
		t.Fatalf("unexpected CloudWatch calls: %+v", client)
	}
	for _, forbidden := range []string{"argv", "error", "secret_ref", "output", "path", "url"} {
		if strings.Contains(client.message, forbidden) {
			t.Fatalf("typed event exposed forbidden field %q: %s", forbidden, client.message)
		}
	}
	if !strings.Contains(client.message, `"kind":"action_succeeded"`) || !strings.Contains(client.message, `"occurred_at":"2026-07-17T04:00:00Z"`) {
		t.Fatalf("unexpected event payload: %s", client.message)
	}
}

func TestCloudWatchSinkRejectsUnsafeScopeAndFreeFormData(t *testing.T) {
	client := &logsFake{}
	for _, test := range []struct{ group, stream string }{
		{"", "AROAABCDEFGHIJKLMNOP/i-0123456789abcdef0"}, {"/group/path", "AROAABCDEFGHIJKLMNOP/i-0123456789abcdef0"},
		{"group", "bad:stream"}, {"group", "bad*stream"}, {"group\nforged", "AROAABCDEFGHIJKLMNOP/i-0123456789abcdef0"},
		{"group", "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		if _, err := NewCloudWatchSink(client, test.group, test.stream); err == nil {
			t.Fatalf("unsafe scope accepted: %#v", test)
		}
	}
	valid, err := NewCloudWatchSink(client, "group", "AROAABCDEFGHIJKLMNOP/i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	base := EventV1{EventID: uuid.NewString(), DeploymentID: uuid.NewString(), WorkerID: uuid.NewString(), Attempt: 1, LeaseEpoch: 1, OccurredAt: time.Now().UTC()}
	for name, mutate := range map[string]func(*EventV1){
		"unknown kind":     func(value *EventV1) { value.Kind = "arbitrary" },
		"action absent":    func(value *EventV1) { value.Kind = KindActionStarted },
		"outcome on start": func(value *EventV1) { value.Kind, value.Outcome = KindExecutionStarted, OutcomeSucceeded },
		"action on finish": func(value *EventV1) {
			value.Kind, value.ActionID, value.Outcome = KindExecutionFinished, "install", OutcomeSucceeded
		},
	} {
		t.Run(name, func(t *testing.T) {
			event := base
			mutate(&event)
			if err := valid.Emit(t.Context(), event); err == nil || client.createCalls != 0 || client.putCalls != 0 {
				t.Fatalf("invalid event reached CloudWatch: err=%v client=%+v", err, client)
			}
		})
	}
}

func TestCloudWatchSinkRedactsProviderErrors(t *testing.T) {
	canary := "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	client := &logsFake{putErr: errors.New("provider leaked " + canary)}
	sink, err := NewCloudWatchSink(client, "group", "AROAABCDEFGHIJKLMNOP/i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	err = sink.Emit(t.Context(), EventV1{
		EventID: uuid.NewString(), DeploymentID: uuid.NewString(), WorkerID: uuid.NewString(), Attempt: 1, LeaseEpoch: 1,
		Kind: KindExecutionStarted, OccurredAt: time.Now().UTC(),
	})
	if err == nil || strings.Contains(err.Error(), canary) || err.Error() != "write Worker log event" {
		t.Fatalf("unsafe provider error: %v", err)
	}
}

type logsFake struct {
	createErr    error
	putErr       error
	createCalls  int
	putCalls     int
	createGroup  string
	createStream string
	putGroup     string
	putStream    string
	message      string
}

func (fake *logsFake) CreateLogStream(_ context.Context, input *cloudwatchlogs.CreateLogStreamInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error) {
	fake.createCalls++
	fake.createGroup, fake.createStream = *input.LogGroupName, *input.LogStreamName
	return &cloudwatchlogs.CreateLogStreamOutput{}, fake.createErr
}

func (fake *logsFake) PutLogEvents(_ context.Context, input *cloudwatchlogs.PutLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	fake.putCalls++
	fake.putGroup, fake.putStream = *input.LogGroupName, *input.LogStreamName
	if len(input.LogEvents) == 1 && input.LogEvents[0].Message != nil {
		fake.message = *input.LogEvents[0].Message
	}
	return &cloudwatchlogs.PutLogEventsOutput{}, fake.putErr
}

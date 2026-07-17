package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerlog"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
)

type workerMilestoneLaunchFake struct {
	operation cloudexecution.Operation
	err       error
	calls     int
}

func (fake *workerMilestoneLaunchFake) GetByDeployment(_ context.Context, _ string) (cloudexecution.Operation, error) {
	fake.calls++
	return fake.operation, fake.err
}

type workerMilestoneConnectionFake struct {
	connection cloudapp.Connection
	err        error
	calls      int
}

func (fake *workerMilestoneConnectionFake) LoadConnection(_ context.Context, _, _ string) (cloudapp.Connection, error) {
	fake.calls++
	return fake.connection, fake.err
}

type workerMilestoneConnectionValidatorFake struct {
	ownerID, connectionID, foundationStack string
	err                                    error
	calls                                  int
}

func (fake *workerMilestoneConnectionValidatorFake) ValidateConnection(connection cloudapp.Connection, ownerID, connectionID string) error {
	fake.calls++
	if fake.err != nil {
		return fake.err
	}
	if ownerID != fake.ownerID || connectionID != fake.connectionID || connection.FoundationStack != fake.foundationStack {
		return errors.New("untrusted connection")
	}
	return nil
}

type workerMilestoneConfigFake struct {
	configuration aws.Config
	foundation    awsprovider.BootstrapIdentitySpec
	err           error
	calls         int
}

func (fake *workerMilestoneConfigFake) controlConfig(_ context.Context, _ cloudapp.Connection) (aws.Config, awsprovider.BootstrapIdentitySpec, error) {
	fake.calls++
	return fake.configuration, fake.foundation, fake.err
}

type workerMilestoneSinkFake struct {
	events []workerlog.EventV1
	err    error
}

func (fake *workerMilestoneSinkFake) Emit(_ context.Context, event workerlog.EventV1) error {
	fake.events = append(fake.events, event)
	return fake.err
}

type workerMilestoneSinkFactoryFake struct {
	sink   workerMilestoneSink
	err    error
	calls  int
	group  string
	prefix string
}

func (fake *workerMilestoneSinkFactoryFake) New(_ aws.Config, group, prefix string) (workerMilestoneSink, error) {
	fake.calls++
	fake.group, fake.prefix = group, prefix
	return fake.sink, fake.err
}

func TestWorkerMilestoneWriterUsesOnlyDerivedControlScopedStream(t *testing.T) {
	deploymentID, workerID, connectionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	const ownerID = "owner-a"
	const group = "dtx-agent-test"
	const prefix = "AROAABCDEFGHIJKLMNOP/i-0123456789abcdef0"
	const foundationStack = "dtx-agent-foundation-test"
	target := worker.MilestoneTarget{
		DeploymentID: deploymentID, WorkerID: workerID, OwnerID: ownerID,
		LogPrefix:    "cloudwatch://" + group + "/" + prefix,
		LogReference: "cloudwatch://" + group + "/" + prefix + "/milestones-a2-e9",
		Attempt:      2, LeaseEpoch: 9,
	}
	launches := &workerMilestoneLaunchFake{operation: cloudexecution.Operation{
		Intent: cloudexecution.Intent{Launch: cloudexecution.LaunchRequest{OwnerID: ownerID}, ConnectionID: connectionID, DeploymentID: deploymentID},
		State:  cloudexecution.StateActive,
	}}
	connections := &workerMilestoneConnectionFake{connection: cloudapp.Connection{
		ConnectionID: connectionID, OwnerID: ownerID, AccountID: "123456789012", Region: "us-east-1",
		FoundationStack: "arn:aws:cloudformation:us-east-1:123456789012:stack/" + foundationStack + "/01234567-89ab-4def-8123-456789abcdef", Status: "active",
	}}
	validator := &workerMilestoneConnectionValidatorFake{ownerID: ownerID, connectionID: connectionID, foundationStack: connections.connection.FoundationStack}
	configs := &workerMilestoneConfigFake{foundation: awsprovider.BootstrapIdentitySpec{
		StackName: foundationStack, WorkerLogGroupName: group, Partition: "aws", AccountID: "123456789012", Region: "us-east-1",
	}}
	sink := &workerMilestoneSinkFake{}
	factory := &workerMilestoneSinkFactoryFake{sink: sink}
	now := time.Date(2026, 7, 18, 3, 4, 5, 0, time.FixedZone("CST", 8*60*60))
	writer, err := newWorkerMilestoneWriter(launches, connections, validator, configs, factory, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	event := workerlog.EventV1{
		SchemaVersion: workerlog.SchemaV1, EventID: uuid.NewString(), DeploymentID: deploymentID, WorkerID: workerID,
		Attempt: 2, LeaseEpoch: 9, Kind: workerlog.KindActionSucceeded, ActionID: "install.openclaw",
		OccurredAt: time.Time{},
	}
	if err := writer.EmitMilestone(t.Context(), target, event); err != nil {
		t.Fatal(err)
	}
	if launches.calls != 1 || connections.calls != 1 || validator.calls != 1 || configs.calls != 1 || factory.calls != 1 || factory.group != group || factory.prefix != prefix || len(sink.events) != 1 {
		t.Fatalf("relay calls launch=%d connection=%d validation=%d config=%d sink=%d group=%q prefix=%q events=%+v", launches.calls, connections.calls, validator.calls, configs.calls, factory.calls, factory.group, factory.prefix, sink.events)
	}
	written := sink.events[0]
	if written.DeploymentID != deploymentID || written.WorkerID != workerID || written.Attempt != 2 || written.LeaseEpoch != 9 ||
		written.Kind != workerlog.KindActionSucceeded || written.ActionID != "install.openclaw" || written.OccurredAt != now.UTC() {
		t.Fatalf("written milestone = %+v", written)
	}

	for _, test := range []struct {
		name           string
		lookupCalls    int
		validatorCalls int
		mutate         func(*worker.MilestoneTarget, *workerlog.EventV1, *cloudapp.Connection)
	}{
		{name: "forged stream reference", mutate: func(target *worker.MilestoneTarget, _ *workerlog.EventV1, _ *cloudapp.Connection) {
			target.LogReference += "/forged"
		}},
		{name: "foreign event lease", mutate: func(_ *worker.MilestoneTarget, event *workerlog.EventV1, _ *cloudapp.Connection) { event.LeaseEpoch++ }},
		{name: "foreign foundation stack", lookupCalls: 1, validatorCalls: 1, mutate: func(_ *worker.MilestoneTarget, _ *workerlog.EventV1, connection *cloudapp.Connection) {
			connection.FoundationStack = "arn:aws:cloudformation:us-east-1:123456789012:stack/other-stack/01234567-89ab-4def-8123-456789abcdef"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			beforeLaunches, beforeConnections, beforeValidators, beforeConfigs, beforeSinks := launches.calls, connections.calls, validator.calls, configs.calls, factory.calls
			candidateTarget, candidateEvent := target, event
			originalConnection := connections.connection
			candidateConnection := originalConnection
			test.mutate(&candidateTarget, &candidateEvent, &candidateConnection)
			connections.connection = candidateConnection
			defer func() { connections.connection = originalConnection }()
			if err := writer.EmitMilestone(t.Context(), candidateTarget, candidateEvent); err == nil {
				t.Fatal("unsafe milestone target reached relay")
			}
			if launches.calls != beforeLaunches+test.lookupCalls || connections.calls != beforeConnections+test.lookupCalls || validator.calls != beforeValidators+test.validatorCalls || configs.calls != beforeConfigs || factory.calls != beforeSinks {
				t.Fatalf("unsafe milestone reached cloud path: launches=%d connections=%d validation=%d configs=%d sinks=%d", launches.calls, connections.calls, validator.calls, configs.calls, factory.calls)
			}
		})
	}

	canary := "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sink.err = errors.New(canary)
	if err := writer.EmitMilestone(t.Context(), target, event); err == nil || strings.Contains(err.Error(), canary) || err.Error() != "Worker milestone delivery failed" {
		t.Fatalf("unsafe sink error = %v", err)
	}
}

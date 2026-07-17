package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerlog"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

type workerMilestoneLaunchReader interface {
	GetByDeployment(context.Context, string) (cloudexecution.Operation, error)
}

type workerMilestoneConnectionReader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type workerMilestoneConnectionValidator interface {
	ValidateConnection(cloudapp.Connection, string, string) error
}

type workerMilestoneControlConfig interface {
	controlConfig(context.Context, cloudapp.Connection) (aws.Config, awsprovider.BootstrapIdentitySpec, error)
}

type workerMilestoneSink interface {
	Emit(context.Context, workerlog.EventV1) error
}

type workerMilestoneSinkFactory interface {
	New(aws.Config, string, string) (workerMilestoneSink, error)
}

type workerMilestoneWriter struct {
	launches    workerMilestoneLaunchReader
	connections workerMilestoneConnectionReader
	validator   workerMilestoneConnectionValidator
	configs     workerMilestoneControlConfig
	sinks       workerMilestoneSinkFactory
	now         func() time.Time
}

func newWorkerMilestoneWriter(
	launches workerMilestoneLaunchReader,
	connections workerMilestoneConnectionReader,
	validator workerMilestoneConnectionValidator,
	configs workerMilestoneControlConfig,
	sinks workerMilestoneSinkFactory,
	now func() time.Time,
) (*workerMilestoneWriter, error) {
	if launches == nil || connections == nil || validator == nil || configs == nil || sinks == nil || now == nil {
		return nil, errors.New("Worker milestone relay is unavailable")
	}
	return &workerMilestoneWriter{launches: launches, connections: connections, validator: validator, configs: configs, sinks: sinks, now: now}, nil
}

// EmitMilestone writes a closed telemetry event with the Control Role. The
// group, prefix, attempt, epoch, and timestamp all come from Agent-owned facts;
// the Worker only supplied the already-validated enum payload to rpcapi.
func (writer *workerMilestoneWriter) EmitMilestone(ctx context.Context, target worker.MilestoneTarget, event workerlog.EventV1) error {
	if writer == nil || ctx == nil || target.DeploymentID == "" || target.WorkerID == "" || target.OwnerID == "" || target.Attempt < 1 || target.LeaseEpoch < 1 {
		return errors.New("Worker milestone relay is unavailable")
	}
	group, prefix, err := workerMilestoneLogScope(target.LogPrefix)
	if err != nil {
		return err
	}
	expectedReference := fmt.Sprintf("cloudwatch://%s/%s/milestones-a%d-e%d", group, prefix, target.Attempt, target.LeaseEpoch)
	if target.LogReference != expectedReference || event.DeploymentID != target.DeploymentID || event.WorkerID != target.WorkerID ||
		event.Attempt != target.Attempt || event.LeaseEpoch != target.LeaseEpoch {
		return errors.New("Worker milestone target is invalid")
	}
	event.OccurredAt = writer.now().UTC()
	normalized, err := workerlog.ValidateEvent(event)
	if err != nil {
		return err
	}
	operation, err := writer.launches.GetByDeployment(ctx, target.DeploymentID)
	if err != nil || operation.DeploymentID != target.DeploymentID || operation.Launch.OwnerID != target.OwnerID || operation.ConnectionID == "" ||
		(operation.State != cloudexecution.StateProvisioning && operation.State != cloudexecution.StateActive) {
		return errors.New("Worker milestone deployment is unavailable")
	}
	connection, err := writer.connections.LoadConnection(ctx, target.OwnerID, operation.ConnectionID)
	if err != nil || connection.ConnectionID != operation.ConnectionID || connection.OwnerID != target.OwnerID || connection.Status != "active" {
		return errors.New("Worker milestone connection is unavailable")
	}
	if err := writer.validator.ValidateConnection(connection, target.OwnerID, operation.ConnectionID); err != nil {
		return errors.New("Worker milestone connection is unavailable")
	}
	configuration, foundation, err := writer.configs.controlConfig(ctx, connection)
	if err != nil || foundation.WorkerLogGroupName != group || foundation.StackName == "" {
		return errors.New("Worker milestone control scope is unavailable")
	}
	sink, err := writer.sinks.New(configuration, group, prefix)
	if err != nil || sink == nil {
		return errors.New("Worker milestone sink is unavailable")
	}
	if err := sink.Emit(ctx, normalized); err != nil {
		return errors.New("Worker milestone delivery failed")
	}
	return nil
}

func workerMilestoneLogScope(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "cloudwatch" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.HasSuffix(parsed.Path, "/") {
		return "", "", errors.New("Worker milestone log scope is invalid")
	}
	group, prefix := parsed.Host, strings.TrimPrefix(parsed.Path, "/")
	if err := workerlog.ValidateScope(group, prefix); err != nil {
		return "", "", err
	}
	return group, prefix, nil
}

type sdkWorkerMilestoneSinkFactory struct{}

func (sdkWorkerMilestoneSinkFactory) New(configuration aws.Config, group, prefix string) (workerMilestoneSink, error) {
	return workerlog.NewCloudWatchSink(cloudwatchlogs.NewFromConfig(configuration), group, prefix)
}

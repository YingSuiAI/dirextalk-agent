package awsreaper

import (
	"context"
	"errors"
	"log/slog"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

var ErrSweepFailed = errors.New("AWS Reaper sweep failed")

type Handler struct {
	reaper *resource.Reaper
	logger *slog.Logger
}

func NewHandler(reaper *resource.Reaper, logger *slog.Logger) (*Handler, error) {
	if reaper == nil || logger == nil {
		return nil, ErrInvalidConfig
	}
	return &Handler{reaper: reaper, logger: logger}, nil
}

func NewAWSHandler(config Config, awsConfig aws.Config, logger *slog.Logger) (*Handler, error) {
	if err := config.Validate(); err != nil || logger == nil || awsConfig.Region != config.Region {
		return nil, ErrInvalidConfig
	}
	mirror, err := NewDynamoManifestStore(dynamodb.NewFromConfig(awsConfig), config.ManifestTable, config.AgentInstanceID)
	if err != nil {
		return nil, err
	}
	ec2Client := ec2.NewFromConfig(awsConfig)
	provider, err := NewProvider(ec2Client, config.AgentInstanceID, config.Region,
		WithSecurityGroupRuleClient(ec2Client),
		WithELBV2Client(elbv2.NewFromConfig(awsConfig)),
	)
	if err != nil {
		return nil, err
	}
	reaper, err := resource.NewReaper(provider, mirror)
	if err != nil {
		return nil, err
	}
	return NewHandler(reaper, logger)
}

func (handler *Handler) Handle(ctx context.Context) (resource.ReapReport, error) {
	handler.logger.InfoContext(ctx, "aws_reaper_sweep_started")
	report, err := handler.reaper.Sweep(ctx)
	if err != nil {
		handler.logger.ErrorContext(ctx, "aws_reaper_sweep_failed", "error_code", errorCode(err))
		return report, ErrSweepFailed
	}
	handler.logger.InfoContext(ctx, "aws_reaper_sweep_completed",
		"examined", report.Examined,
		"skipped_managed", report.SkippedManaged,
		"skipped_not_approved", report.SkippedNotApproved,
		"verified_destroyed", report.VerifiedDestroyed,
		"blocked", report.Blocked,
	)
	return report, nil
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, resource.ErrRevisionConflict):
		return "manifest_revision_conflict"
	case errors.Is(err, ErrManifestStore):
		return "manifest_store_failed"
	case errors.Is(err, ErrCloudReadBack):
		return "cloud_readback_failed"
	case errors.Is(err, ErrCloudMutation):
		return "cloud_mutation_failed"
	case errors.Is(err, ErrOwnershipMismatch):
		return "ownership_mismatch"
	default:
		return "sweep_failed"
	}
}

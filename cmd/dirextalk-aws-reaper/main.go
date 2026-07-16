package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsreaper"
	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := awsreaper.LoadConfig(os.Getenv)
	if err != nil {
		logger.Error("aws_reaper_startup_failed", "error_code", "invalid_configuration")
		os.Exit(78)
	}
	ctx := context.Background()
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(config.Region))
	if err != nil {
		logger.Error("aws_reaper_startup_failed", "error_code", "aws_runtime_configuration_failed")
		os.Exit(78)
	}
	handler, err := awsreaper.NewAWSHandler(config, awsConfig, logger)
	if err != nil {
		logger.Error("aws_reaper_startup_failed", "error_code", "runtime_initialization_failed")
		os.Exit(78)
	}
	if os.Getenv("AWS_LAMBDA_RUNTIME_API") != "" {
		lambda.Start(handler.Handle)
		return
	}
	if _, err := handler.Handle(ctx); err != nil {
		os.Exit(1)
	}
}

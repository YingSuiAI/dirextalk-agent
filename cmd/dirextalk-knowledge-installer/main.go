package main

import (
	"context"
	"fmt"
	"os"
	"time"

	installer "github.com/YingSuiAI/dirextalk-agent/internal/knowledgeinstaller"
)

func main() {
	if len(os.Args) != 2 {
		fail("expected exactly one fixed subcommand")
	}
	timeout, ok := commandTimeout(os.Args[1])
	if !ok {
		fail("unknown fixed subcommand")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	serviceInstaller := installer.ProductionInstaller()
	if err := runCommand(ctx, os.Geteuid(), os.Args[1], serviceInstaller); err != nil {
		fail(err.Error())
	}
}

func commandTimeout(command string) (time.Duration, bool) {
	switch command {
	case "upgrade-v1":
		return 60 * time.Minute, true
	case "install-v1":
		return 40 * time.Minute, true
	case "backup-v1", "restore-v1", "rollback-v1":
		return 30 * time.Minute, true
	case "destroy-v1":
		return 10 * time.Minute, true
	case "restart-v1", "stop-v1":
		return 5 * time.Minute, true
	case "semantic-probe-v1":
		return time.Minute, true
	default:
		return 0, false
	}
}

type commandTarget interface {
	InstallV1(context.Context) error
	RestartV1(context.Context) error
	SemanticProbeV1(context.Context) error
	StopV1(context.Context) error
	BackupV1(context.Context) error
	RestoreV1(context.Context) error
	UpgradeV1(context.Context) error
	RollbackV1(context.Context) error
	DestroyV1(context.Context) error
}

func runCommand(ctx context.Context, effectiveUID int, command string, target commandTarget) error {
	if ctx == nil || target == nil {
		return fmt.Errorf("installer command dependencies are incomplete")
	}
	if command != "semantic-probe-v1" && effectiveUID != 0 {
		return fmt.Errorf("lifecycle command requires root")
	}
	switch command {
	case "install-v1":
		return target.InstallV1(ctx)
	case "restart-v1":
		return target.RestartV1(ctx)
	case "semantic-probe-v1":
		return target.SemanticProbeV1(ctx)
	case "stop-v1":
		return target.StopV1(ctx)
	case "backup-v1":
		return target.BackupV1(ctx)
	case "restore-v1":
		return target.RestoreV1(ctx)
	case "upgrade-v1":
		return target.UpgradeV1(ctx)
	case "rollback-v1":
		return target.RollbackV1(ctx)
	case "destroy-v1":
		return target.DestroyV1(ctx)
	default:
		return fmt.Errorf("unknown fixed subcommand")
	}
}

func fail(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "dirextalk-knowledge-installer:", message)
	os.Exit(1)
}

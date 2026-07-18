package main

import (
	"context"
	"testing"
	"time"
)

type commandTargetFake struct{ calls []string }

func (fake *commandTargetFake) InstallV1(context.Context) error {
	fake.calls = append(fake.calls, "install-v1")
	return nil
}
func (fake *commandTargetFake) RestartV1(context.Context) error {
	fake.calls = append(fake.calls, "restart-v1")
	return nil
}
func (fake *commandTargetFake) SemanticProbeV1(context.Context) error {
	fake.calls = append(fake.calls, "semantic-probe-v1")
	return nil
}
func (fake *commandTargetFake) StopV1(context.Context) error {
	fake.calls = append(fake.calls, "stop-v1")
	return nil
}
func (fake *commandTargetFake) BackupV1(context.Context) error {
	fake.calls = append(fake.calls, "backup-v1")
	return nil
}
func (fake *commandTargetFake) RestoreV1(context.Context) error {
	fake.calls = append(fake.calls, "restore-v1")
	return nil
}
func (fake *commandTargetFake) UpgradeV1(context.Context) error {
	fake.calls = append(fake.calls, "upgrade-v1")
	return nil
}
func (fake *commandTargetFake) RollbackV1(context.Context) error {
	fake.calls = append(fake.calls, "rollback-v1")
	return nil
}
func (fake *commandTargetFake) DestroyV1(context.Context) error {
	fake.calls = append(fake.calls, "destroy-v1")
	return nil
}

func TestLifecycleCommandsRequireRootBeforeDispatch(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"install-v1", "restart-v1", "stop-v1", "backup-v1", "restore-v1", "upgrade-v1", "rollback-v1", "destroy-v1"} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			target := &commandTargetFake{}
			if err := runCommand(context.Background(), 1000, command, target); err == nil || len(target.calls) != 0 {
				t.Fatalf("non-root dispatch error=%v calls=%v", err, target.calls)
			}
		})
	}
	target := &commandTargetFake{}
	if err := runCommand(context.Background(), 1000, "semantic-probe-v1", target); err != nil || len(target.calls) != 1 || target.calls[0] != "semantic-probe-v1" {
		t.Fatalf("unprivileged semantic probe error=%v calls=%v", err, target.calls)
	}
}

func TestRootLifecycleDispatchIsClosedAndExact(t *testing.T) {
	t.Parallel()
	target := &commandTargetFake{}
	for _, command := range []string{"stop-v1", "backup-v1", "restore-v1", "upgrade-v1", "rollback-v1", "destroy-v1"} {
		if err := runCommand(context.Background(), 0, command, target); err != nil {
			t.Fatal(err)
		}
	}
	if err := runCommand(context.Background(), 0, "destroy-v1 --force", target); err == nil {
		t.Fatal("caller-selected command text was accepted")
	}
}

func TestLifecycleCommandTimeoutsCoverSignedRecipeBounds(t *testing.T) {
	t.Parallel()
	for command, minimum := range map[string]time.Duration{
		"install-v1": 40 * time.Minute, "upgrade-v1": 60 * time.Minute,
		"backup-v1": 30 * time.Minute, "restore-v1": 30 * time.Minute, "rollback-v1": 30 * time.Minute,
		"destroy-v1": 10 * time.Minute, "restart-v1": 5 * time.Minute, "stop-v1": 5 * time.Minute,
		"semantic-probe-v1": time.Minute,
	} {
		timeout, ok := commandTimeout(command)
		if !ok || timeout < minimum {
			t.Fatalf("%s timeout = %s, %v", command, timeout, ok)
		}
	}
	if _, ok := commandTimeout("destroy-v1 --force"); ok {
		t.Fatal("caller-selected command timeout was accepted")
	}
}

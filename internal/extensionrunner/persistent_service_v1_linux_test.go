//go:build linux

package extensionrunner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

type persistentDestroyProcess struct {
	killErr error
	waitErr error
}

func (p persistentDestroyProcess) KillGroup() error { return p.killErr }
func (p persistentDestroyProcess) Wait() ([]byte, []byte, string, error) {
	return nil, nil, "failed", p.waitErr
}

func TestPersistentDestroyAcceptsExpectedKilledExit(t *testing.T) {
	service := &PersistentServiceV1{process: persistentDestroyProcess{waitErr: &exec.ExitError{}}}
	if err := service.Destroy(context.Background()); err != nil {
		t.Fatalf("expected killed exit rejected: %v", err)
	}
}

func TestPersistentDestroyPreservesCleanupFailure(t *testing.T) {
	waitErr := errors.Join(&exec.ExitError{}, errCgroupCleanup)
	service := &PersistentServiceV1{process: persistentDestroyProcess{waitErr: waitErr}}
	if err := service.Destroy(context.Background()); !errors.Is(err, errCgroupCleanup) {
		t.Fatalf("cleanup failure lost: %v", err)
	}
}

func TestPersistentIdentityRejectsPIDReuseEvidence(t *testing.T) {
	start, err := processStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidatePersistentIdentity(PersistentIdentity{PID: os.Getpid(), StartTime: start + 1, Cgroup: "/tmp/cgroup"}); err == nil {
		t.Fatal("mismatched start time accepted")
	}
}

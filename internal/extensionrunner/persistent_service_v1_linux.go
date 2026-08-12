//go:build linux

package extensionrunner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PersistentServiceV1 is the reviewed lower-level lifecycle below RunV2.
// Unlike RunV2 it deliberately does not wait or clean the cgroup at start;
// callers must persist PersistentIdentity and invoke Destroy. The same
// descriptor admission, namespace, seccomp, cgroup-v2 and pidfd primitives
// remain mandatory through LinuxBackend.StartV2.
type PersistentServiceV1 struct {
	process  Process
	identity PersistentIdentity
}

func StartPersistentServiceV1(ctx context.Context, backend LinuxBackend, invocation SandboxInvocationV2, grace time.Duration, outputLimit ...int64) (*PersistentServiceV1, error) {
	if grace <= 0 || grace > time.Minute {
		return nil, ErrInvalid
	}
	if len(outputLimit) > 0 && outputLimit[0] > 0 {
		// This must be present before StartV2 starts the child: setting a
		// writer limit after start leaves a window where unbounded raw output
		// can be retained.
		invocation.PersistentOutputLimit = outputLimit[0]
	}
	if err := backend.Probe(ctx); err != nil {
		return nil, err
	}
	p, err := backend.StartV2(ctx, invocation)
	if err != nil {
		return nil, err
	}
	identified, ok := p.(interface {
		PersistentIdentity() (PersistentIdentity, error)
	})
	if !ok {
		_ = p.KillGroup()
		_, _, _, _ = p.Wait()
		return nil, ErrUnavailable
	}
	id, err := identified.PersistentIdentity()
	if err != nil {
		_ = p.KillGroup()
		_, _, _, _ = p.Wait()
		return nil, err
	}
	select {
	case <-ctx.Done():
		_ = p.KillGroup()
		_, _, _, _ = p.Wait()
		return nil, ctx.Err()
	case <-time.After(grace):
	}
	if _, err = identified.PersistentIdentity(); err != nil {
		_ = p.KillGroup()
		_, _, _, _ = p.Wait()
		return nil, ErrUnavailable
	}
	return &PersistentServiceV1{process: p, identity: id}, nil
}
func (s *PersistentServiceV1) Identity() PersistentIdentity {
	if s == nil {
		return PersistentIdentity{}
	}
	return s.identity
}

// OutputBytes returns the bounded stdout+stderr retained by the sandbox
// process. It is intended for higher-level persistent quota monitors.
func (s *PersistentServiceV1) OutputBytes() int64 {
	if s == nil || s.process == nil {
		return 0
	}
	if p, ok := s.process.(interface{ OutputBytes() int64 }); ok {
		return p.OutputBytes()
	}
	return 0
}
func (s *PersistentServiceV1) OutputExceeded() bool {
	if s == nil || s.process == nil {
		return false
	}
	if p, ok := s.process.(interface{ OutputExceeded() bool }); ok {
		return p.OutputExceeded()
	}
	return false
}
func (s *PersistentServiceV1) Destroy(ctx context.Context) error {
	if s == nil || s.process == nil {
		return ErrInvalid
	}
	if err := s.process.KillGroup(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { _, _, _, e := s.process.Wait(); done <- e }()
	select {
	case e := <-done:
		// cgroup.kill deliberately terminates a still-running service. The
		// resulting ExitError proves process exit, while cleanup/accounting
		// failures remain fatal and must not be collapsed into success.
		var exitErr *exec.ExitError
		if errors.As(e, &exitErr) &&
			!errors.Is(e, errCgroupCleanup) &&
			!errors.Is(e, errSandboxRootCleanup) &&
			!errors.Is(e, errCPULimitExceeded) &&
			!errors.Is(e, errCPUAccounting) {
			return nil
		}
		return e
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DestroyPersistentIdentity is the restart-safe half of PersistentServiceV1.
// Callers must first bind Cgroup to their own delegated subtree; the identity
// check prevents a reused host PID from being signalled.
func DestroyPersistentIdentity(ctx context.Context, id PersistentIdentity) error {
	if id.PID <= 0 || id.StartTime == 0 || !filepath.IsAbs(id.Cgroup) || filepath.Clean(id.Cgroup) != id.Cgroup {
		return ErrInvalid
	}
	if _, err := os.Stat(id.Cgroup); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return ErrUnavailable
	}
	start, err := processStartTime(id.PID)
	if err != nil {
		// An already-exited process is safe to finish only when its exact
		// cgroup is provably empty. A live PID with another start time is never
		// treated as an exited service.
		if !os.IsNotExist(err) {
			return errors.Join(ErrUnavailable, err)
		}
		body, readErr := os.ReadFile(filepath.Join(id.Cgroup, "cgroup.events"))
		if readErr != nil || !strings.Contains(string(body), "populated 0") {
			return errCgroupCleanup
		}
		return cleanupCgroup(defaultCgroupOps(), id.Cgroup)
	}
	if start != id.StartTime {
		return ErrUnavailable
	}
	if err := killCgroup(defaultCgroupOps(), id.Cgroup); err != nil {
		return err
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		body, err := os.ReadFile(filepath.Join(id.Cgroup, "cgroup.events"))
		if err != nil {
			return errCgroupCleanup
		}
		if strings.Contains(string(body), "populated 0") {
			return cleanupCgroup(defaultCgroupOps(), id.Cgroup)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errCgroupCleanup
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// DestroyPersistentCgroup reaps a deterministic, runner-owned cgroup before
// a receipt exists.  An absent exact path is the idempotent success case.
func DestroyPersistentCgroup(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return ErrUnavailable
	}
	if err := killCgroup(defaultCgroupOps(), path); err != nil {
		return err
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		body, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return errCgroupCleanup
		}
		if strings.Contains(string(body), "populated 0") {
			return cleanupCgroup(defaultCgroupOps(), path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errCgroupCleanup
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func ValidatePersistentIdentity(id PersistentIdentity) error {
	if id.PID <= 0 || id.StartTime == 0 || !filepath.IsAbs(id.Cgroup) || filepath.Clean(id.Cgroup) != id.Cgroup {
		return ErrInvalid
	}
	start, err := processStartTime(id.PID)
	if err != nil || start != id.StartTime {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

//go:build linux

package extensionrunner

import (
	"context"
	"errors"
	"os"
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

func StartPersistentServiceV1(ctx context.Context, backend LinuxBackend, invocation SandboxInvocationV2, grace time.Duration) (*PersistentServiceV1, error) {
	if grace <= 0 || grace > time.Minute {
		return nil, ErrInvalid
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

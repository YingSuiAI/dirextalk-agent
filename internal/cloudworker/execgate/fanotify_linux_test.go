//go:build linux

package execgate

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type qualificationTestMonitor struct {
	events chan permissionEvent
	errors chan error
}

func (monitor *qualificationTestMonitor) Events() <-chan permissionEvent { return monitor.events }
func (monitor *qualificationTestMonitor) Errors() <-chan error           { return monitor.errors }
func (monitor *qualificationTestMonitor) Close() error                   { return nil }

func TestParseFanotifyPermissionMetadata(t *testing.T) {
	raw := make([]byte, 24)
	binary.NativeEndian.PutUint32(raw[0:4], 24)
	raw[4] = unix.FANOTIFY_METADATA_VERSION
	binary.NativeEndian.PutUint16(raw[6:8], 24)
	binary.NativeEndian.PutUint64(raw[8:16], unix.FAN_OPEN_EXEC_PERM)
	binary.NativeEndian.PutUint32(raw[16:20], uint32(12))
	binary.NativeEndian.PutUint32(raw[20:24], uint32(34))
	events, err := parseFanotifyEvents(raw)
	if err != nil || len(events) != 1 || events[0].Fd != 12 || events[0].Pid != 34 || events[0].Mask != unix.FAN_OPEN_EXEC_PERM {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	raw[4] = 0
	if _, err := parseFanotifyEvents(raw); err == nil {
		t.Fatal("metadata version drift accepted")
	}
}

func TestQualifyPermissionEventsAllowsEveryExecutableOpen(t *testing.T) {
	events := make(chan permissionEvent, 2)
	monitorErrors := make(chan error)
	commandDone := make(chan error, 1)
	responses := make([]bool, 0, 2)
	for index := 0; index < 2; index++ {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		last := index == 1
		events <- permissionEvent{
			PID:  int32(index + 1),
			File: file,
			done: func(allow bool) error {
				responses = append(responses, allow)
				if last {
					commandDone <- nil
				}
				return nil
			},
		}
	}
	if err := qualifyPermissionEvents(t.Context(), events, monitorErrors, commandDone); err != nil {
		t.Fatal(err)
	}
	if len(responses) != 2 || !responses[0] || !responses[1] {
		t.Fatalf("responses=%v, want two allowed executable opens", responses)
	}
}

func TestQualifyWithMonitorLaunchesConcurrentlyAndAllowsEveryExecutableOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	monitor := &qualificationTestMonitor{
		events: make(chan permissionEvent),
		errors: make(chan error),
	}
	run := func() error {
		for index := 0; index < 2; index++ {
			file, err := os.Open(os.DevNull)
			if err != nil {
				return err
			}
			response := make(chan bool, 1)
			event := permissionEvent{
				PID:  int32(index + 1),
				File: file,
				done: func(allow bool) error {
					response <- allow
					return nil
				},
			}
			select {
			case monitor.events <- event:
			case <-ctx.Done():
				_ = file.Close()
				return ctx.Err()
			}
			select {
			case allowed := <-response:
				if !allowed {
					return ErrViolation
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	if err := qualifyWithMonitor(ctx, monitor, run); err != nil {
		t.Fatal(err)
	}
}

func TestQualifyPermissionEventsRejectsUnobservedCompletion(t *testing.T) {
	events := make(chan permissionEvent)
	monitorErrors := make(chan error)
	commandDone := make(chan error, 1)
	commandDone <- nil
	if err := qualifyPermissionEvents(t.Context(), events, monitorErrors, commandDone); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error=%v, want ErrUnavailable", err)
	}
}

func TestQualifyPermissionEventsHonorsContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := qualifyPermissionEvents(ctx, make(chan permissionEvent), make(chan error), make(chan error))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("qualification returned after %v", elapsed)
	}
}

func TestFanotifyExecPermissionExternalAMIGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("AMI qualification requires root and CAP_SYS_ADMIN")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := QualifyFanotifyExecPermission(ctx, "/bin/true"); err != nil {
		if errors.Is(err, ErrUnavailable) {
			t.Skip("kernel/capability does not admit FAN_OPEN_EXEC_PERM; retain AMI external gate")
		}
		t.Fatal(err)
	}
	t.Log("cloud-worker fanotify executable permission qualification: PASS")
}

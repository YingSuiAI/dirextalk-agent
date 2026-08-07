//go:build linux

package execgate

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

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

func TestFanotifyExecPermissionExternalAMIGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("AMI qualification requires root and CAP_SYS_ADMIN")
	}
	monitor, err := newPermissionMonitor("/bin/true")
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			t.Skip("kernel/capability does not admit FAN_OPEN_EXEC_PERM; retain AMI external gate")
		}
		t.Fatal(err)
	}
	defer monitor.Close()
	command := exec.Command("/bin/true")
	done := make(chan error, 1)
	go func() { done <- command.Run() }()
	select {
	case event := <-monitor.Events():
		if event.PID < 1 || event.File == nil {
			t.Fatalf("invalid permission event: %+v", event)
		}
		if err := event.respond(true); err != nil {
			t.Fatal(err)
		}
		_ = event.File.Close()
	case err := <-monitor.Errors():
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("fanotify did not intercept executable open")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

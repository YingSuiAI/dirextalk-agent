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

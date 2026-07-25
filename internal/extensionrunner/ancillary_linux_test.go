//go:build linux

package extensionrunner

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCloseRightsCmsgsClosesRecoverableFDsBeforeMalformedTail(t *testing.T) {
	first := pipeFD(t)
	second := pipeFD(t)
	oob := append(unix.UnixRights(first, second), 0x7f) // malformed cmsghdr tail
	if err := closeRightsCmsgs(oob); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v, want protocol", err)
	}
	for _, fd := range []int{first, second} {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err == nil {
			t.Fatalf("fd %d leaked after malformed tail", fd)
		}
	}
}

func TestCloseRightsCmsgsClosesAllFDsWhenTruncatedRecordFollows(t *testing.T) {
	first := pipeFD(t)
	second := pipeFD(t)
	oob := append(unix.UnixRights(first, second), make([]byte, unix.CmsgLen(0))...)
	// A zero-length trailing header models the incomplete control buffer that
	// accompanies MSG_CTRUNC; the preceding rights must still be reclaimed.
	if err := closeRightsCmsgs(oob); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v, want protocol", err)
	}
	for _, fd := range []int{first, second} {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err == nil {
			t.Fatalf("fd %d leaked after truncation", fd)
		}
	}
}

func pipeFD(t *testing.T) int {
	t.Helper()
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fds[1]); err != nil {
		t.Fatal(err)
	}
	return fds[0]
}

//go:build linux

package extensionrunner

import (
	"os"
	"testing"
)

func TestPersistentIdentityRejectsPIDReuseEvidence(t *testing.T) {
	start, err := processStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidatePersistentIdentity(PersistentIdentity{PID: os.Getpid(), StartTime: start + 1, Cgroup: "/tmp/cgroup"}); err == nil {
		t.Fatal("mismatched start time accepted")
	}
}

//go:build linux

package extensionrunner

import (
	"errors"
	"strings"
	"testing"
)

func TestEnsureCgroupDelegationAlreadyEnabled(t *testing.T) {
	reads, writes := 0, 0
	err := ensureCgroupDelegation("/cgroup/cgroup.subtree_control", func(path string) ([]byte, error) {
		reads++
		if path != "/cgroup/cgroup.subtree_control" {
			t.Fatalf("read path = %q", path)
		}
		return []byte("cpu io memory pids\n"), nil
	}, func(string, string) error {
		writes++
		return nil
	})
	if err != nil {
		t.Fatalf("ensure delegation: %v", err)
	}
	if reads != 2 || writes != 0 {
		t.Fatalf("already-enabled I/O: reads=%d writes=%d", reads, writes)
	}
}

func TestEnsureCgroupDelegationEnablesOnlyMissingControllers(t *testing.T) {
	state := map[string]bool{"cpu": true, "io": true}
	reads := 0
	var writes []string
	read := func(path string) ([]byte, error) {
		reads++
		var enabled []string
		for _, name := range []string{"cpu", "io", "memory", "pids"} {
			if state[name] {
				enabled = append(enabled, name)
			}
		}
		return []byte(strings.Join(enabled, " ") + "\n"), nil
	}
	write := func(path, value string) error {
		writes = append(writes, value)
		for _, command := range strings.Fields(value) {
			state[strings.TrimPrefix(command, "+")] = true
		}
		return nil
	}
	if err := ensureCgroupDelegation("/cgroup/cgroup.subtree_control", read, write); err != nil {
		t.Fatalf("ensure delegation: %v", err)
	}
	if reads != 2 || len(writes) != 1 || writes[0] != "+memory +pids" {
		t.Fatalf("missing-controller I/O: reads=%d writes=%q", reads, writes)
	}
	if !state["cpu"] || !state["memory"] || !state["pids"] || !state["io"] {
		t.Fatalf("enabled state = %+v", state)
	}
}

func TestEnsureCgroupDelegationFailsClosedOnWriteOrReadback(t *testing.T) {
	tests := []struct {
		name  string
		read  func(string) ([]byte, error)
		write func(string, string) error
	}{
		{
			name: "write",
			read: func(string) ([]byte, error) { return []byte("cpu\n"), nil },
			write: func(string, string) error {
				return errors.New("write denied")
			},
		},
		{
			name: "readback error",
			read: func() func(string) ([]byte, error) {
				calls := 0
				return func(string) ([]byte, error) {
					calls++
					if calls == 1 {
						return []byte("cpu\n"), nil
					}
					return nil, errors.New("readback denied")
				}
			}(),
			write: func(string, string) error { return nil },
		},
		{
			name:  "readback incomplete",
			read:  func(string) ([]byte, error) { return []byte("cpu\n"), nil },
			write: func(string, string) error { return nil },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ensureCgroupDelegation("/cgroup/cgroup.subtree_control", test.read, test.write)
			stage, ok := AvailabilityStage(err)
			if !ok || stage != "cgroup_delegation" || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("stage=%q ok=%v err=%v", stage, ok, err)
			}
		})
	}
}

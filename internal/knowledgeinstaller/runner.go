package installer

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

type Runner interface {
	Run(context.Context, string, ...string) error
	UnitState(context.Context, string) (UnitState, error)
}

type UnitState struct {
	LoadState   string
	ActiveState string
}

type FixedRunner struct{}

func (FixedRunner) Run(ctx context.Context, executable string, args ...string) error {
	allowed := [][]string{
		{"/usr/bin/systemd-sysusers", SysusersPath},
		{"/usr/bin/systemd-tmpfiles", "--create", TmpfilesPath},
		{"/usr/bin/systemctl", "daemon-reload"},
		{"/usr/bin/systemctl", "enable", "--now", "dirextalk-qdrant.service"},
		{"/usr/bin/systemctl", "enable", "--now", "dirextalk-knowledge-adapter.service"},
		{"/usr/bin/systemctl", "restart", "dirextalk-qdrant.service"},
		{"/usr/bin/systemctl", "restart", "dirextalk-knowledge-adapter.service"},
		{"/usr/bin/systemctl", "stop", "dirextalk-knowledge-adapter.service"},
		{"/usr/bin/systemctl", "stop", "dirextalk-qdrant.service"},
		{"/usr/bin/systemctl", "disable", "dirextalk-knowledge-adapter.service"},
		{"/usr/bin/systemctl", "disable", "dirextalk-qdrant.service"},
		{"/usr/bin/systemctl", "is-active", "--quiet", "dirextalk-qdrant.service"},
		{"/usr/bin/systemctl", "is-active", "--quiet", "dirextalk-knowledge-adapter.service"},
	}
	invocation := append([]string{executable}, args...)
	if !slices.ContainsFunc(allowed, func(candidate []string) bool { return slices.Equal(candidate, invocation) }) {
		return fmt.Errorf("external executable is not allowed")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{}
	if output, err := command.CombinedOutput(); err != nil {
		// Fixed service-manager output contains no adapter document, query, vector,
		// or API-key arguments. Bound it before returning diagnostic context.
		if len(output) > 4096 {
			output = output[:4096]
		}
		return fmt.Errorf("fixed command failed: %s: %w", string(output), err)
	}
	return nil
}

func (FixedRunner) UnitState(ctx context.Context, unit string) (UnitState, error) {
	if unit != "dirextalk-qdrant.service" && unit != "dirextalk-knowledge-adapter.service" {
		return UnitState{}, fmt.Errorf("service unit is not allowed")
	}
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--property=ActiveState", unit)
	command.Env = []string{}
	output, err := command.Output()
	if err != nil || len(output) > 128 {
		return UnitState{}, fmt.Errorf("read fixed service state")
	}
	return parseFixedUnitState(string(output))
}

func parseFixedUnitState(output string) (UnitState, error) {
	var state UnitState
	for _, line := range strings.Fields(output) {
		key, value, ok := strings.Cut(line, "=")
		if !ok || value == "" {
			return UnitState{}, fmt.Errorf("invalid fixed service state")
		}
		switch key {
		case "LoadState":
			if state.LoadState != "" {
				return UnitState{}, fmt.Errorf("invalid fixed service state")
			}
			state.LoadState = value
		case "ActiveState":
			if state.ActiveState != "" {
				return UnitState{}, fmt.Errorf("invalid fixed service state")
			}
			state.ActiveState = value
		default:
			return UnitState{}, fmt.Errorf("invalid fixed service state")
		}
	}
	if state.LoadState == "" || state.ActiveState == "" {
		return UnitState{}, fmt.Errorf("invalid fixed service state")
	}
	return state, nil
}

type Identity struct {
	UID int
	GID int
}

type IdentityResolver interface {
	Resolve(userName string) (Identity, error)
}

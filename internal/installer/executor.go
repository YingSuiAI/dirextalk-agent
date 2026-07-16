package installer

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

// SafePathEnvironment is the daemon's complete child environment. In
// particular, AWS, proxy, home, credential, and control-process values are not
// inherited. Commands that require a shell must declare it explicitly in the
// signed argv (for example /bin/sh -ceu ...).
const SafePathEnvironment = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type CommandExecution struct {
	Argv             []string
	WorkingDirectory string
	Environment      []string
	Timeout          time.Duration
}

type CommandRunner interface {
	Run(context.Context, CommandExecution) error
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, execution CommandExecution) error {
	if len(execution.Argv) == 0 || len(execution.Environment) != 1 || execution.Environment[0] != SafePathEnvironment ||
		execution.Timeout <= 0 || !path.IsAbs(execution.WorkingDirectory) || path.Clean(execution.WorkingDirectory) != execution.WorkingDirectory {
		return errors.New("approved execution is invalid")
	}
	executable, err := resolveSafeExecutable(execution.Argv[0])
	if err != nil {
		return errors.New("approved executable is unavailable")
	}
	command := exec.CommandContext(ctx, executable, execution.Argv[1:]...)
	command.Dir = execution.WorkingDirectory
	command.Env = append([]string(nil), execution.Environment...)
	command.Stdin = nil
	// Command output can contain service credentials or pairing material. The
	// privileged boundary never returns or journals it.
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	configureCommandCancellation(command)
	return command.Run()
}

func resolveSafeExecutable(executable string) (string, error) {
	if strings.Contains(executable, "/") {
		return executable, nil
	}
	for _, directory := range strings.Split(strings.TrimPrefix(SafePathEnvironment, "PATH="), ":") {
		candidate := path.Join(directory, executable)
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

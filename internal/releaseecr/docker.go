package releaseecr

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"slices"
)

type dockerRunner struct{}

func (dockerRunner) Run(ctx context.Context, command Command) error {
	if command.Executable != "docker" || len(command.Stdin) < 2 || len(command.Stdin) > 8193 ||
		len(command.Arguments) != 5 || !slices.Equal(command.Arguments[:4], []string{"login", "--username", "AWS", "--password-stdin"}) ||
		command.Arguments[4] == "" || command.DockerConfigDir == "" {
		return ErrDockerLogin
	}
	process := exec.CommandContext(ctx, "docker", command.Arguments...)
	process.Env = safeDockerEnvironment(command.DockerConfigDir)
	process.Stdin = bytes.NewReader(command.Stdin)
	process.Stdout = io.Discard
	process.Stderr = io.Discard
	if err := process.Run(); err != nil {
		return ErrDockerLogin
	}
	return nil
}

func safeDockerEnvironment(dockerConfigDir string) []string {
	keys := []string{
		"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
		"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
		"TMP", "TEMP", "TMPDIR", "XDG_CONFIG_HOME",
	}
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, exists := os.LookupEnv(key); exists {
			environment = append(environment, key+"="+value)
		}
	}
	environment = append(environment, "DOCKER_CONFIG="+dockerConfigDir)
	return environment
}

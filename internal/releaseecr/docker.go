package releaseecr

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

const releaseDockerHostEnv = "DIREXTALK_RELEASE_DOCKER_HOST"

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
	if dockerHost, ok := ExplicitDockerHost(); ok {
		environment = append(environment, "DOCKER_HOST="+dockerHost)
	}
	environment = append(environment, "DOCKER_CONFIG="+dockerConfigDir)
	return environment
}

// ExplicitDockerHost returns the release-only Docker endpoint after proving it
// is a TCP listener bound to an IP loopback address.
func ExplicitDockerHost() (string, bool) {
	return validatedReleaseDockerHost(os.Getenv(releaseDockerHostEnv))
}

func validatedReleaseDockerHost(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "tcp" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	host := net.ParseIP(parsed.Hostname())
	if host == nil || !host.IsLoopback() {
		return "", false
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", false
	}
	return value, true
}

package releaseecr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	builderMarkerName     = ".dirextalk-buildx-owned"
	builderNamePrefix     = "dirextalk-release-"
	builderCleanupTimeout = 2 * time.Minute
	maxBuilderOutput      = 64 << 10
)

type builderMarker struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type builderCommandRunner interface {
	Run(context.Context, string, []byte, ...string) ([]byte, error)
}

type execBuilderRunner struct{}

func (execBuilderRunner) Run(ctx context.Context, dockerConfigDir string, stdin []byte, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Env = safeDockerEnvironment(dockerConfigDir)
	if len(stdin) != 0 {
		command.Stdin = bytes.NewReader(stdin)
	}
	var output limitedBuilderOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, ErrBuilder
	}
	return output.Bytes(), nil
}

type limitedBuilderOutput struct {
	buffer bytes.Buffer
}

func (output *limitedBuilderOutput) Write(content []byte) (int, error) {
	if output.buffer.Len()+len(content) > maxBuilderOutput {
		return 0, ErrBuilder
	}
	return output.buffer.Write(content)
}

func (output *limitedBuilderOutput) Bytes() []byte {
	return output.buffer.Bytes()
}

type builderManager struct {
	runner builderCommandRunner
}

func directBuilderName(sessionID string) string {
	return builderNamePrefix + sessionID
}

func ActivateSessionBuilder(ctx context.Context, session SessionV1) error {
	return (builderManager{runner: execBuilderRunner{}}).activate(ctx, session)
}

func cleanupSessionBuilder(session SessionV1) error {
	if session.BuilderMode == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), builderCleanupTimeout)
	defer cancel()
	return (builderManager{runner: execBuilderRunner{}}).cleanup(ctx, session)
}

func (manager builderManager) activate(ctx context.Context, session SessionV1) error {
	if manager.runner == nil || session.BuilderMode != BuilderModeDirect ||
		!session.BuildSourcesVerified || validateSession(session, time.Time{}) != nil {
		return ErrBuilder
	}
	sources, err := PrivateBuildSourceReferences(session.RegistryHost)
	if err != nil {
		return ErrBuilder
	}
	owned, err := readBuilderMarker(session)
	if err != nil || owned {
		return ErrBuilder
	}
	state, err := manager.readState(ctx, session)
	if err != nil {
		return ErrBuilder
	}
	if state.any() {
		return ErrBuilderCollision
	}
	proxy, err := manager.readDockerProxy(ctx, session.DockerConfigDir)
	if err != nil {
		return ErrBuilder
	}
	if err := writeBuilderMarker(session); err != nil {
		return ErrBuilder
	}
	_, createErr := manager.runner.Run(ctx, session.DockerConfigDir, nil,
		"buildx", "create",
		"--name", session.BuilderName,
		"--driver", "docker-container",
		"--driver-opt", "image="+sources.BuildKit,
		"--driver-opt", "env.HTTP_PROXY="+proxy,
		"--driver-opt", "env.HTTPS_PROXY="+proxy,
		"--driver-opt", "env.http_proxy="+proxy,
		"--driver-opt", "env.https_proxy="+proxy,
		"--bootstrap",
	)
	if createErr != nil {
		if cleanupErr := manager.rollback(session); cleanupErr != nil {
			return ErrSessionCleanup
		}
		return ErrBuilder
	}
	state, err = manager.readState(ctx, session)
	if err != nil || !state.builder || !state.container || !state.volume {
		if cleanupErr := manager.rollback(session); cleanupErr != nil {
			return ErrSessionCleanup
		}
		return ErrBuilder
	}
	if err := manager.preflight(ctx, session); err != nil {
		if cleanupErr := manager.rollback(session); cleanupErr != nil {
			return ErrSessionCleanup
		}
		return ErrBuilder
	}
	return nil
}

func (manager builderManager) rollback(session SessionV1) error {
	ctx, cancel := context.WithTimeout(context.Background(), builderCleanupTimeout)
	defer cancel()
	return manager.cleanup(ctx, session)
}

func (manager builderManager) readDockerProxy(ctx context.Context, dockerConfigDir string) (string, error) {
	httpOutput, err := manager.runner.Run(ctx, dockerConfigDir, nil, "info", "--format", "{{json .HTTPProxy}}")
	if err != nil {
		return "", ErrBuilder
	}
	httpsOutput, err := manager.runner.Run(ctx, dockerConfigDir, nil, "info", "--format", "{{json .HTTPSProxy}}")
	if err != nil {
		return "", ErrBuilder
	}
	var httpProxy, httpsProxy string
	if json.Unmarshal(bytes.TrimSpace(httpOutput), &httpProxy) != nil ||
		json.Unmarshal(bytes.TrimSpace(httpsOutput), &httpsProxy) != nil {
		return "", ErrBuilder
	}
	normalize := func(raw string) (string, error) {
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		parsed, err := url.Parse(raw)
		port, portErr := strconv.Atoi(parsed.Port())
		if err != nil || portErr != nil || parsed.Scheme != "http" || parsed.User != nil ||
			parsed.Hostname() != "http.docker.internal" || port < 1 || port > 65535 ||
			parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			net.ParseIP(parsed.Hostname()) != nil {
			return "", ErrBuilder
		}
		return parsed.String(), nil
	}
	httpProxy, err = normalize(httpProxy)
	if err != nil {
		return "", err
	}
	httpsProxy, err = normalize(httpsProxy)
	if err != nil || httpProxy != httpsProxy {
		return "", ErrBuilder
	}
	return httpProxy, nil
}

func (manager builderManager) preflight(ctx context.Context, session SessionV1) error {
	sources, err := PrivateBuildSourceReferences(session.RegistryHost)
	if err != nil {
		return ErrBuilder
	}
	contextDirectory, err := os.MkdirTemp("", "dirextalk-buildkit-probe-")
	if err != nil {
		return ErrBuilder
	}
	defer os.RemoveAll(contextDirectory)
	dockerfile := []byte("ARG GO_BUILD_BASE\nFROM --platform=linux/amd64 ${GO_BUILD_BASE}\n")
	defer clear(dockerfile)
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := manager.runner.Run(ctx, session.DockerConfigDir, dockerfile,
			"buildx", "--builder", session.BuilderName, "build",
			"--platform", "linux/amd64", "--pull", "--no-cache",
			"--build-arg", "BUILDKIT_SYNTAX="+sources.Frontend,
			"--build-arg", "GO_BUILD_BASE="+sources.GoBuildBase,
			"--progress=plain", "--output", "type=cacheonly",
			"--file", "-", contextDirectory,
		); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ErrBuilder
		}
	}
	return ErrBuilder
}

func (manager builderManager) cleanup(ctx context.Context, session SessionV1) error {
	if manager.runner == nil || (session.BuilderMode != "" && session.BuilderMode != BuilderModeDirect) {
		return ErrBuilder
	}
	if session.BuilderMode == "" {
		return nil
	}
	owned, err := readBuilderMarker(session)
	if err != nil {
		return ErrBuilder
	}
	if !owned {
		return nil
	}
	_, _ = manager.runner.Run(ctx, session.DockerConfigDir, nil, "buildx", "rm", session.BuilderName)
	state, err := manager.readState(ctx, session)
	if err != nil {
		return ErrBuilder
	}
	if state.container {
		if _, err := manager.runner.Run(ctx, session.DockerConfigDir, nil, "container", "rm", "--force", builderContainerName(session.BuilderName)); err != nil {
			return ErrBuilder
		}
	}
	if state.volume {
		if _, err := manager.runner.Run(ctx, session.DockerConfigDir, nil, "volume", "rm", builderVolumeName(session.BuilderName)); err != nil {
			return ErrBuilder
		}
	}
	if state.builder {
		_, _ = manager.runner.Run(ctx, session.DockerConfigDir, nil, "buildx", "rm", session.BuilderName)
	}
	state, err = manager.readState(ctx, session)
	if err != nil || state.any() {
		return ErrBuilder
	}
	return nil
}

type builderState struct {
	builder   bool
	container bool
	volume    bool
}

func (state builderState) any() bool {
	return state.builder || state.container || state.volume
}

func (manager builderManager) readState(ctx context.Context, session SessionV1) (builderState, error) {
	builderOutput, err := manager.runner.Run(ctx, session.DockerConfigDir, nil, "buildx", "ls", "--format", "{{.Name}}")
	if err != nil {
		return builderState{}, err
	}
	containerOutput, err := manager.runner.Run(ctx, session.DockerConfigDir, nil,
		"container", "ls", "--all", "--filter", "name=^/"+builderContainerName(session.BuilderName)+"$", "--format", "{{.Names}}")
	if err != nil {
		return builderState{}, err
	}
	volumeOutput, err := manager.runner.Run(ctx, session.DockerConfigDir, nil,
		"volume", "ls", "--filter", "name=^"+builderVolumeName(session.BuilderName)+"$", "--format", "{{.Name}}")
	if err != nil {
		return builderState{}, err
	}
	return builderState{
		builder:   outputHasExactName(builderOutput, session.BuilderName),
		container: outputHasExactName(containerOutput, builderContainerName(session.BuilderName)),
		volume:    outputHasExactName(volumeOutput, builderVolumeName(session.BuilderName)),
	}, nil
}

func outputHasExactName(output []byte, name string) bool {
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSuffix(strings.TrimSpace(line), "*") == name {
			return true
		}
	}
	return false
}

func builderContainerName(name string) string {
	return "buildx_buildkit_" + name + "0"
}

func builderVolumeName(name string) string {
	return "buildx_buildkit_" + name + "0_state"
}

func writeBuilderMarker(session SessionV1) error {
	sources, err := PrivateBuildSourceReferences(session.RegistryHost)
	if err != nil {
		return ErrBuilder
	}
	payload, err := json.Marshal(builderMarker{Name: session.BuilderName, Image: sources.BuildKit})
	if err != nil {
		return ErrBuilder
	}
	payload = append(payload, '\n')
	if err := writePrivateFile(filepath.Join(session.DockerConfigDir, builderMarkerName), payload); err != nil {
		return ErrBuilder
	}
	return nil
}

func readBuilderMarker(session SessionV1) (bool, error) {
	payload, err := os.ReadFile(filepath.Join(session.DockerConfigDir, builderMarkerName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || len(payload) == 0 || len(payload) > 4096 {
		return false, ErrBuilder
	}
	var marker builderMarker
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	sources, sourceErr := PrivateBuildSourceReferences(session.RegistryHost)
	if err := decoder.Decode(&marker); err != nil || sourceErr != nil ||
		marker.Name != session.BuilderName || marker.Image != sources.BuildKit {
		return false, ErrBuilder
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, ErrBuilder
	}
	return true, nil
}

package releaseecr

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeBuilderRunner struct {
	commands   [][]string
	configs    []string
	builder    bool
	container  bool
	volume     bool
	failRemove bool
	httpProxy  string
	httpsProxy string
}

func (runner *fakeBuilderRunner) Run(_ context.Context, config string, stdin []byte, arguments ...string) ([]byte, error) {
	runner.configs = append(runner.configs, config)
	runner.commands = append(runner.commands, append([]string(nil), arguments...))
	switch {
	case len(arguments) >= 4 && slices.Equal(arguments[:4], []string{"buildx", "--builder", directBuilderName(strings.Repeat("a", 32)), "build"}):
		sources, _ := PrivateBuildSourceReferences(registryHost(testAccount, BuildSourceRegion))
		if !strings.Contains(string(stdin), "ARG GO_BUILD_BASE") ||
			!slices.Contains(arguments, "BUILDKIT_SYNTAX="+sources.Frontend) ||
			!slices.Contains(arguments, "GO_BUILD_BASE="+sources.GoBuildBase) {
			return nil, errors.New("unpinned preflight")
		}
		return nil, nil
	case slices.Equal(arguments, []string{"info", "--format", "{{json .HTTPProxy}}"}):
		value := runner.httpProxy
		if value == "" {
			value = "http.docker.internal:3128"
		}
		return []byte(`"` + value + `"`), nil
	case slices.Equal(arguments, []string{"info", "--format", "{{json .HTTPSProxy}}"}):
		value := runner.httpsProxy
		if value == "" {
			value = "http.docker.internal:3128"
		}
		return []byte(`"` + value + `"`), nil
	case slices.Equal(arguments, []string{"buildx", "ls", "--format", "{{.Name}}"}):
		if runner.builder {
			return []byte(directBuilderName(strings.Repeat("a", 32)) + "*\n"), nil
		}
		return []byte("default*\n"), nil
	case len(arguments) == 17 && slices.Equal(arguments[:2], []string{"buildx", "create"}):
		runner.builder, runner.container, runner.volume = true, true, true
		return nil, nil
	case len(arguments) == 3 && slices.Equal(arguments[:2], []string{"buildx", "rm"}):
		if runner.failRemove {
			runner.failRemove = false
			return nil, ErrBuilder
		}
		runner.builder, runner.container, runner.volume = false, false, false
		return nil, nil
	case len(arguments) >= 2 && slices.Equal(arguments[:2], []string{"container", "ls"}):
		if runner.container {
			return []byte(builderContainerName(directBuilderName(strings.Repeat("a", 32))) + "\n"), nil
		}
		return nil, nil
	case len(arguments) >= 2 && slices.Equal(arguments[:2], []string{"volume", "ls"}):
		if runner.volume {
			return []byte(builderVolumeName(directBuilderName(strings.Repeat("a", 32))) + "\n"), nil
		}
		return nil, nil
	case len(arguments) == 4 && slices.Equal(arguments[:3], []string{"container", "rm", "--force"}):
		runner.container = false
		return nil, nil
	case len(arguments) == 9 && slices.Equal(arguments[:2], []string{"container", "exec"}):
		return nil, nil
	case len(arguments) == 3 && slices.Equal(arguments[:2], []string{"volume", "rm"}):
		runner.volume = false
		return nil, nil
	default:
		return nil, errors.New("unexpected builder command")
	}
}

func TestDirectBuilderUsesPinnedPrivateSessionAndCleansWithReadBack(t *testing.T) {
	session := directTestSession(t)
	runner := &fakeBuilderRunner{}
	manager := builderManager{runner: runner}

	if err := manager.activate(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if !runner.builder || !runner.container || !runner.volume {
		t.Fatalf("builder not fully active: %#v", runner)
	}
	sources, err := PrivateBuildSourceReferences(session.RegistryHost)
	if err != nil {
		t.Fatal(err)
	}
	wantCreate := []string{
		"buildx", "create", "--name", session.BuilderName,
		"--driver", "docker-container", "--driver-opt", "image=" + sources.BuildKit, "--bootstrap",
	}
	if !commandWithRequiredArguments(runner.commands, wantCreate[:8], "--bootstrap") {
		t.Fatalf("pinned create command missing: %#v", runner.commands)
	}
	for _, config := range runner.configs {
		if config != session.DockerConfigDir {
			t.Fatalf("builder escaped private Docker config: %q", config)
		}
	}
	if err := manager.cleanup(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(session.DockerConfigDir + "/" + builderMarkerName)
	if err != nil || strings.Contains(string(marker), "http.docker.internal") {
		t.Fatalf("proxy leaked into durable builder marker: %v", err)
	}
	if runner.builder || runner.container || runner.volume {
		t.Fatalf("builder residue after cleanup: %#v", runner)
	}
}

func TestDirectBuilderForeignCollisionFailsClosedWithoutRemoval(t *testing.T) {
	session := directTestSession(t)
	runner := &fakeBuilderRunner{container: true}
	err := (builderManager{runner: runner}).activate(context.Background(), session)
	if !errors.Is(err, ErrBuilderCollision) {
		t.Fatalf("collision error = %v", err)
	}
	if !runner.container || commandWithPrefix(runner.commands, "buildx", "create") ||
		commandWithPrefix(runner.commands, "container", "rm") {
		t.Fatalf("foreign builder was changed: %#v", runner.commands)
	}
	if _, err := os.Lstat(session.DockerConfigDir + "/" + builderMarkerName); !os.IsNotExist(err) {
		t.Fatalf("ownership marker created for foreign builder: %v", err)
	}
}

func TestDirectBuilderInterruptedPrimaryRemovalFallsBackAndReadsBack(t *testing.T) {
	session := directTestSession(t)
	runner := &fakeBuilderRunner{}
	manager := builderManager{runner: runner}
	if err := manager.activate(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	runner.failRemove = true
	if err := manager.cleanup(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if runner.builder || runner.container || runner.volume ||
		!commandWithPrefix(runner.commands, "container", "rm") ||
		!commandWithPrefix(runner.commands, "volume", "rm") {
		t.Fatalf("fallback cleanup/readback incomplete: %#v", runner)
	}
}

func TestDirectBuilderRejectsForeignOrCredentialedProxyBeforeOwnership(t *testing.T) {
	for _, test := range []struct {
		name  string
		proxy string
	}{
		{name: "foreign host", proxy: "http://example.com:3128"},
		{name: "userinfo", proxy: "http://user:password@http.docker.internal:3128"},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := directTestSession(t)
			runner := &fakeBuilderRunner{httpProxy: test.proxy, httpsProxy: test.proxy}
			if err := (builderManager{runner: runner}).activate(context.Background(), session); !errors.Is(err, ErrBuilder) {
				t.Fatalf("proxy rejection error = %v", err)
			}
			if commandWithPrefix(runner.commands, "buildx", "create") {
				t.Fatalf("untrusted proxy reached builder creation: %#v", runner.commands)
			}
			if _, err := os.Lstat(session.DockerConfigDir + "/" + builderMarkerName); !os.IsNotExist(err) {
				t.Fatalf("ownership marker created for rejected proxy: %v", err)
			}
		})
	}
}

func directTestSession(t *testing.T) SessionV1 {
	t.Helper()
	session, err := newDockerSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(session.DockerConfigDir) })
	session.SessionID = strings.Repeat("a", 32)
	if err := os.WriteFile(session.DockerConfigDir+"/"+sessionMarkerName, []byte(session.SessionID), 0o600); err != nil {
		t.Fatal(err)
	}
	session.RegistryHost = registryHost(testAccount, BuildSourceRegion)
	session.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	session.BuilderMode = BuilderModeDirect
	session.BuilderName = directBuilderName(session.SessionID)
	session.BuildSourcesVerified = true
	return session
}

func commandRecorded(commands [][]string, wanted []string) bool {
	for _, command := range commands {
		if slices.Equal(command, wanted) {
			return true
		}
	}
	return false
}

func commandWithPrefix(commands [][]string, prefix ...string) bool {
	for _, command := range commands {
		if len(command) >= len(prefix) && slices.Equal(command[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

func commandWithRequiredArguments(commands [][]string, prefix []string, required string) bool {
	for _, command := range commands {
		if len(command) >= len(prefix) && slices.Equal(command[:len(prefix)], prefix) && slices.Contains(command, required) {
			return true
		}
	}
	return false
}

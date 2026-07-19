package releaseecr

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDirectBuilderLivePrivateBuildSources(t *testing.T) {
	if os.Getenv("AGENT_TEST_DIRECT_BUILDER") != "1" {
		t.Skip("set AGENT_TEST_DIRECT_BUILDER=1 for the explicit local release lane")
	}
	accountID := os.Getenv("AGENT_TEST_DIRECT_BUILDER_ACCOUNT_ID")
	if !accountPattern.MatchString(accountID) {
		t.Fatal("set AGENT_TEST_DIRECT_BUILDER_ACCOUNT_ID to the intended 12-digit Osaka ECR account")
	}
	prepared, err := PrepareDefault(context.Background(), Options{
		Region: BuildSourceRegion, ExpectedAccountID: accountID, BuilderMode: BuilderModeDirect, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = CleanupSession(session)
		}
	})
	if err := ActivateSessionBuilder(context.Background(), session); err != nil {
		t.Fatal(err)
	}

	command := exec.CommandContext(context.Background(), "docker",
		"buildx", "--builder", session.BuilderName, "build",
		"--platform", "linux/amd64", "--pull", "--no-cache",
		"--progress=plain", "--output", "type=cacheonly",
		"--file", "-", t.TempDir(),
	)
	command.Env = safeDockerEnvironment(session.DockerConfigDir)
	sources, err := PrivateBuildSourceReferences(session.RegistryHost)
	if err != nil {
		t.Fatal(err)
	}
	command.Args = append(command.Args[:len(command.Args)-1],
		"--build-arg", "BUILDKIT_SYNTAX="+sources.Frontend,
		"--build-arg", "GO_BUILD_BASE="+sources.GoBuildBase,
		command.Args[len(command.Args)-1])
	command.Stdin = strings.NewReader("ARG GO_BUILD_BASE\nFROM --platform=linux/amd64 ${GO_BUILD_BASE}\n")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		t.Fatalf("pinned-base resolver build: %v", err)
	}
	if err := CleanupSession(session); err != nil {
		t.Fatalf("direct builder cleanup: %v", err)
	}
	cleaned = true
	assertDockerObjectAbsent(t, "container", "ls", "--all", "--filter", "name=^/"+builderContainerName(session.BuilderName)+"$", "--format", "{{.Names}}")
	assertDockerObjectAbsent(t, "volume", "ls", "--filter", "name=^"+builderVolumeName(session.BuilderName)+"$", "--format", "{{.Name}}")
}

func assertDockerObjectAbsent(t *testing.T, arguments ...string) {
	t.Helper()
	output, err := exec.Command("docker", arguments...).Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(output)) != "" {
		t.Fatalf("task-owned Docker residue remains")
	}
}

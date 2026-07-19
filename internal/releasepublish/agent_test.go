package releasepublish

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseecr"
)

func TestPublishAgentBuildsOnlyAgentImageAndReturnsImmutableReceipt(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	runner := &fakeRunner{repositoryRoot: repositoryRoot, digests: []string{digestOf('a')}}
	request := validAgentRequest(outputRoot)

	result, err := testPublisher(t, repositoryRoot, outputRoot, runner, nil).publishAgent(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != AgentResultSchemaV1 || result.ReleaseTag != request.ReleaseTag || result.GitRevision != testRevision ||
		result.OS != "linux" || result.Architecture != request.Architecture || result.AgentDigest != digestOf('a') {
		t.Fatalf("agent release receipt = %#v", result)
	}
	wantImage := request.AgentRepository + ":" + request.ReleaseTag + "@" + digestOf('a')
	if result.AgentImage != wantImage {
		t.Fatalf("agent image = %q, want %q", result.AgentImage, wantImage)
	}
	if runner.imageBuilds != 1 || runner.tagCreates != 1 || runner.registry[request.AgentRepository+":"+request.ReleaseTag] != digestOf('a') {
		t.Fatalf("Agent image publication = builds=%d tags=%d registry=%#v", runner.imageBuilds, runner.tagCreates, runner.registry)
	}

	for _, command := range runner.commands {
		joined := strings.Join(command.arguments, " ")
		if strings.Contains(joined, "worker.Containerfile") || strings.Contains(joined, "reaper.Containerfile") ||
			strings.Contains(joined, "worker-rootfs") || strings.Contains(joined, "dirextalk-cloud-worker") || strings.Contains(joined, "dirextalk-aws-reaper") {
			t.Fatalf("Agent-only publish invoked a non-Agent release surface: %#v", command)
		}
	}
}

func TestPublishAgentRejectsNonAgentRepositoryBeforeGitOrDocker(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	runner := &fakeRunner{repositoryRoot: repositoryRoot, digests: []string{digestOf('a')}}
	request := validAgentRequest(outputRoot)
	request.AgentRepository = request.RegistryHost + "/dirextalk-cloud-worker"

	_, err := testPublisher(t, repositoryRoot, outputRoot, runner, nil).publishAgent(context.Background(), request)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("publish non-Agent repository error = %v, want ErrInvalidInput", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("invalid request reached Git or Docker: %#v", runner.commands)
	}
}

func TestPublishAgentRejectsExistingImmutableTagWithDifferentDigest(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	request := validAgentRequest(outputRoot)
	runner := &fakeRunner{
		repositoryRoot: repositoryRoot,
		digests:        []string{digestOf('a')},
		registry:       map[string]string{request.AgentRepository + ":" + request.ReleaseTag: digestOf('b')},
		createdTags:    make(map[string]int),
	}

	_, err := testPublisher(t, repositoryRoot, outputRoot, runner, nil).publishAgent(context.Background(), request)
	if !errors.Is(err, ErrTagConflict) {
		t.Fatalf("publish conflicting immutable tag error = %v, want ErrTagConflict", err)
	}
	if runner.tagCreates != 0 || runner.registry[request.AgentRepository+":"+request.ReleaseTag] != digestOf('b') {
		t.Fatalf("conflicting tag was mutated: tags=%d registry=%#v", runner.tagCreates, runner.registry)
	}
}

func TestDirectBuilderIsExplicitForBuildAndRegistryOperations(t *testing.T) {
	builder := "dirextalk-release-" + strings.Repeat("a", 32)
	request := validAgentRequest(t.TempDir())
	request.BuilderName = builder
	build := agentPushByDigestArguments(request, testRevision, filepath.Join(t.TempDir(), "metadata.json"))
	if len(build) < 4 || build[0] != "buildx" || build[1] != "--builder" || build[2] != builder || build[3] != "build" {
		t.Fatalf("build does not explicitly select private builder: %#v", build)
	}
	inspect := buildxArguments(builder, "imagetools", "inspect", "example")
	if !slices.Equal(inspect[:5], []string{"buildx", "--builder", builder, "imagetools", "inspect"}) {
		t.Fatalf("registry operation does not explicitly select private builder: %#v", inspect)
	}
}

func TestPublishAgentRejectsUntrustedBuilderNameBeforeGitOrDocker(t *testing.T) {
	runner := &fakeRunner{repositoryRoot: t.TempDir(), digests: []string{digestOf('a')}}
	request := validAgentRequest(t.TempDir())
	request.BuilderName = "foreign-builder"
	if _, err := testPublisher(t, runner.repositoryRoot, t.TempDir(), runner, nil).publishAgent(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("untrusted builder error = %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("untrusted builder reached tools: %#v", runner.commands)
	}
}

func validAgentRequest(outputRoot string) AgentRequest {
	registryHost := "123456789012.dkr.ecr.ap-northeast-3.amazonaws.com"
	return AgentRequest{
		ReleaseTag:           "v0.1.0-alpha-" + testRevision[:12],
		Architecture:         "amd64",
		AgentRepository:      registryHost + "/dirextalk-agent",
		DockerConfigDir:      filepath.Join(outputRoot, "docker-session"),
		RegistryHost:         registryHost,
		BuildSourcesVerified: true,
	}
}

func TestAgentBuildUsesVerifiedPrivateSourcesAndRejectsNonAMD64(t *testing.T) {
	request := validAgentRequest(t.TempDir())
	references, err := releaseecr.PrivateBuildSourceReferences(request.RegistryHost)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(agentPushByDigestArguments(request, testRevision, "/tmp/metadata"), "\n")
	for _, required := range []string{
		"--platform\nlinux/amd64",
		"--build-arg\nBUILDKIT_SYNTAX=" + references.Frontend,
		"--build-arg\nGO_BUILD_BASE=" + references.GoBuildBase,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("agent build lacks %q: %s", required, joined)
		}
	}
	request.Architecture = "arm64"
	if _, err := normalizeAgentRequest(request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("arm64 request error = %v", err)
	}
}

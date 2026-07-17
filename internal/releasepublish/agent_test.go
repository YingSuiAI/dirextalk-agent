package releasepublish

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
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

func validAgentRequest(outputRoot string) AgentRequest {
	registryHost := "123456789012.dkr.ecr.us-east-1.amazonaws.com"
	return AgentRequest{
		ReleaseTag:      "v0.1.0-alpha-" + testRevision[:12],
		Architecture:    "amd64",
		AgentRepository: registryHost + "/dirextalk-agent",
		DockerConfigDir: filepath.Join(outputRoot, "docker-session"),
		RegistryHost:    registryHost,
	}
}

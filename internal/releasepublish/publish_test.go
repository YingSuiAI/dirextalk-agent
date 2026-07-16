package releasepublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrootfs"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

type recordedCommand struct {
	directory  string
	executable string
	arguments  []string
}

type fakeRunner struct {
	repositoryRoot string
	status         string
	statuses       []string
	digests        []string
	metadata       func(index int, path string) []byte
	failDockerAt   int
	failImageAt    int
	loseTagAt      int
	afterAllTags   func()
	commands       []recordedCommand
	dockerCalls    int
	imageBuilds    int
	tagCreates     int
	registry       map[string]string
	createdTags    map[string]int
	statusReads    int
}

func (runner *fakeRunner) Run(_ context.Context, directory, executable string, arguments ...string) ([]byte, error) {
	runner.commands = append(runner.commands, recordedCommand{
		directory: directory, executable: executable, arguments: append([]string(nil), arguments...),
	})
	if executable == "git" {
		switch strings.Join(arguments, " ") {
		case "rev-parse --show-toplevel":
			return []byte(runner.repositoryRoot + "\n"), nil
		case "rev-parse HEAD":
			return []byte(testRevision + "\n"), nil
		case "status --porcelain=v1 --untracked-files=normal":
			status := runner.status
			if runner.statusReads < len(runner.statuses) {
				status = runner.statuses[runner.statusReads]
			}
			runner.statusReads++
			return []byte(status), nil
		default:
			return nil, errors.New("unexpected git command")
		}
	}
	if executable != "docker" {
		return nil, errors.New("unexpected executable")
	}
	runner.dockerCalls++
	if runner.failDockerAt == runner.dockerCalls {
		return nil, errors.New("docker failed with sensitive stderr")
	}
	if len(arguments) >= 2 && arguments[0] == "buildx" && arguments[1] == "build" {
		metadataPath := argumentAfter(arguments, "--metadata-file")
		if metadataPath == "" {
			return nil, errors.New("missing metadata path")
		}
		if destination := outputDestination(arguments); destination != "" {
			if err := os.MkdirAll(destination, 0o700); err != nil {
				return nil, err
			}
			return nil, os.WriteFile(metadataPath, []byte(`{"exporter":"local"}`), 0o600)
		}
		runner.imageBuilds++
		if runner.failImageAt == runner.imageBuilds {
			return nil, errors.New("image build failed with sensitive stderr")
		}
		index := imageIndex(arguments)
		if index < 0 || index >= len(runner.digests) {
			return nil, errors.New("unknown image build")
		}
		content := []byte(`{"containerimage.digest":"` + runner.digests[index] + `","buildx.build.ref":"opaque"}`)
		if runner.metadata != nil {
			content = runner.metadata(index, metadataPath)
		}
		return nil, os.WriteFile(metadataPath, content, 0o600)
	}
	if len(arguments) >= 3 && arguments[0] == "buildx" && arguments[1] == "imagetools" && arguments[2] == "inspect" {
		runner.ensureRegistry()
		reference := arguments[len(arguments)-1]
		digest := runner.registry[reference]
		if digest == "" {
			return nil, errors.New("registry tag not found")
		}
		return []byte(`{"schemaVersion":2,"digest":"` + digest + `"}`), nil
	}
	if len(arguments) >= 3 && arguments[0] == "buildx" && arguments[1] == "imagetools" && arguments[2] == "create" {
		runner.ensureRegistry()
		tag := argumentAfter(arguments, "--tag")
		source := arguments[len(arguments)-1]
		at := strings.LastIndexByte(source, '@')
		if tag == "" || at < 0 || !strings.HasPrefix(source[at+1:], "sha256:") {
			return nil, errors.New("invalid immutable tag command")
		}
		digest := source[at+1:]
		if existing := runner.registry[tag]; existing != "" && existing != digest {
			return nil, errors.New("immutable tag conflict")
		}
		runner.registry[tag] = digest
		runner.tagCreates++
		runner.createdTags[tag]++
		if len(runner.registry) == 3 && runner.afterAllTags != nil {
			hook := runner.afterAllTags
			runner.afterAllTags = nil
			hook()
		}
		if runner.loseTagAt == runner.tagCreates {
			return nil, errors.New("tag response lost")
		}
		return nil, nil
	}
	return nil, errors.New("unexpected docker command")
}

func (runner *fakeRunner) ensureRegistry() {
	if runner.registry == nil {
		runner.registry = make(map[string]string)
	}
	if runner.createdTags == nil {
		runner.createdTags = make(map[string]int)
	}
}

func TestPublishBuildsFixedArtifactsAndWritesImmutableManifest(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	temporaryRoot := filepath.Join(outputRoot, "temporary")
	digests := []string{digestOf('a'), digestOf('b'), digestOf('c')}
	runner := &fakeRunner{repositoryRoot: repositoryRoot, digests: digests}
	packCalls := 0
	tool := publisher{
		repositoryRoot: repositoryRoot,
		runner:         runner,
		packRootFS: func(root, output string) (workerrootfs.ManifestV1, error) {
			packCalls++
			if root != filepath.Join(temporaryRoot, "worker-rootfs") {
				t.Fatalf("pack root = %q", root)
			}
			manifest, err := writeRootFS(output, []byte("rootfs"))
			if err != nil {
				t.Fatal(err)
			}
			return manifest, nil
		},
		now: func() time.Time { return time.Date(2026, 7, 17, 1, 2, 3, 4, time.FixedZone("test", 8*60*60)) },
		makeTempDir: func() (string, error) {
			return temporaryRoot, os.Mkdir(temporaryRoot, 0o700)
		},
	}
	request := validRequest(outputRoot)
	result, err := tool.publish(context.Background(), request)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if packCalls != 1 {
		t.Fatalf("pack calls = %d", packCalls)
	}
	if result.SchemaVersion != releaseartifact.SchemaVersionV1 || result.ReleaseTag != request.ReleaseTag ||
		result.AgentDigest != digests[0] || result.WorkerDigest != digests[1] || result.ReaperDigest != digests[2] ||
		result.WorkerRootFSDigest != rootFSDigest([]byte("rootfs")) || result.WorkerBinaryDigest != digestOf('e') {
		t.Fatalf("unexpected result: %#v", result)
	}

	manifestBytes, err := os.ReadFile(request.ManifestOutput)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := releaseartifact.ParseJSON(manifestBytes)
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if manifest.GeneratedAt != "2026-07-16T17:02:03.000000004Z" {
		t.Fatalf("generated_at = %q", manifest.GeneratedAt)
	}
	if manifest.AgentImage != request.AgentRepository+":"+request.ReleaseTag+"@"+digests[0] ||
		manifest.WorkerImage != request.WorkerRepository+":"+request.ReleaseTag+"@"+digests[1] ||
		manifest.ReaperImage != request.ReaperRepository+":"+request.ReleaseTag+"@"+digests[2] {
		t.Fatalf("unexpected image references: %#v", manifest)
	}
	wantManifestDigest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if result.ManifestDigest != wantManifestDigest {
		t.Fatalf("manifest digest = %q, want %q", result.ManifestDigest, wantManifestDigest)
	}
	if _, err := os.Stat(request.RootFSOutput); err != nil {
		t.Fatalf("rootfs output: %v", err)
	}
	if _, err := os.Stat(temporaryRoot); !os.IsNotExist(err) {
		t.Fatalf("temporary directory was not removed: %v", err)
	}
	assertFixedCommands(t, runner.commands, repositoryRoot, request, temporaryRoot)

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{request.AgentRepository, request.WorkerRepository, request.ReaperRepository, outputRoot} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("safe result exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestPublishRejectsDirtyRepositoryBeforeBuild(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	runner := &fakeRunner{repositoryRoot: repositoryRoot, status: "?? local-secret.txt\n"}
	packCalled := false
	tool := testPublisher(t, repositoryRoot, outputRoot, runner, func(_, _ string) (workerrootfs.ManifestV1, error) {
		packCalled = true
		return workerrootfs.ManifestV1{}, nil
	})
	_, err := tool.publish(context.Background(), validRequest(outputRoot))
	if !errors.Is(err, ErrGitState) {
		t.Fatalf("error = %v", err)
	}
	if runner.dockerCalls != 0 || packCalled {
		t.Fatal("dirty repository reached artifact build")
	}
	if len(runner.commands) != 3 {
		t.Fatalf("commands = %#v", runner.commands)
	}
}

func TestPublishRejectsInvalidCoordinatesWithoutDocker(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Request)
		beforeGit bool
	}{
		{name: "latest", mutate: func(request *Request) { request.ReleaseTag = "latest" }},
		{name: "stable semver", mutate: func(request *Request) { request.ReleaseTag = "v2.0.0" }},
		{name: "reserved version", mutate: func(request *Request) { request.ReleaseTag = "v1.0.3-alpha-" + testRevision[:12] }},
		{name: "wrong revision", mutate: func(request *Request) { request.ReleaseTag = "v0.1.0-alpha-ffffffffffff" }},
		{name: "uppercase repository", mutate: func(request *Request) { request.AgentRepository = "ghcr.io/Owner/agent" }},
		{name: "duplicate repository", mutate: func(request *Request) { request.AgentRepository = request.WorkerRepository }},
		{name: "registry session mismatch", beforeGit: true, mutate: func(request *Request) { request.RegistryHost = "registry.example" }},
		{name: "relative Docker config", beforeGit: true, mutate: func(request *Request) { request.DockerConfigDir = "relative/docker" }},
		{name: "embedded credentials", beforeGit: true, mutate: func(request *Request) { request.AgentRepository = "user@ghcr.io/owner/agent" }},
		{name: "access key", beforeGit: true, mutate: func(request *Request) { request.AgentRepository = "ghcr.io/akia0123456789012345/agent" }},
		{name: "secret token", beforeGit: true, mutate: func(request *Request) { request.ReleaseTag = "token=sensitive" }},
		{name: "architecture", mutate: func(request *Request) { request.Architecture = "s390x" }, beforeGit: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			outputRoot := t.TempDir()
			runner := &fakeRunner{repositoryRoot: repositoryRoot}
			tool := testPublisher(t, repositoryRoot, outputRoot, runner, nil)
			request := validRequest(outputRoot)
			test.mutate(&request)
			_, err := tool.publish(context.Background(), request)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
			if runner.dockerCalls != 0 {
				t.Fatal("invalid coordinates reached docker")
			}
			if test.beforeGit && len(runner.commands) != 0 {
				t.Fatalf("secret-like input reached git: %#v", runner.commands)
			}
		})
	}
}

func TestPublishRejectsTamperedMetadataAndRemovesPartialRootFS(t *testing.T) {
	tests := []struct {
		name     string
		metadata []byte
	}{
		{name: "missing digest", metadata: []byte(`{"other":"value"}`)},
		{name: "uppercase digest", metadata: []byte(`{"containerimage.digest":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)},
		{name: "duplicate digest", metadata: []byte(`{"containerimage.digest":"` + digestOf('a') + `","containerimage.digest":"` + digestOf('b') + `"}`)},
		{name: "trailing json", metadata: []byte(`{"containerimage.digest":"` + digestOf('a') + `"}{}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			outputRoot := t.TempDir()
			runner := &fakeRunner{
				repositoryRoot: repositoryRoot,
				digests:        []string{digestOf('a'), digestOf('b'), digestOf('c')},
				metadata: func(index int, _ string) []byte {
					if index == 0 {
						return test.metadata
					}
					return []byte(`{"containerimage.digest":"` + digestOf(byte('a'+index)) + `"}`)
				},
			}
			tool := testPublisher(t, repositoryRoot, outputRoot, runner, successfulPacker)
			request := validRequest(outputRoot)
			_, err := tool.publish(context.Background(), request)
			if !errors.Is(err, ErrMetadata) {
				t.Fatalf("error = %v", err)
			}
			if _, err := os.Stat(request.RootFSOutput); !os.IsNotExist(err) {
				t.Fatalf("partial rootfs remains: %v", err)
			}
			if _, err := os.Stat(request.ManifestOutput); !os.IsNotExist(err) {
				t.Fatalf("manifest exists after metadata failure: %v", err)
			}
			if runner.dockerCalls != 2 {
				t.Fatalf("docker calls = %d", runner.dockerCalls)
			}
		})
	}
}

func TestPublishRootFSPackFailureDoesNotPush(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	runner := &fakeRunner{repositoryRoot: repositoryRoot}
	tool := testPublisher(t, repositoryRoot, outputRoot, runner, func(_, output string) (workerrootfs.ManifestV1, error) {
		_ = os.WriteFile(output, []byte("partial"), 0o600)
		_ = os.Remove(output)
		return workerrootfs.ManifestV1{}, errors.New("unexpected local path and secret")
	})
	request := validRequest(outputRoot)
	_, err := tool.publish(context.Background(), request)
	if !errors.Is(err, ErrRootFS) {
		t.Fatalf("error = %v", err)
	}
	if runner.dockerCalls != 1 {
		t.Fatalf("docker calls = %d", runner.dockerCalls)
	}
	if _, err := os.Stat(request.ManifestOutput); !os.IsNotExist(err) {
		t.Fatalf("manifest exists after pack failure: %v", err)
	}
}

func TestPublishRejectsMalformedOrMutatedRootFSBeforePush(t *testing.T) {
	tests := []struct {
		name string
		pack rootFSPacker
	}{
		{name: "wrong schema", pack: func(_, output string) (workerrootfs.ManifestV1, error) {
			manifest, err := writeRootFS(output, []byte("rootfs"))
			manifest.Schema = "unknown"
			return manifest, err
		}},
		{name: "wrong digest", pack: func(_, output string) (workerrootfs.ManifestV1, error) {
			manifest, err := writeRootFS(output, []byte("rootfs"))
			manifest.RootFSDigest = digestOf('d')
			return manifest, err
		}},
		{name: "wrong size", pack: func(_, output string) (workerrootfs.ManifestV1, error) {
			manifest, err := writeRootFS(output, []byte("rootfs"))
			manifest.Size++
			return manifest, err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			outputRoot := t.TempDir()
			runner := &fakeRunner{repositoryRoot: repositoryRoot}
			tool := testPublisher(t, repositoryRoot, outputRoot, runner, test.pack)
			request := validRequest(outputRoot)
			_, err := tool.publish(context.Background(), request)
			if !errors.Is(err, ErrRootFS) {
				t.Fatalf("error = %v", err)
			}
			if runner.dockerCalls != 1 {
				t.Fatalf("docker calls = %d", runner.dockerCalls)
			}
			if _, err := os.Stat(request.RootFSOutput); !os.IsNotExist(err) {
				t.Fatalf("rootfs remains: %v", err)
			}
		})
	}
}

func TestPublishRejectsExistingOutputsWithoutCommands(t *testing.T) {
	for _, field := range []string{"manifest", "rootfs"} {
		t.Run(field, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			outputRoot := t.TempDir()
			request := validRequest(outputRoot)
			path := request.ManifestOutput
			if field == "rootfs" {
				path = request.RootFSOutput
			}
			if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := &fakeRunner{repositoryRoot: repositoryRoot}
			tool := testPublisher(t, repositoryRoot, outputRoot, runner, nil)
			_, err := tool.publish(context.Background(), request)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
			if len(runner.commands) != 0 {
				t.Fatalf("commands = %#v", runner.commands)
			}
			content, err := os.ReadFile(path)
			if err != nil || string(content) != "keep" {
				t.Fatalf("existing output changed: %q, %v", content, err)
			}
		})
	}
}

func TestPublishDockerFailureReturnsFixedErrorAndCleansOutput(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	runner := &fakeRunner{repositoryRoot: repositoryRoot, digests: []string{digestOf('a'), digestOf('b'), digestOf('c')}, failImageAt: 2}
	tool := testPublisher(t, repositoryRoot, outputRoot, runner, successfulPacker)
	request := validRequest(outputRoot)
	_, err := tool.publish(context.Background(), request)
	if err != ErrBuild || err.Error() != "release image build failed" {
		t.Fatalf("error = %q", err)
	}
	if _, err := os.Stat(request.RootFSOutput); !os.IsNotExist(err) {
		t.Fatalf("partial rootfs remains: %v", err)
	}
	if _, err := os.Stat(request.ManifestOutput); !os.IsNotExist(err) {
		t.Fatalf("manifest exists: %v", err)
	}
}

func TestPublishEnvironmentUsesOnlyExplicitDockerSession(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", "C:/user-home/.docker")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "provider-secret")
	environment := safeEnvironment("C:/private/release-session")
	wanted := false
	for _, value := range environment {
		if value == "DOCKER_CONFIG=C:/private/release-session" {
			wanted = true
		}
		if value == "DOCKER_CONFIG=C:/user-home/.docker" || strings.HasPrefix(value, "AWS_") || strings.Contains(value, "provider-secret") {
			t.Fatalf("unsafe release environment: %#v", environment)
		}
	}
	if !wanted {
		t.Fatalf("explicit Docker session missing: %#v", environment)
	}
}

func TestPublishRecoversImmutableTagAfterPartialPublish(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	digests := []string{digestOf('a'), digestOf('b'), digestOf('c')}
	runner := &fakeRunner{repositoryRoot: repositoryRoot, digests: digests, failImageAt: 2}
	request := validRequest(outputRoot)
	tool := testPublisher(t, repositoryRoot, outputRoot, runner, successfulPacker)

	if _, err := tool.publish(context.Background(), request); !errors.Is(err, ErrBuild) {
		t.Fatalf("first publish error = %v", err)
	}
	agentTag := request.AgentRepository + ":" + request.ReleaseTag
	if runner.registry[agentTag] != digests[0] || runner.createdTags[agentTag] != 1 {
		t.Fatalf("first immutable tag was not persisted: registry=%#v creates=%#v", runner.registry, runner.createdTags)
	}

	runner.failImageAt = 0
	if _, err := tool.publish(context.Background(), request); err != nil {
		t.Fatalf("resumed publish: %v", err)
	}
	if runner.registry[agentTag] != digests[0] || runner.createdTags[agentTag] != 1 {
		t.Fatalf("resume rewrote immutable tag: registry=%#v creates=%#v", runner.registry, runner.createdTags)
	}
}

func TestPublishAcceptsLostTagResponseButRejectsDifferentDigest(t *testing.T) {
	t.Run("response loss", func(t *testing.T) {
		repositoryRoot := t.TempDir()
		outputRoot := t.TempDir()
		runner := &fakeRunner{repositoryRoot: repositoryRoot, digests: []string{digestOf('a'), digestOf('b'), digestOf('c')}, loseTagAt: 1}
		request := validRequest(outputRoot)
		if _, err := testPublisher(t, repositoryRoot, outputRoot, runner, successfulPacker).publish(context.Background(), request); err != nil {
			t.Fatalf("publish after lost tag response: %v", err)
		}
		if runner.registry[request.AgentRepository+":"+request.ReleaseTag] != digestOf('a') {
			t.Fatalf("lost response was not recovered: %#v", runner.registry)
		}
	})

	t.Run("conflict", func(t *testing.T) {
		repositoryRoot := t.TempDir()
		outputRoot := t.TempDir()
		request := validRequest(outputRoot)
		agentTag := request.AgentRepository + ":" + request.ReleaseTag
		runner := &fakeRunner{
			repositoryRoot: repositoryRoot,
			digests:        []string{digestOf('a'), digestOf('b'), digestOf('c')},
			registry:       map[string]string{agentTag: digestOf('f')},
		}
		_, err := testPublisher(t, repositoryRoot, outputRoot, runner, successfulPacker).publish(context.Background(), request)
		if !errors.Is(err, ErrTagConflict) {
			t.Fatalf("conflict error = %v", err)
		}
		if runner.registry[agentTag] != digestOf('f') || runner.tagCreates != 0 {
			t.Fatalf("conflicting tag was mutated: registry=%#v creates=%d", runner.registry, runner.tagCreates)
		}
	})
}

func TestPublishRecoversAfterManifestWriteFailure(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	manifestDirectory := filepath.Join(outputRoot, "manifest")
	if err := os.Mkdir(manifestDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	request := validRequest(outputRoot)
	request.ManifestOutput = filepath.Join(manifestDirectory, "release.json")
	runner := &fakeRunner{
		repositoryRoot: repositoryRoot,
		digests:        []string{digestOf('a'), digestOf('b'), digestOf('c')},
		afterAllTags: func() {
			_ = os.Remove(manifestDirectory)
		},
	}
	tool := testPublisher(t, repositoryRoot, outputRoot, runner, successfulPacker)
	if _, err := tool.publish(context.Background(), request); !errors.Is(err, ErrOutput) {
		t.Fatalf("first publish error = %v", err)
	}
	if err := os.Mkdir(manifestDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := tool.publish(context.Background(), request); err != nil {
		t.Fatalf("publish after output recovery: %v", err)
	}
	for _, repository := range []string{request.AgentRepository, request.WorkerRepository, request.ReaperRepository} {
		if runner.createdTags[repository+":"+request.ReleaseTag] != 1 {
			t.Fatalf("output retry rewrote %s: %#v", repository, runner.createdTags)
		}
	}
}

func TestPublishRejectsRepositoryChangeBeforeManifest(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	runner := &fakeRunner{
		repositoryRoot: repositoryRoot,
		digests:        []string{digestOf('a'), digestOf('b'), digestOf('c')},
		statuses:       []string{"", " M internal/releasepublish/publish.go\n"},
	}
	request := validRequest(outputRoot)
	_, err := testPublisher(t, repositoryRoot, outputRoot, runner, successfulPacker).publish(context.Background(), request)
	if !errors.Is(err, ErrGitState) {
		t.Fatalf("changed repository error = %v", err)
	}
	if _, err := os.Stat(request.ManifestOutput); !os.IsNotExist(err) {
		t.Fatalf("manifest published from changed worktree: %v", err)
	}
}

func assertFixedCommands(t *testing.T, commands []recordedCommand, repositoryRoot string, request Request, temporaryRoot string) {
	t.Helper()
	if len(commands) != 19 {
		t.Fatalf("command count = %d: %#v", len(commands), commands)
	}
	wantGit := [][]string{
		{"rev-parse", "--show-toplevel"},
		{"rev-parse", "HEAD"},
		{"status", "--porcelain=v1", "--untracked-files=normal"},
	}
	for index, arguments := range wantGit {
		if commands[index].directory != repositoryRoot || commands[index].executable != "git" || !reflect.DeepEqual(commands[index].arguments, arguments) {
			t.Fatalf("git command %d = %#v", index, commands[index])
		}
	}
	wantDocker := [][]string{workerExportArguments(request, testRevision, filepath.Join(temporaryRoot, "worker-rootfs"), filepath.Join(temporaryRoot, "worker-export.json"))}
	for _, image := range []struct {
		name, containerfile, repository string
	}{
		{name: "agent", containerfile: "deploy/container/agent.Containerfile", repository: request.AgentRepository},
		{name: "worker", containerfile: "deploy/container/worker.Containerfile", repository: request.WorkerRepository},
		{name: "reaper", containerfile: "deploy/container/reaper.Containerfile", repository: request.ReaperRepository},
	} {
		metadata := filepath.Join(temporaryRoot, image.name+"-push.json")
		reference := image.repository + ":" + request.ReleaseTag
		digest := digestOf(byte('a' + len(wantDocker)/4))
		wantDocker = append(wantDocker,
			pushByDigestArguments(request, testRevision, image.containerfile, image.repository, metadata),
			[]string{"buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", reference},
			[]string{"buildx", "imagetools", "create", "--prefer-index=false", "--tag", reference, image.repository + "@" + digest},
			[]string{"buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", reference},
		)
	}
	for index, arguments := range wantDocker {
		command := commands[index+3]
		if command.directory != repositoryRoot || command.executable != "docker" || !reflect.DeepEqual(command.arguments, arguments) {
			t.Fatalf("docker command %d = %#v\nwant %#v", index, command, arguments)
		}
		joined := strings.ToLower(strings.Join(command.arguments, " "))
		for _, forbidden := range []string{"password", "token", "authorization", "aws_access", "aws_secret"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("docker argv contains forbidden %q: %#v", forbidden, command.arguments)
			}
		}
		joinedArguments := strings.Join(command.arguments, " ")
		isImageBuild := len(command.arguments) >= 2 && command.arguments[0] == "buildx" && command.arguments[1] == "build" && outputDestination(command.arguments) == ""
		isReaperBuild := isImageBuild && argumentAfter(command.arguments, "--file") == "deploy/container/reaper.Containerfile"
		if isImageBuild && (isReaperBuild != strings.Contains(joinedArguments, "--provenance=false")) {
			t.Fatalf("Lambda provenance flag mismatch for docker command %d: %#v", index, command.arguments)
		}
	}
	for index, arguments := range wantGit {
		command := commands[len(commands)-len(wantGit)+index]
		if command.directory != repositoryRoot || command.executable != "git" || !reflect.DeepEqual(command.arguments, arguments) {
			t.Fatalf("final git command %d = %#v", index, command)
		}
	}
}

func testPublisher(t *testing.T, repositoryRoot, outputRoot string, runner *fakeRunner, pack rootFSPacker) publisher {
	t.Helper()
	if pack == nil {
		pack = func(_, _ string) (workerrootfs.ManifestV1, error) {
			t.Fatal("unexpected pack")
			return workerrootfs.ManifestV1{}, nil
		}
	}
	return publisher{
		repositoryRoot: repositoryRoot,
		runner:         runner,
		packRootFS:     pack,
		now:            func() time.Time { return time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC) },
		makeTempDir: func() (string, error) {
			return os.MkdirTemp(outputRoot, "temporary-")
		},
	}
}

func validRequest(outputRoot string) Request {
	return Request{
		ReleaseTag:       "v0.1.0-alpha-" + testRevision[:12],
		Architecture:     "amd64",
		AgentRepository:  "ghcr.io/yingsuiai/dirextalk-agent",
		WorkerRepository: "ghcr.io/yingsuiai/dirextalk-cloud-worker",
		ReaperRepository: "ghcr.io/yingsuiai/dirextalk-aws-reaper",
		ManifestOutput:   filepath.Join(outputRoot, "release.json"),
		RootFSOutput:     filepath.Join(outputRoot, "worker-rootfs.tar"),
		DockerConfigDir:  filepath.Join(outputRoot, "docker-session"),
		RegistryHost:     "ghcr.io",
	}
}

func successfulPacker(_, output string) (workerrootfs.ManifestV1, error) {
	return writeRootFS(output, []byte("rootfs"))
}

func writeRootFS(output string, content []byte) (workerrootfs.ManifestV1, error) {
	if err := os.WriteFile(output, content, 0o600); err != nil {
		return workerrootfs.ManifestV1{}, err
	}
	return workerrootfs.ManifestV1{
		Schema: workerrootfs.SchemaV1, RootFSDigest: rootFSDigest(content), BinaryDigest: digestOf('e'), Size: int64(len(content)),
	}, nil
}

func rootFSDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func digestOf(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

func argumentAfter(arguments []string, flag string) string {
	for index := range arguments {
		if arguments[index] == flag && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func outputDestination(arguments []string) string {
	value := argumentAfter(arguments, "--output")
	if !strings.HasPrefix(value, "type=local,dest=") {
		return ""
	}
	return strings.TrimPrefix(value, "type=local,dest=")
}

func imageIndex(arguments []string) int {
	switch argumentAfter(arguments, "--file") {
	case "deploy/container/agent.Containerfile":
		return 0
	case "deploy/container/worker.Containerfile":
		return 1
	case "deploy/container/reaper.Containerfile":
		return 2
	default:
		return -1
	}
}

// Package releasepublish owns the repository-local, offline release publisher.
// It is deliberately not linked into the Agent runtime: the only external
// processes it can start are fixed git inspections and fixed docker buildx
// builds, and it never accepts registry or cloud credentials.
package releasepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrootfs"
)

var (
	ErrInvalidInput = errors.New("invalid release publish input")
	ErrGitState     = errors.New("release repository state rejected")
	ErrBuild        = errors.New("release image build failed")
	ErrMetadata     = errors.New("release image metadata rejected")
	ErrRootFS       = errors.New("release Worker rootfs rejected")
	ErrOutput       = errors.New("release output failed")
	ErrTagConflict  = errors.New("release image tag conflict")
)

const (
	maxCommandOutput = 1 << 20
	maxMetadataBytes = 1 << 20
)

var (
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tagPattern      = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:[0-9A-Za-z.-]*)-([0-9a-f]{12})$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	awsKeyPattern   = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:akia|asia)[a-z0-9]{16}(?:$|[^a-z0-9])`)
	apiKeyPattern   = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:sk-[a-z0-9_-]{12,}|ghp_[a-z0-9]{12,}|github_pat_[a-z0-9_]{12,}|xox[bp]-[a-z0-9-]{12,})(?:$|[^a-z0-9])`)
)

// Request contains public release coordinates plus a trusted, de-secreted
// Docker session binding supplied by the release CLI. DockerConfigDir locates
// the private short-lived config; credential bytes are never accepted here.
type Request struct {
	ReleaseTag       string
	Architecture     string
	AgentRepository  string
	WorkerRepository string
	ReaperRepository string
	ManifestOutput   string
	RootFSOutput     string
	DockerConfigDir  string
	RegistryHost     string
}

// Result is safe for stdout and logs. It omits registry repositories and all
// local filesystem paths.
type Result struct {
	SchemaVersion      string `json:"schema_version"`
	ReleaseTag         string `json:"release_tag"`
	ManifestDigest     string `json:"manifest_digest"`
	AgentDigest        string `json:"agent_digest"`
	WorkerDigest       string `json:"worker_digest"`
	ReaperDigest       string `json:"reaper_digest"`
	WorkerRootFSDigest string `json:"worker_rootfs_digest"`
	WorkerBinaryDigest string `json:"worker_binary_digest"`
}

type commandRunner interface {
	Run(ctx context.Context, directory, executable string, arguments ...string) ([]byte, error)
}

type rootFSPacker func(root, output string) (workerrootfs.ManifestV1, error)

type publisher struct {
	repositoryRoot string
	runner         commandRunner
	packRootFS     rootFSPacker
	now            func() time.Time
	makeTempDir    func() (string, error)
}

// Publish executes a release from the current working directory. The current
// directory must be the clean root of the Git repository.
func Publish(ctx context.Context, request Request) (Result, error) {
	repositoryRoot, err := os.Getwd()
	if err != nil {
		return Result{}, ErrGitState
	}
	tool := publisher{
		repositoryRoot: repositoryRoot,
		runner:         execRunner{dockerConfigDir: strings.TrimSpace(request.DockerConfigDir)},
		packRootFS:     workerrootfs.Pack,
		now:            time.Now,
		makeTempDir: func() (string, error) {
			return os.MkdirTemp("", "dirextalk-release-")
		},
	}
	return tool.publish(ctx, request)
}

func (tool publisher) publish(ctx context.Context, input Request) (result Result, err error) {
	request, err := normalizeRequest(input)
	if err != nil {
		return Result{}, err
	}
	repositoryRoot, err := canonicalExistingDirectory(tool.repositoryRoot)
	if err != nil {
		return Result{}, ErrGitState
	}
	manifestOutput, rootFSOutput, err := validateOutputPaths(repositoryRoot, request.ManifestOutput, request.RootFSOutput)
	if err != nil {
		return Result{}, err
	}

	revision, err := tool.validateRepository(ctx, repositoryRoot)
	if err != nil {
		return Result{}, err
	}
	if err := validateTagAndRepositories(request, revision); err != nil {
		return Result{}, err
	}

	temporaryRoot, err := tool.makeTempDir()
	if err != nil {
		return Result{}, ErrBuild
	}
	if chmodErr := os.Chmod(temporaryRoot, 0o700); chmodErr != nil {
		_ = os.RemoveAll(temporaryRoot)
		return Result{}, ErrBuild
	}
	defer os.RemoveAll(temporaryRoot)

	rootFSCreated := false
	defer func() {
		if err != nil && rootFSCreated {
			_ = os.Remove(rootFSOutput)
		}
	}()

	workerExportRoot := filepath.Join(temporaryRoot, "worker-rootfs")
	workerExportMetadata := filepath.Join(temporaryRoot, "worker-export.json")
	if err := prepareMetadataFile(workerExportMetadata); err != nil {
		return Result{}, ErrBuild
	}
	if _, err := tool.runner.Run(ctx, repositoryRoot, "docker", workerExportArguments(request, revision, workerExportRoot, workerExportMetadata)...); err != nil {
		return Result{}, ErrBuild
	}
	rootFSManifest, err := tool.packRootFS(workerExportRoot, rootFSOutput)
	if err != nil {
		return Result{}, ErrRootFS
	}
	rootFSCreated = true
	if err := verifyRootFSOutput(rootFSOutput, rootFSManifest); err != nil {
		return Result{}, err
	}

	imageSpecs := []struct {
		name          string
		containerfile string
		repository    string
	}{
		{name: "agent", containerfile: "deploy/container/agent.Containerfile", repository: request.AgentRepository},
		{name: "worker", containerfile: "deploy/container/worker.Containerfile", repository: request.WorkerRepository},
		{name: "reaper", containerfile: "deploy/container/reaper.Containerfile", repository: request.ReaperRepository},
	}
	digests := make(map[string]string, len(imageSpecs))
	for _, image := range imageSpecs {
		metadataPath := filepath.Join(temporaryRoot, image.name+"-push.json")
		if err := prepareMetadataFile(metadataPath); err != nil {
			return Result{}, ErrBuild
		}
		// Upload the content-addressed manifest before touching the immutable
		// release tag. A failed upload can be retried without reserving the tag.
		arguments := pushByDigestArguments(request, revision, image.containerfile, image.repository, metadataPath)
		if _, err := tool.runner.Run(ctx, repositoryRoot, "docker", arguments...); err != nil {
			return Result{}, ErrBuild
		}
		digest, err := parseImageDigest(metadataPath)
		if err != nil {
			return Result{}, err
		}
		if err := tool.reconcileImmutableTag(ctx, repositoryRoot, image.repository, request.ReleaseTag, digest); err != nil {
			return Result{}, err
		}
		digests[image.name] = digest
	}
	if err := verifyRootFSOutput(rootFSOutput, rootFSManifest); err != nil {
		return Result{}, err
	}
	confirmedRevision, err := tool.validateRepository(ctx, repositoryRoot)
	if err != nil || confirmedRevision != revision {
		return Result{}, ErrGitState
	}

	manifest := releaseartifact.ReleaseManifestV1{
		SchemaVersion:      releaseartifact.SchemaVersionV1,
		ReleaseTag:         request.ReleaseTag,
		GitRevision:        revision,
		OS:                 "linux",
		Architecture:       request.Architecture,
		AgentImage:         immutableReference(request.AgentRepository, request.ReleaseTag, digests["agent"]),
		WorkerImage:        immutableReference(request.WorkerRepository, request.ReleaseTag, digests["worker"]),
		ReaperImage:        immutableReference(request.ReaperRepository, request.ReleaseTag, digests["reaper"]),
		WorkerRootFSDigest: rootFSManifest.RootFSDigest,
		WorkerBinaryDigest: rootFSManifest.BinaryDigest,
		GeneratedAt:        tool.now().UTC().Format(time.RFC3339Nano),
	}
	normalized, err := releaseartifact.Normalize(manifest)
	if err != nil {
		return Result{}, ErrMetadata
	}
	manifestDigest, err := normalized.Digest()
	if err != nil {
		return Result{}, ErrMetadata
	}
	manifestJSON, err := normalized.CanonicalJSON()
	if err != nil {
		return Result{}, ErrMetadata
	}
	if err := writeNewOutput(manifestOutput, manifestJSON); err != nil {
		return Result{}, err
	}

	return Result{
		SchemaVersion:      normalized.SchemaVersion,
		ReleaseTag:         normalized.ReleaseTag,
		ManifestDigest:     manifestDigest,
		AgentDigest:        digests["agent"],
		WorkerDigest:       digests["worker"],
		ReaperDigest:       digests["reaper"],
		WorkerRootFSDigest: normalized.WorkerRootFSDigest,
		WorkerBinaryDigest: normalized.WorkerBinaryDigest,
	}, nil
}

func normalizeRequest(input Request) (Request, error) {
	request := Request{
		ReleaseTag:       strings.TrimSpace(input.ReleaseTag),
		Architecture:     strings.TrimSpace(input.Architecture),
		AgentRepository:  strings.TrimSpace(input.AgentRepository),
		WorkerRepository: strings.TrimSpace(input.WorkerRepository),
		ReaperRepository: strings.TrimSpace(input.ReaperRepository),
		ManifestOutput:   strings.TrimSpace(input.ManifestOutput),
		RootFSOutput:     strings.TrimSpace(input.RootFSOutput),
		DockerConfigDir:  strings.TrimSpace(input.DockerConfigDir),
		RegistryHost:     strings.TrimSpace(input.RegistryHost),
	}
	if request.ReleaseTag == "" || request.ManifestOutput == "" || request.RootFSOutput == "" ||
		(request.Architecture != "amd64" && request.Architecture != "arm64") ||
		request.RegistryHost == "" || strings.ContainsAny(request.RegistryHost, "/:@ \t\r\n") ||
		!filepath.IsAbs(request.DockerConfigDir) || filepath.Clean(request.DockerConfigDir) != request.DockerConfigDir {
		return Request{}, ErrInvalidInput
	}
	for _, value := range []string{request.ReleaseTag, request.AgentRepository, request.WorkerRepository, request.ReaperRepository} {
		if containsSpaceOrControl(value) || secretLike(value) {
			return Request{}, ErrInvalidInput
		}
	}
	for _, repository := range []string{request.AgentRepository, request.WorkerRepository, request.ReaperRepository} {
		if !strings.HasPrefix(repository, request.RegistryHost+"/") {
			return Request{}, ErrInvalidInput
		}
	}
	return request, nil
}

func validateTagAndRepositories(request Request, revision string) error {
	match := tagPattern.FindStringSubmatch(request.ReleaseTag)
	if len(match) != 2 || match[1] != revision[:releaseartifact.RevisionSuffixLength] {
		return ErrInvalidInput
	}
	if strings.HasPrefix(request.ReleaseTag, "v1.0.3-") || request.ReleaseTag == "latest" || request.ReleaseTag == "stable" {
		return ErrInvalidInput
	}
	placeholder := "sha256:" + strings.Repeat("0", 64)
	_, err := releaseartifact.Normalize(releaseartifact.ReleaseManifestV1{
		SchemaVersion:      releaseartifact.SchemaVersionV1,
		ReleaseTag:         request.ReleaseTag,
		GitRevision:        revision,
		OS:                 "linux",
		Architecture:       request.Architecture,
		AgentImage:         immutableReference(request.AgentRepository, request.ReleaseTag, placeholder),
		WorkerImage:        immutableReference(request.WorkerRepository, request.ReleaseTag, placeholder),
		ReaperImage:        immutableReference(request.ReaperRepository, request.ReleaseTag, placeholder),
		WorkerRootFSDigest: placeholder,
		WorkerBinaryDigest: placeholder,
		GeneratedAt:        time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return ErrInvalidInput
	}
	return nil
}

func (tool publisher) validateRepository(ctx context.Context, repositoryRoot string) (string, error) {
	rootOutput, err := tool.runner.Run(ctx, repositoryRoot, "git", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", ErrGitState
	}
	reportedRoot, err := canonicalExistingDirectory(strings.TrimSpace(string(rootOutput)))
	if err != nil || !samePath(reportedRoot, repositoryRoot) {
		return "", ErrGitState
	}
	revisionOutput, err := tool.runner.Run(ctx, repositoryRoot, "git", "rev-parse", "HEAD")
	if err != nil {
		return "", ErrGitState
	}
	revision := strings.TrimSpace(string(revisionOutput))
	if !revisionPattern.MatchString(revision) {
		return "", ErrGitState
	}
	status, err := tool.runner.Run(ctx, repositoryRoot, "git", "status", "--porcelain=v1", "--untracked-files=normal")
	if err != nil || len(bytes.TrimSpace(status)) != 0 {
		return "", ErrGitState
	}
	return revision, nil
}

func validateOutputPaths(repositoryRoot, manifest, rootFS string) (string, string, error) {
	manifestPath, err := canonicalNewPath(repositoryRoot, manifest)
	if err != nil {
		return "", "", ErrInvalidInput
	}
	rootFSPath, err := canonicalNewPath(repositoryRoot, rootFS)
	if err != nil {
		return "", "", ErrInvalidInput
	}
	if samePath(manifestPath, rootFSPath) || withinDirectory(repositoryRoot, manifestPath) || withinDirectory(repositoryRoot, rootFSPath) {
		return "", "", ErrInvalidInput
	}
	return manifestPath, rootFSPath, nil
}

func canonicalExistingDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("not a directory")
	}
	return filepath.Clean(resolved), nil
}

func canonicalNewPath(repositoryRoot, path string) (string, error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("invalid path")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(repositoryRoot, path)
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(parent, filepath.Base(absolute))
	if _, err := os.Lstat(resolved); err == nil || !os.IsNotExist(err) {
		return "", errors.New("output already exists")
	}
	return resolved, nil
}

func withinDirectory(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func samePath(first, second string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(first), filepath.Clean(second))
	}
	return filepath.Clean(first) == filepath.Clean(second)
}

func prepareMetadataFile(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func workerExportArguments(request Request, revision, destination, metadata string) []string {
	return []string{
		"buildx", "build",
		"--file", "deploy/container/worker.Containerfile",
		"--platform", "linux/" + request.Architecture,
		"--build-arg", "VERSION=" + request.ReleaseTag,
		"--build-arg", "REVISION=" + revision,
		"--tag", request.WorkerRepository + ":" + request.ReleaseTag,
		"--metadata-file", metadata,
		"--output", "type=local,dest=" + destination,
		".",
	}
}

func pushByDigestArguments(request Request, revision, containerfile, repository, metadata string) []string {
	arguments := []string{
		"buildx", "build",
		"--file", containerfile,
		"--platform", "linux/" + request.Architecture,
		"--build-arg", "VERSION=" + request.ReleaseTag,
		"--build-arg", "REVISION=" + revision,
		"--metadata-file", metadata,
		"--output", "type=image,name=" + repository + ",push-by-digest=true,push=true",
	}
	// Lambda rejects BuildKit's default provenance index for image functions;
	// publish the Reaper as a single runnable image manifest.
	if containerfile == "deploy/container/reaper.Containerfile" {
		arguments = append(arguments, "--provenance=false")
	}
	return append(arguments, ".")
}

func (tool publisher) reconcileImmutableTag(ctx context.Context, repositoryRoot, repository, tag, expectedDigest string) error {
	if !digestPattern.MatchString(expectedDigest) {
		return ErrMetadata
	}
	reference := repository + ":" + tag
	observed, found, err := tool.inspectRegistryDigest(ctx, repositoryRoot, reference)
	if err != nil {
		return err
	}
	if found {
		if observed != expectedDigest {
			return ErrTagConflict
		}
		return nil
	}

	// The expected digest is already durable in the registry. Creating the tag
	// is the only non-content-addressed mutation; always read it back, including
	// after a lost command response.
	_, createErr := tool.runner.Run(ctx, repositoryRoot, "docker",
		"buildx", "imagetools", "create", "--prefer-index=false", "--tag", reference, repository+"@"+expectedDigest)
	observed, found, err = tool.inspectRegistryDigest(ctx, repositoryRoot, reference)
	if err != nil {
		return err
	}
	if !found {
		if createErr != nil {
			return ErrBuild
		}
		return ErrMetadata
	}
	if observed != expectedDigest {
		return ErrTagConflict
	}
	return nil
}

func (tool publisher) inspectRegistryDigest(ctx context.Context, repositoryRoot, reference string) (string, bool, error) {
	output, err := tool.runner.Run(ctx, repositoryRoot, "docker",
		"buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", reference)
	if err != nil {
		return "", false, nil
	}
	digest, err := parseRegistryDigest(output)
	if err != nil {
		return "", true, err
	}
	return digest, true, nil
}

func immutableReference(repository, tag, digest string) string {
	return repository + ":" + tag + "@" + digest
}

func parseImageDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxMetadataBytes {
		return "", ErrMetadata
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != info.Size() {
		return "", ErrMetadata
	}
	return parseDigestJSON(content, "containerimage.digest")
}

func parseRegistryDigest(content []byte) (string, error) {
	if len(content) == 0 || len(content) > maxMetadataBytes {
		return "", ErrMetadata
	}
	return parseDigestJSON(content, "digest")
}

func parseDigestJSON(content []byte, digestKey string) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", ErrMetadata
	}
	seen := make(map[string]struct{})
	digest := ""
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return "", ErrMetadata
		}
		key, ok := keyToken.(string)
		if !ok {
			return "", ErrMetadata
		}
		if _, duplicate := seen[key]; duplicate {
			return "", ErrMetadata
		}
		seen[key] = struct{}{}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return "", ErrMetadata
		}
		if key == digestKey {
			text, ok := value.(string)
			if !ok || !digestPattern.MatchString(text) {
				return "", ErrMetadata
			}
			digest = text
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return "", ErrMetadata
	}
	if decoder.Decode(new(any)) != io.EOF || digest == "" {
		return "", ErrMetadata
	}
	return digest, nil
}

func verifyRootFSOutput(path string, manifest workerrootfs.ManifestV1) error {
	if manifest.Schema != workerrootfs.SchemaV1 || manifest.Size <= 0 || manifest.Size > 1<<30 ||
		!digestPattern.MatchString(manifest.RootFSDigest) || !digestPattern.MatchString(manifest.BinaryDigest) {
		return ErrRootFS
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != manifest.Size {
		return ErrRootFS
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrRootFS
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, io.LimitReader(file, manifest.Size+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != manifest.Size {
		return ErrRootFS
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(info, after) || after.Size() != manifest.Size {
		return ErrRootFS
	}
	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if digest != manifest.RootFSDigest {
		return ErrRootFS
	}
	return nil
}

func writeNewOutput(path string, content []byte) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrOutput
	}
	created := true
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if err != nil && created {
			_ = os.Remove(path)
		}
	}()
	if chmodErr := file.Chmod(0o600); chmodErr != nil {
		return ErrOutput
	}
	if _, writeErr := file.Write(content); writeErr != nil {
		return ErrOutput
	}
	if syncErr := file.Sync(); syncErr != nil {
		return ErrOutput
	}
	if closeErr := file.Close(); closeErr != nil {
		file = nil
		return ErrOutput
	}
	file = nil
	created = false
	return nil
}

func containsSpaceOrControl(value string) bool {
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func secretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://", "@", "authorization=", "access_key=", "access-key=", "secret_key=", "secret-key=",
		"password=", "passwd=", "token=", "bearer ",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return awsKeyPattern.MatchString(value) || apiKeyPattern.MatchString(value)
}

type execRunner struct {
	dockerConfigDir string
}

func (runner execRunner) Run(ctx context.Context, directory, executable string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = directory
	command.Env = safeEnvironment(runner.dockerConfigDir)
	var stdout limitedBuffer
	stdout.limit = maxCommandOutput
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("command failed")
	}
	return stdout.Bytes(), nil
}

func safeEnvironment(dockerConfigDir string) []string {
	keys := []string{
		"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
		"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
		"TMP", "TEMP", "TMPDIR", "XDG_CONFIG_HOME",
		"SSH_AUTH_SOCK", "GIT_CONFIG_NOSYSTEM",
	}
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			environment = append(environment, key+"="+value)
		}
	}
	environment = append(environment, "DOCKER_CONFIG="+dockerConfigDir)
	return environment
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (buffer *limitedBuffer) Write(content []byte) (int, error) {
	if buffer.buffer.Len()+len(content) > buffer.limit {
		return 0, errors.New("command output limit exceeded")
	}
	return buffer.buffer.Write(content)
}

func (buffer *limitedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

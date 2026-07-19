package releasepublish

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseecr"
)

const AgentResultSchemaV1 = "dirextalk.agent.agent-image-release/v1"

// AgentRequest contains the closed coordinates for publishing only the Agent
// container. The Docker session is supplied by the Agent-only ECR preparer;
// it is a directory reference rather than credentials and is never emitted in
// a result or receipt.
type AgentRequest struct {
	ReleaseTag           string
	Architecture         string
	AgentRepository      string
	DockerConfigDir      string
	RegistryHost         string
	BuilderName          string
	BuildSourcesVerified bool
}

// AgentResult is the safe Agent-image release receipt. It deliberately has no
// Worker, Reaper, rootfs, AMI, runtime-pull credential, or P4 acceptance
// field. AgentImage is the only value a host may use, and includes both the
// immutable prerelease tag and resolved registry digest.
type AgentResult struct {
	SchemaVersion string `json:"schema_version"`
	ReleaseTag    string `json:"release_tag"`
	GitRevision   string `json:"git_revision"`
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	AgentImage    string `json:"agent_image"`
	AgentDigest   string `json:"agent_digest"`
	PublishedAt   string `json:"published_at"`
}

// PublishAgent builds and pushes only deploy/container/agent.Containerfile.
// The content-addressed image is uploaded before the immutable prerelease tag
// is created and read back. The repository must be the fixed private
// dirextalk-agent repository under the authenticated registry host.
func PublishAgent(ctx context.Context, request AgentRequest) (AgentResult, error) {
	repositoryRoot, err := os.Getwd()
	if err != nil {
		return AgentResult{}, ErrGitState
	}
	tool := publisher{
		repositoryRoot: repositoryRoot,
		runner:         execRunner{dockerConfigDir: strings.TrimSpace(request.DockerConfigDir)},
		now:            time.Now,
		makeTempDir: func() (string, error) {
			return os.MkdirTemp("", "dirextalk-agent-image-")
		},
	}
	return tool.publishAgent(ctx, request)
}

func (tool publisher) publishAgent(ctx context.Context, input AgentRequest) (AgentResult, error) {
	request, err := normalizeAgentRequest(input)
	if err != nil {
		return AgentResult{}, err
	}
	repositoryRoot, err := canonicalExistingDirectory(tool.repositoryRoot)
	if err != nil {
		return AgentResult{}, ErrGitState
	}
	revision, err := tool.validateRepository(ctx, repositoryRoot)
	if err != nil {
		return AgentResult{}, err
	}
	if err := validateAgentTagAndRepository(request, revision); err != nil {
		return AgentResult{}, err
	}

	temporaryRoot, err := tool.makeTempDir()
	if err != nil {
		return AgentResult{}, ErrBuild
	}
	if chmodErr := os.Chmod(temporaryRoot, 0o700); chmodErr != nil {
		_ = os.RemoveAll(temporaryRoot)
		return AgentResult{}, ErrBuild
	}
	defer os.RemoveAll(temporaryRoot)

	metadataPath := filepath.Join(temporaryRoot, "agent-push.json")
	if err := prepareMetadataFile(metadataPath); err != nil {
		return AgentResult{}, ErrBuild
	}
	// Upload by digest before mutating the immutable human-readable tag, so an
	// interrupted build may be resumed without reserving or overwriting it.
	if _, err := tool.runner.Run(ctx, repositoryRoot, "docker", agentPushByDigestArguments(request, revision, metadataPath)...); err != nil {
		return AgentResult{}, ErrBuild
	}
	digest, err := parseImageDigest(metadataPath)
	if err != nil {
		return AgentResult{}, err
	}
	if err := tool.reconcileImmutableTag(ctx, repositoryRoot, request.AgentRepository, request.ReleaseTag, digest, request.BuilderName); err != nil {
		return AgentResult{}, err
	}
	confirmedRevision, err := tool.validateRepository(ctx, repositoryRoot)
	if err != nil || confirmedRevision != revision {
		return AgentResult{}, ErrGitState
	}

	return AgentResult{
		SchemaVersion: AgentResultSchemaV1,
		ReleaseTag:    request.ReleaseTag,
		GitRevision:   revision,
		OS:            "linux",
		Architecture:  request.Architecture,
		AgentImage:    immutableReference(request.AgentRepository, request.ReleaseTag, digest),
		AgentDigest:   digest,
		PublishedAt:   tool.now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func normalizeAgentRequest(input AgentRequest) (AgentRequest, error) {
	request := AgentRequest{
		ReleaseTag:           strings.TrimSpace(input.ReleaseTag),
		Architecture:         strings.TrimSpace(input.Architecture),
		AgentRepository:      strings.TrimSpace(input.AgentRepository),
		DockerConfigDir:      strings.TrimSpace(input.DockerConfigDir),
		RegistryHost:         strings.TrimSpace(input.RegistryHost),
		BuilderName:          strings.TrimSpace(input.BuilderName),
		BuildSourcesVerified: input.BuildSourcesVerified,
	}
	if request.ReleaseTag == "" || request.AgentRepository == "" || request.RegistryHost == "" ||
		request.Architecture != "amd64" || !request.BuildSourcesVerified ||
		strings.ContainsAny(request.RegistryHost, "/:@ \t\r\n") || containsSpaceOrControl(request.ReleaseTag) ||
		containsSpaceOrControl(request.AgentRepository) || secretLike(request.ReleaseTag) || secretLike(request.AgentRepository) ||
		!filepath.IsAbs(request.DockerConfigDir) || filepath.Clean(request.DockerConfigDir) != request.DockerConfigDir ||
		(request.BuilderName != "" && !builderNamePattern.MatchString(request.BuilderName)) ||
		request.AgentRepository != request.RegistryHost+"/"+releaseecr.RepositoryAgent {
		return AgentRequest{}, ErrInvalidInput
	}
	if _, err := releaseecr.PrivateBuildSourceReferences(request.RegistryHost); err != nil {
		return AgentRequest{}, ErrInvalidInput
	}
	return request, nil
}

func validateAgentTagAndRepository(request AgentRequest, revision string) error {
	match := tagPattern.FindStringSubmatch(request.ReleaseTag)
	if len(match) != 2 || match[1] != revision[:12] || strings.HasPrefix(request.ReleaseTag, "v1.0.3-") ||
		request.ReleaseTag == "latest" || request.ReleaseTag == "stable" ||
		request.AgentRepository != request.RegistryHost+"/"+releaseecr.RepositoryAgent {
		return ErrInvalidInput
	}
	return nil
}

func agentPushByDigestArguments(request AgentRequest, revision, metadata string) []string {
	arguments := buildxArguments(request.BuilderName,
		"build",
		"--file", "deploy/container/agent.Containerfile",
		"--platform", "linux/"+request.Architecture,
	)
	arguments = append(arguments, privateSourceBuildArguments(request.RegistryHost, "deploy/container/agent.Containerfile")...)
	return append(arguments,
		"--build-arg", "VERSION="+request.ReleaseTag,
		"--build-arg", "REVISION="+revision,
		"--metadata-file", metadata,
		"--output", "type=image,name="+request.AgentRepository+",push-by-digest=true,push=true",
		".")
}

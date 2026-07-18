// Package releaseecr prepares and independently verifies the fixed private ECR
// repositories used by a Dirextalk Agent release. It intentionally exposes no
// general registry or AWS mutation surface.
package releaseecr

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	ResultSchemaV1         = "dirextalk.agent.ecr-release-preparation/v1"
	AgentResultSchemaV1    = "dirextalk.agent.agent-image-ecr-preparation/v1"
	SessionSchemaV1        = "dirextalk.agent.ecr-docker-session/v1"
	ManagedReceiptSchemaV1 = "dirextalk.agent.ecr-managed-verification/v1"
	ManagedRetention       = "managed_retained"

	RepositoryAgent  = "dirextalk-agent"
	RepositoryWorker = "dirextalk-cloud-worker"
	RepositoryReaper = "dirextalk-aws-reaper"
)

var (
	ErrInvalidInput           = errors.New("invalid ECR preparation input")
	ErrRegionMismatch         = errors.New("AWS region does not match ECR preparation")
	ErrIdentityMismatch       = errors.New("AWS identity does not match ECR preparation")
	ErrRepositoryDrift        = errors.New("ECR repository configuration drift")
	ErrAuthorizationMismatch  = errors.New("ECR authorization does not match prepared registry")
	ErrAWSOperation           = errors.New("AWS ECR preparation failed")
	ErrDockerLogin            = errors.New("Docker ECR login failed")
	ErrSession                = errors.New("ECR Docker session rejected")
	ErrSessionCleanup         = errors.New("ECR Docker session cleanup failed")
	ErrReleaseManifestBinding = errors.New("release manifest does not bind the managed ECR repositories")
	ErrReleaseImageBinding    = errors.New("release image tag and digest binding drift")
)

type RepositorySpec struct {
	Component string
	Name      string
}

var fixedRepositories = []RepositorySpec{
	{Component: "agent", Name: RepositoryAgent},
	{Component: "worker", Name: RepositoryWorker},
	{Component: "reaper", Name: RepositoryReaper},
}

func FixedRepositories() []RepositorySpec {
	return append([]RepositorySpec(nil), fixedRepositories...)
}

// AgentRepositories returns the closed repository set used by the standalone
// Agent-image release path. It intentionally excludes the Worker and Reaper
// repositories so preparing an Agent image cannot provision their release
// surfaces as a side effect.
func AgentRepositories() []RepositorySpec {
	return []RepositorySpec{{Component: "agent", Name: RepositoryAgent}}
}

type Options struct {
	Region            string
	ExpectedAccountID string
	Now               func() time.Time
}

type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type ECRAPI interface {
	DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	CreateRepository(context.Context, *ecr.CreateRepositoryInput, ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error)
	ListTagsForResource(context.Context, *ecr.ListTagsForResourceInput, ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error)
	GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

type Clients struct {
	Region string
	STS    STSAPI
	ECR    ECRAPI
}

// ManagedECRAPI intentionally exposes only read operations. Managed release
// verification cannot create, retag, authenticate to, publish to, or delete a
// repository or image through this provider boundary.
type ManagedECRAPI interface {
	DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	ListTagsForResource(context.Context, *ecr.ListTagsForResourceInput, ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error)
	DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}

type ManagedClients struct {
	Region string
	STS    STSAPI
	ECR    ManagedECRAPI
}

type ManagedVerifyOptions struct {
	Region            string
	ExpectedAccountID string
	ReleaseManifest   releaseartifact.ReleaseManifestV1
	Now               func() time.Time
}

type Command struct {
	Executable      string
	Arguments       []string
	Stdin           []byte
	DockerConfigDir string
}

// CommandRunner must consume Stdin synchronously and must not retain it. The
// caller clears the password buffer immediately after Run returns.
type CommandRunner interface {
	Run(context.Context, Command) error
}

type RepositoryResultV1 struct {
	Component string `json:"component"`
	Name      string `json:"name"`
	URI       string `json:"uri"`
	Created   bool   `json:"created"`
}

// ResultV1 is safe for public JSON output. It never contains an authorization
// token, password, credential source, caller ARN, or provider error.
type ResultV1 struct {
	SchemaVersion  string               `json:"schema_version"`
	AccountID      string               `json:"account_id"`
	Region         string               `json:"region"`
	RegistryHost   string               `json:"registry_host"`
	LoginExpiresAt string               `json:"login_expires_at"`
	Repositories   []RepositoryResultV1 `json:"repositories"`
}

// SessionV1 is a de-secreted, single-use handoff. DockerConfigDir identifies a
// private directory that contains Docker's short-lived ECR authorization; the
// descriptor never contains the authorization token or config.json bytes.
type SessionV1 struct {
	SchemaVersion   string `json:"schema_version"`
	SessionID       string `json:"session_id"`
	RegistryHost    string `json:"registry_host"`
	DockerConfigDir string `json:"docker_config_dir"`
	ExpiresAt       string `json:"expires_at"`
}

type PreparedV1 struct {
	Result  ResultV1
	Session SessionV1
}

type ManagedRepositoryReceiptV1 struct {
	Component   string `json:"component"`
	Name        string `json:"name"`
	ARN         string `json:"arn"`
	URI         string `json:"uri"`
	Retention   string `json:"retention"`
	ReleaseTag  string `json:"release_tag"`
	ImageDigest string `json:"image_digest"`
	Image       string `json:"image"`
}

// ManagedReceiptV1 is the de-secreted result of an independent, read-only
// identity, repository, tag, release-manifest, and image-binding read-back.
// It never contains a caller ARN, provider response, credential source,
// authorization token, Docker session, or mutable repository input.
type ManagedReceiptV1 struct {
	SchemaVersion         string                       `json:"schema_version"`
	AccountID             string                       `json:"account_id"`
	Region                string                       `json:"region"`
	RegistryHost          string                       `json:"registry_host"`
	Retention             string                       `json:"retention"`
	ReleaseTag            string                       `json:"release_tag"`
	ReleaseManifestDigest string                       `json:"release_manifest_digest"`
	VerifiedAt            string                       `json:"verified_at"`
	Repositories          []ManagedRepositoryReceiptV1 `json:"repositories"`
}

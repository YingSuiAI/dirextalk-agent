// Package releaseecr prepares the fixed private ECR repositories used by a
// Dirextalk Agent release. It intentionally exposes no general registry or AWS
// mutation surface.
package releaseecr

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	ResultSchemaV1  = "dirextalk.agent.ecr-release-preparation/v1"
	SessionSchemaV1 = "dirextalk.agent.ecr-docker-session/v1"

	RepositoryAgent  = "dirextalk-agent"
	RepositoryWorker = "dirextalk-cloud-worker"
	RepositoryReaper = "dirextalk-aws-reaper"
)

var (
	ErrInvalidInput          = errors.New("invalid ECR preparation input")
	ErrRegionMismatch        = errors.New("AWS region does not match ECR preparation")
	ErrIdentityMismatch      = errors.New("AWS identity does not match ECR preparation")
	ErrRepositoryDrift       = errors.New("ECR repository configuration drift")
	ErrAuthorizationMismatch = errors.New("ECR authorization does not match prepared registry")
	ErrAWSOperation          = errors.New("AWS ECR preparation failed")
	ErrDockerLogin           = errors.New("Docker ECR login failed")
	ErrSession               = errors.New("ECR Docker session rejected")
	ErrSessionCleanup        = errors.New("ECR Docker session cleanup failed")
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

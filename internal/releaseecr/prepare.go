package releaseecr

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var (
	regionPattern  = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$`)
	accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
)

type Preparer struct {
	options       Options
	clients       Clients
	runner        CommandRunner
	repositories  []RepositorySpec
	resultSchema  string
	newSession    func() (SessionV1, error)
	verifySources func(context.Context, buildSourceReadAPI, string, string, string, string) error
}

func New(options Options, clients Clients, runner CommandRunner) (*Preparer, error) {
	return newPreparer(options, clients, runner, FixedRepositories(), ResultSchemaV1)
}

// NewAgent constructs the closed ECR preparation path for an Agent image
// only. It shares the same identity, immutable-tag, scan-on-push, AES-256,
// ownership-tag, and read-back checks as the bundle preparer, but it never
// reads, creates, or returns Worker or Reaper repositories.
func NewAgent(options Options, clients Clients, runner CommandRunner) (*Preparer, error) {
	return newPreparer(options, clients, runner, AgentRepositories(), AgentResultSchemaV1)
}

func newPreparer(options Options, clients Clients, runner CommandRunner, repositories []RepositorySpec, resultSchema string) (*Preparer, error) {
	if !regionPattern.MatchString(options.Region) || !accountPattern.MatchString(options.ExpectedAccountID) ||
		(options.BuilderMode != "" && options.BuilderMode != BuilderModeDirect) ||
		(options.BuilderMode == BuilderModeDirect && options.Region != BuildSourceRegion) ||
		options.Now == nil || clients.STS == nil || clients.ECR == nil || runner == nil || len(repositories) == 0 || resultSchema == "" {
		return nil, ErrInvalidInput
	}
	if clients.Region != options.Region {
		return nil, ErrRegionMismatch
	}
	return &Preparer{
		options: options, clients: clients, runner: runner,
		repositories: append([]RepositorySpec(nil), repositories...), resultSchema: resultSchema, newSession: newDockerSession,
		verifySources: verifyBuildSources,
	}, nil
}

// PrepareDefault uses only the AWS SDK default credential chain. Options must
// carry an explicit region and expected account ID; there is deliberately no
// access-key, secret-key, session-token, profile-file, or rootkey input.
func PrepareDefault(ctx context.Context, options Options) (PreparedV1, error) {
	return prepareDefault(ctx, options, New)
}

// PrepareAgentDefault prepares only the fixed private dirextalk-agent ECR
// repository. It obtains credentials solely through the AWS SDK default
// chain, creates no Worker/Reaper repository, and emits no runtime pull
// credential. The returned Docker session is a short-lived publisher session
// that must be consumed and cleaned by the release CLI.
func PrepareAgentDefault(ctx context.Context, options Options) (PreparedV1, error) {
	return prepareDefault(ctx, options, NewAgent)
}

type preparerFactory func(Options, Clients, CommandRunner) (*Preparer, error)

func prepareDefault(ctx context.Context, options Options, factory preparerFactory) (PreparedV1, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if !regionPattern.MatchString(options.Region) || !accountPattern.MatchString(options.ExpectedAccountID) ||
		(options.BuilderMode != "" && options.BuilderMode != BuilderModeDirect) ||
		(options.BuilderMode == BuilderModeDirect && options.Region != BuildSourceRegion) {
		return PreparedV1{}, ErrInvalidInput
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(options.Region))
	if err != nil {
		return PreparedV1{}, redactedAWSFailure(ctx)
	}
	preparer, err := factory(options, Clients{
		Region: awsConfig.Region,
		STS:    sts.NewFromConfig(awsConfig),
		ECR:    ecr.NewFromConfig(awsConfig),
	}, dockerRunner{})
	if err != nil {
		return PreparedV1{}, err
	}
	return preparer.Prepare(ctx)
}

func (preparer *Preparer) Prepare(ctx context.Context) (prepared PreparedV1, err error) {
	partition, err := preparer.verifyIdentity(ctx)
	if err != nil {
		return PreparedV1{}, err
	}
	registryHost, err := expectedRegistryHost(partition, preparer.options.ExpectedAccountID, preparer.options.Region)
	if err != nil {
		return PreparedV1{}, err
	}
	results := make([]RepositoryResultV1, 0, len(preparer.repositories))
	for _, spec := range preparer.repositories {
		repository, created, ensureErr := preparer.ensureRepository(ctx, partition, registryHost, spec)
		if ensureErr != nil {
			return PreparedV1{}, ensureErr
		}
		results = append(results, RepositoryResultV1{
			Component: spec.Component, Name: spec.Name, URI: aws.ToString(repository.RepositoryUri), Created: created,
		})
	}
	if preparer.options.BuilderMode == BuilderModeDirect {
		sourceClient, ok := preparer.clients.ECR.(buildSourceReadAPI)
		if !ok {
			return PreparedV1{}, ErrBuildSource
		}
		if err := preparer.verifySources(ctx, sourceClient, partition, preparer.options.ExpectedAccountID,
			preparer.options.Region, registryHost); err != nil {
			return PreparedV1{}, err
		}
	}
	session, err := preparer.newSession()
	if err != nil {
		return PreparedV1{}, err
	}
	keepSession := false
	defer func() {
		if !keepSession {
			_ = os.RemoveAll(session.DockerConfigDir)
		}
	}()
	expiresAt, err := preparer.login(ctx, registryHost, session.DockerConfigDir)
	if err != nil {
		return PreparedV1{}, err
	}
	session.RegistryHost = registryHost
	session.ExpiresAt = expiresAt.UTC().Format(time.RFC3339Nano)
	if preparer.options.BuilderMode == BuilderModeDirect {
		session.BuilderMode = BuilderModeDirect
		session.BuilderName = directBuilderName(session.SessionID)
		session.BuildSourcesVerified = true
	}
	if err := validateSession(session, preparer.options.Now().UTC()); err != nil {
		return PreparedV1{}, err
	}
	keepSession = true
	return PreparedV1{Result: ResultV1{
		SchemaVersion: preparer.resultSchema, AccountID: preparer.options.ExpectedAccountID, Region: preparer.options.Region,
		RegistryHost: registryHost, LoginExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), Repositories: results,
	}, Session: session}, nil
}

func (preparer *Preparer) verifyIdentity(ctx context.Context) (string, error) {
	return verifyExpectedIdentity(ctx, preparer.options.ExpectedAccountID, preparer.clients.STS)
}

func verifyExpectedIdentity(ctx context.Context, expectedAccountID string, client STSAPI) (string, error) {
	output, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", redactedAWSFailure(ctx)
	}
	if output == nil || aws.ToString(output.Account) != expectedAccountID || aws.ToString(output.UserId) == "" {
		return "", ErrIdentityMismatch
	}
	identityARN, err := arn.Parse(aws.ToString(output.Arn))
	if err != nil || (identityARN.Service != "iam" && identityARN.Service != "sts") ||
		identityARN.AccountID != expectedAccountID || identityARN.Partition == "" {
		return "", ErrIdentityMismatch
	}
	return identityARN.Partition, nil
}

func (preparer *Preparer) ensureRepository(ctx context.Context, partition, registryHost string, spec RepositorySpec) (ecrtypes.Repository, bool, error) {
	repository, found, err := preparer.describeRepository(ctx, spec)
	if err != nil {
		return ecrtypes.Repository{}, false, err
	}
	created := false
	if !found {
		_, createErr := preparer.clients.ECR.CreateRepository(ctx, &ecr.CreateRepositoryInput{
			RepositoryName: aws.String(spec.Name), ImageTagMutability: ecrtypes.ImageTagMutabilityImmutable,
			ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: true},
			EncryptionConfiguration:    &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeAes256},
			Tags:                       repositoryTags(spec),
		})
		if createErr != nil {
			var exists *ecrtypes.RepositoryAlreadyExistsException
			if !errors.As(createErr, &exists) {
				// CreateRepository has no client token. Close the response-loss
				// window with an exact read-back before reporting failure.
				repository, found, err = preparer.describeRepository(ctx, spec)
				if err != nil {
					return ecrtypes.Repository{}, false, err
				}
				if !found {
					return ecrtypes.Repository{}, false, redactedAWSFailure(ctx)
				}
			}
		} else {
			created = true
		}
		// Never trust the mutation response. A strict regional Describe is the
		// only source for the returned repository.
		if repository.RepositoryName == nil {
			repository, found, err = preparer.describeRepository(ctx, spec)
			if err != nil {
				return ecrtypes.Repository{}, false, err
			}
			if !found {
				return ecrtypes.Repository{}, false, ErrRepositoryDrift
			}
		}
	}
	if err := validateRepository(repository, partition, preparer.options.ExpectedAccountID, preparer.options.Region, registryHost, spec.Name); err != nil {
		return ecrtypes.Repository{}, false, err
	}
	return repository, created, nil
}

func (preparer *Preparer) describeRepository(ctx context.Context, spec RepositorySpec) (ecrtypes.Repository, bool, error) {
	output, err := preparer.clients.ECR.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		RegistryId: aws.String(preparer.options.ExpectedAccountID), RepositoryNames: []string{spec.Name},
	})
	if err != nil {
		var missing *ecrtypes.RepositoryNotFoundException
		if errors.As(err, &missing) {
			return ecrtypes.Repository{}, false, nil
		}
		return ecrtypes.Repository{}, false, redactedAWSFailure(ctx)
	}
	if output == nil || len(output.Repositories) != 1 {
		return ecrtypes.Repository{}, false, ErrRepositoryDrift
	}
	repository := output.Repositories[0]
	if aws.ToString(repository.RepositoryArn) == "" {
		return ecrtypes.Repository{}, false, ErrRepositoryDrift
	}
	tags, err := preparer.clients.ECR.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{ResourceArn: repository.RepositoryArn})
	if err != nil {
		return ecrtypes.Repository{}, false, redactedAWSFailure(ctx)
	}
	if tags == nil || !exactRepositoryTags(tags.Tags, spec) {
		return ecrtypes.Repository{}, false, ErrRepositoryDrift
	}
	return repository, true, nil
}

func repositoryTags(spec RepositorySpec) []ecrtypes.Tag {
	return []ecrtypes.Tag{
		{Key: aws.String("managed_by"), Value: aws.String("dirextalk-agent")},
		{Key: aws.String("component"), Value: aws.String("release-registry")},
		{Key: aws.String("artifact"), Value: aws.String(spec.Component)},
		{Key: aws.String("retention"), Value: aws.String(ManagedRetention)},
	}
}

func exactRepositoryTags(tags []ecrtypes.Tag, spec RepositorySpec) bool {
	if len(tags) != 4 {
		return false
	}
	wanted := map[string]string{
		"managed_by": "dirextalk-agent",
		"component":  "release-registry",
		"artifact":   spec.Component,
		"retention":  ManagedRetention,
	}
	for _, tag := range tags {
		key := aws.ToString(tag.Key)
		if expected, ok := wanted[key]; !ok || aws.ToString(tag.Value) != expected {
			return false
		}
		delete(wanted, key)
	}
	return len(wanted) == 0
}

func validateRepository(repository ecrtypes.Repository, partition, accountID, region, registryHost, name string) error {
	if aws.ToString(repository.RegistryId) != accountID || aws.ToString(repository.RepositoryName) != name ||
		aws.ToString(repository.RepositoryUri) != registryHost+"/"+name ||
		repository.ImageTagMutability != ecrtypes.ImageTagMutabilityImmutable ||
		repository.ImageScanningConfiguration == nil || !repository.ImageScanningConfiguration.ScanOnPush ||
		repository.EncryptionConfiguration == nil || repository.EncryptionConfiguration.EncryptionType != ecrtypes.EncryptionTypeAes256 ||
		aws.ToString(repository.EncryptionConfiguration.KmsKey) != "" {
		return ErrRepositoryDrift
	}
	repositoryARN, err := arn.Parse(aws.ToString(repository.RepositoryArn))
	if err != nil || repositoryARN.Partition != partition || repositoryARN.Service != "ecr" || repositoryARN.Region != region ||
		repositoryARN.AccountID != accountID || repositoryARN.Resource != "repository/"+name {
		return ErrRepositoryDrift
	}
	return nil
}

func (preparer *Preparer) login(ctx context.Context, registryHost, dockerConfigDir string) (time.Time, error) {
	output, err := preparer.clients.ECR.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{RegistryIds: []string{preparer.options.ExpectedAccountID}})
	if err != nil {
		return time.Time{}, redactedAWSFailure(ctx)
	}
	if output == nil || len(output.AuthorizationData) != 1 {
		return time.Time{}, ErrAuthorizationMismatch
	}
	authorization := &output.AuthorizationData[0]
	token := aws.ToString(authorization.AuthorizationToken)
	if authorization.AuthorizationToken != nil {
		*authorization.AuthorizationToken = ""
	}
	endpoint, err := url.Parse(aws.ToString(authorization.ProxyEndpoint))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host != registryHost || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil ||
		authorization.ExpiresAt == nil || !preparer.options.Now().UTC().Before(authorization.ExpiresAt.UTC()) {
		return time.Time{}, ErrAuthorizationMismatch
	}
	decoded, err := decodeAuthorizationToken(token)
	token = ""
	if err != nil {
		return time.Time{}, err
	}
	defer clear(decoded)
	separator := bytes.IndexByte(decoded, ':')
	if separator != len("AWS") || !bytes.Equal(decoded[:separator], []byte("AWS")) || separator+1 >= len(decoded) {
		return time.Time{}, ErrAuthorizationMismatch
	}
	password := decoded[separator+1:]
	if len(password) > 8192 || bytesContainControl(password) {
		return time.Time{}, ErrAuthorizationMismatch
	}
	stdin := make([]byte, len(password)+1)
	copy(stdin, password)
	stdin[len(stdin)-1] = '\n'
	defer clear(stdin)
	command := Command{
		Executable: "docker", DockerConfigDir: dockerConfigDir,
		Arguments: []string{"login", "--username", "AWS", "--password-stdin", registryHost}, Stdin: stdin,
	}
	if err := preparer.runner.Run(ctx, command); err != nil {
		if ctx.Err() != nil {
			return time.Time{}, ctx.Err()
		}
		return time.Time{}, ErrDockerLogin
	}
	if err := finalizeDockerConfig(SessionV1{DockerConfigDir: dockerConfigDir}); err != nil {
		return time.Time{}, ErrSession
	}
	return authorization.ExpiresAt.UTC(), nil
}

func decodeAuthorizationToken(token string) ([]byte, error) {
	if len(token) == 0 || len(token) > 32<<10 {
		return nil, ErrAuthorizationMismatch
	}
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(decoded) < len("AWS:x") {
		clear(decoded)
		return nil, ErrAuthorizationMismatch
	}
	return decoded, nil
}

func bytesContainControl(value []byte) bool {
	for _, item := range value {
		if item < 0x21 || item == 0x7f {
			return true
		}
	}
	return false
}

func expectedRegistryHost(partition, accountID, region string) (string, error) {
	suffix := ""
	switch partition {
	case "aws", "aws-us-gov":
		suffix = "amazonaws.com"
	case "aws-cn":
		suffix = "amazonaws.com.cn"
	default:
		return "", ErrIdentityMismatch
	}
	return accountID + ".dkr.ecr." + region + "." + suffix, nil
}

func redactedAWSFailure(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrAWSOperation
}

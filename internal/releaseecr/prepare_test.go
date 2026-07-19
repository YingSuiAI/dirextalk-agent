package releaseecr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	testAccount  = "123456789012"
	testRegion   = "us-east-1"
	testPassword = "ecr-super-secret-password"
)

type fakeSTS struct {
	output *sts.GetCallerIdentityOutput
	err    error
	calls  int
}

func (client *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	client.calls++
	return client.output, client.err
}

type fakeECR struct {
	repositories        map[string]ecrtypes.Repository
	repositoryTags      map[string][]ecrtypes.Tag
	describeCalls       []string
	listTagCalls        []string
	createCalls         []ecr.CreateRepositoryInput
	authorizationCalls  int
	driftAfterCreate    bool
	authorizationHost   string
	err                 error
	createErrAfterStore error
	lastTokenPointer    *string
}

func (client *fakeECR) DescribeRepositories(_ context.Context, input *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if client.err != nil {
		return nil, client.err
	}
	if input == nil || len(input.RepositoryNames) != 1 || aws.ToString(input.RegistryId) != testAccount {
		return nil, errors.New("bad describe request")
	}
	name := input.RepositoryNames[0]
	client.describeCalls = append(client.describeCalls, name)
	repository, exists := client.repositories[name]
	if !exists {
		return nil, &ecrtypes.RepositoryNotFoundException{Message: aws.String("repository missing with sensitive provider detail")}
	}
	return &ecr.DescribeRepositoriesOutput{Repositories: []ecrtypes.Repository{repository}}, nil
}

func (client *fakeECR) CreateRepository(_ context.Context, input *ecr.CreateRepositoryInput, _ ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error) {
	if client.err != nil {
		return nil, client.err
	}
	if input == nil {
		return nil, errors.New("missing create input")
	}
	client.createCalls = append(client.createCalls, *input)
	name := aws.ToString(input.RepositoryName)
	repository := validRepository(name)
	if client.driftAfterCreate {
		repository.ImageTagMutability = ecrtypes.ImageTagMutabilityMutable
	}
	client.repositories[name] = repository
	if client.repositoryTags == nil {
		client.repositoryTags = make(map[string][]ecrtypes.Tag)
	}
	client.repositoryTags[name] = append([]ecrtypes.Tag(nil), input.Tags...)
	if client.createErrAfterStore != nil {
		return nil, client.createErrAfterStore
	}
	return &ecr.CreateRepositoryOutput{Repository: &repository}, nil
}

func (client *fakeECR) ListTagsForResource(_ context.Context, input *ecr.ListTagsForResourceInput, _ ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
	if client.err != nil {
		return nil, client.err
	}
	if input == nil || aws.ToString(input.ResourceArn) == "" {
		return nil, errors.New("bad list tags request")
	}
	for name, repository := range client.repositories {
		if aws.ToString(repository.RepositoryArn) != aws.ToString(input.ResourceArn) {
			continue
		}
		client.listTagCalls = append(client.listTagCalls, name)
		if tags, ok := client.repositoryTags[name]; ok {
			return &ecr.ListTagsForResourceOutput{Tags: append([]ecrtypes.Tag(nil), tags...)}, nil
		}
		return &ecr.ListTagsForResourceOutput{Tags: validRepositoryTags(name)}, nil
	}
	return nil, errors.New("unknown repository ARN")
}

func (client *fakeECR) GetAuthorizationToken(_ context.Context, input *ecr.GetAuthorizationTokenInput, _ ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	client.authorizationCalls++
	if input == nil || !slices.Equal(input.RegistryIds, []string{testAccount}) {
		return nil, errors.New("bad authorization request")
	}
	host := client.authorizationHost
	if host == "" {
		host = registryHost(testAccount, testRegion)
	}
	token := base64.StdEncoding.EncodeToString([]byte("AWS:" + testPassword))
	client.lastTokenPointer = aws.String(token)
	expiresAt := testNow.Add(12 * time.Hour)
	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []ecrtypes.AuthorizationData{{
		AuthorizationToken: client.lastTokenPointer, ProxyEndpoint: aws.String("https://" + host), ExpiresAt: &expiresAt,
	}}}, nil
}

func (client *fakeECR) BatchGetImage(context.Context, *ecr.BatchGetImageInput, ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error) {
	return nil, errors.New("unexpected build source image read")
}

func (client *fakeECR) DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	return nil, errors.New("unexpected build source detail read")
}

type recordedCommand struct {
	executable      string
	arguments       []string
	stdin           []byte
	dockerConfigDir string
}

type fakeRunner struct {
	commands       []recordedCommand
	stdinReference []byte
	err            error
}

func (runner *fakeRunner) Run(_ context.Context, command Command) error {
	runner.stdinReference = command.Stdin
	runner.commands = append(runner.commands, recordedCommand{
		executable: command.Executable, dockerConfigDir: command.DockerConfigDir,
		arguments: append([]string(nil), command.Arguments...), stdin: append([]byte(nil), command.Stdin...),
	})
	return runner.err
}

var testNow = time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

func TestPrepareCreatesFixedRepositoriesReadsBackAndLogsInWithoutPasswordArgv(t *testing.T) {
	stsClient := validSTS()
	ecrClient := &fakeECR{repositories: make(map[string]ecrtypes.Repository)}
	runner := &fakeRunner{}
	preparer := newTestPreparer(t, stsClient, ecrClient, runner)

	prepared := prepareSuccess(t, preparer)
	result := prepared.Result
	if result.SchemaVersion != ResultSchemaV1 || result.AccountID != testAccount || result.Region != testRegion ||
		result.RegistryHost != registryHost(testAccount, testRegion) || len(result.Repositories) != 3 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(ecrClient.createCalls) != 3 || len(ecrClient.describeCalls) != 6 || len(ecrClient.listTagCalls) != 3 || ecrClient.authorizationCalls != 1 {
		t.Fatalf("unexpected AWS calls: create=%d describe=%#v list_tags=%#v auth=%d", len(ecrClient.createCalls), ecrClient.describeCalls, ecrClient.listTagCalls, ecrClient.authorizationCalls)
	}
	for _, input := range ecrClient.createCalls {
		if input.ImageTagMutability != ecrtypes.ImageTagMutabilityImmutable || input.ImageScanningConfiguration == nil || !input.ImageScanningConfiguration.ScanOnPush ||
			input.EncryptionConfiguration == nil || input.EncryptionConfiguration.EncryptionType != ecrtypes.EncryptionTypeAes256 || aws.ToString(input.EncryptionConfiguration.KmsKey) != "" ||
			!equalRepositoryTags(input.Tags, validRepositoryTags(aws.ToString(input.RepositoryName))) {
			t.Fatalf("unsafe repository create input: %#v", input)
		}
	}
	if len(runner.commands) != 1 {
		t.Fatalf("docker calls = %d", len(runner.commands))
	}
	command := runner.commands[0]
	wantArguments := []string{"login", "--username", "AWS", "--password-stdin", registryHost(testAccount, testRegion)}
	if command.executable != "docker" || command.dockerConfigDir != prepared.Session.DockerConfigDir ||
		!slices.Equal(command.arguments, wantArguments) || string(command.stdin) != testPassword+"\n" {
		t.Fatalf("unexpected docker command: executable=%q arguments=%#v stdin_length=%d", command.executable, command.arguments, len(command.stdin))
	}
	for _, argument := range command.arguments {
		if strings.Contains(argument, testPassword) {
			t.Fatalf("password leaked into docker argv: %#v", command.arguments)
		}
	}
	if ecrClient.lastTokenPointer == nil || *ecrClient.lastTokenPointer != "" {
		t.Fatal("SDK authorization token pointer was retained")
	}
	for _, value := range runner.stdinReference {
		if value != 0 {
			t.Fatal("docker password stdin buffer was not cleared")
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testPassword) || strings.Contains(strings.ToLower(string(encoded)), "authorizationtoken") {
		t.Fatalf("public result leaked authorization material: %s", encoded)
	}
}

func TestPrepareExistingRepositoriesIsIdempotent(t *testing.T) {
	repositories := make(map[string]ecrtypes.Repository)
	for _, spec := range FixedRepositories() {
		repositories[spec.Name] = validRepository(spec.Name)
	}
	ecrClient := &fakeECR{repositories: repositories}
	preparer := newTestPreparer(t, validSTS(), ecrClient, &fakeRunner{})
	prepareSuccess(t, preparer)
	if len(ecrClient.createCalls) != 0 || len(ecrClient.describeCalls) != 3 || len(ecrClient.listTagCalls) != 3 {
		t.Fatalf("idempotent prepare mutated repositories: create=%d describe=%#v list_tags=%#v", len(ecrClient.createCalls), ecrClient.describeCalls, ecrClient.listTagCalls)
	}
}

func TestPrepareDirectBuilderModeBindsOnlyDeterministicSessionMetadata(t *testing.T) {
	options := validOptions()
	options.BuilderMode = BuilderModeDirect
	options.Region = BuildSourceRegion
	preparer, err := New(options, Clients{Region: BuildSourceRegion, STS: validSTS(), ECR: &fakeECR{
		authorizationHost: registryHost(testAccount, BuildSourceRegion),
		repositories: map[string]ecrtypes.Repository{
			RepositoryAgent:  validRepositoryIn(RepositoryAgent, BuildSourceRegion),
			RepositoryWorker: validRepositoryIn(RepositoryWorker, BuildSourceRegion),
			RepositoryReaper: validRepositoryIn(RepositoryReaper, BuildSourceRegion),
		},
	}}, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	sourceVerifyCalls := 0
	preparer.verifySources = func(context.Context, buildSourceReadAPI, string, string, string, string) error {
		sourceVerifyCalls++
		return nil
	}
	prepared := prepareSuccess(t, preparer)
	if prepared.Session.BuilderMode != BuilderModeDirect ||
		prepared.Session.BuilderName != directBuilderName(prepared.Session.SessionID) ||
		!prepared.Session.BuildSourcesVerified || sourceVerifyCalls != 1 ||
		strings.Contains(prepared.Session.BuilderName, prepared.Session.DockerConfigDir) {
		t.Fatalf("direct builder session binding = %#v", prepared.Session)
	}
}

func TestPrepareRecoversCreateResponseLossThroughStrictReadBack(t *testing.T) {
	secret := "provider response loss with secret detail"
	ecrClient := &fakeECR{repositories: make(map[string]ecrtypes.Repository), createErrAfterStore: errors.New(secret)}
	runner := &fakeRunner{}
	preparer := newTestPreparer(t, validSTS(), ecrClient, runner)
	prepared, err := preparer.Prepare(context.Background())
	if err == nil {
		t.Cleanup(func() { _ = CleanupSession(prepared.Session) })
	}
	result := prepared.Result
	if err != nil || strings.Contains(errString(err), secret) {
		t.Fatalf("response-loss recovery failed: result=%#v err=%v", result, err)
	}
	if len(ecrClient.createCalls) != 3 || len(ecrClient.listTagCalls) != 3 || len(runner.commands) != 1 {
		t.Fatalf("unexpected recovery calls: create=%d list_tags=%#v docker=%d", len(ecrClient.createCalls), ecrClient.listTagCalls, len(runner.commands))
	}
	for _, repository := range result.Repositories {
		if repository.Created {
			t.Fatalf("unknown mutation result was reported as definitely created: %#v", repository)
		}
		if !equalRepositoryTags(ecrClient.repositoryTags[repository.Name], validRepositoryTags(repository.Name)) {
			t.Fatalf("response-loss repository ownership was not exact: %s", repository.Name)
		}
	}
}

func TestPrepareRejectsRepositoryDriftAndFailedReadBackBeforeLogin(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeECR)
	}{
		{name: "existing mutability drift", setup: func(client *fakeECR) {
			for _, spec := range FixedRepositories() {
				client.repositories[spec.Name] = validRepository(spec.Name)
			}
			repository := client.repositories[RepositoryAgent]
			repository.ImageTagMutability = ecrtypes.ImageTagMutabilityMutable
			client.repositories[RepositoryAgent] = repository
		}},
		{name: "scan-on-push drift", setup: func(client *fakeECR) {
			for _, spec := range FixedRepositories() {
				client.repositories[spec.Name] = validRepository(spec.Name)
			}
			repository := client.repositories[RepositoryAgent]
			repository.ImageScanningConfiguration.ScanOnPush = false
			client.repositories[RepositoryAgent] = repository
		}},
		{name: "encryption drift", setup: func(client *fakeECR) {
			for _, spec := range FixedRepositories() {
				client.repositories[spec.Name] = validRepository(spec.Name)
			}
			repository := client.repositories[RepositoryAgent]
			repository.EncryptionConfiguration.EncryptionType = ecrtypes.EncryptionTypeKms
			repository.EncryptionConfiguration.KmsKey = aws.String("alias/provider-secret")
			client.repositories[RepositoryAgent] = repository
		}},
		{name: "create response not trusted without readback", setup: func(client *fakeECR) { client.driftAfterCreate = true }},
		{name: "ownership tag missing", setup: func(client *fakeECR) {
			for _, spec := range FixedRepositories() {
				client.repositories[spec.Name] = validRepository(spec.Name)
			}
			client.repositoryTags = map[string][]ecrtypes.Tag{RepositoryAgent: {
				{Key: aws.String("managed_by"), Value: aws.String("dirextalk-agent")},
				{Key: aws.String("artifact"), Value: aws.String("agent")},
			}}
		}},
		{name: "legacy ownership tags without managed retention", setup: func(client *fakeECR) {
			for _, spec := range FixedRepositories() {
				client.repositories[spec.Name] = validRepository(spec.Name)
			}
			client.repositoryTags = map[string][]ecrtypes.Tag{RepositoryAgent: {
				{Key: aws.String("managed_by"), Value: aws.String("dirextalk-agent")},
				{Key: aws.String("component"), Value: aws.String("release-registry")},
				{Key: aws.String("artifact"), Value: aws.String("agent")},
			}}
		}},
		{name: "ownership tag changed", setup: func(client *fakeECR) {
			for _, spec := range FixedRepositories() {
				client.repositories[spec.Name] = validRepository(spec.Name)
			}
			client.repositoryTags = map[string][]ecrtypes.Tag{RepositoryAgent: {
				{Key: aws.String("managed_by"), Value: aws.String("another-system")},
				{Key: aws.String("component"), Value: aws.String("release-registry")},
				{Key: aws.String("artifact"), Value: aws.String("agent")},
			}}
		}},
		{name: "unexpected ownership tag", setup: func(client *fakeECR) {
			for _, spec := range FixedRepositories() {
				client.repositories[spec.Name] = validRepository(spec.Name)
			}
			client.repositoryTags = map[string][]ecrtypes.Tag{RepositoryAgent: append(validRepositoryTags(RepositoryAgent),
				ecrtypes.Tag{Key: aws.String("adopted"), Value: aws.String("true")})}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ecrClient := &fakeECR{repositories: make(map[string]ecrtypes.Repository)}
			test.setup(ecrClient)
			runner := &fakeRunner{}
			preparer := newTestPreparer(t, validSTS(), ecrClient, runner)
			if _, err := preparer.Prepare(context.Background()); !errors.Is(err, ErrRepositoryDrift) {
				t.Fatalf("error = %v, want repository drift", err)
			}
			if ecrClient.authorizationCalls != 0 || len(runner.commands) != 0 {
				t.Fatal("drift reached registry authentication")
			}
			if len(ecrClient.createCalls) != 0 && strings.Contains(test.name, "ownership tag") {
				t.Fatal("existing ownership drift was automatically adopted")
			}
		})
	}
}

func TestPrepareRejectsIdentityAndRegionMismatchBeforeECR(t *testing.T) {
	tests := []struct {
		name    string
		options Options
		clients Clients
		want    error
	}{
		{name: "SDK region mismatch", options: validOptions(), clients: Clients{Region: "eu-west-1", STS: validSTS(), ECR: &fakeECR{}}, want: ErrRegionMismatch},
		{name: "caller account mismatch", options: validOptions(), clients: Clients{Region: testRegion, STS: &fakeSTS{output: &sts.GetCallerIdentityOutput{
			Account: aws.String("999999999999"), Arn: aws.String("arn:aws:iam::999999999999:role/release"), UserId: aws.String("AROATEST:release"),
		}}, ECR: &fakeECR{}}, want: ErrIdentityMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preparer, err := New(test.options, test.clients, &fakeRunner{})
			if errors.Is(test.want, ErrRegionMismatch) {
				if !errors.Is(err, test.want) {
					t.Fatalf("New error = %v, want %v", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := preparer.Prepare(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("Prepare error = %v, want %v", err, test.want)
			}
			if client := test.clients.ECR.(*fakeECR); len(client.describeCalls) != 0 {
				t.Fatal("identity mismatch reached ECR")
			}
		})
	}
}

func TestPrepareRejectsAuthorizationEndpointMismatchAndRedactsErrors(t *testing.T) {
	ecrClient := &fakeECR{repositories: make(map[string]ecrtypes.Repository), authorizationHost: "attacker.example"}
	for _, spec := range FixedRepositories() {
		ecrClient.repositories[spec.Name] = validRepository(spec.Name)
	}
	runner := &fakeRunner{}
	preparer := newTestPreparer(t, validSTS(), ecrClient, runner)
	if _, err := preparer.Prepare(context.Background()); !errors.Is(err, ErrAuthorizationMismatch) || strings.Contains(err.Error(), "attacker.example") {
		t.Fatalf("unsafe authorization error = %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("mismatched endpoint reached docker")
	}

	secret := "provider-error-with-secret-value"
	ecrClient = &fakeECR{repositories: make(map[string]ecrtypes.Repository), err: errors.New(secret)}
	preparer = newTestPreparer(t, validSTS(), ecrClient, runner)
	if _, err := preparer.Prepare(context.Background()); !errors.Is(err, ErrAWSOperation) || strings.Contains(err.Error(), secret) {
		t.Fatalf("AWS error was not redacted: %v", err)
	}
}

func TestDockerEnvironmentDoesNotForwardAWSCredentialsOrInheritedConfig(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLESECRET")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "provider-secret")
	t.Setenv("AWS_SESSION_TOKEN", "provider-session")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "C:/secret/credentials")
	t.Setenv("DOCKER_CONFIG", "C:/user-home/.docker")
	t.Setenv("BUILDX_BUILDER", "foreign-builder")
	t.Setenv("HTTP_PROXY", "http://foreign-proxy")
	t.Setenv("HTTPS_PROXY", "http://foreign-proxy")
	t.Setenv("PATH", "C:/safe-bin")
	environment := safeDockerEnvironment("C:/private-release-session")
	if !slices.Contains(environment, "PATH=C:/safe-bin") {
		t.Fatalf("safe PATH missing: %#v", environment)
	}
	for _, value := range environment {
		if strings.HasPrefix(value, "AWS_") || strings.Contains(value, "provider-secret") || strings.Contains(value, "provider-session") {
			t.Fatalf("AWS credential reached docker environment: %q", value)
		}
		if value == "DOCKER_CONFIG=C:/user-home/.docker" {
			t.Fatalf("inherited Docker config reached login: %#v", environment)
		}
		if strings.HasPrefix(value, "BUILDX_") || strings.HasPrefix(value, "HTTP_PROXY=") || strings.HasPrefix(value, "HTTPS_PROXY=") {
			t.Fatalf("inherited builder/proxy configuration reached private session: %q", value)
		}
	}
	if !slices.Contains(environment, "DOCKER_CONFIG=C:/private-release-session") {
		t.Fatalf("private Docker config missing: %#v", environment)
	}
}

func TestPrepareDockerLoginFailureRemovesPrivateSession(t *testing.T) {
	parent := t.TempDir()
	ecrClient := &fakeECR{repositories: make(map[string]ecrtypes.Repository)}
	for _, spec := range FixedRepositories() {
		ecrClient.repositories[spec.Name] = validRepository(spec.Name)
	}
	preparer := newTestPreparer(t, validSTS(), ecrClient, &fakeRunner{err: errors.New("docker login failed with token")})
	preparer.newSession = func() (SessionV1, error) { return newDockerSessionIn(parent) }
	if _, err := preparer.Prepare(context.Background()); !errors.Is(err, ErrDockerLogin) {
		t.Fatalf("error = %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(parent, dockerSessionPrefix+"*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("failed login retained Docker credentials: %#v, %v", matches, err)
	}
}

func newTestPreparer(t *testing.T, stsClient *fakeSTS, ecrClient *fakeECR, runner *fakeRunner) *Preparer {
	t.Helper()
	preparer, err := New(validOptions(), Clients{Region: testRegion, STS: stsClient, ECR: ecrClient}, runner)
	if err != nil {
		t.Fatal(err)
	}
	return preparer
}

func prepareSuccess(t *testing.T, preparer *Preparer) PreparedV1 {
	t.Helper()
	prepared, err := preparer.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := CleanupSession(prepared.Session); err != nil {
			t.Errorf("cleanup Docker session: %v", err)
		}
	})
	return prepared
}

func validOptions() Options {
	return Options{Region: testRegion, ExpectedAccountID: testAccount, Now: func() time.Time { return testNow }}
}

func validSTS() *fakeSTS {
	return &fakeSTS{output: &sts.GetCallerIdentityOutput{
		Account: aws.String(testAccount), Arn: aws.String("arn:aws:iam::" + testAccount + ":role/release-publisher"), UserId: aws.String("AROATEST:release"),
	}}
}

func validRepository(name string) ecrtypes.Repository {
	return validRepositoryIn(name, testRegion)
}

func validRepositoryIn(name, region string) ecrtypes.Repository {
	host := registryHost(testAccount, region)
	return ecrtypes.Repository{
		RegistryId: aws.String(testAccount), RepositoryName: aws.String(name),
		RepositoryArn: aws.String("arn:aws:ecr:" + region + ":" + testAccount + ":repository/" + name),
		RepositoryUri: aws.String(host + "/" + name), ImageTagMutability: ecrtypes.ImageTagMutabilityImmutable,
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: true},
		EncryptionConfiguration:    &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeAes256},
	}
}

func validRepositoryTags(name string) []ecrtypes.Tag {
	artifact := map[string]string{
		RepositoryAgent: "agent", RepositoryWorker: "worker", RepositoryReaper: "reaper",
	}[name]
	return []ecrtypes.Tag{
		{Key: aws.String("managed_by"), Value: aws.String("dirextalk-agent")},
		{Key: aws.String("component"), Value: aws.String("release-registry")},
		{Key: aws.String("artifact"), Value: aws.String(artifact)},
		{Key: aws.String("retention"), Value: aws.String(ManagedRetention)},
	}
}

func equalRepositoryTags(left, right []ecrtypes.Tag) bool {
	if len(left) != len(right) {
		return false
	}
	want := make(map[string]string, len(right))
	for _, tag := range right {
		want[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	for _, tag := range left {
		if want[aws.ToString(tag.Key)] != aws.ToString(tag.Value) {
			return false
		}
		delete(want, aws.ToString(tag.Key))
	}
	return len(want) == 0
}

func registryHost(accountID, region string) string {
	return accountID + ".dkr.ecr." + region + ".amazonaws.com"
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

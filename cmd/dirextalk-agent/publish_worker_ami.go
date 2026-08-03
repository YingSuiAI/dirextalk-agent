package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/releaseprocess"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeramictl"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

const workerAMIPublishUsage = "usage: dirextalk-agent publish-worker-ami --owner-id <owner> --connection-id <uuid> --release-manifest <path> --rootfs-archive <path> --work-dir <path>"

var builderInstancePattern = regexp.MustCompile(
	`^[a-z][a-z0-9.]{1,31}$`,
)

type workerAMIPublishRequest struct {
	OwnerID            string
	ConnectionID       string
	ReleaseManifest    string
	RootFSArchive      string
	WorkDirectory      string
	BuilderInstance    string
	BuildTimeoutSecond int64
}

type workerAMIPublishScope struct {
	AccountID       string
	Region          string
	AgentInstanceID string
}

type closedWorkerAMIRunner func(
	context.Context,
	[]string,
	io.Writer,
	io.Writer,
	workeramictl.Dependencies,
) int

func publishWorkerAMI(arguments []string) error {
	request, err := parseWorkerAMIPublishRequest(arguments)
	if err != nil {
		return err
	}
	parent, stop := releaseprocess.Context()
	defer stop()
	ctx, cancel := context.WithTimeout(
		parent,
		time.Duration(request.BuildTimeoutSecond+900)*time.Second,
	)
	defer cancel()
	configuration, scope, err := loadWorkerAMIPublisherAWS(
		ctx,
		request.OwnerID,
		request.ConnectionID,
	)
	if err != nil {
		return errors.New("could not authorize Worker AMI publisher")
	}
	dependencies, err := workeramictl.DependenciesForConfig(
		configuration,
	)
	if err != nil {
		return errors.New("could not initialize Worker AMI publisher")
	}
	if err := runWorkerAMIPublish(
		ctx,
		request,
		scope,
		dependencies,
		workeramictl.Run,
		os.Stdout,
		os.Stderr,
	); err != nil {
		return err
	}
	return nil
}

func parseWorkerAMIPublishRequest(
	arguments []string,
) (workerAMIPublishRequest, error) {
	flags := flag.NewFlagSet(
		"publish-worker-ami",
		flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	ownerID := flags.String("owner-id", "", "connection owner")
	connectionID := flags.String(
		"connection-id",
		"",
		"active cloud connection",
	)
	releaseManifest := flags.String(
		"release-manifest",
		"",
		"Worker release manifest",
	)
	rootFSArchive := flags.String(
		"rootfs-archive",
		"",
		"deterministic Worker rootfs",
	)
	workDirectory := flags.String(
		"work-dir",
		"",
		"protected persistent output directory",
	)
	builderInstance := flags.String(
		"builder-instance-type",
		"t3.small",
		"fixed AMI builder shape",
	)
	timeoutSeconds := flags.Int64(
		"timeout-seconds",
		3600,
		"AMI build timeout",
	)
	if flags.Parse(arguments) != nil || flags.NArg() != 0 {
		return workerAMIPublishRequest{},
			errors.New(workerAMIPublishUsage)
	}
	request := workerAMIPublishRequest{
		OwnerID:            strings.TrimSpace(*ownerID),
		ConnectionID:       strings.TrimSpace(*connectionID),
		BuilderInstance:    strings.TrimSpace(*builderInstance),
		BuildTimeoutSecond: *timeoutSeconds,
	}
	request.ReleaseManifest, _ = resolveExistingRegularPath(
		*releaseManifest,
	)
	request.RootFSArchive, _ = resolveExistingRegularPath(
		*rootFSArchive,
	)
	request.WorkDirectory, _ = resolveProtectedDirectory(
		*workDirectory,
	)
	connectionUUID, connectionErr := uuid.Parse(
		request.ConnectionID,
	)
	if request.OwnerID == "" ||
		len(request.OwnerID) > 255 ||
		strings.ContainsAny(request.OwnerID, "\r\n\x00") ||
		connectionErr != nil ||
		connectionUUID == uuid.Nil ||
		connectionUUID.String() != request.ConnectionID ||
		!canonicalAbsolutePath(request.ReleaseManifest) ||
		!canonicalAbsolutePath(request.RootFSArchive) ||
		!canonicalAbsolutePath(request.WorkDirectory) ||
		!builderInstancePattern.MatchString(
			request.BuilderInstance,
		) ||
		request.BuildTimeoutSecond < 300 ||
		request.BuildTimeoutSecond > 7200 {
		return workerAMIPublishRequest{},
			errors.New(workerAMIPublishUsage)
	}
	return request, nil
}

func canonicalAbsolutePath(value string) bool {
	return value != "" &&
		filepath.IsAbs(value) &&
		filepath.Clean(value) == value
}

func resolveExistingRegularPath(value string) (string, error) {
	cleaned := filepath.Clean(value)
	if !canonicalAbsolutePath(cleaned) {
		return "", os.ErrInvalid
	}
	before, err := os.Lstat(cleaned)
	if err != nil ||
		before.Mode()&os.ModeSymlink != 0 ||
		!before.Mode().IsRegular() {
		return "", os.ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", os.ErrInvalid
	}
	resolved = filepath.Clean(resolved)
	after, err := os.Stat(resolved)
	if err != nil ||
		!after.Mode().IsRegular() ||
		!os.SameFile(before, after) {
		return "", os.ErrInvalid
	}
	return resolved, nil
}

func resolveProtectedDirectory(value string) (string, error) {
	cleaned := filepath.Clean(value)
	if !canonicalAbsolutePath(cleaned) {
		return "", os.ErrInvalid
	}
	before, err := os.Lstat(cleaned)
	if err != nil ||
		before.Mode()&os.ModeSymlink != 0 ||
		!before.IsDir() ||
		before.Mode().Perm()&0o022 != 0 {
		return "", os.ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", os.ErrInvalid
	}
	resolved = filepath.Clean(resolved)
	after, err := os.Stat(resolved)
	if err != nil ||
		!after.IsDir() ||
		after.Mode().Perm()&0o022 != 0 ||
		!os.SameFile(before, after) {
		return "", os.ErrInvalid
	}
	return resolved, nil
}

func loadWorkerAMIPublisherAWS(
	ctx context.Context,
	ownerID,
	connectionID string,
) (aws.Config, workerAMIPublishScope, error) {
	common, err := config.LoadCommon()
	if err != nil {
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	masterKeyPath := strings.TrimSpace(
		os.Getenv(awsfoundation.MasterKeyFileEnv),
	)
	masterKey, err := config.ReadKeyMaterial(masterKeyPath)
	if err != nil || len(masterKey) != 32 {
		clear(masterKey)
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	defer clear(masterKey)
	pool, err := postgres.Open(ctx, common.DatabaseURL)
	if err != nil {
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	defer pool.Close()
	if err := postgres.VerifySchema(
		ctx,
		pool,
		common.InstanceID,
	); err != nil {
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	store, err := postgres.New(pool, common.InstanceID)
	if err != nil {
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	connection, err := store.LoadConnection(
		ctx,
		ownerID,
		connectionID,
	)
	if err != nil ||
		connection.Status != "active" ||
		connection.Revision < 1 {
		return aws.Config{}, workerAMIPublishScope{},
			errors.New("active cloud connection is unavailable")
	}
	controlARN, err := arn.Parse(connection.ControlRoleARN)
	if err != nil ||
		controlARN.Service != "iam" ||
		controlARN.AccountID != connection.AccountID ||
		controlARN.Region != "" {
		return aws.Config{}, workerAMIPublishScope{},
			errors.New("cloud connection role is invalid")
	}
	foundation, err := awsfoundation.BuildSpec(
		awsfoundation.SpecInput{
			AgentInstanceID: common.InstanceID,
			Partition:       controlARN.Partition,
			AccountID:       connection.AccountID,
			Region:          connection.Region,
		},
	)
	expectedControlARN := fmt.Sprintf(
		"arn:%s:iam::%s:role/%s",
		controlARN.Partition,
		connection.AccountID,
		foundation.ControlRoleName,
	)
	stackARN, stackErr := arn.Parse(connection.FoundationStack)
	if err != nil ||
		connection.ControlRoleARN != expectedControlARN ||
		stackErr != nil ||
		stackARN.Partition != controlARN.Partition ||
		stackARN.Service != "cloudformation" ||
		stackARN.AccountID != connection.AccountID ||
		stackARN.Region != connection.Region ||
		!strings.HasPrefix(
			stackARN.Resource,
			"stack/"+foundation.StackName+"/",
		) {
		return aws.Config{}, workerAMIPublishScope{},
			errors.New("cloud connection binding is invalid")
	}
	vault, err := awsfoundation.NewCredentialVault(
		store.AWSCredentialStore(),
		masterKey,
		rand.Reader,
		time.Now,
	)
	if err != nil {
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	defer vault.Close()
	source, err := vault.Open(
		ctx,
		awsfoundation.SourceCredentialBinding{
			AgentInstanceID: common.InstanceID,
			AccountID:       connection.AccountID,
			Region:          connection.Region,
		},
	)
	if err != nil {
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	defer source.Wipe()
	sessionID := strings.ReplaceAll(uuid.NewString(), "-", "")
	configuration, err := awsprovider.AssumedControlAWSConfig(
		connection.Region,
		&source,
		connection.ControlRoleARN,
		"dtx-ami-"+sessionID[:16],
	)
	if err != nil {
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	if _, err := configuration.Credentials.Retrieve(ctx); err != nil {
		return aws.Config{}, workerAMIPublishScope{}, err
	}
	return configuration, workerAMIPublishScope{
		AccountID:       connection.AccountID,
		Region:          connection.Region,
		AgentInstanceID: common.InstanceID,
	}, nil
}

func runWorkerAMIPublish(
	ctx context.Context,
	request workerAMIPublishRequest,
	scope workerAMIPublishScope,
	dependencies workeramictl.Dependencies,
	runner closedWorkerAMIRunner,
	stdout,
	stderr io.Writer,
) error {
	if ctx == nil || runner == nil || stdout == nil || stderr == nil {
		return errors.New("Worker AMI publisher is unavailable")
	}
	buildRequestPath := filepath.Join(
		request.WorkDirectory,
		"build-request.json",
	)
	publicationPath := filepath.Join(
		request.WorkDirectory,
		"worker-ami-publication.json",
	)
	if _, err := os.Lstat(buildRequestPath); errors.Is(
		err,
		os.ErrNotExist,
	) {
		prepareArguments := []string{
			"prepare",
			"--account-id", scope.AccountID,
			"--region", scope.Region,
			"--agent-instance-id", scope.AgentInstanceID,
			"--release-manifest", request.ReleaseManifest,
			"--rootfs-archive", request.RootFSArchive,
			"--output", buildRequestPath,
			"--builder-instance-type", request.BuilderInstance,
			"--timeout-seconds",
			fmt.Sprintf("%d", request.BuildTimeoutSecond),
		}
		if runner(
			ctx,
			prepareArguments,
			stdout,
			stderr,
			dependencies,
		) != 0 {
			return errors.New(
				"Worker AMI preparation failed",
			)
		}
	} else if err != nil {
		return errors.New("Worker AMI recovery state is invalid")
	}
	if err := workeramictl.VerifyBuildRequestBinding(
		buildRequestPath,
		workeramictl.BuildRequestBinding{
			AccountID:           scope.AccountID,
			Region:              scope.Region,
			AgentInstanceID:     scope.AgentInstanceID,
			ReleaseManifestPath: request.ReleaseManifest,
			RootFSArchivePath:   request.RootFSArchive,
		},
	); err != nil {
		return errors.New("Worker AMI recovery scope changed")
	}
	if runner(
		ctx,
		[]string{
			"build",
			"--request", buildRequestPath,
			"--output", publicationPath,
		},
		stdout,
		stderr,
		dependencies,
	) != 0 {
		return errors.New("Worker AMI build failed")
	}
	if runner(
		ctx,
		[]string{
			"verify",
			"--manifest", publicationPath,
		},
		stdout,
		stderr,
		dependencies,
	) != 0 {
		return errors.New("Worker AMI verification failed")
	}
	if _, err := fmt.Fprintln(
		stdout,
		"worker_ami_publication=verified",
	); err != nil {
		return errors.New("Worker AMI output failed")
	}
	return nil
}

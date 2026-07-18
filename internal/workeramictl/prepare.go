package workeramictl

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
)

func runPrepare(ctx context.Context, args []string, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	accountID := flags.String("account-id", "", "expected AWS account")
	region := flags.String("region", "", "AWS region")
	agentInstanceID := flags.String("agent-instance-id", "", "Agent instance UUID")
	releasePath := flags.String("release-manifest", "", "immutable release manifest")
	rootFSPath := flags.String("rootfs-archive", "", "deterministic Worker rootfs archive")
	outputPath := flags.String("output", "", "new protected build-request v2")
	instanceType := flags.String("builder-instance-type", "t3.small", "fixed builder instance type")
	timeoutSeconds := flags.Int64("timeout-seconds", 3600, "build timeout")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !accountPattern.MatchString(*accountID) || !regionPattern.MatchString(*region) ||
		strings.TrimSpace(*agentInstanceID) == "" || !validLocalPath(*releasePath) || !validLocalPath(*rootFSPath) || !validLocalPath(*outputPath) ||
		strings.TrimSpace(*instanceType) == "" || *timeoutSeconds < 300 || *timeoutSeconds > 7200 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	releaseInput, err := readBoundedRegularFile(*releasePath, releaseartifact.MaxJSONBytes)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: invalid release inputs\n")
		return 1
	}
	releaseManifest, err := releaseartifact.ParseJSON(releaseInput)
	clear(releaseInput)
	if err != nil || releaseManifest.Architecture != "amd64" {
		_, _ = io.WriteString(stderr, "worker-ami: invalid release inputs\n")
		return 1
	}
	releaseDigest, err := releaseManifest.Digest()
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: invalid release inputs\n")
		return 1
	}
	rootFSManifest, err := inspectRootFSArchive(*rootFSPath, releaseManifest)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: invalid release inputs\n")
		return 1
	}
	config, err := loadAndConfirmIdentity(ctx, dependencies, *accountID, *region)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: AWS identity confirmation failed\n")
		return 1
	}
	resolver, err := dependencies.NewPrepareResolver(config)
	if err != nil || resolver == nil {
		_, _ = io.WriteString(stderr, "worker-ami: Foundation preparation failed\n")
		return 1
	}
	prepareCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	environment, err := resolver.Resolve(prepareCtx, PrepareEnvironmentRequestV2{AccountID: *accountID, Region: *region, AgentInstanceID: *agentInstanceID})
	cancel()
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: Foundation preparation failed\n")
		return 1
	}
	artifactKey := "worker-ami/releases/" + strings.TrimPrefix(releaseDigest, "sha256:") + "/" + strings.TrimPrefix(rootFSManifest.RootFSDigest, "sha256:") + ".tar"
	request := BuildRequestFileV2{
		SchemaVersion: BuildRequestSchemaV2, AccountID: *accountID, Region: *region, AgentInstanceID: *agentInstanceID,
		ReleaseManifestPath: *releasePath, ReleaseManifestDigest: releaseDigest, RootFSArchivePath: *rootFSPath,
		WorkerRootFSDigest: rootFSManifest.RootFSDigest, WorkerBinaryDigest: rootFSManifest.BinaryDigest, WorkerRootFSSize: rootFSManifest.Size,
		FoundationStackName: environment.FoundationStackName, FoundationStackID: environment.FoundationStackID, FoundationVPCID: environment.FoundationVPCID,
		FoundationRouteTableID: environment.FoundationRouteTableID, PrivateSubnetID: environment.PrivateSubnetID,
		ZeroIngressSecurityGroupID: environment.ZeroIngressSecurityGroupID, ArtifactBucket: environment.ArtifactBucket, ArtifactKey: artifactKey,
		ArtifactKMSKeyARN: environment.ArtifactKMSKeyARN, S3PrefixListID: environment.S3PrefixListID,
		BaseAMIID: environment.BaseAMIID, BaseAMIOwnerID: environment.BaseAMIOwnerID, BuilderInstanceType: *instanceType,
		RootDeviceName: environment.RootDeviceName, TimeoutSeconds: *timeoutSeconds, NetworkMode: workerami.NetworkModeS3GatewayV2,
	}
	if _, err := workerami.BuildDigest(buildRequestFromV2(request, releaseManifest, rootFSManifest)); err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: Foundation preparation failed\n")
		return 1
	}
	encoded, err := json.Marshal(request)
	if err != nil || writeExclusiveFile(*outputPath, encoded) != nil {
		_, _ = io.WriteString(stderr, "worker-ami: cannot persist build request\n")
		return 1
	}
	return 0
}

package workeramictl

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestVerifyBuildRequestBindingAcceptsOnlyExactV2Scope(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	requestPath := writeV2BuildRequestForFixture(t, fixture)
	binding := BuildRequestBinding{
		AccountID:           fixture.image.AccountID,
		Region:              fixture.image.Region,
		AgentInstanceID:     fixture.image.AgentInstanceID,
		ReleaseManifestPath: fixture.releasePath,
		RootFSArchivePath:   fixture.archivePath,
	}
	if err := VerifyBuildRequestBinding(requestPath, binding); err != nil {
		t.Fatalf("VerifyBuildRequestBinding() error = %v", err)
	}
	binding.AgentInstanceID = "substituted-agent"
	if err := VerifyBuildRequestBinding(requestPath, binding); err == nil {
		t.Fatal("substituted Agent identity was accepted")
	}
	if err := VerifyBuildRequestBinding(
		fixture.requestPath,
		BuildRequestBinding{
			AccountID:           fixture.image.AccountID,
			Region:              fixture.image.Region,
			AgentInstanceID:     fixture.image.AgentInstanceID,
			ReleaseManifestPath: fixture.releasePath,
			RootFSArchivePath:   fixture.archivePath,
		},
	); err == nil {
		t.Fatal("legacy v1 request was accepted by the bound publisher")
	}
}

func TestDependenciesForConfigPinsRegion(t *testing.T) {
	t.Parallel()
	configuration := aws.Config{
		Region: "ap-northeast-3",
		Credentials: aws.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider(
				"AKIAABCDEFGHIJKLMNOP",
				"test-secret-access-key-material",
				"",
			),
		),
	}
	dependencies, err := DependenciesForConfig(configuration)
	if err != nil {
		t.Fatalf("DependenciesForConfig() error = %v", err)
	}
	if _, err := dependencies.LoadConfig(
		t.Context(),
		configuration.Region,
	); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if _, err := dependencies.LoadConfig(
		t.Context(),
		"us-east-1",
	); err == nil {
		t.Fatal("cross-region configuration was accepted")
	}
}

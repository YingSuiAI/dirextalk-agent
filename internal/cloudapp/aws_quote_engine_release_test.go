package cloudapp

import (
	"context"
	"errors"
	"testing"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
)

type quoteReleaseResolver struct {
	release workerrelease.ReleaseV1
	err     error
	calls   int
}

func (resolver *quoteReleaseResolver) ResolveActiveWorkerRelease(_ context.Context, agentInstanceID, accountID, region string, architecture recipe.Architecture) (workerrelease.ReleaseV1, error) {
	resolver.calls++
	if resolver.err != nil {
		return workerrelease.ReleaseV1{}, resolver.err
	}
	return resolver.release, nil
}

func TestQuoteEngineBindsServerOwnedWorkerRelease(t *testing.T) {
	resolver := &quoteReleaseResolver{release: workerrelease.ReleaseV1{
		AgentInstanceID: testAgentID, AccountID: "123456789012", Region: "us-east-1", Architecture: recipe.ArchitectureAMD64,
		ImageID: "ami-0123456789abcdef0", ImageDigest: testCloudDigest("f"),
	}}
	engine := &AWSBootstrapQuoteEngine{agentInstanceID: testAgentID, releases: resolver}
	request := cloudquote.RequestV1{Scopes: []cloudquote.ScopeV1{
		{Resource: cloudquote.ResourceScopeV1{Region: "us-east-1", Architecture: recipe.ArchitectureAMD64, WorkerImageID: "ami-0fedcba9876543210", WorkerImageDigest: testCloudDigest("e")}},
		{Resource: cloudquote.ResourceScopeV1{Region: "us-east-1", Architecture: recipe.ArchitectureAMD64}},
	}}

	bound, err := engine.bindWorkerRelease(context.Background(), request, "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 {
		t.Fatalf("release resolver calls=%d, want one per Region/architecture", resolver.calls)
	}
	for index, scope := range bound.Scopes {
		if scope.Resource.WorkerImageID != resolver.release.ImageID || scope.Resource.WorkerImageDigest != resolver.release.ImageDigest {
			t.Fatalf("scope[%d] was not bound to server release: %#v", index, scope.Resource)
		}
	}
	if request.Scopes[0].Resource.WorkerImageID == resolver.release.ImageID {
		t.Fatal("binding mutated the caller request")
	}
}

func TestQuoteEngineFailsClosedWithoutMatchingWorkerRelease(t *testing.T) {
	resolver := &quoteReleaseResolver{err: workerrelease.ErrNotFound}
	engine := &AWSBootstrapQuoteEngine{agentInstanceID: testAgentID, releases: resolver}
	request := cloudquote.RequestV1{Scopes: []cloudquote.ScopeV1{{Resource: cloudquote.ResourceScopeV1{Region: "us-east-1", Architecture: recipe.ArchitectureAMD64}}}}
	if _, err := engine.bindWorkerRelease(context.Background(), request, "123456789012"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing release error=%v", err)
	}
}

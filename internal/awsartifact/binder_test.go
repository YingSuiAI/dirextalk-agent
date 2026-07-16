package awsartifact

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
)

const (
	testWorkerInstanceID = "i-0123456789abcdef0"
	testWorkerRoleID     = "AROATESTROLEIDENTIFIER"
)

func TestPrincipalBinderCreatesImmutableWorkerPolicyScopedArtifacts(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	recipeBytes := []byte("approved recipe")
	executionBytes := []byte(`{"schema_version":1,"actions":[{"kind":"worker.noop"}]}`)
	published, err := publisher.PublishBundles(context.Background(), connection, deploymentID, cloudexecution.CompiledBundles{RecipeBytes: recipeBytes, ExecutionBytes: executionBytes}, nil)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := NewPrincipalBinder(publisher.agentInstanceID, publisher.vault, factory)
	if err != nil {
		t.Fatal(err)
	}
	principalID := testWorkerRoleID + ":" + testWorkerInstanceID
	spec, err := publisher.foundationSpec(connection)
	if err != nil {
		t.Fatal(err)
	}
	targetRecipeKey := spec.ArtifactBucketName + "/workers/" + principalID + "/" + deploymentID + "/bundles/recipe.cbor"
	factory.client.lostResponse[targetRecipeKey] = true

	bound, err := binder.Bind(context.Background(), PrincipalBindRequest{
		Connection: connection, DeploymentID: deploymentID, InstanceID: testWorkerInstanceID,
		STSUserID: principalID, Published: published,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "s3://" + spec.ArtifactBucketName + "/workers/" + principalID + "/" + deploymentID + "/"
	if bound.Recipe.S3Ref != base+"bundles/recipe.cbor" || bound.Execution.S3Ref != base+"bundles/execution.json" ||
		bound.Recipe.SHA256 != published.Recipe.SHA256 || bound.Execution.SHA256 != published.Execution.SHA256 ||
		bound.ArtifactPrefix != base+"artifacts/" || bound.CheckpointPrefix != base+"checkpoints/" || bound.EvidencePrefix != base+"evidence/" ||
		bound.LogPrefix != "cloudwatch://"+spec.StackName+"/"+testWorkerRoleID+"/"+testWorkerInstanceID ||
		bound.CloudWatchLogGroup != spec.WorkerLogGroupName || bound.CloudWatchLogStream != testWorkerRoleID+"/"+testWorkerInstanceID {
		t.Fatalf("unexpected principal binding: %+v", bound)
	}
	if err := (worker.AccessScope{
		ArtifactPrefix: bound.ArtifactPrefix, CheckpointPrefix: bound.CheckpointPrefix,
		EvidencePrefix: bound.EvidencePrefix, LogPrefix: bound.LogPrefix, SecretRefs: []string{},
	}).Validate(); err != nil {
		t.Fatalf("binding cannot form Worker access scope: %v", err)
	}
	for _, suffix := range []string{"bundles/recipe.cbor", "bundles/execution.json"} {
		object, ok := factory.client.objects[spec.ArtifactBucketName+"/workers/"+principalID+"/"+deploymentID+"/"+suffix]
		if !ok || object.kmsKey != "alias/"+spec.StackName || !object.bucketKey || object.metadata["principal-id"] != principalID || object.metadata["deployment-id"] != deploymentID {
			t.Fatalf("unsafe target object %q: %#v", suffix, object)
		}
	}
	puts := factory.client.putCalls
	replayed, err := binder.Bind(context.Background(), PrincipalBindRequest{
		Connection: connection, DeploymentID: deploymentID, InstanceID: testWorkerInstanceID,
		STSUserID: principalID, Published: published,
	})
	if err != nil || replayed != bound || factory.client.putCalls != puts {
		t.Fatalf("idempotent replay binding=%+v puts=%d want=%d err=%v", replayed, factory.client.putCalls, puts, err)
	}
}

func TestPrincipalBinderRejectsUntrustedPrincipalAndSecretsBeforeAWS(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	published, err := publisher.PublishBundles(context.Background(), connection, deploymentID, cloudexecution.CompiledBundles{RecipeBytes: []byte("recipe"), ExecutionBytes: []byte(`{"safe":true}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := NewPrincipalBinder(publisher.agentInstanceID, publisher.vault, factory)
	if err != nil {
		t.Fatal(err)
	}
	factory.calls = 0
	puts := factory.client.putCalls
	tests := map[string]string{
		"wrong principal kind": "AIDATESTROLEIDENTIFIER:" + testWorkerInstanceID,
		"wrong instance":       testWorkerRoleID + ":i-0abcdef0123456789",
		"path injection":       testWorkerRoleID + ":" + testWorkerInstanceID + "/../../other",
		"extra session":        testWorkerRoleID + ":" + testWorkerInstanceID + ":other",
		"lowercase role id":    strings.ToLower(testWorkerRoleID) + ":" + testWorkerInstanceID,
	}
	for name, principalID := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := binder.Bind(context.Background(), PrincipalBindRequest{
				Connection: connection, DeploymentID: deploymentID, InstanceID: testWorkerInstanceID,
				STSUserID: principalID, Published: published,
			})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("principal %q error=%v", principalID, err)
			}
		})
	}
	unsafe := published
	unsafe.SecretBindings = map[string]string{"model": "secret://must-not-be-copied"}
	_, err = binder.Bind(context.Background(), PrincipalBindRequest{
		Connection: connection, DeploymentID: deploymentID, InstanceID: testWorkerInstanceID,
		STSUserID: testWorkerRoleID + ":" + testWorkerInstanceID, Published: unsafe,
	})
	if !errors.Is(err, ErrSecretReferencesUnsupported) {
		t.Fatalf("secret binding error=%v", err)
	}
	crossDeployment := published
	crossDeployment.Recipe.S3Ref = strings.Replace(crossDeployment.Recipe.S3Ref, deploymentID, "019b2d57-b3c0-7e65-a1d2-10c43de26799", 1)
	_, err = binder.Bind(context.Background(), PrincipalBindRequest{
		Connection: connection, DeploymentID: deploymentID, InstanceID: testWorkerInstanceID,
		STSUserID: testWorkerRoleID + ":" + testWorkerInstanceID, Published: crossDeployment,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("cross-deployment source error=%v", err)
	}
	if factory.calls != 0 || factory.client.putCalls != puts {
		t.Fatalf("rejected binding reached AWS: factory=%d puts=%d want=%d", factory.calls, factory.client.putCalls, puts)
	}
}

func TestPrincipalBinderVerifiesPublishedSourceDigestBeforeWriting(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	published, err := publisher.PublishBundles(context.Background(), connection, deploymentID, cloudexecution.CompiledBundles{RecipeBytes: []byte("recipe"), ExecutionBytes: []byte(`{"safe":true}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := NewPrincipalBinder(publisher.agentInstanceID, publisher.vault, factory)
	if err != nil {
		t.Fatal(err)
	}
	sourceKey := strings.TrimPrefix(published.Recipe.S3Ref, "s3://")
	object := factory.client.objects[sourceKey]
	object.payload[0] ^= 1
	factory.client.objects[sourceKey] = object
	puts := factory.client.putCalls

	_, err = binder.Bind(context.Background(), PrincipalBindRequest{
		Connection: connection, DeploymentID: deploymentID, InstanceID: testWorkerInstanceID,
		STSUserID: testWorkerRoleID + ":" + testWorkerInstanceID, Published: published,
	})
	if !errors.Is(err, ErrSourceIntegrity) || factory.client.putCalls != puts {
		t.Fatalf("tampered source error=%v puts=%d want=%d", err, factory.client.putCalls, puts)
	}
}

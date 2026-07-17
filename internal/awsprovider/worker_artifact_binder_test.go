package awsprovider

import (
	"context"
	"errors"
	"testing"

	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	artifactBindingAgentID     = "11111111-1111-4111-8111-111111111111"
	artifactBindingDeployment  = "22222222-2222-4222-8222-222222222222"
	artifactBindingRoleName    = "dtx-agent-test-worker"
	artifactBindingRoleID      = "AROATESTROLEIDENTIFIER"
	artifactBindingInstanceID  = "i-0123456789abcdef0"
	artifactBindingBucket      = "dtx-agent-artifacts"
	artifactBindingPrincipalID = artifactBindingRoleID + ":" + artifactBindingInstanceID
)

func TestWorkerArtifactBinderBindsExactVersionAndPreservesOwnedTags(t *testing.T) {
	source := testWorkerInstallerArtifact("service", "version-a")
	client := newArtifactTaggingFake(source)
	binder := newTestWorkerArtifactBinder(t, client)

	if err := binder.Bind(context.Background(), WorkerArtifactBindingRequest{
		InstanceID: artifactBindingInstanceID, RoleName: artifactBindingRoleName, DeploymentID: artifactBindingDeployment,
		Artifacts: []installerbootstrap.ArtifactSourceV1{source},
	}); err != nil {
		t.Fatal(err)
	}
	if client.getRoleName != artifactBindingRoleName || len(client.gets) != 2 || len(client.puts) != 1 {
		t.Fatalf("unexpected IAM/S3 calls: role=%q gets=%d puts=%d", client.getRoleName, len(client.gets), len(client.puts))
	}
	for _, input := range client.gets {
		if aws.ToString(input.Bucket) != source.Bucket || aws.ToString(input.Key) != source.Key || aws.ToString(input.VersionId) != source.VersionID {
			t.Fatalf("GetObjectTagging escaped the approved object version: %+v", input)
		}
	}
	put := client.puts[0]
	if aws.ToString(put.Bucket) != source.Bucket || aws.ToString(put.Key) != source.Key || aws.ToString(put.VersionId) != source.VersionID {
		t.Fatalf("PutObjectTagging escaped the approved object version: %+v", put)
	}
	tags := tagValues(put.Tagging.TagSet)
	if tags["dirextalk:worker_principal"] != artifactBindingPrincipalID || tags["dirextalk:agent_instance_id"] != artifactBindingAgentID ||
		tags["dirextalk:deployment_id"] != artifactBindingDeployment || tags["preserve"] != "yes" {
		t.Fatalf("binding did not preserve exact object tags: %#v", tags)
	}
}

func TestWorkerArtifactBinderRejectsAnotherWorkerAndMalformedOldTagWithoutOverwrite(t *testing.T) {
	for name, principal := range map[string]string{
		"other worker":  artifactBindingRoleID + ":i-0abcdef0123456789",
		"empty old tag": "",
	} {
		t.Run(name, func(t *testing.T) {
			source := testWorkerInstallerArtifact("service", "version-a")
			client := newArtifactTaggingFake(source)
			key := artifactTaggingKey(source.Bucket, source.Key, source.VersionID)
			client.tags[key] = append(client.tags[key], s3types.Tag{Key: aws.String("dirextalk:worker_principal"), Value: aws.String(principal)})
			binder := newTestWorkerArtifactBinder(t, client)

			err := binder.Bind(context.Background(), WorkerArtifactBindingRequest{
				InstanceID: artifactBindingInstanceID, RoleName: artifactBindingRoleName, DeploymentID: artifactBindingDeployment,
				Artifacts: []installerbootstrap.ArtifactSourceV1{source},
			})
			if !errors.Is(err, resource.ErrReadBack) || len(client.puts) != 0 {
				t.Fatalf("old worker binding was overwritten: err=%v puts=%d", err, len(client.puts))
			}
		})
	}
}

func TestWorkerArtifactBinderResumesPartialAndLostResponseWithoutRebindingActiveVersion(t *testing.T) {
	first := testWorkerInstallerArtifact("service", "version-a")
	second := testWorkerInstallerArtifact("helper", "version-b")
	client := newArtifactTaggingFake(first, second)
	// The first object is written successfully but the response is lost. The
	// binder must reconcile its exact tag read-back instead of writing again.
	client.putPersistThenError = map[string]error{artifactTaggingKey(first.Bucket, first.Key, first.VersionID): errors.New("response lost")}
	// The second write really fails once, leaving the first object bound. A
	// retry must retain that first binding and only write the remaining object.
	client.putFailNoPersist = map[string]error{artifactTaggingKey(second.Bucket, second.Key, second.VersionID): errors.New("temporary S3 outage")}
	binder := newTestWorkerArtifactBinder(t, client)
	request := WorkerArtifactBindingRequest{
		InstanceID: artifactBindingInstanceID, RoleName: artifactBindingRoleName, DeploymentID: artifactBindingDeployment,
		Artifacts: []installerbootstrap.ArtifactSourceV1{first, second},
	}
	if err := binder.Bind(context.Background(), request); !errors.Is(err, resource.ErrReadBack) {
		t.Fatalf("partial bind error = %v, want read-back failure", err)
	}
	if err := binder.Bind(context.Background(), request); err != nil {
		t.Fatalf("retry did not converge: %v", err)
	}
	firstWrites, secondWrites := 0, 0
	for _, input := range client.puts {
		switch aws.ToString(input.Key) {
		case first.Key:
			firstWrites++
		case second.Key:
			secondWrites++
		}
	}
	if firstWrites != 1 || secondWrites != 2 {
		t.Fatalf("partial retry rewrote a bound object or skipped recovery: first=%d second=%d", firstWrites, secondWrites)
	}
	for _, source := range []installerbootstrap.ArtifactSourceV1{first, second} {
		if tags := tagValues(client.tags[artifactTaggingKey(source.Bucket, source.Key, source.VersionID)]); tags["dirextalk:worker_principal"] != artifactBindingPrincipalID {
			t.Fatalf("artifact %s lacks exact final binding: %#v", source.Name, tags)
		}
	}
}

func newTestWorkerArtifactBinder(t *testing.T, client *artifactTaggingFake) *WorkerArtifactSessionBinder {
	t.Helper()
	binder, err := NewWorkerArtifactSessionBinder(client, client, artifactBindingAgentID, "aws", "123456789012", "ap-south-1", artifactBindingRoleName, artifactBindingBucket)
	if err != nil {
		t.Fatal(err)
	}
	return binder
}

func testWorkerInstallerArtifact(name, version string) installerbootstrap.ArtifactSourceV1 {
	return installerbootstrap.ArtifactSourceV1{
		SchemaVersion: installerbootstrap.ArtifactSourceSchemaV1, Name: name, Bucket: artifactBindingBucket,
		Key: "deployments/" + artifactBindingDeployment + "/artifacts/" + name, VersionID: version,
		KMSKeyARN: "arn:aws:kms:ap-south-1:123456789012:key/11111111-2222-4333-8444-555555555555",
		SHA256:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 1,
		TargetPath:   "/usr/local/share/dirextalk-worker/artifacts/" + name,
		RecipeDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
}

type artifactTaggingFake struct {
	role                *iam.GetRoleOutput
	getRoleName         string
	tags                map[string][]s3types.Tag
	gets                []*s3.GetObjectTaggingInput
	puts                []*s3.PutObjectTaggingInput
	putPersistThenError map[string]error
	putFailNoPersist    map[string]error
}

type workerArtifactBinderFake struct {
	requests []WorkerArtifactBindingRequest
	err      error
	onBind   func(WorkerArtifactBindingRequest)
}

func (fake *workerArtifactBinderFake) Bind(_ context.Context, request WorkerArtifactBindingRequest) error {
	fake.requests = append(fake.requests, request)
	if fake.onBind != nil {
		fake.onBind(request)
	}
	return fake.err
}

func newArtifactTaggingFake(sources ...installerbootstrap.ArtifactSourceV1) *artifactTaggingFake {
	client := &artifactTaggingFake{
		role: &iam.GetRoleOutput{Role: &iamtypes.Role{
			Arn: aws.String("arn:aws:iam::123456789012:role/" + artifactBindingRoleName), RoleId: aws.String(artifactBindingRoleID), RoleName: aws.String(artifactBindingRoleName),
		}},
		tags: map[string][]s3types.Tag{}, putPersistThenError: map[string]error{}, putFailNoPersist: map[string]error{},
	}
	for _, source := range sources {
		client.tags[artifactTaggingKey(source.Bucket, source.Key, source.VersionID)] = []s3types.Tag{
			{Key: aws.String("dirextalk:agent_instance_id"), Value: aws.String(artifactBindingAgentID)},
			{Key: aws.String("dirextalk:deployment_id"), Value: aws.String(artifactBindingDeployment)},
			{Key: aws.String("dirextalk:component"), Value: aws.String("installer-artifact")},
			{Key: aws.String("preserve"), Value: aws.String("yes")},
		}
	}
	return client
}

func (fake *artifactTaggingFake) GetRole(_ context.Context, input *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	fake.getRoleName = aws.ToString(input.RoleName)
	return fake.role, nil
}

func (fake *artifactTaggingFake) GetObjectTagging(_ context.Context, input *s3.GetObjectTaggingInput, _ ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
	fake.gets = append(fake.gets, input)
	key := artifactTaggingKey(aws.ToString(input.Bucket), aws.ToString(input.Key), aws.ToString(input.VersionId))
	return &s3.GetObjectTaggingOutput{VersionId: input.VersionId, TagSet: append([]s3types.Tag(nil), fake.tags[key]...)}, nil
}

func (fake *artifactTaggingFake) PutObjectTagging(_ context.Context, input *s3.PutObjectTaggingInput, _ ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error) {
	fake.puts = append(fake.puts, input)
	key := artifactTaggingKey(aws.ToString(input.Bucket), aws.ToString(input.Key), aws.ToString(input.VersionId))
	if err, ok := fake.putFailNoPersist[key]; ok {
		delete(fake.putFailNoPersist, key)
		return nil, err
	}
	fake.tags[key] = append([]s3types.Tag(nil), input.Tagging.TagSet...)
	if err, ok := fake.putPersistThenError[key]; ok {
		delete(fake.putPersistThenError, key)
		return nil, err
	}
	return &s3.PutObjectTaggingOutput{VersionId: input.VersionId}, nil
}

func artifactTaggingKey(bucket, key, version string) string {
	return bucket + "/" + key + "?" + version
}

func tagValues(tags []s3types.Tag) map[string]string {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		result[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return result
}

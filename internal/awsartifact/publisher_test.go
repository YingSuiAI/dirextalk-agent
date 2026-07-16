package awsartifact

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

type fakeS3Factory struct {
	client *fakeS3
	calls  int
	config aws.Config
}

func (factory *fakeS3Factory) New(config aws.Config) S3API {
	factory.calls++
	factory.config = config
	return factory.client
}

type storedObject struct {
	payload     []byte
	contentType string
	checksum    string
	kmsKey      string
	bucketKey   bool
	metadata    map[string]string
	tagging     string
}

type fakeS3 struct {
	objects         map[string]storedObject
	getCalls        int
	putCalls        int
	lostResponse    map[string]bool
	corruptReadback bool
}

func (fake *fakeS3) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	fake.getCalls++
	object, ok := fake.objects[aws.ToString(input.Bucket)+"/"+aws.ToString(input.Key)]
	if !ok {
		return nil, fakeAPIError{code: "NoSuchKey"}
	}
	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(append([]byte(nil), object.payload...))), ChecksumSHA256: &object.checksum,
		ContentLength: aws.Int64(int64(len(object.payload))), ContentType: &object.contentType,
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: &object.kmsKey,
		BucketKeyEnabled: aws.Bool(object.bucketKey), Metadata: cloneMetadata(object.metadata),
	}, nil
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: make(map[string]storedObject), lostResponse: make(map[string]bool)}
}

func (fake *fakeS3) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	object, ok := fake.objects[aws.ToString(input.Bucket)+"/"+aws.ToString(input.Key)]
	if !ok {
		return nil, fakeAPIError{code: "NotFound"}
	}
	kmsKey := object.kmsKey
	if fake.corruptReadback {
		kmsKey = ""
	}
	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(object.payload))), ContentType: &object.contentType,
		ChecksumSHA256: &object.checksum, ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId: &kmsKey, BucketKeyEnabled: aws.Bool(object.bucketKey), Metadata: cloneMetadata(object.metadata),
	}, nil
}

func (fake *fakeS3) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	fake.putCalls++
	key := aws.ToString(input.Bucket) + "/" + aws.ToString(input.Key)
	if _, exists := fake.objects[key]; exists {
		return nil, fakeAPIError{code: "PreconditionFailed"}
	}
	payload, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	if aws.ToString(input.IfNoneMatch) != "*" || input.ChecksumAlgorithm != s3types.ChecksumAlgorithmSha256 ||
		aws.ToString(input.ChecksumSHA256) != base64.StdEncoding.EncodeToString(digest[:]) ||
		input.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms || aws.ToString(input.SSEKMSKeyId) == "" || !aws.ToBool(input.BucketKeyEnabled) {
		return nil, errors.New("unsafe PutObject request")
	}
	fake.objects[key] = storedObject{
		payload: append([]byte(nil), payload...), contentType: aws.ToString(input.ContentType),
		checksum: aws.ToString(input.ChecksumSHA256), kmsKey: aws.ToString(input.SSEKMSKeyId),
		bucketKey: aws.ToBool(input.BucketKeyEnabled), metadata: cloneMetadata(input.Metadata), tagging: aws.ToString(input.Tagging),
	}
	if fake.lostResponse[key] {
		return nil, errors.New("response lost after durable write")
	}
	return &s3.PutObjectOutput{}, nil
}

func TestBundlePublisherUploadsEncryptedImmutableDeploymentArtifactsIdempotently(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	recipeBytes := []byte{0xa1, 0x64, 'n', 'a', 'm', 'e', 0x64, 't', 'e', 's', 't'}
	executionBytes := []byte(`{"schema_version":1,"actions":[{"kind":"worker.noop"}]}`)

	published, err := publisher.PublishBundles(context.Background(), connection, deploymentID, recipeBytes, executionBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if factory.calls != 1 || factory.config.Region != connection.Region || factory.config.Credentials == nil || factory.client.putCalls != 3 {
		t.Fatalf("factory calls=%d region=%s puts=%d", factory.calls, factory.config.Region, factory.client.putCalls)
	}
	prefix := "s3://" + bucketFromRef(published.Recipe.S3Ref) + "/deployments/" + deploymentID + "/"
	if published.Recipe.S3Ref != prefix+"bundles/recipe.cbor" || published.Execution.S3Ref != prefix+"bundles/execution.json" ||
		published.Access.ArtifactPrefix != prefix+"artifacts/" || published.Access.CheckpointPrefix != prefix+"checkpoints/" ||
		published.Access.EvidencePrefix != prefix+"evidence/" || len(published.Access.SecretRefs) != 0 || len(published.SecretBindings) != 0 {
		t.Fatalf("unexpected publication scope: %+v", published)
	}
	launchKey := strings.TrimPrefix(prefix, "s3://") + "launch/config.json"
	launch, ok := factory.client.objects[launchKey]
	if !ok || bytes.Contains(bytes.ToLower(launch.payload), []byte("enrollment")) || bytes.Contains(bytes.ToLower(launch.payload), []byte("secret")) ||
		!strings.Contains(launch.tagging, "dirextalk%3Adeployment_id=") {
		t.Fatalf("unsafe or missing launch config: key=%s payload=%s tags=%s", launchKey, launch.payload, launch.tagging)
	}
	firstPuts := factory.client.putCalls
	replayed, err := publisher.PublishBundles(context.Background(), connection, deploymentID, recipeBytes, executionBytes, []string{})
	if err != nil || replayed.Recipe != published.Recipe || replayed.Execution != published.Execution || factory.client.putCalls != firstPuts {
		t.Fatalf("idempotent replay failed: published=%+v puts=%d err=%v", replayed, factory.client.putCalls, err)
	}
}

func TestBundlePublisherFailsClosedBeforeAWSForSecretRefsOrSecretLikePayload(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	tests := []struct {
		name       string
		recipe     []byte
		secretRefs []string
		want       error
	}{
		{name: "service secret reference", recipe: []byte("safe recipe"), secretRefs: []string{"secret://deployment/model"}, want: ErrSecretReferencesUnsupported},
		{name: "secret-like recipe bytes", recipe: []byte("token=sk-abcdefghijklmnopqrstuvwxyz012345"), want: ErrSecretMaterial},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := publisher.PublishBundles(context.Background(), connection, deploymentID, test.recipe, []byte(`{"safe":true}`), test.secretRefs)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
	if factory.calls != 0 || factory.client.putCalls != 0 {
		t.Fatalf("AWS was reached for rejected secret input: factory=%d puts=%d", factory.calls, factory.client.putCalls)
	}
}

func TestBundlePublisherRejectsImmutableConflictAndRecoversLostPutResponse(t *testing.T) {
	t.Run("conflict", func(t *testing.T) {
		publisher, factory, connection, deploymentID := publisherFixture(t)
		if _, err := publisher.PublishBundles(context.Background(), connection, deploymentID, []byte("recipe-v1"), []byte(`{"v":1}`), nil); err != nil {
			t.Fatal(err)
		}
		puts := factory.client.putCalls
		if _, err := publisher.PublishBundles(context.Background(), connection, deploymentID, []byte("recipe-v2"), []byte(`{"v":1}`), nil); !errors.Is(err, ErrImmutableConflict) {
			t.Fatalf("conflict error=%v", err)
		}
		if factory.client.putCalls != puts {
			t.Fatalf("conflict performed a write: puts=%d before=%d", factory.client.putCalls, puts)
		}
	})

	t.Run("lost response", func(t *testing.T) {
		publisher, factory, connection, deploymentID := publisherFixture(t)
		spec, _ := publisher.foundationSpec(connection)
		key := spec.ArtifactBucketName + "/deployments/" + deploymentID + "/bundles/recipe.cbor"
		factory.client.lostResponse[key] = true
		if _, err := publisher.PublishBundles(context.Background(), connection, deploymentID, []byte("recipe"), []byte(`{"v":1}`), nil); err != nil {
			t.Fatalf("lost response was not reconciled: %v", err)
		}
		if factory.client.putCalls != 3 {
			t.Fatalf("unexpected put count: %d", factory.client.putCalls)
		}
	})
}

func TestBundlePublisherRequiresSSEKMSDigestReadBack(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	factory.client.corruptReadback = true
	if _, err := publisher.PublishBundles(context.Background(), connection, deploymentID, []byte("recipe"), []byte(`{"v":1}`), nil); !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatalf("corrupt read-back error=%v", err)
	}
}

func TestBundlePublisherRejectsConnectionOutsideDeterministicControlRole(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	tests := map[string]func(*cloudapp.Connection){
		"arbitrary role": func(value *cloudapp.Connection) {
			value.ControlRoleARN = "arn:aws:iam::123456789012:role/Admin"
		},
		"wrong account": func(value *cloudapp.Connection) {
			value.ControlRoleARN = strings.Replace(value.ControlRoleARN, "123456789012", "210987654321", 1)
		},
		"inactive": func(value *cloudapp.Connection) { value.Status = "destroying" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := connection
			mutate(&changed)
			if _, err := publisher.PublishBundles(context.Background(), changed, deploymentID, []byte("recipe"), []byte(`{"v":1}`), nil); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if factory.calls != 0 || factory.client.putCalls != 0 {
		t.Fatalf("invalid connection reached AWS: factory=%d puts=%d", factory.calls, factory.client.putCalls)
	}
}

func publisherFixture(t *testing.T) (*BundlePublisher, *fakeS3Factory, cloudapp.Connection, string) {
	t.Helper()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	agentID := uuid.NewString()
	binding := awsfoundation.SourceCredentialBinding{AgentInstanceID: agentID, AccountID: "123456789012", Region: "us-west-2"}
	vault, err := awsfoundation.NewCredentialVault(awsfoundation.NewMemoryCredentialStore(), bytes.Repeat([]byte{0x44}, 32), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vault.Close)
	credentials := awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("0123456789012345678901234567890123456789")}
	_, err = vault.SealAndStore(context.Background(), binding, 0, awsfoundation.AdminAuthorization{
		SessionID: uuid.NewString(), AccountID: binding.AccountID, Region: binding.Region,
		VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}, credentials)
	credentials.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: agentID, Partition: "aws", AccountID: binding.AccountID, Region: binding.Region})
	if err != nil {
		t.Fatal(err)
	}
	connection := cloudapp.Connection{
		ConnectionID: uuid.NewString(), OwnerID: "owner-1", AccountID: binding.AccountID, Region: binding.Region,
		ControlRoleARN:  "arn:aws:iam::" + binding.AccountID + ":role/" + spec.ControlRoleName,
		FoundationStack: "arn:aws:cloudformation:us-west-2:123456789012:stack/" + spec.StackName + "/fixture",
		Status:          "active", Revision: 1,
	}
	factory := &fakeS3Factory{client: newFakeS3()}
	publisher, err := NewBundlePublisher(agentID, vault, factory)
	if err != nil {
		t.Fatal(err)
	}
	return publisher, factory, connection, uuid.NewString()
}

func bucketFromRef(ref string) string {
	trimmed := strings.TrimPrefix(ref, "s3://")
	return strings.SplitN(trimmed, "/", 2)[0]
}

func cloneMetadata(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

type fakeAPIError struct{ code string }

func (err fakeAPIError) Error() string                 { return err.code }
func (err fakeAPIError) ErrorCode() string             { return err.code }
func (err fakeAPIError) ErrorMessage() string          { return err.code }
func (err fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

package cloudworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/google/uuid"
)

type artifactDownloadStoreFake struct {
	authority       ArtifactDownloadAuthority
	readErr         error
	revalidateErr   error
	readCalls       int
	revalidateCalls int
}

func (store *artifactDownloadStoreFake) ReadArtifactDownloadAuthority(_ context.Context, request ArtifactDownloadRequest, at time.Time) (ArtifactDownloadAuthority, error) {
	store.readCalls++
	if store.readErr != nil {
		return ArtifactDownloadAuthority{}, store.readErr
	}
	if store.authority.Retention.Identity.OwnerID != request.OwnerID ||
		store.authority.Retention.Identity.AccountGeneration != request.AccountGeneration ||
		store.authority.Retention.Identity.ArtifactID != request.ArtifactID || store.authority.ValidateAt(at) != nil {
		return ArtifactDownloadAuthority{}, ErrStaleAuthorization
	}
	return store.authority, nil
}

func (store *artifactDownloadStoreFake) RevalidateArtifactDownload(_ context.Context, expected ArtifactDownloadAuthority, at time.Time) error {
	store.revalidateCalls++
	if store.revalidateErr != nil {
		return store.revalidateErr
	}
	if !store.authority.Equal(expected) || store.authority.ValidateAt(at) != nil {
		return ErrStaleAuthorization
	}
	return nil
}

type artifactDownloadReaderFactoryFake struct {
	content []byte
	err     error
	calls   int
}

func (factory *artifactDownloadReaderFactoryFake) ReaderForArtifact(_ context.Context, authority ArtifactDownloadAuthority) (cloudresult.ObjectReader, error) {
	factory.calls++
	if factory.err != nil {
		return nil, factory.err
	}
	return artifactDownloadObjectReader{identity: authority.Retention.Identity, content: bytes.Clone(factory.content)}, nil
}

type artifactDownloadObjectReader struct {
	identity ArtifactRetentionIdentity
	content  []byte
}

func (reader artifactDownloadObjectReader) ReadObject(_ context.Context, request cloudresult.ObjectRequest) (cloudresult.ObjectRead, error) {
	claim := reader.identity.Claim
	if request.Bucket != claim.Bucket || request.Key != claim.Key || request.VersionID != claim.VersionID ||
		request.MaximumBytes != claim.SizeBytes {
		return cloudresult.ObjectRead{}, cloudresult.ErrInvalid
	}
	return cloudresult.ObjectRead{
		Bucket: claim.Bucket, Key: claim.Key, VersionID: claim.VersionID,
		SizeBytes: claim.SizeBytes, MediaType: claim.MediaType,
		Body: io.NopCloser(bytes.NewReader(reader.content)),
	}, nil
}

type artifactDownloadAWSFake struct {
	bindings []AWSBinding
	calls    int
}

func (resolver *artifactDownloadAWSFake) ResolveCurrentAWSBinding(context.Context) (AWSBinding, error) {
	return resolver.nextBinding()
}

func (resolver *artifactDownloadAWSFake) nextBinding() (AWSBinding, error) {
	resolver.calls++
	index := resolver.calls - 1
	if index >= len(resolver.bindings) {
		index = len(resolver.bindings) - 1
	}
	if index < 0 {
		return AWSBinding{}, ErrStaleAuthorization
	}
	return resolver.bindings[index], nil
}

func (resolver *artifactDownloadAWSFake) ResolveExactAWSBinding(_ context.Context, expected AWSBinding) (AWSBinding, error) {
	actual, err := resolver.nextBinding()
	if err != nil || actual != expected {
		return AWSBinding{}, errors.Join(ErrStaleAuthorization, err)
	}
	return actual, nil
}

func TestArtifactDownloadReadsAndVerifiesFullObjectBeforeReturningBoundedChunk(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	content := []byte("verified-cloud-worker-artifact")
	authority := artifactDownloadFixture(t, now, content)
	store := &artifactDownloadStoreFake{authority: authority}
	reader := &artifactDownloadReaderFactoryFake{content: content}
	aws := &artifactDownloadAWSFake{bindings: []AWSBinding{authority.Plan.AWS}}
	service, err := NewArtifactDownloadService(store, aws, reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := ArtifactDownloadRequest{
		OwnerID: authority.Plan.OwnerID, AccountGeneration: authority.Plan.AccountGeneration,
		ArtifactID: authority.Artifact.ArtifactID, OffsetBytes: 5, MaxChunkBytes: 7,
	}
	chunk, err := service.DownloadArtifact(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Data) != string(content[5:12]) || chunk.EOF || chunk.NextOffsetBytes != 12 ||
		chunk.ArtifactSHA256 != authority.Artifact.SHA256 || store.readCalls != 1 ||
		store.revalidateCalls != 1 || reader.calls != 1 || aws.calls != 2 || chunk.ValidateFor(request) != nil {
		t.Fatalf("chunk=%+v read=%d post=%d readers=%d aws=%d", chunk, store.readCalls, store.revalidateCalls, reader.calls, aws.calls)
	}
}

func TestArtifactDownloadFailsClosedAcrossCleanerAndCredentialRaces(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	content := []byte("verified-cloud-worker-artifact")
	authority := artifactDownloadFixture(t, now, content)
	request := ArtifactDownloadRequest{
		OwnerID: authority.Plan.OwnerID, AccountGeneration: authority.Plan.AccountGeneration,
		ArtifactID: authority.Artifact.ArtifactID, MaxChunkBytes: MaxArtifactDownloadChunkBytes,
	}

	t.Run("cleaner claims during read", func(t *testing.T) {
		store := &artifactDownloadStoreFake{authority: authority, revalidateErr: ErrStaleAuthorization}
		service, _ := NewArtifactDownloadService(store, &artifactDownloadAWSFake{bindings: []AWSBinding{authority.Plan.AWS}}, &artifactDownloadReaderFactoryFake{content: content}, func() time.Time { return now })
		if _, err := service.DownloadArtifact(context.Background(), request); !errors.Is(err, ErrStaleAuthorization) || store.revalidateCalls != 1 {
			t.Fatalf("err=%v post=%d", err, store.revalidateCalls)
		}
	})

	t.Run("retention expires during read", func(t *testing.T) {
		store := &artifactDownloadStoreFake{authority: authority}
		clocks := []time.Time{now, authority.Retention.Identity.ExpiresAt}
		index := 0
		service, _ := NewArtifactDownloadService(store, &artifactDownloadAWSFake{bindings: []AWSBinding{authority.Plan.AWS}}, &artifactDownloadReaderFactoryFake{content: content}, func() time.Time {
			value := clocks[index]
			if index < len(clocks)-1 {
				index++
			}
			return value
		})
		if _, err := service.DownloadArtifact(context.Background(), request); !errors.Is(err, ErrStaleAuthorization) {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("credential revision drifts after read", func(t *testing.T) {
		drifted := authority.Plan.AWS
		drifted.CredentialRevision++
		service, _ := NewArtifactDownloadService(&artifactDownloadStoreFake{authority: authority}, &artifactDownloadAWSFake{bindings: []AWSBinding{authority.Plan.AWS, drifted}}, &artifactDownloadReaderFactoryFake{content: content}, func() time.Time { return now })
		if _, err := service.DownloadArtifact(context.Background(), request); !errors.Is(err, ErrStaleAuthorization) {
			t.Fatalf("err=%v", err)
		}
	})
}

func artifactDownloadFixture(t *testing.T, now time.Time, content []byte) ArtifactDownloadAuthority {
	t.Helper()
	plan, execution, _, source := stagingFixture(t, now)
	_ = source.Body.Close()
	createdAt := now.Add(time.Minute).Truncate(time.Microsecond)
	claim := cloudresult.ObjectClaim{
		Name: cloudruntime.WorkspaceDeltaArtifactName, Bucket: plan.ArtifactGrant.Bucket,
		Key: plan.ArtifactGrant.KeyPrefix + cloudruntime.WorkspaceDeltaArtifactName, VersionID: "artifact-version-1",
		SHA256: digestBytesForTest(content), SizeBytes: int64(len(content)), MediaType: "application/gzip",
	}
	artifact := Artifact{
		ArtifactID: uuid.NewString(), ExecutionID: plan.ExecutionID, Kind: "archive",
		Name: claim.Name, MediaType: claim.MediaType, SizeBytes: uint64(claim.SizeBytes),
		SHA256: claim.SHA256, Status: ArtifactVerified, CreatedAt: createdAt,
	}
	identity := ArtifactRetentionIdentity{
		ArtifactID: artifact.ArtifactID, OwnerID: plan.OwnerID, AccountID: plan.AWS.AccountID,
		AccountGeneration: plan.AccountGeneration, Region: plan.AWS.Region,
		CredentialID: plan.AWS.CredentialID, CredentialRevision: plan.AWS.CredentialRevision,
		ProviderID: providerIDForCredential(plan.AWS), ExecutionID: plan.ExecutionID, PlanID: plan.PlanID,
		PlanDigest: plan.Digest, KeyPrefix: plan.ArtifactGrant.KeyPrefix, KMSKeyARN: plan.ArtifactGrant.KMSKeyARN,
		Claim: claim, ExpiresAt: createdAt.Add(time.Duration(plan.ArtifactGrant.RetentionSeconds) * time.Second),
	}
	record, err := NewArtifactRetentionRecord(identity, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := createdAt.Add(time.Second)
	execution.State, execution.Status, execution.Revision = StateSucceeded, StateSucceeded, 9
	execution.ProviderMutationStarted = true
	execution.Cleanup = CleanupSummary{
		VerifiedDestroyed: true, VerifiedAt: &verifiedAt,
		ResourcesTotal: expectedEphemeralAWSResourceCount(), ResourcesVerifiedDestroyed: expectedEphemeralAWSResourceCount(),
	}
	execution.ArtifactIDs = []string{artifact.ArtifactID}
	execution.UpdatedAt = verifiedAt
	if err = execution.Seal(); err != nil {
		t.Fatal(err)
	}
	authority := ArtifactDownloadAuthority{Plan: plan, Execution: execution, Artifact: artifact, Retention: record}
	if err = authority.ValidateAt(now); err != nil {
		t.Fatal(err)
	}
	return authority
}

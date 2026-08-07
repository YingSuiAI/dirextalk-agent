package cloudworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"

	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
)

const MaxArtifactDownloadChunkBytes uint64 = 512 << 10

// ArtifactDownloadRequest is the complete public read authority supplied for
// one bounded chunk. Offset zero is valid; every successful response contains
// at least one byte, so callers cannot probe past the immutable object size.
type ArtifactDownloadRequest struct {
	OwnerID           string
	AccountGeneration uint64
	ArtifactID        string
	OffsetBytes       uint64
	MaxChunkBytes     uint64
}

func (request ArtifactDownloadRequest) Validate() error {
	if strings.TrimSpace(request.OwnerID) == "" || request.OwnerID != strings.TrimSpace(request.OwnerID) ||
		request.AccountGeneration == 0 || !validUUID(request.ArtifactID) ||
		request.OffsetBytes >= MaxCloudWorkerOutputBytes || request.MaxChunkBytes == 0 ||
		request.MaxChunkBytes > MaxArtifactDownloadChunkBytes {
		return ErrInvalid
	}
	return nil
}

// ArtifactDownloadAuthority is a private, immutable snapshot read from one
// PostgreSQL transaction. It binds the public owner to the terminal execution,
// sealed Plan, verified artifact and exact retained S3 version.
type ArtifactDownloadAuthority struct {
	Plan      Plan
	Execution Execution
	Artifact  Artifact
	Retention ArtifactRetentionRecord
}

func (authority ArtifactDownloadAuthority) ValidateAt(at time.Time) error {
	at = at.UTC()
	plan, execution := authority.Plan, authority.Execution
	identity := authority.Retention.Identity
	if at.IsZero() || authority.Retention.Validate() != nil ||
		authority.Retention.State != ArtifactRetained || !identity.ExpiresAt.After(at) ||
		plan.Seal() != nil || execution.Seal() != nil ||
		execution.State != StateSucceeded || !execution.Cleanup.VerifiedDestroyed ||
		execution.OwnerID != plan.OwnerID || execution.AccountGeneration != plan.AccountGeneration ||
		execution.ExecutionID != plan.ExecutionID || execution.PlanID != plan.PlanID ||
		execution.PlanDigest != plan.Digest || execution.ExecutionDigest != plan.ExecutionDigest ||
		identity.OwnerID != plan.OwnerID || identity.AccountGeneration != plan.AccountGeneration ||
		identity.ExecutionID != plan.ExecutionID || identity.PlanID != plan.PlanID ||
		identity.PlanDigest != plan.Digest || identity.AccountID != plan.AWS.AccountID ||
		identity.Region != plan.AWS.Region || identity.CredentialID != plan.AWS.CredentialID ||
		identity.CredentialRevision != plan.AWS.CredentialRevision ||
		identity.Claim.Bucket != plan.ArtifactGrant.Bucket || identity.KeyPrefix != plan.ArtifactGrant.KeyPrefix ||
		identity.KMSKeyARN != plan.ArtifactGrant.KMSKeyARN ||
		authority.Artifact.Retention != nil || authority.Artifact.ArtifactID != identity.ArtifactID ||
		authority.Artifact.ExecutionID != identity.ExecutionID || authority.Artifact.Status != ArtifactVerified ||
		authority.Artifact.Name != identity.Claim.Name || authority.Artifact.MediaType != identity.Claim.MediaType ||
		authority.Artifact.SizeBytes != uint64(identity.Claim.SizeBytes) ||
		authority.Artifact.SHA256 != identity.Claim.SHA256 || !containsArtifactID(execution.ArtifactIDs, identity.ArtifactID) {
		return ErrStaleAuthorization
	}
	return nil
}

func (authority ArtifactDownloadAuthority) Equal(other ArtifactDownloadAuthority) bool {
	return reflect.DeepEqual(authority, other)
}

func containsArtifactID(values []string, expected string) bool {
	found := false
	for _, value := range values {
		if value != expected {
			continue
		}
		if found {
			return false
		}
		found = true
	}
	return found
}

// ArtifactDownloadAuthorityStore performs the before/after PostgreSQL
// retention CAS. Implementations must compare the complete snapshot and exact
// retention revision after the external read; they must never extend expiry.
type ArtifactDownloadAuthorityStore interface {
	ReadArtifactDownloadAuthority(context.Context, ArtifactDownloadRequest, time.Time) (ArtifactDownloadAuthority, error)
	RevalidateArtifactDownload(context.Context, ArtifactDownloadAuthority, time.Time) error
}

// ArtifactDownloadReaderFactory returns a reader bound to the exact private
// retention identity. The reader must verify account, Region, bucket owner,
// bucket/key/version, KMS identity and object metadata before yielding bytes.
type ArtifactDownloadReaderFactory interface {
	ReaderForArtifact(context.Context, ArtifactDownloadAuthority) (cloudresult.ObjectReader, error)
}

type ArtifactDownloadChunk struct {
	OwnerID           string
	AccountGeneration uint64
	ArtifactID        string
	ExecutionID       string
	OffsetBytes       uint64
	Data              []byte
	ChunkSHA256       string
	ArtifactSHA256    string
	SizeBytes         uint64
	NextOffsetBytes   uint64
	EOF               bool
}

func (chunk ArtifactDownloadChunk) ValidateFor(request ArtifactDownloadRequest) error {
	if request.Validate() != nil || chunk.OwnerID != request.OwnerID ||
		chunk.AccountGeneration != request.AccountGeneration || chunk.ArtifactID != request.ArtifactID ||
		!validUUID(chunk.ExecutionID) || chunk.OffsetBytes != request.OffsetBytes || len(chunk.Data) == 0 ||
		uint64(len(chunk.Data)) > request.MaxChunkBytes || chunk.SizeBytes == 0 ||
		chunk.SizeBytes > MaxCloudWorkerOutputBytes || !validDigest(chunk.ChunkSHA256) ||
		!validDigest(chunk.ArtifactSHA256) || chunk.NextOffsetBytes <= chunk.OffsetBytes ||
		chunk.NextOffsetBytes > chunk.SizeBytes || chunk.NextOffsetBytes-chunk.OffsetBytes != uint64(len(chunk.Data)) ||
		chunk.EOF != (chunk.NextOffsetBytes == chunk.SizeBytes) {
		return ErrInvalid
	}
	digest := sha256.Sum256(chunk.Data)
	if hex.EncodeToString(digest[:]) != chunk.ChunkSHA256 {
		return ErrInvalid
	}
	return nil
}

type ArtifactDownloadService struct {
	store   ArtifactDownloadAuthorityStore
	aws     ExactAWSBindingResolver
	readers ArtifactDownloadReaderFactory
	now     func() time.Time
}

func NewArtifactDownloadService(
	store ArtifactDownloadAuthorityStore,
	aws ExactAWSBindingResolver,
	readers ArtifactDownloadReaderFactory,
	clocks ...func() time.Time,
) (*ArtifactDownloadService, error) {
	if store == nil || aws == nil || readers == nil {
		return nil, ErrInvalid
	}
	clock := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &ArtifactDownloadService{store: store, aws: aws, readers: readers, now: clock}, nil
}

func (service *ArtifactDownloadService) DownloadArtifact(ctx context.Context, request ArtifactDownloadRequest) (ArtifactDownloadChunk, error) {
	if service == nil || ctx == nil || service.store == nil || service.aws == nil || service.readers == nil ||
		request.Validate() != nil {
		return ArtifactDownloadChunk{}, ErrInvalid
	}
	beforeAt := service.now().UTC()
	authority, err := service.store.ReadArtifactDownloadAuthority(ctx, request, beforeAt)
	if err != nil || authority.ValidateAt(beforeAt) != nil || authority.Artifact.ArtifactID != request.ArtifactID ||
		authority.Plan.OwnerID != request.OwnerID || authority.Plan.AccountGeneration != request.AccountGeneration ||
		request.OffsetBytes >= authority.Artifact.SizeBytes {
		return ArtifactDownloadChunk{}, errorsJoinStale(err)
	}
	if err = service.revalidateAWS(ctx, authority.Retention.Identity); err != nil {
		return ArtifactDownloadChunk{}, err
	}
	reader, err := service.readers.ReaderForArtifact(ctx, authority)
	if err != nil || reader == nil {
		return ArtifactDownloadChunk{}, errorsJoinStale(err)
	}
	identity := authority.Retention.Identity
	verifier, err := cloudresult.NewVerifier(reader, cloudresult.Scope{Bucket: identity.Claim.Bucket, KeyPrefix: identity.KeyPrefix})
	if err != nil {
		return ArtifactDownloadChunk{}, ErrStaleAuthorization
	}
	object, err := verifier.Verify(ctx, identity.Claim)
	if err != nil {
		return ArtifactDownloadChunk{}, err
	}
	defer object.Destroy()
	afterAt := service.now().UTC()
	if err = service.store.RevalidateArtifactDownload(ctx, authority, afterAt); err != nil {
		return ArtifactDownloadChunk{}, errorsJoinStale(err)
	}
	if err = service.revalidateAWS(ctx, identity); err != nil {
		return ArtifactDownloadChunk{}, err
	}
	remaining := authority.Artifact.SizeBytes - request.OffsetBytes
	length := request.MaxChunkBytes
	if remaining < length {
		length = remaining
	}
	data := append([]byte(nil), object.Content[request.OffsetBytes:request.OffsetBytes+length]...)
	chunkDigest := sha256.Sum256(data)
	chunk := ArtifactDownloadChunk{
		OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration,
		ArtifactID: request.ArtifactID, ExecutionID: authority.Artifact.ExecutionID,
		OffsetBytes: request.OffsetBytes, Data: data, ChunkSHA256: hex.EncodeToString(chunkDigest[:]),
		ArtifactSHA256: authority.Artifact.SHA256, SizeBytes: authority.Artifact.SizeBytes,
		NextOffsetBytes: request.OffsetBytes + length,
	}
	chunk.EOF = chunk.NextOffsetBytes == chunk.SizeBytes
	if chunk.ValidateFor(request) != nil {
		clear(data)
		return ArtifactDownloadChunk{}, ErrInvalid
	}
	return chunk, nil
}

func (service *ArtifactDownloadService) revalidateAWS(ctx context.Context, identity ArtifactRetentionIdentity) error {
	expected := AWSBinding{AccountID: identity.AccountID, Region: identity.Region,
		CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision}
	binding, err := service.aws.ResolveExactAWSBinding(ctx, expected)
	if err != nil || binding.AccountID != identity.AccountID || binding.Region != identity.Region ||
		binding.CredentialID != identity.CredentialID || binding.CredentialRevision != identity.CredentialRevision {
		return errorsJoinStale(err)
	}
	return nil
}

func errorsJoinStale(err error) error {
	if err == nil {
		return ErrStaleAuthorization
	}
	return errors.Join(ErrStaleAuthorization, err)
}

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

type PutObject struct {
	Name      string
	Bucket    string
	Key       string
	SHA256    string
	SizeBytes int64
	MediaType string
	Content   []byte
}

type VersionedObjectWriter interface {
	Put(context.Context, Binding, cloudresult.Scope, PutObject) (cloudresult.ObjectClaim, error)
}

type ManifestUploader struct {
	objects VersionedObjectWriter
	now     func() time.Time
}

func NewManifestUploader(objects VersionedObjectWriter) (*ManifestUploader, error) {
	return newManifestUploader(objects, func() time.Time { return time.Now().UTC() })
}

func newManifestUploader(
	objects VersionedObjectWriter,
	now func() time.Time,
) (*ManifestUploader, error) {
	if objects == nil || now == nil {
		return nil, ErrInvalid
	}
	return &ManifestUploader{objects: objects, now: now}, nil
}

func (uploader *ManifestUploader) Upload(
	ctx context.Context,
	claimed ClaimedTask,
	runtimeResult cloudruntime.Result,
) (cloudresult.ObjectClaim, error) {
	if uploader == nil || ctx == nil ||
		validateClaimedTask(claimed, claimed.Binding, uploader.now().UTC()) != nil ||
		runtimeResult.ValidateFor(claimed.Task.WorkspaceMode) != nil {
		return cloudresult.ObjectClaim{}, ErrInvalid
	}
	claims := make([]cloudresult.ObjectClaim, 0, len(runtimeResult.Artifacts))
	for _, artifact := range runtimeResult.Artifacts {
		digest, err := artifact.Digest()
		if err != nil {
			return cloudresult.ObjectClaim{}, ErrInvalid
		}
		key, err := artifactKey(
			claimed.ArtifactScope.KeyPrefix,
			claimed.Binding.Attempt,
			claimed.Binding.LeaseEpoch,
			artifact.Name,
			digest,
		)
		if err != nil {
			return cloudresult.ObjectClaim{}, err
		}
		spec := PutObject{
			Name: artifact.Name, Bucket: claimed.ArtifactScope.Bucket, Key: key,
			SHA256: digest, SizeBytes: int64(len(artifact.Content)),
			MediaType: artifact.MediaType, Content: artifact.Content,
		}
		claim, err := uploader.objects.Put(
			ctx, claimed.Binding, claimed.ArtifactScope, spec,
		)
		if err != nil {
			return cloudresult.ObjectClaim{}, err
		}
		if !claimMatchesPut(claim, spec) || !claimed.ArtifactScope.Contains(claim) {
			return cloudresult.ObjectClaim{}, ErrInvalid
		}
		claims = append(claims, claim)
	}
	manifest := cloudresult.Manifest{
		SchemaVersion:   cloudresult.ManifestSchemaV1,
		ExecutionID:     claimed.Binding.ExecutionID,
		ExecutionSHA256: claimed.Binding.ExecutionSHA256,
		TaskID:          claimed.Binding.TaskID, TaskSHA256: claimed.Binding.TaskSHA256,
		SessionID: claimed.SessionID,
		Attempt:   int32(claimed.Binding.Attempt), LeaseEpoch: int64(claimed.Binding.LeaseEpoch),
		Adapter:       cloudruntime.AdapterPiJSONTaskV1,
		WorkspaceMode: claimed.Task.WorkspaceMode,
		Status:        "succeeded", Usage: runtimeResult.Usage, Artifacts: claims,
	}
	expectation := cloudresult.Expectation{
		ExecutionID:     claimed.Binding.ExecutionID,
		ExecutionSHA256: claimed.Binding.ExecutionSHA256,
		TaskID:          claimed.Binding.TaskID, TaskSHA256: claimed.Binding.TaskSHA256,
		SessionID: claimed.SessionID,
		Attempt:   int32(claimed.Binding.Attempt), LeaseEpoch: int64(claimed.Binding.LeaseEpoch),
		WorkspaceMode: claimed.Task.WorkspaceMode,
	}
	if manifest.Validate(expectation, claimed.ArtifactScope) != nil {
		return cloudresult.ObjectClaim{}, ErrInvalid
	}
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) == 0 || len(raw) > cloudresult.MaxManifestBytes {
		clear(raw)
		return cloudresult.ObjectClaim{}, ErrInvalid
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	digestText := hex.EncodeToString(digest[:])
	manifestKey := fmt.Sprintf(
		"%sresult-a%d-e%d-%s.json",
		claimed.ArtifactScope.KeyPrefix,
		claimed.Binding.Attempt,
		claimed.Binding.LeaseEpoch,
		digestText,
	)
	spec := PutObject{
		Name: "result.json", Bucket: claimed.ArtifactScope.Bucket, Key: manifestKey,
		SHA256: digestText, SizeBytes: int64(len(raw)),
		MediaType: "application/json", Content: raw,
	}
	claim, err := uploader.objects.Put(
		ctx, claimed.Binding, claimed.ArtifactScope, spec,
	)
	if err != nil {
		return cloudresult.ObjectClaim{}, err
	}
	if !claimMatchesPut(claim, spec) || !claimed.ArtifactScope.Contains(claim) {
		return cloudresult.ObjectClaim{}, ErrInvalid
	}
	return claim, nil
}

func artifactKey(prefix string, attempt uint32, epoch uint64, name, digest string) (string, error) {
	if prefix == "" || !strings.HasSuffix(prefix, "/") || attempt == 0 || epoch == 0 ||
		!validDigest(digest) {
		return "", ErrInvalid
	}
	extension := ""
	switch name {
	case "final.json":
		extension = "json"
	case "changes.patch":
		extension = "patch"
	case cloudruntime.WorkspaceDeltaArtifactName:
		extension = "tar.gz"
	default:
		return "", ErrInvalid
	}
	nameDigest := sha256.Sum256([]byte(name))
	return fmt.Sprintf(
		"%sruntime-a%d-e%d-%s-%s.%s",
		prefix, attempt, epoch, hex.EncodeToString(nameDigest[:8]), digest, extension,
	), nil
}

func claimMatchesPut(claim cloudresult.ObjectClaim, spec PutObject) bool {
	return claim.Validate() == nil && claim.Name == spec.Name &&
		claim.Bucket == spec.Bucket && claim.Key == spec.Key &&
		claim.SHA256 == spec.SHA256 && claim.SizeBytes == spec.SizeBytes &&
		claim.MediaType == spec.MediaType
}

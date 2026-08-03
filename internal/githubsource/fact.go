package githubsource

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

const (
	ArtifactSchemaV1 = "dirextalk.agent.github-source-artifact/v1"
	FactSchemaV1     = "dirextalk.agent.github-source-fact/v1"

	SourceArtifactProvider  = "aws_s3"
	SourceArtifactMediaType = "application/x-tar"
)

var bucketNamePattern = regexp.MustCompile(
	`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`,
)

// ArtifactV1 identifies one immutable, KMS-encrypted source object in the
// approved AWS connection. The object is never exposed to a Worker directly.
type ArtifactV1 struct {
	SchemaVersion      string `json:"schema_version"`
	Provider           string `json:"provider"`
	ConnectionID       string `json:"connection_id"`
	InputID            string `json:"input_id"`
	InputDigest        string `json:"input_digest"`
	InputBindingDigest string `json:"input_binding_digest"`
	SourceDigest       string `json:"source_digest"`
	WorkspaceDigest    string `json:"workspace_digest"`
	SizeBytes          int64  `json:"size_bytes"`
	MediaType          string `json:"media_type"`
	Bucket             string `json:"bucket"`
	Key                string `json:"key"`
	VersionID          string `json:"version_id"`
}

func NewArtifactV1(
	snapshot SnapshotV1,
	connectionID,
	bucket,
	versionID string,
) (ArtifactV1, error) {
	artifact := ArtifactV1{
		SchemaVersion:      ArtifactSchemaV1,
		Provider:           SourceArtifactProvider,
		ConnectionID:       connectionID,
		InputID:            snapshot.InputID,
		InputDigest:        snapshot.InputDigest,
		InputBindingDigest: snapshot.InputBindingDigest,
		SourceDigest:       snapshot.SourceDigest,
		WorkspaceDigest:    snapshot.WorkspaceDigest,
		SizeBytes:          snapshot.SizeBytes,
		MediaType:          SourceArtifactMediaType,
		Bucket:             bucket,
		Key:                ArtifactKey(snapshot),
		VersionID:          versionID,
	}
	if artifact.Validate() != nil {
		return ArtifactV1{}, ErrInvalid
	}
	return artifact, nil
}

func (artifact ArtifactV1) Validate() error {
	connectionID, connectionErr := uuid.Parse(artifact.ConnectionID)
	inputID, inputErr := uuid.Parse(artifact.InputID)
	if artifact.SchemaVersion != ArtifactSchemaV1 ||
		artifact.Provider != SourceArtifactProvider ||
		connectionErr != nil ||
		connectionID == uuid.Nil ||
		connectionID.String() != artifact.ConnectionID ||
		inputErr != nil ||
		inputID == uuid.Nil ||
		inputID.String() != artifact.InputID ||
		!digestPattern.MatchString(artifact.InputDigest) ||
		!digestPattern.MatchString(artifact.InputBindingDigest) ||
		!digestPattern.MatchString(artifact.SourceDigest) ||
		!digestPattern.MatchString(artifact.WorkspaceDigest) ||
		artifact.SizeBytes < 1 ||
		artifact.SizeBytes > maximumCompressedBytes ||
		artifact.MediaType != SourceArtifactMediaType ||
		!validBucketName(artifact.Bucket) ||
		artifact.Key != artifactKey(
			artifact.InputID,
			artifact.WorkspaceDigest,
		) ||
		!validOpaqueVersionID(artifact.VersionID) {
		return ErrInvalid
	}
	return nil
}

func ArtifactKey(snapshot SnapshotV1) string {
	if snapshot.Validate() != nil {
		return ""
	}
	return artifactKey(snapshot.InputID, snapshot.WorkspaceDigest)
}

func artifactKey(inputID, workspaceDigest string) string {
	if _, err := uuid.Parse(inputID); err != nil ||
		!digestPattern.MatchString(workspaceDigest) {
		return ""
	}
	return "source-snapshots/github/" +
		inputID + "/" +
		strings.TrimPrefix(workspaceDigest, "sha256:") +
		".tar"
}

// FactV1 is the immutable relationship between an approved GitHub source and
// the exact encrypted artifact used by every role in one AWS connection.
type FactV1 struct {
	SchemaVersion string     `json:"schema_version"`
	SnapshotID    string     `json:"snapshot_id"`
	ConnectionID  string     `json:"connection_id"`
	Snapshot      SnapshotV1 `json:"snapshot"`
	Artifact      ArtifactV1 `json:"artifact"`
}

func NewFactV1(
	snapshot SnapshotV1,
	artifact ArtifactV1,
) (FactV1, error) {
	connectionID, err := uuid.Parse(artifact.ConnectionID)
	if err != nil || connectionID == uuid.Nil {
		return FactV1{}, ErrInvalid
	}
	inputID, err := uuid.Parse(snapshot.InputID)
	if err != nil || inputID == uuid.Nil {
		return FactV1{}, ErrInvalid
	}
	fact := FactV1{
		SchemaVersion: FactSchemaV1,
		SnapshotID: uuid.NewSHA1(
			inputID,
			[]byte(
				"github-source-fact/v1\x00"+
					connectionID.String(),
			),
		).String(),
		ConnectionID: connectionID.String(),
		Snapshot:     snapshot,
		Artifact:     artifact,
	}
	if fact.Validate() != nil {
		return FactV1{}, ErrInvalid
	}
	return fact, nil
}

func (fact FactV1) Validate() error {
	connectionID, connectionErr := uuid.Parse(fact.ConnectionID)
	inputID, inputErr := uuid.Parse(fact.Snapshot.InputID)
	if fact.SchemaVersion != FactSchemaV1 ||
		connectionErr != nil ||
		connectionID == uuid.Nil ||
		connectionID.String() != fact.ConnectionID ||
		inputErr != nil ||
		inputID == uuid.Nil ||
		fact.Snapshot.Validate() != nil ||
		fact.Artifact.Validate() != nil {
		return ErrInvalid
	}
	expectedID := uuid.NewSHA1(
		inputID,
		[]byte(
			"github-source-fact/v1\x00"+
				connectionID.String(),
		),
	).String()
	if fact.SnapshotID != expectedID ||
		fact.Artifact.ConnectionID != fact.ConnectionID ||
		fact.Artifact.InputID != fact.Snapshot.InputID ||
		fact.Artifact.InputDigest != fact.Snapshot.InputDigest ||
		fact.Artifact.InputBindingDigest !=
			fact.Snapshot.InputBindingDigest ||
		fact.Artifact.SourceDigest != fact.Snapshot.SourceDigest ||
		fact.Artifact.WorkspaceDigest != fact.Snapshot.WorkspaceDigest ||
		fact.Artifact.SizeBytes != fact.Snapshot.SizeBytes {
		return ErrInvalid
	}
	return nil
}

func (fact FactV1) Digest() (string, error) {
	if fact.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(fact)
}

type StoredFact struct {
	Fact       FactV1
	FactDigest string
	CreatedAt  time.Time
}

func (stored StoredFact) Validate() error {
	digest, err := stored.Fact.Digest()
	if err != nil ||
		stored.FactDigest != digest ||
		stored.CreatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type LookupKey struct {
	InputID      string
	InputDigest  string
	ConnectionID string
}

func (key LookupKey) Validate() error {
	inputID, inputErr := uuid.Parse(key.InputID)
	connectionID, connectionErr := uuid.Parse(key.ConnectionID)
	if inputErr != nil ||
		inputID == uuid.Nil ||
		inputID.String() != key.InputID ||
		!digestPattern.MatchString(key.InputDigest) ||
		connectionErr != nil ||
		connectionID == uuid.Nil ||
		connectionID.String() != key.ConnectionID {
		return ErrInvalid
	}
	return nil
}

type Repository interface {
	FindGitHubSourceSnapshot(
		context.Context,
		LookupKey,
	) (StoredFact, bool, error)
	PersistGitHubSourceSnapshot(
		context.Context,
		FactV1,
	) (StoredFact, error)
}

func validBucketName(value string) bool {
	return bucketNamePattern.MatchString(value) &&
		!strings.Contains(value, "..") &&
		!strings.Contains(value, ".-") &&
		!strings.Contains(value, "-.")
}

func validOpaqueVersionID(value string) bool {
	if value == "" ||
		value != strings.TrimSpace(value) ||
		len(value) > 1024 ||
		!utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

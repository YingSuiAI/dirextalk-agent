// Package taskinput defines immutable, task-bound input snapshots used by
// Team Plans. It contains no storage coordinate, URL, or filesystem path.
package taskinput

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

const (
	SnapshotSchemaV1    = "dirextalk.agent.task-input-snapshot/v1"
	WorkspaceMediaType  = "application/x-tar"
	MaxWorkspaceBytes   = 1 << 30
	emptySnapshotDomain = "task-input-snapshot/v1\x00empty"
)

var (
	ErrInvalid     = errors.New("invalid task input snapshot")
	digestPattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	emptyWorkspace = mustEmptyWorkspace()
)

// SnapshotV1 binds one immutable workspace archive to an owner, Task, and
// exact goal. Storage coordinates are deliberately excluded.
type SnapshotV1 struct {
	SchemaVersion      string `json:"schema_version"`
	SnapshotID         string `json:"snapshot_id"`
	OwnerID            string `json:"owner_id"`
	TaskID             string `json:"task_id"`
	GoalDigest         string `json:"goal_digest"`
	WorkspaceDigest    string `json:"workspace_digest"`
	WorkspaceSizeBytes int64  `json:"workspace_size_bytes"`
	WorkspaceMediaType string `json:"workspace_media_type"`
}

// BindingV1 is the signed, de-secreted projection carried by Team Plan and
// Team Execution. SnapshotDigest authenticates the complete SnapshotV1.
type BindingV1 struct {
	SnapshotID         string `json:"snapshot_id"`
	SnapshotDigest     string `json:"snapshot_digest"`
	WorkspaceDigest    string `json:"workspace_digest"`
	WorkspaceSizeBytes int64  `json:"workspace_size_bytes"`
	WorkspaceMediaType string `json:"workspace_media_type"`
}

func New(
	ownerID,
	taskID,
	goalDigest,
	workspaceDigest string,
	workspaceSizeBytes int64,
) (SnapshotV1, error) {
	taskUUID, err := uuid.Parse(taskID)
	if err != nil || taskUUID == uuid.Nil ||
		taskUUID.String() != taskID {
		return SnapshotV1{}, ErrInvalid
	}
	snapshot := SnapshotV1{
		SchemaVersion: SnapshotSchemaV1,
		SnapshotID: uuid.NewSHA1(
			taskUUID,
			[]byte(
				"task-input-snapshot/v1\x00"+
					workspaceDigest,
			),
		).String(),
		OwnerID:            ownerID,
		TaskID:             taskID,
		GoalDigest:         goalDigest,
		WorkspaceDigest:    workspaceDigest,
		WorkspaceSizeBytes: workspaceSizeBytes,
		WorkspaceMediaType: WorkspaceMediaType,
	}
	if snapshot.Validate() != nil {
		return SnapshotV1{}, ErrInvalid
	}
	return snapshot, nil
}

func NewEmpty(
	ownerID,
	taskID,
	goalDigest string,
) (SnapshotV1, error) {
	return New(
		ownerID,
		taskID,
		goalDigest,
		emptyWorkspace.digest,
		int64(len(emptyWorkspace.content)),
	)
}

func (snapshot SnapshotV1) Validate() error {
	if snapshot.SchemaVersion != SnapshotSchemaV1 ||
		!canonicalUUID(snapshot.SnapshotID) ||
		!validOwnerID(snapshot.OwnerID) ||
		!canonicalUUID(snapshot.TaskID) ||
		!digestPattern.MatchString(snapshot.GoalDigest) ||
		!digestPattern.MatchString(snapshot.WorkspaceDigest) ||
		snapshot.WorkspaceSizeBytes < 1 ||
		snapshot.WorkspaceSizeBytes > MaxWorkspaceBytes ||
		snapshot.WorkspaceMediaType != WorkspaceMediaType {
		return ErrInvalid
	}
	taskUUID := uuid.MustParse(snapshot.TaskID)
	expectedID := uuid.NewSHA1(
		taskUUID,
		[]byte(
			"task-input-snapshot/v1\x00"+
				snapshot.WorkspaceDigest,
		),
	).String()
	if snapshot.SnapshotID != expectedID {
		return ErrInvalid
	}
	return nil
}

func (snapshot SnapshotV1) Digest() (string, error) {
	if snapshot.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(snapshot)
}

func (snapshot SnapshotV1) Binding() (BindingV1, error) {
	digest, err := snapshot.Digest()
	if err != nil {
		return BindingV1{}, err
	}
	binding := BindingV1{
		SnapshotID:         snapshot.SnapshotID,
		SnapshotDigest:     digest,
		WorkspaceDigest:    snapshot.WorkspaceDigest,
		WorkspaceSizeBytes: snapshot.WorkspaceSizeBytes,
		WorkspaceMediaType: snapshot.WorkspaceMediaType,
	}
	if binding.Validate() != nil {
		return BindingV1{}, ErrInvalid
	}
	return binding, nil
}

func (binding BindingV1) Validate() error {
	if !canonicalUUID(binding.SnapshotID) ||
		!digestPattern.MatchString(binding.SnapshotDigest) ||
		!digestPattern.MatchString(binding.WorkspaceDigest) ||
		binding.WorkspaceSizeBytes < 1 ||
		binding.WorkspaceSizeBytes > MaxWorkspaceBytes ||
		binding.WorkspaceMediaType != WorkspaceMediaType {
		return ErrInvalid
	}
	return nil
}

func (binding BindingV1) Matches(snapshot SnapshotV1) bool {
	actual, err := snapshot.Binding()
	return err == nil && actual == binding
}

func EmptyWorkspace() ([]byte, string) {
	return bytes.Clone(emptyWorkspace.content), emptyWorkspace.digest
}

func IsEmpty(binding BindingV1) bool {
	return binding.Validate() == nil &&
		binding.WorkspaceDigest == emptyWorkspace.digest &&
		binding.WorkspaceSizeBytes == int64(len(emptyWorkspace.content))
}

type emptyWorkspaceValue struct {
	content []byte
	digest  string
}

func mustEmptyWorkspace() emptyWorkspaceValue {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.Close(); err != nil || buffer.Len() == 0 {
		panic("create canonical empty task workspace")
	}
	content := bytes.Clone(buffer.Bytes())
	digest := sha256.Sum256(content)
	return emptyWorkspaceValue{
		content: content,
		digest:  "sha256:" + hex.EncodeToString(digest[:]),
	}
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil &&
		parsed.String() == value
}

func validOwnerID(value string) bool {
	if value != strings.TrimSpace(value) ||
		value == "" ||
		len(value) > 255 ||
		!utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return len(value) <= math.MaxUint8
}

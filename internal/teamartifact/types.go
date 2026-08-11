// Package teamartifact defines immutable, verified Worker deliverables that
// remain available after the temporary Worker resources are destroyed.
package teamartifact

import (
	"context"
	"errors"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/artifactmedia"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const SchemaV1 = "dirextalk.agent.team-artifact/v1"

const (
	MaximumArtifactsPerRole = 32
	MaximumArtifactBytes    = int64(8 << 20)
)

type Kind string

const (
	KindResult Kind = "result"
	KindPatch  Kind = "patch"
	KindFile   Kind = "file"
)

type VerificationState string

const VerificationPassed VerificationState = "passed"

var (
	ErrInvalid      = errors.New("invalid Team artifact")
	ErrNotFound     = errors.New("Team artifact was not found")
	ErrFactMismatch = errors.New("Team artifact fact mismatch")

	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	roleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

// ArtifactV1 stores the exact object binding internally. Public projections
// omit ObjectRef and ConnectionID and expose only verification metadata.
type ArtifactV1 struct {
	SchemaVersion    string            `json:"schema_version"`
	ArtifactID       string            `json:"artifact_id"`
	AgentInstanceID  string            `json:"agent_instance_id"`
	OwnerID          string            `json:"owner_id"`
	ExecutionID      string            `json:"execution_id"`
	OperationID      string            `json:"operation_id"`
	TaskID           string            `json:"task_id"`
	PlanID           string            `json:"plan_id"`
	PlanRevision     uint64            `json:"plan_revision"`
	ConnectionID     string            `json:"connection_id"`
	RoleID           string            `json:"role_id"`
	ActionID         string            `json:"action_id"`
	DeploymentID     string            `json:"deployment_id"`
	Name             string            `json:"name"`
	Kind             Kind              `json:"kind"`
	MediaType        string            `json:"media_type"`
	SizeBytes        int64             `json:"size_bytes"`
	SHA256           string            `json:"sha256"`
	ObjectRef        string            `json:"object_ref"`
	Verification     VerificationState `json:"verification"`
	CreatedAt        time.Time         `json:"created_at"`
	RetentionExpires time.Time         `json:"retention_expires_at"`
}

func (value ArtifactV1) Validate() error {
	for _, candidate := range []string{
		value.ArtifactID,
		value.AgentInstanceID,
		value.ExecutionID,
		value.OperationID,
		value.TaskID,
		value.PlanID,
		value.ConnectionID,
		value.DeploymentID,
	} {
		if !canonicalUUID(candidate) {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != SchemaV1 ||
		!validOwnerID(value.OwnerID) ||
		value.PlanRevision == 0 ||
		value.PlanRevision > uint64(math.MaxInt64) ||
		!roleIDPattern.MatchString(value.RoleID) ||
		!actionPattern.MatchString(value.ActionID) ||
		!namePattern.MatchString(value.Name) ||
		!validKind(value.Kind, value.Name) ||
		!validMediaType(value.MediaType) ||
		value.SizeBytes < 1 ||
		value.SizeBytes > MaximumArtifactBytes ||
		!digestPattern.MatchString(value.SHA256) ||
		!validS3Object(value.ObjectRef) ||
		value.Verification != VerificationPassed ||
		!utcMicrosecond(value.CreatedAt) ||
		!utcMicrosecond(value.RetentionExpires) ||
		!value.RetentionExpires.After(value.CreatedAt) ||
		value.RetentionExpires.After(value.CreatedAt.Add(366*24*time.Hour)) ||
		security.ContainsLikelySecret(value.Name) {
		return ErrInvalid
	}
	return nil
}

type BuildRequest struct {
	AgentInstanceID  string
	OwnerID          string
	ExecutionID      string
	OperationID      string
	TaskID           string
	PlanID           string
	PlanRevision     uint64
	ConnectionID     string
	RoleID           string
	ActionID         string
	DeploymentID     string
	Name             string
	MediaType        string
	SizeBytes        int64
	SHA256           string
	ObjectRef        string
	CreatedAt        time.Time
	RetentionExpires time.Time
}

func NewVerified(request BuildRequest) (ArtifactV1, error) {
	namespace, err := uuid.Parse(request.AgentInstanceID)
	if err != nil || namespace == uuid.Nil {
		return ArtifactV1{}, ErrInvalid
	}
	createdAt := request.CreatedAt.UTC().Truncate(time.Microsecond)
	retentionExpires := request.RetentionExpires.UTC().Truncate(time.Microsecond)
	identity := strings.Join([]string{
		SchemaV1,
		request.ExecutionID,
		request.RoleID,
		request.ActionID,
		request.Name,
		request.SHA256,
	}, "\x00")
	artifact := ArtifactV1{
		SchemaVersion:    SchemaV1,
		ArtifactID:       uuid.NewSHA1(namespace, []byte(identity)).String(),
		AgentInstanceID:  request.AgentInstanceID,
		OwnerID:          request.OwnerID,
		ExecutionID:      request.ExecutionID,
		OperationID:      request.OperationID,
		TaskID:           request.TaskID,
		PlanID:           request.PlanID,
		PlanRevision:     request.PlanRevision,
		ConnectionID:     request.ConnectionID,
		RoleID:           request.RoleID,
		ActionID:         request.ActionID,
		DeploymentID:     request.DeploymentID,
		Name:             request.Name,
		Kind:             kindForName(request.Name),
		MediaType:        request.MediaType,
		SizeBytes:        request.SizeBytes,
		SHA256:           request.SHA256,
		ObjectRef:        request.ObjectRef,
		Verification:     VerificationPassed,
		CreatedAt:        createdAt,
		RetentionExpires: retentionExpires,
	}
	if artifact.Validate() != nil {
		return ArtifactV1{}, ErrInvalid
	}
	return artifact, nil
}

type Reader interface {
	ListTeamArtifacts(
		context.Context,
		string,
		string,
	) ([]ArtifactV1, error)
	GetTeamArtifact(
		context.Context,
		string,
		string,
	) (ArtifactV1, error)
}

func kindForName(name string) Kind {
	switch name {
	case "final.json":
		return KindResult
	case "changes.patch":
		return KindPatch
	default:
		return KindFile
	}
}

func validKind(kind Kind, name string) bool {
	return kind == kindForName(name)
}

func validMediaType(value string) bool {
	return artifactmedia.Supported(value)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validOwnerID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 255
}

func validS3Object(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil &&
		value == strings.TrimSpace(value) &&
		len(value) <= 2048 &&
		parsed.Scheme == "s3" &&
		parsed.Host != "" &&
		parsed.Path != "" &&
		!strings.HasSuffix(parsed.Path, "/") &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		!strings.ContainsAny(value, "*?#") &&
		!security.ContainsLikelySecret(value)
}

func utcMicrosecond(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Nanosecond()%1000 == 0
}

// Package teamresult defines the durable, secret-free evidence retained after
// a temporary Team Worker result has been independently verified.
package teamresult

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

const SchemaV1 = "dirextalk.agent.team-role-result/v1"

const (
	maxFinals        = 8
	maxFinalList     = 64
	maxFinalTextSize = 8 << 10
	maxResultSize    = 8 << 20
)

var (
	ErrInvalid = errors.New("invalid Team role result evidence")

	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	roleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

type FinalV1 struct {
	ActionID          string                `json:"action_id"`
	Adapter           workerruntime.Adapter `json:"adapter"`
	Usage             workerruntime.Usage   `json:"usage"`
	Status            string                `json:"status"`
	Summary           string                `json:"summary"`
	Deliverables      []string              `json:"deliverables"`
	Tests             []string              `json:"tests"`
	Risks             []string              `json:"risks"`
	ArtifactRef       string                `json:"artifact_ref"`
	ArtifactSHA256    string                `json:"artifact_sha256"`
	ArtifactSizeBytes int64                 `json:"artifact_size_bytes"`
	ArtifactMediaType string                `json:"artifact_media_type"`
}

func (value FinalV1) Validate() error {
	if !actionPattern.MatchString(value.ActionID) ||
		!value.Adapter.IsSupported() ||
		value.Usage.Validate() != nil ||
		(value.Status != "completed" &&
			value.Status != "partial" &&
			value.Status != "blocked") ||
		!validText(value.Summary) ||
		!validList(value.Deliverables) ||
		!validList(value.Tests) ||
		!validList(value.Risks) ||
		!validS3Object(value.ArtifactRef) ||
		!digestPattern.MatchString(value.ArtifactSHA256) ||
		value.ArtifactSizeBytes < 1 ||
		value.ArtifactSizeBytes > workerruntime.MaxFinalArtifactBytes ||
		value.ArtifactMediaType != "application/json" {
		return ErrInvalid
	}
	return nil
}

// EvidenceV1 deliberately stores only verified object coordinates, digests,
// bounded summaries, and token counters. Raw Worker output stays in the
// deployment-scoped object store.
type EvidenceV1 struct {
	SchemaVersion    string    `json:"schema_version"`
	OperationID      string    `json:"operation_id"`
	ExecutionID      string    `json:"execution_id"`
	RoleID           string    `json:"role_id"`
	DeploymentID     string    `json:"deployment_id"`
	ExpectedWorkerID string    `json:"expected_worker_id"`
	TaskID           string    `json:"task_id"`
	TaskStepID       string    `json:"task_step_id"`
	WorkerID         string    `json:"worker_id"`
	Attempt          int32     `json:"attempt"`
	LeaseEpoch       int64     `json:"lease_epoch"`
	ResultRef        string    `json:"result_ref"`
	ResultSHA256     string    `json:"result_sha256"`
	ResultSizeBytes  int64     `json:"result_size_bytes"`
	ResultMediaType  string    `json:"result_media_type"`
	Finals           []FinalV1 `json:"finals"`
}

func (value EvidenceV1) Validate() error {
	for _, candidate := range []string{
		value.OperationID,
		value.ExecutionID,
		value.DeploymentID,
		value.ExpectedWorkerID,
		value.TaskID,
		value.TaskStepID,
		value.WorkerID,
	} {
		if !canonicalUUID(candidate) {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != SchemaV1 ||
		!roleIDPattern.MatchString(value.RoleID) ||
		value.WorkerID != value.ExpectedWorkerID ||
		value.Attempt < 1 ||
		value.LeaseEpoch < 1 ||
		!validS3Object(value.ResultRef) ||
		!digestPattern.MatchString(value.ResultSHA256) ||
		value.ResultSizeBytes < 1 ||
		value.ResultSizeBytes > maxResultSize ||
		value.ResultMediaType != "application/json" ||
		len(value.Finals) == 0 ||
		len(value.Finals) > maxFinals {
		return ErrInvalid
	}
	seenActions := make(map[string]struct{}, len(value.Finals))
	seenArtifacts := make(map[string]struct{}, len(value.Finals))
	for _, final := range value.Finals {
		if final.Validate() != nil ||
			final.ArtifactRef == value.ResultRef {
			return ErrInvalid
		}
		if _, duplicate := seenActions[final.ActionID]; duplicate {
			return ErrInvalid
		}
		if _, duplicate := seenArtifacts[final.ArtifactRef]; duplicate {
			return ErrInvalid
		}
		seenActions[final.ActionID] = struct{}{}
		seenArtifacts[final.ArtifactRef] = struct{}{}
	}
	return nil
}

func (value EvidenceV1) Digest() (string, error) {
	if value.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(value)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == value
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

func validList(values []string) bool {
	if values == nil || len(values) > maxFinalList {
		return false
	}
	for _, value := range values {
		if !validText(value) {
			return false
		}
	}
	return true
}

func validText(value string) bool {
	if value == "" ||
		value != strings.TrimSpace(value) ||
		len(value) > maxFinalTextSize ||
		!utf8.ValidString(value) ||
		security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) &&
			character != '\n' &&
			character != '\r' &&
			character != '\t' {
			return false
		}
	}
	return true
}

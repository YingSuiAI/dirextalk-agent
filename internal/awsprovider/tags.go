package awsprovider

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	TagAgentInstanceID = "dirextalk:agent_instance_id"
	TagOwnerID         = "dirextalk:owner_id"
	TagTaskID          = "dirextalk:task_id"
	TagDeploymentID    = "dirextalk:deployment_id"
	TagRetention       = "dirextalk:retention"
	TagDestroyDeadline = "dirextalk:destroy_deadline"

	RetentionEphemeral  = "ephemeral"
	RetentionManaged    = "managed"
	DestroyDeadlineNone = "none"
)

var (
	ErrInvalidOwnership = errors.New("invalid AWS resource ownership")
	tagIdentifier       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+=-]{0,127}$`)
)

type Tag struct {
	Key   string
	Value string
}

type ResourceOwnership struct {
	AgentInstanceID string
	OwnerID         string
	TaskID          string
	DeploymentID    string
	Retention       string
	DestroyDeadline time.Time
}

// BuildOwnershipTags is the only supported ownership-tag constructor. Typed
// mutation adapters must reject resources that did not pass through it.
func BuildOwnershipTags(value ResourceOwnership) ([]Tag, error) {
	for _, item := range []string{value.AgentInstanceID, value.OwnerID, value.TaskID, value.DeploymentID} {
		if !tagIdentifier.MatchString(item) || strings.HasPrefix(strings.ToLower(item), "aws:") {
			return nil, ErrInvalidOwnership
		}
	}
	deadline := DestroyDeadlineNone
	switch value.Retention {
	case RetentionEphemeral:
		if value.DestroyDeadline.IsZero() {
			return nil, ErrInvalidOwnership
		}
		deadline = value.DestroyDeadline.UTC().Truncate(time.Second).Format(time.RFC3339)
	case RetentionManaged:
		if !value.DestroyDeadline.IsZero() {
			return nil, ErrInvalidOwnership
		}
	default:
		return nil, ErrInvalidOwnership
	}
	tags := []Tag{
		{Key: TagAgentInstanceID, Value: value.AgentInstanceID},
		{Key: TagOwnerID, Value: value.OwnerID},
		{Key: TagTaskID, Value: value.TaskID},
		{Key: TagDeploymentID, Value: value.DeploymentID},
		{Key: TagRetention, Value: value.Retention},
		{Key: TagDestroyDeadline, Value: deadline},
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].Key < tags[j].Key })
	return tags, nil
}

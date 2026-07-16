package awsprovider

import (
	"errors"
	"testing"
	"time"
)

func TestOwnershipTagsAreCompleteDeterministicAndValidated(t *testing.T) {
	deadline := time.Date(2026, 7, 16, 12, 30, 0, 0, time.UTC)
	tags, err := BuildOwnershipTags(ResourceOwnership{
		AgentInstanceID: "019f5e2d-5350-7073-87d9-3ba4fdbc6818",
		OwnerID:         "project-owner-01",
		TaskID:          "019f5e2d-5350-7073-87d9-3ba4fdbc6819",
		DeploymentID:    "019f5e2d-5350-7073-87d9-3ba4fdbc6820",
		Retention:       RetentionEphemeral,
		DestroyDeadline: deadline,
	})
	if err != nil {
		t.Fatalf("build tags: %v", err)
	}
	want := []Tag{
		{Key: TagAgentInstanceID, Value: "019f5e2d-5350-7073-87d9-3ba4fdbc6818"},
		{Key: TagDeploymentID, Value: "019f5e2d-5350-7073-87d9-3ba4fdbc6820"},
		{Key: TagDestroyDeadline, Value: "2026-07-16T12:30:00Z"},
		{Key: TagOwnerID, Value: "project-owner-01"},
		{Key: TagRetention, Value: "ephemeral"},
		{Key: TagTaskID, Value: "019f5e2d-5350-7073-87d9-3ba4fdbc6819"},
	}
	if len(tags) != len(want) {
		t.Fatalf("tags = %#v", tags)
	}
	for index := range want {
		if tags[index] != want[index] {
			t.Fatalf("tag[%d] = %#v, want %#v", index, tags[index], want[index])
		}
	}
}

func TestOwnershipTagsFailClosedForMissingOrManagedDeadline(t *testing.T) {
	base := ResourceOwnership{
		AgentInstanceID: "019f5e2d-5350-7073-87d9-3ba4fdbc6818",
		OwnerID:         "owner",
		TaskID:          "019f5e2d-5350-7073-87d9-3ba4fdbc6819",
		DeploymentID:    "019f5e2d-5350-7073-87d9-3ba4fdbc6820",
		Retention:       RetentionEphemeral,
		DestroyDeadline: time.Now().UTC().Add(time.Hour),
	}
	tests := map[string]ResourceOwnership{
		"missing owner":       func() ResourceOwnership { value := base; value.OwnerID = ""; return value }(),
		"missing deployment":  func() ResourceOwnership { value := base; value.DeploymentID = ""; return value }(),
		"missing deadline":    func() ResourceOwnership { value := base; value.DestroyDeadline = time.Time{}; return value }(),
		"managed with expiry": func() ResourceOwnership { value := base; value.Retention = RetentionManaged; return value }(),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildOwnershipTags(value); !errors.Is(err, ErrInvalidOwnership) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	base.Retention = RetentionManaged
	base.DestroyDeadline = time.Time{}
	tags, err := BuildOwnershipTags(base)
	if err != nil {
		t.Fatalf("managed tags: %v", err)
	}
	if value := tagValue(tags, TagDestroyDeadline); value != DestroyDeadlineNone {
		t.Fatalf("managed deadline = %q", value)
	}
}

func tagValue(tags []Tag, key string) string {
	for _, tag := range tags {
		if tag.Key == key {
			return tag.Value
		}
	}
	return ""
}

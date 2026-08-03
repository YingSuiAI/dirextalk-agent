package taskinput

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestInputV2BindsEmptyWorkspaceDeterministically(t *testing.T) {
	t.Parallel()
	taskID := uuid.NewString()
	goalDigest := "sha256:" + strings.Repeat("1", 64)
	first, err := NewEmptyInput("owner-a", taskID, goalDigest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEmptyInput("owner-a", taskID, goalDigest)
	if err != nil {
		t.Fatal(err)
	}
	firstBinding, err := first.Binding()
	if err != nil {
		t.Fatal(err)
	}
	secondBinding, err := second.Binding()
	if err != nil ||
		first != second ||
		firstBinding != secondBinding ||
		!firstBinding.Matches(first) ||
		!IsEmptyInput(firstBinding) {
		t.Fatalf(
			"empty input drifted: first=%#v second=%#v binding=%#v error=%v",
			first,
			second,
			firstBinding,
			err,
		)
	}
}

func TestInputV2BindsGitHubRepositoryWithoutCredential(t *testing.T) {
	t.Parallel()
	input, err := NewGitHubInput(
		"owner-a",
		uuid.NewString(),
		"sha256:"+strings.Repeat("2", 64),
		gitHubRepositoryFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := input.Binding()
	if err != nil ||
		binding.SourceKind != SourceGitHubRepository ||
		binding.Repository.BaseCommitSHA !=
			strings.Repeat("a", 40) ||
		binding.Workspace != (BindingV1{}) ||
		!binding.Matches(input) {
		t.Fatalf("GitHub input=%#v binding=%#v error=%v", input, binding, err)
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"token",
		"credential",
		"clone_url",
		"secret",
		"github_pat_",
		"ghs_",
	} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("binding leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestInputV2RejectsRepositoryAndSourceSubstitution(t *testing.T) {
	t.Parallel()
	input, err := NewGitHubInput(
		"owner-a",
		uuid.NewString(),
		"sha256:"+strings.Repeat("3", 64),
		gitHubRepositoryFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*InputV2)
	}{
		{
			name: "repository id",
			mutate: func(value *InputV2) {
				value.Repository.RepositoryID = "43"
			},
		},
		{
			name: "commit",
			mutate: func(value *InputV2) {
				value.Repository.BaseCommitSHA = strings.Repeat("b", 40)
			},
		},
		{
			name: "connection",
			mutate: func(value *InputV2) {
				value.Repository.ConnectionID = uuid.NewString()
			},
		},
		{
			name: "source kind",
			mutate: func(value *InputV2) {
				value.SourceKind = SourceWorkspaceArchive
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			changed := input
			test.mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("substituted task input was accepted")
			}
		})
	}
}

func TestBindingV2RejectsOwnerTaskOrGoalSubstitution(t *testing.T) {
	t.Parallel()
	taskID := uuid.NewString()
	goalDigest := "sha256:" + strings.Repeat("4", 64)
	input, err := NewGitHubInput(
		"owner-a",
		taskID,
		goalDigest,
		gitHubRepositoryFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := input.Binding()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := FromBinding(
		input.OwnerID,
		input.TaskID,
		input.GoalDigest,
		binding,
	)
	if err != nil || restored != input {
		t.Fatalf("FromBinding() = %#v, %v", restored, err)
	}
	for _, context := range []struct {
		ownerID    string
		taskID     string
		goalDigest string
	}{
		{"owner-b", taskID, goalDigest},
		{"owner-a", uuid.NewString(), goalDigest},
		{"owner-a", taskID, "sha256:" + strings.Repeat("5", 64)},
	} {
		if binding.ValidateFor(
			context.ownerID,
			context.taskID,
			context.goalDigest,
		) == nil {
			t.Fatalf("substituted context was accepted: %#v", context)
		}
	}
}

func TestGitRepositoryV1RejectsUnsafeReference(t *testing.T) {
	t.Parallel()
	repository := gitHubRepositoryFixture()
	for _, reference := range []string{
		"main",
		"refs/heads/../main",
		"refs/heads/main lock",
		"refs/heads/main@{1}",
		"refs/heads/main/",
	} {
		changed := repository
		changed.BaseRef = reference
		if changed.Validate() == nil {
			t.Fatalf("unsafe ref %q was accepted", reference)
		}
	}
}

func gitHubRepositoryFixture() GitRepositoryV1 {
	return GitRepositoryV1{
		Provider:      GitProviderGitHub,
		Host:          GitHubHost,
		ConnectionID:  uuid.NewString(),
		RepositoryID:  "42",
		Owner:         "YingSuiAI",
		Name:          "dirextalk-agent",
		BaseCommitSHA: strings.Repeat("a", 40),
		BaseRef:       "refs/heads/codex/native-agent-v2",
	}
}

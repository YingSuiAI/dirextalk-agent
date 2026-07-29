package workerruntime

import (
	"bytes"
	"errors"
	"testing"
)

func TestTaskV1IsDeterministicAndSecretFree(t *testing.T) {
	t.Parallel()
	task := validTask()
	first, err := task.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := task.Digest()
	if err != nil || first != second {
		t.Fatalf("runtime task digest first=%q second=%q err=%v",
			first, second, err)
	}

	task.Objective = "Use token sk-abcdefghijklmnopqrstuvwxyz"
	if !errors.Is(task.Validate(), ErrInvalid) {
		t.Fatal("secret-shaped objective was accepted")
	}
}

func TestTaskV1WorkspacePolicyIsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*TaskV1)
	}{
		{
			name: "read only patch",
			edit: func(task *TaskV1) {
				task.WorkspaceMode = WorkspaceReadOnly
				task.IncludePatch = true
			},
		},
		{
			name: "no workspace with digest",
			edit: func(task *TaskV1) {
				task.WorkspaceMode = WorkspaceNone
			},
		},
		{
			name: "unknown adapter",
			edit: func(task *TaskV1) {
				task.Adapter = "shell_command_v1"
			},
		},
		{
			name: "secret credential slot",
			edit: func(task *TaskV1) {
				task.CredentialSlot = "sk-abcdefghijklmnopqrstuvwxyz"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task := validTask()
			test.edit(&task)
			if !errors.Is(task.Validate(), ErrInvalid) {
				t.Fatalf("invalid runtime task accepted: %+v", task)
			}
		})
	}
}

func TestResultRejectsSecretsDuplicatesAndOversize(t *testing.T) {
	t.Parallel()
	valid := Result{
		Usage: Usage{InputTokens: 20, CachedInputTokens: 5,
			OutputTokens: 10, ReasoningOutputTokens: 2},
		Artifacts: []Artifact{{
			Name: "final.json", MediaType: "application/json",
			Content: []byte(`{"status":"completed"}`),
		}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	duplicate := valid
	duplicate.Artifacts = append(
		append([]Artifact(nil), valid.Artifacts...),
		valid.Artifacts[0],
	)
	if !errors.Is(duplicate.Validate(), ErrInvalid) {
		t.Fatal("duplicate output artifact was accepted")
	}

	secret := valid
	secret.Artifacts = []Artifact{{
		Name: "final.txt", MediaType: "text/plain; charset=utf-8",
		Content: []byte("sk-abcdefghijklmnopqrstuvwxyz"),
	}}
	if !errors.Is(secret.Validate(), ErrInvalid) {
		t.Fatal("secret-shaped output artifact was accepted")
	}

	oversize := valid
	oversize.Artifacts = []Artifact{{
		Name: "large.txt", MediaType: "text/plain; charset=utf-8",
		Content: bytes.Repeat([]byte{0x41}, MaxArtifactBytes+1),
	}}
	if !errors.Is(oversize.Validate(), ErrInvalid) {
		t.Fatal("oversized output artifact was accepted")
	}
}

func validTask() TaskV1 {
	return TaskV1{
		SchemaVersion:      TaskSchemaV1,
		TaskID:             "11111111-1111-4111-8111-111111111111",
		RoleID:             "implement-api",
		Adapter:            AdapterCodexV1,
		RuntimeReleaseID:   "22222222-2222-4222-8222-222222222222",
		RuntimeVersion:     "0.144.1",
		RuntimeImageDigest: "sha256:" + string(bytes.Repeat([]byte{'a'}, 64)),
		ContextDigest:      "sha256:" + string(bytes.Repeat([]byte{'b'}, 64)),
		WorkspaceMode:      WorkspaceIsolated,
		WorkspaceDigest:    "sha256:" + string(bytes.Repeat([]byte{'c'}, 64)),
		Objective:          "Implement the approved API change and run tests.",
		ModelProfileID:     "openai-codex",
		ModelProvider:      "openai",
		Model:              "gpt-5.3-codex",
		ModelInterface:     ModelOpenAIResponses,
		CredentialSlot:     "model-token",
		IncludePatch:       true,
	}
}

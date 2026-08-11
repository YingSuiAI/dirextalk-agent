package workerruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPiExecutorCollectsDeclaredWorkspaceArtifacts(t *testing.T) {
	t.Parallel()
	task := validPiTask()
	task.IncludePatch = false
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	resultJSON := []byte(`{"prime_count":9592,"prime_sum":454396537}`)
	report := []byte("# Prime report\n\nThe result was independently checked.\n")
	presentation := validPPTXBytes(t, false)
	if err := os.WriteFile(filepath.Join(workspace, "result.json"), resultJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "report.md"), report, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "summary.pptx"), presentation, 0o600); err != nil {
		t.Fatal(err)
	}
	events := bytes.Replace(
		validPiEventStream(),
		[]byte(`"risks":[]}`),
		[]byte(`"risks":[],"artifacts":["result.json","report.md","summary.pptx"]}`),
		1,
	)
	executor := newTestPiExecutor(
		t,
		task,
		workspace,
		[]byte("scoped-test-credential-1234567890"),
		&piFakeProcess{events: events},
		nil,
	)

	result, err := executor.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	defer destroyArtifacts(result.Artifacts)
	if len(result.Artifacts) != 4 ||
		result.Artifacts[0].Name != "final.json" ||
		result.Artifacts[1].Name != "result.json" ||
		result.Artifacts[1].MediaType != "application/json" ||
		!bytes.Equal(result.Artifacts[1].Content, resultJSON) ||
		result.Artifacts[2].Name != "report.md" ||
		result.Artifacts[2].MediaType != "text/plain; charset=utf-8" ||
		!bytes.Equal(result.Artifacts[2].Content, report) ||
		result.Artifacts[3].Name != "summary.pptx" ||
		result.Artifacts[3].MediaType != "application/vnd.openxmlformats-officedocument.presentationml.presentation" ||
		!bytes.Equal(result.Artifacts[3].Content, presentation) {
		t.Fatalf("artifacts = %+v", result.Artifacts)
	}
}

func TestCollectPiArtifactsRejectsUnsafeClaims(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*testing.T, string) []string{
		"path traversal": func(t *testing.T, workspace string) []string {
			return []string{"../result.json"}
		},
		"missing file": func(t *testing.T, workspace string) []string {
			return []string{"missing.json"}
		},
		"unsupported type": func(t *testing.T, workspace string) []string {
			writePiArtifactTestFile(t, workspace, "result.bin", []byte("bounded"))
			return []string{"result.bin"}
		},
		"secret content": func(t *testing.T, workspace string) []string {
			writePiArtifactTestFile(t, workspace, "report.md", []byte("api_key=abcdefghijklmnopqrstuvwxyz"))
			return []string{"report.md"}
		},
		"duplicate basename": func(t *testing.T, workspace string) []string {
			for _, directory := range []string{"one", "two"} {
				if err := os.Mkdir(filepath.Join(workspace, directory), 0o700); err != nil {
					t.Fatal(err)
				}
				writePiArtifactTestFile(t, filepath.Join(workspace, directory), "report.md", []byte("bounded"))
			}
			return []string{"one/report.md", "two/report.md"}
		},
		"symlink": func(t *testing.T, workspace string) []string {
			target := filepath.Join(t.TempDir(), "outside.json")
			if err := os.WriteFile(target, []byte(`{"outside":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(workspace, "result.json")); err != nil {
				t.Fatal(err)
			}
			return []string{"result.json"}
		},
	}
	for name, prepare := range tests {
		name, prepare := name, prepare
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			workspace := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(workspace, 0o700); err != nil {
				t.Fatal(err)
			}
			task := validPiTask()
			task.IncludePatch = false
			artifacts, err := collectPiArtifacts(
				context.Background(),
				task,
				workspace,
				prepare(t, workspace),
			)
			destroyArtifacts(artifacts)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unsafe artifact claim error = %v", err)
			}
		})
	}
}

func TestCollectPiArtifactsRejectsReadOnlyWorkspaceClaims(t *testing.T) {
	t.Parallel()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	writePiArtifactTestFile(t, workspace, "report.md", []byte("bounded"))
	task := validPiTask()
	task.WorkspaceMode = WorkspaceReadOnly
	task.IncludePatch = false

	artifacts, err := collectPiArtifacts(
		context.Background(),
		task,
		workspace,
		[]string{"report.md"},
	)
	destroyArtifacts(artifacts)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("read-only artifact claim error = %v", err)
	}
}

func writePiArtifactTestFile(
	t *testing.T,
	directory string,
	name string,
	content []byte,
) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

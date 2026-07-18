package installer

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestExactInstalledTreeDetectsBinaryModelAndAdapterDrift(t *testing.T) {
	t.Parallel()
	expected := filepath.Join(t.TempDir(), "expected")
	actual := filepath.Join(t.TempDir(), "actual")
	files := map[string]string{
		"qdrant":                "binary",
		"model/onnx/model.onnx": "model",
		"adapter/main.py":       "adapter",
		"adapter-manifest.json": "manifest",
		".provenance-sha256":    "provenance",
	}
	for name, content := range files {
		for _, root := range []string{expected, actual} {
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if exact, err := exactInstalledTree(actual, expected); err != nil || !exact {
		t.Fatalf("exact tree=%v err=%v", exact, err)
	}
	for _, name := range []string{"qdrant", "model/onnx/model.onnx", "adapter/main.py"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(actual, name)
			original, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
				t.Fatal(err)
			}
			if exact, err := exactInstalledTree(actual, expected); err != nil || exact {
				t.Fatalf("tampered tree=%v err=%v", exact, err)
			}
			if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExactInstalledTreeTreatsUnsafeInstalledEntriesAsRepairableDrift(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			expected := filepath.Join(t.TempDir(), "expected")
			actual := filepath.Join(t.TempDir(), "actual")
			if err := os.MkdirAll(expected, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(actual, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(actual, "unsafe")
			switch kind {
			case "symlink":
				if err := os.Symlink("/etc/passwd", path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if exact, err := exactInstalledTree(actual, expected); err != nil || exact {
				t.Fatalf("unsafe installed tree exact=%v err=%v", exact, err)
			}
		})
	}
}

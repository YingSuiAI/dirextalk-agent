package workerruntime

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestOSProcessRunnerUsesClosedEnvironmentAndBoundedOutput(t *testing.T) {
	t.Parallel()

	output, err := (OSProcessRunner{}).Run(context.Background(), ProcessSpec{
		Executable: "/bin/sh",
		Arguments:  []string{"-c", "printf '%s' \"$SAFE_VALUE\""},
		Directory:  filepath.Clean(t.TempDir()),
		Environment: map[string]string{
			"PATH":       "/usr/bin:/bin",
			"SAFE_VALUE": "visible",
		},
		SecretEnvironment: map[string][]byte{
			"CODEX_API_KEY": []byte("scoped-test-credential-1234567890"),
		},
		MaxStdoutBytes: 64,
		MaxStderrBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(output.Stdout) != "visible" {
		t.Fatalf("stdout = %q", output.Stdout)
	}

	_, err = (OSProcessRunner{}).Run(context.Background(), ProcessSpec{
		Executable: "/bin/sh",
		Arguments:  []string{"-c", "printf 'too-long'"},
		Directory:  filepath.Clean(t.TempDir()),
		Environment: map[string]string{
			"PATH": "/usr/bin:/bin",
		},
		MaxStdoutBytes: 3,
		MaxStderrBytes: 16,
	})
	if !errors.Is(err, ErrExecution) {
		t.Fatalf("output-bound error = %v", err)
	}
}

func TestOSProcessRunnerRejectsNilContext(t *testing.T) {
	t.Parallel()
	if _, err := (OSProcessRunner{}).Run(
		nil, ProcessSpec{},
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestOSProcessRunnerCancelsProcessGroup(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := (OSProcessRunner{}).Run(ctx, ProcessSpec{
		Executable: "/bin/sh",
		Arguments:  []string{"-c", "sleep 5"},
		Directory:  filepath.Clean(t.TempDir()),
		Environment: map[string]string{
			"PATH": "/usr/bin:/bin",
		},
		MaxStdoutBytes: 16,
		MaxStderrBytes: 16,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation error = %v", err)
	}
}

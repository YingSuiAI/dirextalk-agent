package workerruntime

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
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

func TestOSProcessRunnerBoundsRetainedPiEventsInsteadOfTransientStream(t *testing.T) {
	t.Parallel()

	transient := bytes.Repeat(
		[]byte(`{"type":"message_update","message":{"role":"assistant","content":[{"type":"thinking","thinking":"accumulated-stream-content"}]}}`+"\n"),
		64,
	)
	stream := bytes.Replace(
		validPiEventStream(),
		[]byte(`{"type":"agent_start"}`+"\n"),
		append(
			[]byte(`{"type":"agent_start"}`+"\n"),
			transient...,
		),
		1,
	)
	const retainedLimit = 1024
	if len(stream) <= retainedLimit {
		t.Fatalf("Pi stream fixture = %d bytes", len(stream))
	}

	output, err := (OSProcessRunner{}).Run(t.Context(), ProcessSpec{
		Executable:     "/bin/cat",
		Arguments:      []string{"-"},
		Directory:      filepath.Clean(t.TempDir()),
		Environment:    map[string]string{"PATH": "/usr/bin:/bin"},
		Stdin:          stream,
		StdoutPolicy:   ProcessStdoutPiEventsV1,
		MaxStdoutBytes: retainedLimit,
		MaxStderrBytes: 64,
	})
	if err != nil {
		t.Fatalf("filter transient Pi stream: %v", err)
	}
	defer clear(output.Stdout)
	if len(output.Stdout) >= retainedLimit ||
		bytes.Contains(output.Stdout, []byte(`"type":"message_update"`)) {
		t.Fatalf("retained Pi output = %d bytes", len(output.Stdout))
	}
	usage, final, err := parsePiEvents(output.Stdout)
	defer clear(final)
	if err != nil || usage.Validate() != nil || len(final) == 0 {
		t.Fatalf("parse retained Pi events: usage=%+v final=%d err=%v", usage, len(final), err)
	}
}

func TestOSProcessRunnerPiPolicyPreservesUnknownEventsForClosedParsing(t *testing.T) {
	t.Parallel()

	stream := bytes.Replace(
		validPiEventStream(),
		[]byte(`{"type":"agent_start"}`+"\n"),
		[]byte(
			`{"type":"agent_start"}`+"\n"+
				`{"type":"future_pi_event","payload":"must-not-be-hidden"}`+"\n",
		),
		1,
	)
	output, err := (OSProcessRunner{}).Run(t.Context(), ProcessSpec{
		Executable:     "/bin/cat",
		Arguments:      []string{"-"},
		Directory:      filepath.Clean(t.TempDir()),
		Environment:    map[string]string{"PATH": "/usr/bin:/bin"},
		Stdin:          stream,
		StdoutPolicy:   ProcessStdoutPiEventsV1,
		MaxStdoutBytes: 2048,
		MaxStderrBytes: 64,
	})
	if err != nil {
		t.Fatalf("capture Pi stream with unknown event: %v", err)
	}
	defer clear(output.Stdout)
	if !bytes.Contains(output.Stdout, []byte(`"type":"future_pi_event"`)) {
		t.Fatal("unknown Pi event was silently discarded")
	}
	usage, final, err := parsePiEvents(output.Stdout)
	clear(final)
	if usage != (Usage{}) {
		t.Fatalf("invalid Pi stream usage = %+v", usage)
	}
	requireFailure(t, err, FailureCodePiEventInvalid, FailureStagePi)
}

func TestOSProcessRunnerPiPolicyPreservesEventsAfterSettlement(t *testing.T) {
	t.Parallel()

	stream := append(
		bytes.Clone(validPiEventStream()),
		[]byte(`{"type":"message_update","message":{"role":"assistant"}}`+"\n")...,
	)
	output, err := (OSProcessRunner{}).Run(t.Context(), ProcessSpec{
		Executable:     "/bin/cat",
		Arguments:      []string{"-"},
		Directory:      filepath.Clean(t.TempDir()),
		Environment:    map[string]string{"PATH": "/usr/bin:/bin"},
		Stdin:          stream,
		StdoutPolicy:   ProcessStdoutPiEventsV1,
		MaxStdoutBytes: 2048,
		MaxStderrBytes: 64,
	})
	if err != nil {
		t.Fatalf("capture Pi post-settlement event: %v", err)
	}
	defer clear(output.Stdout)
	usage, final, err := parsePiEvents(output.Stdout)
	clear(final)
	if usage != (Usage{}) {
		t.Fatalf("post-settlement Pi stream usage = %+v", usage)
	}
	requireFailure(t, err, FailureCodePiEventInvalid, FailureStagePi)
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

func TestOSProcessRunnerClassifiesClosedFailures(t *testing.T) {
	t.Parallel()
	directory := filepath.Clean(t.TempDir())
	tests := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		spec ProcessSpec
		code FailureCode
	}{
		{
			name: "process start",
			ctx:  backgroundContext,
			spec: validProcessSpec(directory, "/missing/dirextalk-worker-binary"),
			code: FailureCodeProcessStart,
		},
		{
			name: "timeout",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 25*time.Millisecond)
			},
			spec: processShellSpec(directory, "sleep 5"),
			code: FailureCodeProcessTimeout,
		},
		{
			name: "stdout limit",
			ctx:  backgroundContext,
			spec: processShellSpec(directory, "printf 'output-overflow'"),
			code: FailureCodeProcessOutputLimit,
		},
		{
			name: "stderr limit",
			ctx:  backgroundContext,
			spec: processShellSpec(directory, "printf 'stderr-overflow' >&2"),
			code: FailureCodeProcessOutputLimit,
		},
		{
			name: "non-zero exit",
			ctx:  backgroundContext,
			spec: processExitSpec(
				directory,
				"printf 'sensitive-process-canary' >&2; exit 17",
			),
			code: FailureCodeProcessExitNonZero,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := test.ctx()
			defer cancel()
			_, err := (OSProcessRunner{}).Run(ctx, test.spec)
			requireFailure(t, err, test.code, FailureStageProcess)
			if strings.Contains(err.Error(), "sensitive-process-canary") {
				t.Fatalf("raw process diagnostic escaped: %v", err)
			}
		})
	}
}

func backgroundContext() (context.Context, context.CancelFunc) {
	return context.Background(), func() {}
}

func validProcessSpec(directory, executable string) ProcessSpec {
	return ProcessSpec{
		Executable: executable,
		Arguments:  []string{"--version"},
		Directory:  directory,
		Environment: map[string]string{
			"PATH": "/usr/bin:/bin",
		},
		MaxStdoutBytes: 8,
		MaxStderrBytes: 8,
	}
}

func processShellSpec(directory, script string) ProcessSpec {
	spec := validProcessSpec(directory, "/bin/sh")
	spec.Arguments = []string{"-c", script}
	return spec
}

func processExitSpec(directory, script string) ProcessSpec {
	spec := processShellSpec(directory, script)
	spec.MaxStderrBytes = 64
	return spec
}

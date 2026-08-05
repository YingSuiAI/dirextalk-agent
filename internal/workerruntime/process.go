package workerruntime

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const MaxProcessOutputBytes = 8 << 20

var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// ProcessSpec is constructed only by a compiled runtime adapter. Secret values
// are kept separate so they cannot enter diagnostics, command arguments, or
// ordinary environment validation.
type ProcessSpec struct {
	Executable        string
	Arguments         []string
	Directory         string
	Environment       map[string]string
	SecretEnvironment map[string][]byte
	Stdin             []byte
	AllowedExitCodes  []int
	StdoutPolicy      ProcessStdoutPolicy
	MaxStdoutBytes    int
	MaxStderrBytes    int
}

type ProcessStdoutPolicy string

const (
	ProcessStdoutRaw        ProcessStdoutPolicy = ""
	ProcessStdoutPiEventsV1 ProcessStdoutPolicy = "pi_events_v1"
)

type ProcessOutput struct {
	Stdout []byte
}

type ProcessRunner interface {
	Run(context.Context, ProcessSpec) (ProcessOutput, error)
}

type OSProcessRunner struct{}

func (OSProcessRunner) Run(
	ctx context.Context,
	spec ProcessSpec,
) (ProcessOutput, error) {
	if ctx == nil {
		return ProcessOutput{}, ErrInvalid
	}
	if err := validateProcessSpec(spec); err != nil {
		return ProcessOutput{}, err
	}
	processCtx, cancelProcess := context.WithCancel(ctx)
	defer cancelProcess()
	command := exec.CommandContext(
		processCtx,
		spec.Executable,
		spec.Arguments...,
	)
	command.Dir = spec.Directory
	command.Stdin = bytes.NewReader(spec.Stdin)
	command.Env = buildProcessEnvironment(spec)
	stdout := newProcessOutputBuffer(
		spec.StdoutPolicy,
		spec.MaxStdoutBytes,
		cancelProcess,
	)
	stderr := &boundedBuffer{
		maximum:    spec.MaxStderrBytes,
		onExceeded: cancelProcess,
	}
	command.Stdout = stdout
	command.Stderr = stderr
	configureProcessCancellation(command)
	err := command.Run()
	stdout.finalize()
	clear(command.Env)
	clear(stderr.buffer)
	if stdout.exceededLimit() || stderr.exceeded {
		stdout.destroy()
		return ProcessOutput{}, newFailure(
			FailureStageProcess,
			FailureCodeProcessOutputLimit,
		)
	}
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) ||
			!allowedExitCode(exitError.ExitCode(), spec.AllowedExitCodes) {
			stdout.destroy()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return ProcessOutput{}, errors.Join(
					ctx.Err(),
					newFailure(
						FailureStageProcess,
						FailureCodeProcessTimeout,
					),
				)
			}
			if ctx.Err() != nil {
				return ProcessOutput{}, ctx.Err()
			}
			if errors.As(err, &exitError) {
				return ProcessOutput{}, newFailure(
					FailureStageProcess,
					FailureCodeProcessExitNonZero,
				)
			}
			return ProcessOutput{}, newFailure(
				FailureStageProcess,
				FailureCodeProcessStart,
			)
		}
	}
	result := stdout.clone()
	stdout.destroy()
	return ProcessOutput{Stdout: result}, nil
}

func validateProcessSpec(spec ProcessSpec) error {
	if spec.MaxStdoutBytes < 1 ||
		spec.MaxStdoutBytes > MaxProcessOutputBytes ||
		spec.MaxStderrBytes < 1 ||
		spec.MaxStderrBytes > MaxProcessOutputBytes ||
		len(spec.Stdin) > MaxProcessOutputBytes ||
		!validProcessStdoutPolicy(spec.StdoutPolicy) ||
		!cleanAbsolute(spec.Executable) ||
		!cleanAbsolute(spec.Directory) ||
		len(spec.Arguments) == 0 ||
		len(spec.Arguments) > 128 {
		return ErrInvalid
	}
	for _, argument := range spec.Arguments {
		if argument == "" || strings.IndexByte(argument, 0) >= 0 ||
			security.ContainsLikelySecret(argument) {
			return ErrInvalid
		}
	}
	seenExitCodes := make(map[int]struct{}, len(spec.AllowedExitCodes))
	for _, code := range spec.AllowedExitCodes {
		if code < 0 || code > 255 {
			return ErrInvalid
		}
		if _, duplicate := seenExitCodes[code]; duplicate {
			return ErrInvalid
		}
		seenExitCodes[code] = struct{}{}
	}
	for name, value := range spec.Environment {
		if !environmentNamePattern.MatchString(name) ||
			strings.IndexByte(value, 0) >= 0 ||
			security.ContainsLikelySecret(name) ||
			security.ContainsLikelySecret(value) {
			return ErrInvalid
		}
		if _, duplicate := spec.SecretEnvironment[name]; duplicate {
			return ErrInvalid
		}
	}
	for name, value := range spec.SecretEnvironment {
		if !environmentNamePattern.MatchString(name) ||
			len(value) < 16 || len(value) > MaxCredentialBytes ||
			bytes.IndexByte(value, 0) >= 0 {
			return ErrInvalid
		}
	}
	return nil
}

func validProcessStdoutPolicy(policy ProcessStdoutPolicy) bool {
	return policy == ProcessStdoutRaw ||
		policy == ProcessStdoutPiEventsV1
}

func buildProcessEnvironment(spec ProcessSpec) []string {
	names := make([]string, 0, len(spec.Environment)+len(spec.SecretEnvironment))
	for name := range spec.Environment {
		names = append(names, name)
	}
	for name := range spec.SecretEnvironment {
		names = append(names, name)
	}
	sort.Strings(names)
	environment := make([]string, 0, len(names))
	for _, name := range names {
		if value, ok := spec.Environment[name]; ok {
			environment = append(environment, name+"="+value)
			continue
		}
		environment = append(
			environment,
			name+"="+string(spec.SecretEnvironment[name]),
		)
	}
	return environment
}

func allowedExitCode(value int, allowed []int) bool {
	if value == 0 {
		return true
	}
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value
}

type boundedBuffer struct {
	maximum    int
	buffer     []byte
	exceeded   bool
	onExceeded func()
}

type processOutputBuffer interface {
	Write([]byte) (int, error)
	finalize()
	exceededLimit() bool
	clone() []byte
	destroy()
}

func newProcessOutputBuffer(
	policy ProcessStdoutPolicy,
	maximum int,
	onExceeded func(),
) processOutputBuffer {
	if policy == ProcessStdoutPiEventsV1 {
		return &piProcessOutputBuffer{
			retained: boundedBuffer{
				maximum:    maximum,
				onExceeded: onExceeded,
			},
			onExceeded: onExceeded,
		}
	}
	return &boundedBuffer{
		maximum:    maximum,
		onExceeded: onExceeded,
	}
}

func (buffer *boundedBuffer) Write(input []byte) (int, error) {
	if buffer.exceeded {
		return len(input), nil
	}
	remaining := buffer.maximum - len(buffer.buffer)
	if remaining <= 0 {
		buffer.markExceeded()
		return len(input), nil
	}
	if len(input) > remaining {
		buffer.buffer = append(buffer.buffer, input[:remaining]...)
		buffer.markExceeded()
		return len(input), nil
	}
	buffer.buffer = append(buffer.buffer, input...)
	return len(input), nil
}

func (buffer *boundedBuffer) markExceeded() {
	if buffer.exceeded {
		return
	}
	buffer.exceeded = true
	if buffer.onExceeded != nil {
		buffer.onExceeded()
	}
}

func (*boundedBuffer) finalize() {}

func (buffer *boundedBuffer) exceededLimit() bool {
	return buffer.exceeded
}

func (buffer *boundedBuffer) clone() []byte {
	return bytes.Clone(buffer.buffer)
}

func (buffer *boundedBuffer) destroy() {
	clear(buffer.buffer)
	buffer.buffer = nil
}

func processWaitDelay() time.Duration { return 2 * time.Second }

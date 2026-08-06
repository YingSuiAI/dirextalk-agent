package coreteamruntime

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

type SandboxAccess uint8

const (
	SandboxReadOnly SandboxAccess = iota + 1
	SandboxReadWrite
	SandboxReadExecute
	SandboxReadWriteExecute
)

type SandboxPath struct {
	Path   string
	Access SandboxAccess
}

type SandboxPolicy struct {
	LauncherPath       string
	MinimumLandlockABI uint32
	Paths              []SandboxPath
}

func (policy *SandboxPolicy) clone() *SandboxPolicy {
	if policy == nil {
		return nil
	}
	cloned := *policy
	cloned.Paths = append([]SandboxPath(nil), policy.Paths...)
	return &cloned
}

func (policy *SandboxPolicy) validate() error {
	if policy == nil || !cleanAbsolute(policy.LauncherPath) || policy.MinimumLandlockABI != 2 ||
		len(policy.Paths) == 0 || len(policy.Paths) > 64 {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(policy.Paths))
	for _, path := range policy.Paths {
		if !cleanAbsolute(path.Path) || path.Access < SandboxReadOnly || path.Access > SandboxReadWriteExecute {
			return ErrInvalid
		}
		key := path.Path + "\x00" + string(rune(path.Access))
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalid
		}
		seen[key] = struct{}{}
	}
	return nil
}

type ProcessSpec struct {
	Executable        string
	Arguments         []string
	Directory         string
	Environment       map[string]string
	SecretEnvironment map[string][]byte
	Stdin             []byte
	MaxStdoutBytes    int
	MaxStderrBytes    int
	Timeout           time.Duration
	Sandbox           *SandboxPolicy
}

func (spec ProcessSpec) clone() ProcessSpec {
	cloned := spec
	cloned.Arguments = append([]string(nil), spec.Arguments...)
	cloned.Environment = make(map[string]string, len(spec.Environment))
	for name, value := range spec.Environment {
		cloned.Environment[name] = value
	}
	cloned.SecretEnvironment = make(map[string][]byte, len(spec.SecretEnvironment))
	for name, value := range spec.SecretEnvironment {
		cloned.SecretEnvironment[name] = bytes.Clone(value)
	}
	cloned.Stdin = bytes.Clone(spec.Stdin)
	cloned.Sandbox = spec.Sandbox.clone()
	return cloned
}

type ProcessRunner interface {
	Run(context.Context, ProcessSpec) ([]byte, ClosedFailure, error)
}

type OSProcessRunner struct{}

func (OSProcessRunner) Run(ctx context.Context, spec ProcessSpec) ([]byte, ClosedFailure, error) {
	if ctx == nil || validateProcessSpec(spec) != nil {
		return nil, ClosedFailure{}, ErrInvalid
	}
	defer destroySecretEnvironment(spec.SecretEnvironment)
	processContext, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	executable, arguments, err := processCommand(spec)
	if err != nil {
		return nil, ClosedFailure{}, ErrInvalid
	}
	command := exec.CommandContext(processContext, executable, arguments...)
	command.Dir = spec.Directory
	command.Stdin = bytes.NewReader(spec.Stdin)
	environment := buildProcessEnvironment(spec)
	command.Env = environment
	stdout := &boundedBuffer{maximum: spec.MaxStdoutBytes, onExceeded: cancel}
	stderr := &boundedBuffer{maximum: spec.MaxStderrBytes, onExceeded: cancel}
	command.Stdout, command.Stderr = stdout, stderr
	configureProcessCancellation(command)
	configureSandboxIdentity(command, spec.Sandbox != nil)
	err = command.Run()
	clear(environment)
	stderr.destroy()
	if stdout.exceeded || stderr.exceeded {
		stdout.destroy()
		return nil, ClosedFailure{Stage: FailureProcess, Code: FailureProcessOutputLimit}, nil
	}
	if err != nil {
		stdout.destroy()
		if errors.Is(processContext.Err(), context.DeadlineExceeded) {
			return nil, ClosedFailure{Stage: FailureProcess, Code: FailureProcessTimeout}, nil
		}
		if ctx.Err() != nil {
			return nil, ClosedFailure{}, ctx.Err()
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, ClosedFailure{Stage: FailureProcess, Code: FailureProcessExitNonZero}, nil
		}
		return nil, ClosedFailure{Stage: FailureProcess, Code: FailureProcessStart}, nil
	}
	output := bytes.Clone(stdout.buffer)
	stdout.destroy()
	return output, ClosedFailure{}, nil
}

func processCommand(spec ProcessSpec) (string, []string, error) {
	if validateProcessSpec(spec) != nil {
		return "", nil, ErrInvalid
	}
	if spec.Sandbox == nil {
		return spec.Executable, append([]string(nil), spec.Arguments...), nil
	}
	paths := append([]SandboxPath(nil), spec.Sandbox.Paths...)
	sort.Slice(paths, func(left, right int) bool {
		if paths[left].Path == paths[right].Path {
			return paths[left].Access < paths[right].Access
		}
		return paths[left].Path < paths[right].Path
	})
	arguments := []string{"--landlock-abi", strconv.FormatUint(uint64(spec.Sandbox.MinimumLandlockABI), 10)}
	for _, path := range paths {
		flag := ""
		switch path.Access {
		case SandboxReadOnly:
			flag = "--ro"
		case SandboxReadWrite:
			flag = "--rw"
		case SandboxReadExecute:
			flag = "--rx"
		case SandboxReadWriteExecute:
			flag = "--rwx"
		default:
			return "", nil, ErrInvalid
		}
		arguments = append(arguments, flag, path.Path)
	}
	arguments = append(arguments, "--", spec.Executable)
	arguments = append(arguments, spec.Arguments...)
	return spec.Sandbox.LauncherPath, arguments, nil
}

func validateProcessSpec(spec ProcessSpec) error {
	if !cleanAbsolute(spec.Executable) || !cleanAbsolute(spec.Directory) || len(spec.Arguments) == 0 || len(spec.Arguments) > 128 ||
		spec.MaxStdoutBytes < 1 || spec.MaxStdoutBytes > MaxProcessOutputBytes || spec.MaxStderrBytes < 1 ||
		spec.MaxStderrBytes > MaxProcessOutputBytes || len(spec.Stdin) > MaxProcessOutputBytes ||
		spec.Timeout < time.Millisecond || spec.Timeout > 6*time.Hour {
		return ErrInvalid
	}
	for _, argument := range spec.Arguments {
		if argument == "" || strings.IndexByte(argument, 0) >= 0 || security.ContainsLikelySecret(argument) {
			return ErrInvalid
		}
	}
	for name, value := range spec.Environment {
		if !environmentNamePattern.MatchString(name) || strings.IndexByte(value, 0) >= 0 ||
			security.ContainsLikelySecret(name) || security.ContainsLikelySecret(value) {
			return ErrInvalid
		}
		if _, duplicate := spec.SecretEnvironment[name]; duplicate {
			return ErrInvalid
		}
	}
	for name, value := range spec.SecretEnvironment {
		if !environmentNamePattern.MatchString(name) || len(value) < 16 || len(value) > maxModelCredentialBytes || bytes.IndexByte(value, 0) >= 0 {
			return ErrInvalid
		}
	}
	if spec.Sandbox != nil && spec.Sandbox.validate() != nil {
		return ErrInvalid
	}
	return nil
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
		} else {
			environment = append(environment, name+"="+string(spec.SecretEnvironment[name]))
		}
	}
	return environment
}

type boundedBuffer struct {
	maximum    int
	buffer     []byte
	exceeded   bool
	onExceeded func()
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

func (buffer *boundedBuffer) destroy() { clear(buffer.buffer); buffer.buffer = nil }

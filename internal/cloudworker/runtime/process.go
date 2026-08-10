package runtime

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

type ProcessStdoutPolicy string

const (
	ProcessStdoutRaw        ProcessStdoutPolicy = ""
	ProcessStdoutPiEventsV1 ProcessStdoutPolicy = "pi_events_v1"
)

// ProcessSpec is built by compiled runtime code. SecretEnvironment is a
// separate, one-entry model-token channel so credentials never enter args,
// stdin, diagnostics, or inherited host environment.
type ProcessSpec struct {
	Executable               string
	ExpectedExecutableSHA256 string
	Arguments                []string
	Directory                string
	Environment              map[string]string
	SecretEnvironment        map[string][]byte
	Stdin                    []byte
	AllowedExitCodes         []int
	StdoutPolicy             ProcessStdoutPolicy
	MaxStdoutBytes           int
	MaxStderrBytes           int
}

type ProcessOutput struct {
	Stdout          []byte
	RuntimeTopology execgate.Proof
}

type ProcessRunner interface {
	Run(context.Context, ProcessSpec) (ProcessOutput, error)
}

type ProcessBinding struct {
	ExecutionID       string
	TaskID            string
	Attempt           uint32
	LeaseEpoch        uint64
	RuntimeTaskSHA256 string
}

func (binding ProcessBinding) validate() error {
	registration := execgate.Registration{
		ExecutionID: binding.ExecutionID, TaskID: binding.TaskID,
		Attempt: binding.Attempt, LeaseEpoch: binding.LeaseEpoch,
		RuntimeTaskSHA256: binding.RuntimeTaskSHA256,
		PiExecutable:      "/placeholder", PiSHA256: strings.Repeat("0", 64),
	}
	return registration.Validate()
}

type ProcessBinder interface {
	BindProcess(ProcessBinding) (ProcessRunner, error)
}

type RuntimeTopologySource interface {
	TerminalRuntimeTopology() (execgate.Proof, error)
}

type processRunnerState struct {
	mu       sync.Mutex
	terminal execgate.Proof
}

type OSProcessRunner struct {
	uid     uint32
	gid     uint32
	gate    processExecGate
	binding ProcessBinding
	state   *processRunnerState
}

func NewOSProcessRunner(uid, gid uint32) (OSProcessRunner, error) {
	if uid == 0 || gid == 0 || validateProcessIdentity(uid, gid) != nil {
		return OSProcessRunner{}, ErrInvalid
	}
	gate, err := newProductionProcessExecGate()
	if err != nil {
		return OSProcessRunner{}, err
	}
	return OSProcessRunner{uid: uid, gid: gid, gate: gate, state: &processRunnerState{}}, nil
}

func (runner OSProcessRunner) BindProcess(binding ProcessBinding) (ProcessRunner, error) {
	if runner.uid == 0 || runner.gid == 0 || runner.gate == nil || runner.state == nil ||
		runner.binding != (ProcessBinding{}) || binding.validate() != nil {
		return nil, ErrInvalid
	}
	runner.binding = binding
	return runner, nil
}

func (runner OSProcessRunner) TerminalRuntimeTopology() (execgate.Proof, error) {
	if runner.state == nil {
		return execgate.Proof{}, ErrInvalid
	}
	runner.state.mu.Lock()
	defer runner.state.mu.Unlock()
	if runner.state.terminal.ValidateTerminal() != nil {
		return execgate.Proof{}, ErrExecution
	}
	return runner.state.terminal, nil
}

func (runner OSProcessRunner) Run(ctx context.Context, spec ProcessSpec) (ProcessOutput, error) {
	if ctx == nil {
		return ProcessOutput{}, ErrInvalid
	}
	if err := validateProcessSpec(spec); err != nil {
		return ProcessOutput{}, err
	}
	if validateProcessIdentity(runner.uid, runner.gid) != nil {
		return ProcessOutput{}, ErrInvalid
	}
	var gateRun processExecGateRun
	if runner.uid != 0 {
		if runner.gate == nil || runner.state == nil || runner.binding.validate() != nil ||
			!digestPattern.MatchString(spec.ExpectedExecutableSHA256) {
			return ProcessOutput{}, ErrInvalid
		}
		runner.state.mu.Lock()
		runner.state.terminal = execgate.Proof{}
		runner.state.mu.Unlock()
		registered, err := runner.gate.Register(ctx, execgate.Registration{
			ExecutionID: runner.binding.ExecutionID, TaskID: runner.binding.TaskID,
			Attempt: runner.binding.Attempt, LeaseEpoch: runner.binding.LeaseEpoch,
			RuntimeTaskSHA256: runner.binding.RuntimeTaskSHA256,
			PiExecutable:      spec.Executable, PiSHA256: spec.ExpectedExecutableSHA256,
		})
		if err != nil {
			logProcessFailure("gate_register", FailureCodeProcessTopology)
			return ProcessOutput{}, newFailure(FailureStageProcess, FailureCodeProcessTopology)
		}
		gateRun = registered
	}
	processCtx, cancelProcess := context.WithCancel(ctx)
	defer cancelProcess()
	gateFinished := false
	var terminalProof execgate.Proof
	if gateRun != nil {
		defer func() {
			if !gateFinished {
				cancelCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = gateRun.Cancel(cancelCtx)
			}
		}()
	}
	command := exec.CommandContext(processCtx, spec.Executable, spec.Arguments...)
	command.Dir = spec.Directory
	command.Stdin = bytes.NewReader(spec.Stdin)
	command.Env = buildProcessEnvironment(spec)
	stdout := newProcessOutputBuffer(spec.StdoutPolicy, spec.MaxStdoutBytes, cancelProcess)
	stderr := &boundedBuffer{maximum: spec.MaxStderrBytes, onExceeded: cancelProcess}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := configureProcessCancellation(command, runner.uid, runner.gid); err != nil {
		stdout.destroy()
		stderr.destroy()
		clear(command.Env)
		return ProcessOutput{}, err
	}
	startErr := startIsolatedProcess(command, runner.uid != 0)
	var waitErr, lifecycleErr error
	if startErr == nil && gateRun != nil {
		if _, activateErr := gateRun.Activate(processCtx, command.Process.Pid); activateErr != nil {
			_ = command.Cancel()
			waitErr = command.Wait()
			logProcessFailure("gate_activate", FailureCodeProcessTopology)
			lifecycleErr = newFailure(FailureStageProcess, FailureCodeProcessTopology)
		}
	}
	if startErr == nil && lifecycleErr == nil {
		waitErr = command.Wait()
	}
	if gateRun != nil && startErr == nil {
		terminalCtx, cancelTerminal := context.WithTimeout(context.Background(), 2*time.Second)
		proof, topologyErr := gateRun.Terminal(terminalCtx)
		cancelTerminal()
		if topologyErr != nil || proof.ValidateTerminal() != nil {
			logProcessFailure("gate_terminal", FailureCodeProcessTopology)
			lifecycleErr = newFailure(FailureStageProcess, FailureCodeProcessTopology)
		} else {
			terminalProof = proof
			runner.state.mu.Lock()
			runner.state.terminal = proof
			runner.state.mu.Unlock()
			gateFinished = true
		}
	}
	stdout.finalize()
	clear(command.Env)
	stderr.destroy()
	if stdout.exceededLimit() || stderr.exceeded {
		stdout.destroy()
		return ProcessOutput{}, newFailure(FailureStageProcess, FailureCodeProcessOutputLimit)
	}
	if startErr != nil || waitErr != nil || lifecycleErr != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			stdout.destroy()
			return ProcessOutput{}, errors.Join(
				ctx.Err(),
				newFailure(FailureStageProcess, FailureCodeProcessTimeout),
			)
		case ctx.Err() != nil:
			stdout.destroy()
			return ProcessOutput{}, ctx.Err()
		}
	}
	if lifecycleErr != nil {
		stdout.destroy()
		if _, ok := FailureOf(lifecycleErr); ok {
			return ProcessOutput{}, lifecycleErr
		}
		return ProcessOutput{}, ErrExecution
	}
	if startErr != nil {
		stdout.destroy()
		if failure, ok := FailureOf(startErr); ok {
			logProcessFailure("start", failure.Code)
			return ProcessOutput{}, startErr
		}
		logProcessFailure("start", FailureCodeProcessStart)
		return ProcessOutput{}, newFailure(FailureStageProcess, FailureCodeProcessStart)
	}
	if waitErr != nil {
		var exitError *exec.ExitError
		switch {
		case errors.As(waitErr, &exitError) &&
			allowedExitCode(exitError.ExitCode(), spec.AllowedExitCodes):
			// The compiled runtime explicitly allowed this exit status.
		case acceptPiEventsAfterWaitDelay(
			waitErr,
			command.ProcessState != nil && command.ProcessState.Success(),
			terminalProof,
			spec.StdoutPolicy,
			stdout.exceededLimit() || stderr.exceeded,
		):
			// The Pi event parser remains responsible for proving a complete,
			// valid terminal event stream after os/exec closed lingering pipes.
			slog.Info(
				"[cloud-worker.process] outcome=continued",
				"phase", "wait", "code", "wait_delay_pi_events",
			)
		case errors.As(waitErr, &exitError):
			stdout.destroy()
			logProcessFailure("wait", FailureCodeProcessExitNonZero)
			return ProcessOutput{}, newFailure(
				FailureStageProcess,
				FailureCodeProcessExitNonZero,
			)
		default:
			stdout.destroy()
			if failure, ok := FailureOf(waitErr); ok {
				logProcessFailure("wait", failure.Code)
				return ProcessOutput{}, waitErr
			}
			logProcessFailure("wait", FailureCodeProcessWait)
			return ProcessOutput{}, newFailure(FailureStageProcess, FailureCodeProcessWait)
		}
	}
	result := stdout.clone()
	stdout.destroy()
	return ProcessOutput{Stdout: result, RuntimeTopology: terminalProof}, nil
}

func logProcessFailure(phase string, code FailureCode) {
	// Phases and closed failure codes are the only diagnostic values emitted;
	// process errors, paths, arguments, environment, and output stay private.
	slog.Error(
		"[cloud-worker.process] outcome=failed",
		"phase", phase, "code", string(code),
	)
}

func acceptPiEventsAfterWaitDelay(
	waitErr error,
	processStateSuccess bool,
	terminalProof execgate.Proof,
	stdoutPolicy ProcessStdoutPolicy,
	outputExceeded bool,
) bool {
	return errors.Is(waitErr, exec.ErrWaitDelay) && processStateSuccess &&
		terminalProof.ValidateTerminal() == nil &&
		stdoutPolicy == ProcessStdoutPiEventsV1 && !outputExceeded
}

func validateProcessSpec(spec ProcessSpec) error {
	if spec.MaxStdoutBytes < 1 || spec.MaxStdoutBytes > MaxProcessOutputBytes ||
		spec.MaxStderrBytes < 1 || spec.MaxStderrBytes > MaxProcessOutputBytes ||
		len(spec.Stdin) > MaxProcessOutputBytes ||
		(spec.StdoutPolicy != ProcessStdoutRaw && spec.StdoutPolicy != ProcessStdoutPiEventsV1) ||
		!cleanAbsolute(spec.Executable) || !cleanAbsolute(spec.Directory) ||
		len(spec.Arguments) == 0 || len(spec.Arguments) > 128 ||
		len(spec.SecretEnvironment) > 1 {
		return ErrInvalid
	}
	if spec.ExpectedExecutableSHA256 != "" && !digestPattern.MatchString(spec.ExpectedExecutableSHA256) {
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
		if !validCredentialEnvironment(name) || len(value) < 16 ||
			len(value) > MaxCredentialBytes || bytes.IndexAny(value, "\r\n\x00") >= 0 {
			return ErrInvalid
		}
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

func newProcessOutputBuffer(policy ProcessStdoutPolicy, maximum int, onExceeded func()) processOutputBuffer {
	if policy == ProcessStdoutPiEventsV1 {
		return &piProcessOutputBuffer{
			retained:   boundedBuffer{maximum: maximum, onExceeded: onExceeded},
			onExceeded: onExceeded,
		}
	}
	return &boundedBuffer{maximum: maximum, onExceeded: onExceeded}
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

func (*boundedBuffer) finalize()                  {}
func (buffer *boundedBuffer) exceededLimit() bool { return buffer.exceeded }
func (buffer *boundedBuffer) clone() []byte       { return bytes.Clone(buffer.buffer) }
func (buffer *boundedBuffer) destroy() {
	clear(buffer.buffer)
	buffer.buffer = nil
}

func processWaitDelay() time.Duration { return 2 * time.Second }

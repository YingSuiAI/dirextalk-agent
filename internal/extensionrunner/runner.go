package extensionrunner

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/sys/unix"
)

var errOutputLimitExceeded = errors.New("extension output limit exceeded")

// RunCoreResultV1 is the internal Core Runner install path. Unlike RunV2 it
// never exposes a host workspace to the command: the Linux child receives a
// private tmpfs /work and only the trusted manager can fill this sealed memfd.
func RunCoreResultV1(ctx context.Context, backend LinuxBackend, invocation SandboxInvocationV2, tmpfsBytes int64, resultPath string) ([]byte, error) {
	if tmpfsBytes <= 0 || resultPath == "" || invocation.Install == nil || invocation.WorkspaceFD < 0 {
		return nil, ErrDenied
	}
	fd, err := unix.MemfdCreate("core-result", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err = unix.Ftruncate(fd, coreResultMaxBytes); err != nil {
		return nil, err
	}
	invocation.CoreTmpfsBytes, invocation.CoreResultPath, invocation.CoreResultFD = tmpfsBytes, resultPath, fd
	p, err := backend.StartV2(ctx, invocation)
	if err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(invocation.Request.TimeoutMS)*time.Millisecond)
	defer cancel()
	if waiter, ok := p.(interface {
		WaitContext(context.Context) ([]byte, []byte, string, error)
	}); ok {
		_, _, _, err = waiter.WaitContext(waitCtx)
	} else {
		_, _, _, err = p.Wait()
	}
	if err != nil {
		return nil, err
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	required := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if err != nil || seals&required != required {
		return nil, ErrDenied
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > coreResultMaxBytes {
		return nil, ErrDenied
	}
	b := make([]byte, st.Size)
	if n, e := unix.Pread(fd, b, 0); e != nil || n != len(b) {
		return nil, ErrDenied
	}
	return b, nil
}

type Runner struct {
	InstallResolver   InstallResolver
	WorkspaceResolver WorkspaceResolver
	V2Backend         V2Backend
	Logger            *slog.Logger
}

// RunV2 is the descriptor-only execution path.
func (r Runner) RunV2(ctx context.Context, request RequestV2, fds []int, registry *RunRegistry) (terminal StatusV1, retErr error) {
	if err := ValidateRequestFDs(request, fds); err != nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorInvalidRequest}, err
	}
	if registry == nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorUnavailableBackend}, ErrUnavailable
	}
	requestBytes, _ := json.Marshal(request)
	requestDigest := DigestBytes(requestBytes)
	if replay, ok, err := registry.ClaimDigest(request.RunID, requestDigest); err != nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseTombstone, Error: ErrorReplay}, err
	} else if ok {
		return replay, nil
	}
	if r.InstallResolver == nil || r.WorkspaceResolver == nil || r.V2Backend == nil {
		_ = registry.Abort(request.RunID, ErrorUnavailableBackend)
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorUnavailableBackend}, ErrUnavailable
	}
	code := ErrorUnavailableBackend
	defer func() {
		if terminal.Phase == PhaseTombstone || terminal.Phase == PhaseFailed {
			_ = registry.Record(request.RunID, requestDigest, terminal)
		} else {
			_ = registry.Abort(request.RunID, code)
		}
	}()
	install, err := r.InstallResolver.ResolveInstall(request.InstallDigest)
	if err != nil {
		r.logDenied(request.RunID, "install_resolve")
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorDeniedRequest}, ErrDenied
	}
	defer install.Close()
	workspaceFD, err := r.WorkspaceResolver.ResolveWorkspace(request.TaskID, request.TaskFence)
	if err != nil {
		r.logDenied(request.RunID, "workspace_resolve")
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorDeniedRequest}, ErrDenied
	}
	defer unix.Close(workspaceFD)
	baseline, err := SnapshotWorkspaceFD(workspaceFD, request.Limits.FileBytes)
	if err != nil {
		r.logDenied(request.RunID, "workspace_snapshot")
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorDeniedRequest}, ErrDenied
	}
	if err = registry.Transition(request.RunID, PhaseAdmitted, ErrorNone); err != nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorExecution}, err
	}
	if err = r.V2Backend.Probe(ctx); err != nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorUnavailableBackend}, ErrUnavailable
	}
	if err = registry.Transition(request.RunID, PhasePrepared, ErrorNone); err != nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorExecution}, err
	}
	stdin, secrets, err := duplicateV2Inputs(request, fds)
	if err != nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorInvalidRequest}, err
	}
	defer closeV2Inputs(stdin, secrets)
	p, err := r.V2Backend.StartV2(ctx, SandboxInvocationV2{Request: request, Install: install, WorkspaceFD: workspaceFD, StdinFD: stdin, SecretFDs: secrets})
	if err != nil || p == nil {
		if cleanupErr := CleanupWorkspaceFD(workspaceFD, baseline, nil, request.Limits.FileBytes); cleanupErr != nil {
			code = ErrorCleanup
		}
		if err != nil {
			return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: code}, err
		}
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: code}, ErrUnavailable
	}
	if err = registry.Transition(request.RunID, PhaseRunning, ErrorNone); err != nil {
		killAndReap(p)
		_ = CleanupWorkspaceFD(workspaceFD, baseline, nil, request.Limits.FileBytes)
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorExecution}, err
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, time.Duration(request.TimeoutMS)*time.Millisecond)
	defer cancelWait()
	var stdout, stderr []byte
	var status string
	var waitErr error
	if waiter, ok := p.(interface {
		WaitContext(context.Context) ([]byte, []byte, string, error)
	}); ok {
		stdout, stderr, status, waitErr = waiter.WaitContext(waitCtx)
	} else {
		done := make(chan struct{})
		go func() {
			select {
			case <-waitCtx.Done():
				_ = p.KillGroup()
			case <-done:
			}
		}()
		stdout, stderr, status, waitErr = p.Wait()
		close(done)
		if waitCtx.Err() != nil {
			waitErr = waitCtx.Err()
		}
	}
	outputExceeded := len(stdout) > MaxOutputBytes || len(stderr) > MaxOutputBytes
	if reporter, ok := p.(interface{ OutputExceeded() bool }); ok {
		outputExceeded = outputExceeded || reporter.OutputExceeded()
	}
	if len(stdout) > MaxOutputBytes {
		stdout = stdout[:MaxOutputBytes]
	}
	if len(stderr) > MaxOutputBytes {
		stderr = stderr[:MaxOutputBytes]
	}
	// Output exhaustion is proven by the bounded collectors, independently of
	// the process exit. Keep that deterministic resource terminal authoritative
	// when a command also exits non-zero or its waiter reports another error.
	if outputExceeded {
		status = "output_limit"
		waitErr = errOutputLimitExceeded
	}
	if waitErr != nil {
		_ = p.KillGroup()
		switch {
		case errors.Is(waitErr, errCgroupCleanup):
			code = ErrorCleanup
		case errors.Is(waitErr, context.DeadlineExceeded):
			code = ErrorTimeout
		case errors.Is(waitErr, context.Canceled):
			code = ErrorCancelled
		default:
			code = ErrorExecution
		}
		resultFiles, collectErr := CollectAvailableResultFilesFD(workspaceFD, request.ResultFiles, request.Limits.FileBytes)
		if collectErr != nil && code == ErrorNone {
			code = ErrorExecution
		}
		if cleanupErr := CleanupWorkspaceFD(workspaceFD, baseline, resultFilePaths(resultFiles), request.Limits.FileBytes); cleanupErr != nil {
			code = ErrorCleanup
		}
		return StatusV1{
			RunID:       request.RunID,
			Phase:       PhaseFailed,
			Error:       code,
			Status:      status,
			Stdout:      stdout,
			Stderr:      stderr,
			ExitCode:    processExitCode(p),
			ResultFiles: resultFiles,
		}, nil
	}
	if err = registry.Transition(request.RunID, PhaseCollecting, ErrorNone); err != nil {
		_ = CleanupWorkspaceFD(workspaceFD, baseline, nil, request.Limits.FileBytes)
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorExecution}, err
	}
	resultFiles, err := VerifyResultFilesFD(workspaceFD, request.ResultFiles, request.Limits.FileBytes)
	if err != nil {
		code = ErrorExecution
		if cleanupErr := CleanupWorkspaceFD(workspaceFD, baseline, resultFilePaths(resultFiles), request.Limits.FileBytes); cleanupErr != nil {
			code = ErrorCleanup
		}
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: code, Status: status, Stdout: stdout, Stderr: stderr, ExitCode: processExitCode(p), ResultFiles: resultFiles}, nil
	}
	if err = registry.Transition(request.RunID, PhaseExited, ErrorNone); err != nil {
		_ = CleanupWorkspaceFD(workspaceFD, baseline, resultFilePaths(resultFiles), request.Limits.FileBytes)
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorExecution}, err
	}
	if err = CleanupWorkspaceFD(workspaceFD, baseline, resultFilePaths(resultFiles), request.Limits.FileBytes); err != nil {
		code = ErrorCleanup
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: code, Status: status, Stdout: stdout, Stderr: stderr, ExitCode: processExitCode(p), ResultFiles: resultFiles}, nil
	}
	if err = registry.Transition(request.RunID, PhaseCleaned, ErrorNone); err != nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorCleanup}, err
	}
	if err = registry.Transition(request.RunID, PhaseTombstone, ErrorNone); err != nil {
		return StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorCleanup}, err
	}
	code = ErrorNone
	return StatusV1{RunID: request.RunID, Phase: PhaseTombstone, Status: status, Stdout: stdout, Stderr: stderr, ExitCode: processExitCode(p), ResultFiles: resultFiles}, nil
}

func (r Runner) logDenied(runID, stage string) {
	if r.Logger != nil {
		r.Logger.Warn("extension runner request denied", "run_id", runID, "stage", stage, "error_code", ErrorDeniedRequest)
	}
}

func processExitCode(process Process) *int {
	if value, ok := process.(interface{ ExitCode() *int }); ok {
		return value.ExitCode()
	}
	return nil
}

func resultFilePaths(files []ResultFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}

func killAndReap(process Process) {
	_ = process.KillGroup()
	if waiter, ok := process.(interface {
		WaitContext(context.Context) ([]byte, []byte, string, error)
	}); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _, _, _ = waiter.WaitContext(ctx)
		cancel()
		return
	}
	_, _, _, _ = process.Wait()
}

func duplicateV2Inputs(r RequestV2, fds []int) (int, []int, error) {
	stdin := -1
	secrets := make([]int, len(r.Secrets))
	for i := range secrets {
		secrets[i] = -1
	}
	if r.Stdin != nil {
		var e error
		stdin, e = unix.Dup(fds[r.Stdin.Index])
		if e != nil {
			return -1, secrets, ErrInvalid
		}
	}
	for i, s := range r.Secrets {
		fd, e := unix.Dup(fds[s.Index])
		if e != nil {
			closeV2Inputs(stdin, secrets)
			return -1, nil, ErrInvalid
		}
		secrets[i] = fd
	}
	return stdin, secrets, nil
}
func closeV2Inputs(stdin int, secrets []int) {
	if stdin >= 0 {
		_ = unix.Close(stdin)
	}
	for _, fd := range secrets {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}

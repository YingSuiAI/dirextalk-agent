package execution

import (
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
)

const (
	LocalResourceBusyCode         = "local_resource_busy"
	LocalResourceExhaustedCode    = "local_resource_exhausted"
	LocalExecutionFailedCode      = "local_execution_failed"
	LocalResourceBusySummary      = "local sandbox is busy; retry later or explicitly authorize Cloud Worker"
	LocalResourceExhaustedSummary = "local sandbox resources were exhausted; retry later or explicitly authorize Cloud Worker"
	LocalExecutionFailedSummary   = "local execution failed; check the tool input and requested result files"
)

var (
	ErrLocalResourceBusy      = errors.New(LocalResourceBusyCode)
	ErrLocalResourceExhausted = errors.New(LocalResourceExhaustedCode)
	ErrLocalExecutionFailed   = errors.New(LocalExecutionFailedCode)
	ErrLocalOutcomeUncertain  = errors.New("local extension execution outcome is uncertain")
)

func LocalExecutionFailure(err error) (code, summary string, ok bool) {
	if errors.Is(err, ErrLocalExecutionFailed) {
		return LocalExecutionFailedCode, LocalExecutionFailedSummary, true
	}
	return "", "", false
}

// LocalResourceFailure maps only terminal runner receipts whose execution
// outcome is known. Transport failures remain unclassified because the caller
// cannot safely infer whether a dispatched process ran.
func LocalResourceFailure(err error) (code, summary string, ok bool) {
	switch {
	case errors.Is(err, ErrLocalResourceBusy):
		return LocalResourceBusyCode, LocalResourceBusySummary, true
	case errors.Is(err, ErrLocalResourceExhausted):
		return LocalResourceExhaustedCode, LocalResourceExhaustedSummary, true
	default:
		return "", "", false
	}
}

func localRunnerResourceFailure(status extensionrunner.StatusV1) error {
	if status.Phase != extensionrunner.PhaseFailed {
		return nil
	}
	if status.Error == extensionrunner.ErrorUnavailableBackend && status.Status == "capacity" {
		return ErrLocalResourceBusy
	}
	if status.Error == extensionrunner.ErrorTimeout ||
		(status.Error == extensionrunner.ErrorInvalidRequest && status.Status == "limits") ||
		status.Status == "cpu_limit" || status.Status == "output_limit" {
		return ErrLocalResourceExhausted
	}
	return nil
}

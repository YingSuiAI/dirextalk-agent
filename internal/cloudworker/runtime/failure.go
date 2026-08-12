package runtime

import "errors"

type FailureCode string

const (
	FailureCodeProcessStart           FailureCode = "process_start"
	FailureCodeProcessTimeout         FailureCode = "process_timeout"
	FailureCodeProcessOutputLimit     FailureCode = "process_output_limit"
	FailureCodeProcessExitNonZero     FailureCode = "process_exit_nonzero"
	FailureCodeProcessWait            FailureCode = "process_wait"
	FailureCodeProcessTopology        FailureCode = "process_topology"
	FailureCodeProviderAuthentication FailureCode = "provider_authentication"
	FailureCodeProviderQuota          FailureCode = "provider_quota"
	FailureCodeProviderRateLimit      FailureCode = "provider_rate_limit"
	FailureCodeModelBudgetExhausted   FailureCode = "model_budget_exhausted"
	FailureCodeProviderRequest        FailureCode = "provider_request"
	FailureCodeProviderServer         FailureCode = "provider_server"
	FailureCodeProviderNetwork        FailureCode = "provider_network"
	FailureCodeProviderUnknown        FailureCode = "provider_unknown"
	FailureCodePiAborted              FailureCode = "pi_aborted"
	FailureCodePiEventInvalid         FailureCode = "pi_event_invalid"
	FailureCodePiFinalMissing         FailureCode = "pi_final_missing"
	FailureCodeOutputInvalid          FailureCode = "output_invalid"
)

type FailureStage string

const (
	FailureStageProcess FailureStage = "process"
	FailureStagePi      FailureStage = "pi"
	FailureStageOutput  FailureStage = "output"
)

// Failure is intentionally closed and contains no provider, process, or user
// diagnostic text. It is safe to persist in control-plane events.
type Failure struct {
	Code  FailureCode
	Stage FailureStage
}

func (failure Failure) Valid() bool {
	switch failure.Stage {
	case FailureStageProcess:
		switch failure.Code {
		case FailureCodeProcessStart, FailureCodeProcessTimeout,
			FailureCodeProcessOutputLimit, FailureCodeProcessExitNonZero,
			FailureCodeProcessWait, FailureCodeProcessTopology:
			return true
		}
	case FailureStagePi:
		switch failure.Code {
		case FailureCodeProviderAuthentication, FailureCodeProviderQuota,
			FailureCodeProviderRateLimit, FailureCodeModelBudgetExhausted,
			FailureCodeProviderRequest,
			FailureCodeProviderServer, FailureCodeProviderNetwork,
			FailureCodeProviderUnknown, FailureCodePiAborted,
			FailureCodePiEventInvalid, FailureCodePiFinalMissing:
			return true
		}
	case FailureStageOutput:
		return failure.Code == FailureCodeOutputInvalid
	}
	return false
}

type failureError struct{ failure Failure }

func (err *failureError) Error() string {
	return ErrExecution.Error() + ": " + string(err.failure.Stage) + "/" +
		string(err.failure.Code)
}

func (*failureError) Unwrap() error { return ErrExecution }

func newFailure(stage FailureStage, code FailureCode) error {
	failure := Failure{Code: code, Stage: stage}
	if !failure.Valid() {
		return ErrExecution
	}
	return &failureError{failure: failure}
}

func FailureOf(err error) (Failure, bool) {
	var typed *failureError
	if !errors.As(err, &typed) || typed == nil || !typed.failure.Valid() {
		return Failure{}, false
	}
	return typed.failure, true
}

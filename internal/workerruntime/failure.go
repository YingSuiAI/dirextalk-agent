package workerruntime

import "errors"

type FailureCode string

const (
	FailureCodeProcessStart           FailureCode = "process_start"
	FailureCodeProcessTimeout         FailureCode = "process_timeout"
	FailureCodeProcessOutputLimit     FailureCode = "process_output_limit"
	FailureCodeProcessExitNonZero     FailureCode = "process_exit_nonzero"
	FailureCodeProviderAuthentication FailureCode = "provider_authentication"
	FailureCodeProviderQuota          FailureCode = "provider_quota"
	FailureCodeProviderRateLimit      FailureCode = "provider_rate_limit"
	FailureCodeProviderRequest        FailureCode = "provider_request"
	FailureCodeProviderServer         FailureCode = "provider_server"
	FailureCodeProviderNetwork        FailureCode = "provider_network"
	FailureCodeProviderUnknown        FailureCode = "provider_unknown"
	FailureCodePiAborted              FailureCode = "pi_aborted"
	FailureCodePiEventInvalid         FailureCode = "pi_event_invalid"
	FailureCodePiFinalMissing         FailureCode = "pi_final_missing"
)

type FailureStage string

const (
	FailureStageProcess FailureStage = "process"
	FailureStagePi      FailureStage = "pi"
)

type Failure struct {
	Code  FailureCode
	Stage FailureStage
}

func (failure Failure) valid() bool {
	if failure.Stage == FailureStageProcess {
		switch failure.Code {
		case FailureCodeProcessStart,
			FailureCodeProcessTimeout,
			FailureCodeProcessOutputLimit,
			FailureCodeProcessExitNonZero:
			return true
		}
	}
	if failure.Stage == FailureStagePi {
		switch failure.Code {
		case FailureCodeProviderAuthentication,
			FailureCodeProviderQuota,
			FailureCodeProviderRateLimit,
			FailureCodeProviderRequest,
			FailureCodeProviderServer,
			FailureCodeProviderNetwork,
			FailureCodeProviderUnknown,
			FailureCodePiAborted,
			FailureCodePiEventInvalid,
			FailureCodePiFinalMissing:
			return true
		}
	}
	return false
}

// Valid reports whether the stage and code form one closed runtime failure.
func (failure Failure) Valid() bool { return failure.valid() }

type failureError struct{ failure Failure }

func (err *failureError) Error() string {
	return ErrExecution.Error() + ": " + string(err.failure.Stage) + "/" +
		string(err.failure.Code)
}

func (*failureError) Unwrap() error { return ErrExecution }

func newFailure(stage FailureStage, code FailureCode) error {
	failure := Failure{Code: code, Stage: stage}
	if !failure.valid() {
		return ErrExecution
	}
	return &failureError{failure: failure}
}

func FailureOf(err error) (Failure, bool) {
	var typed *failureError
	if !errors.As(err, &typed) || typed == nil || !typed.failure.valid() {
		return Failure{}, false
	}
	return typed.failure, true
}

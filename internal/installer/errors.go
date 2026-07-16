package installer

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeInvalidRequest       ErrorCode = "invalid_request"
	CodeRequestTooLarge      ErrorCode = "request_too_large"
	CodeNonCanonicalCBOR     ErrorCode = "non_canonical_cbor"
	CodeUnsupportedAction    ErrorCode = "unsupported_action"
	CodeInvalidSignature     ErrorCode = "invalid_signature"
	CodePlanExpired          ErrorCode = "plan_expired"
	CodeBindingMismatch      ErrorCode = "binding_mismatch"
	CodeIdempotencyConflict  ErrorCode = "idempotency_conflict"
	CodeArtifactNotAllowed   ErrorCode = "artifact_not_allowed"
	CodeInvalidPath          ErrorCode = "invalid_path"
	CodeArtifactVerification ErrorCode = "artifact_verification_failed"
	CodeCommandNotAllowed    ErrorCode = "command_not_allowed"
	CodeLeaseRejected        ErrorCode = "lease_rejected"
	CodeExecutionFailed      ErrorCode = "execution_failed"
	CodeExecutionTimedOut    ErrorCode = "execution_timed_out"
	CodeExecutionInterrupted ErrorCode = "execution_interrupted"
	CodeJournalUnavailable   ErrorCode = "journal_unavailable"
	CodeInternal             ErrorCode = "internal_error"
)

type protocolError struct {
	code ErrorCode
	err  error
}

func (e *protocolError) Error() string {
	if e.err == nil {
		return string(e.code)
	}
	return fmt.Sprintf("%s: %v", e.code, e.err)
}

func (e *protocolError) Unwrap() error { return e.err }

func (e *protocolError) Is(target error) bool {
	other, ok := target.(*protocolError)
	return ok && e.code == other.code
}

func Error(code ErrorCode) error { return &protocolError{code: code} }

func errorf(code ErrorCode, format string, values ...any) error {
	return &protocolError{code: code, err: fmt.Errorf(format, values...)}
}

func ErrorCodeOf(err error) ErrorCode {
	var coded *protocolError
	if errors.As(err, &coded) {
		return coded.code
	}
	return CodeInternal
}

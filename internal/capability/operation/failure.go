package operation

import (
	"errors"
	"strings"
)

// Failure is a safe, typed capability failure that may cross the durable
// operation and query boundaries. Cause remains available only for errors.Is
// and internal tests; clients receive the fixed code and redacted message.
type Failure struct {
	code    string
	message string
	cause   error
}

const (
	KnowledgeQuotaExceededMessage     = "Knowledge content quota is exhausted"
	ExtensionInstallBusyMessage       = "Another extension installation is in progress"
	ExtensionInstallationLimitMessage = "Extension installation capacity is exhausted"
	ExtensionNodeStorageQuotaMessage  = "Managed Node extension storage quota is exhausted"
)

func (e *Failure) Error() string { return e.message }
func (e *Failure) Unwrap() error { return e.cause }

func NewFailure(code, message string, cause error) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	message = strings.TrimSpace(message)
	if code == "" || message == "" || cause == nil {
		return cause
	}
	return &Failure{code: code, message: message, cause: cause}
}

func SafeFailureDetails(code, message string) map[string]string {
	code = strings.ToUpper(strings.TrimSpace(code))
	message = strings.TrimSpace(message)
	if code == "RESOURCE_EXHAUSTED" && message == KnowledgeQuotaExceededMessage {
		return map[string]string{"code": "knowledge_quota_exceeded"}
	}
	if code == "PRECONDITION_FAILED" && message == ExtensionInstallBusyMessage {
		return map[string]string{"code": "extension_install_busy"}
	}
	if code == "RESOURCE_EXHAUSTED" && message == ExtensionInstallationLimitMessage {
		return map[string]string{"code": "extension_installation_limit"}
	}
	if code == "RESOURCE_EXHAUSTED" && message == ExtensionNodeStorageQuotaMessage {
		return map[string]string{"code": "extension_node_storage_quota"}
	}
	return nil
}

func FailureDetails(err error) (code, message string, ok bool) {
	var failure *Failure
	if !errors.As(err, &failure) || failure == nil || failure.code == "" || failure.message == "" {
		return "", "", false
	}
	return failure.code, failure.message, true
}

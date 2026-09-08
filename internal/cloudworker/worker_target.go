package cloudworker

import (
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

var ErrTargetWorkerUnavailable = errors.New("selected Worker is unavailable or does not meet the requested requirements; no replacement Worker will be created")

type workerTargetCorrection struct{ message string }

func (e workerTargetCorrection) Error() string { return e.message }
func (e workerTargetCorrection) Unwrap() error {
	return errors.Join(ErrInvalid, coreconversation.ErrInvalid)
}
func (e workerTargetCorrection) IntrinsicCorrection() string { return e.message }

func NewWorkerServiceConflict() error {
	return workerTargetCorrection{message: "The requested service contract conflicts with the selected Worker's existing service. For maintenance/optimization keep worker_id, set workload_kind=job and omit service; do not redeclare or remove its existing hostname. No new Worker will be created."}
}

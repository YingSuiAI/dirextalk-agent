// Package scheduling owns process-local admission for model-backed Agent work.
// Durable task state remains in PostgreSQL; this budget only prevents a small
// control process from admitting more simultaneous reasoning runs than its
// CPU and memory envelope can safely hold.
package scheduling

import (
	"errors"
	"sync"
)

type RunClass string

const (
	RunInteractive RunClass = "interactive"
	RunBackground  RunClass = "background"
)

var ErrInvalidRunBudget = errors.New("local Agent run budget is invalid")

// Admission is deliberately non-blocking. Interactive callers receive a
// retryable capacity response instead of occupying a goroutine and request
// lease while waiting. Durable background dispatchers leave work queued.
type Admission interface {
	TryAcquire() (release func(), ok bool)
}

type RunBudgetLimits struct {
	MaxActive      int
	MaxInteractive int
	MaxBackground  int
}

type RunBudget struct {
	mu     sync.Mutex
	limits RunBudgetLimits
	active int
	byKind map[RunClass]int
}

func NewRunBudget(limits RunBudgetLimits) (*RunBudget, error) {
	if limits.MaxActive < 1 || limits.MaxInteractive < 1 || limits.MaxInteractive > limits.MaxActive ||
		limits.MaxBackground < 0 || limits.MaxBackground > limits.MaxActive {
		return nil, ErrInvalidRunBudget
	}
	return &RunBudget{limits: limits, byKind: make(map[RunClass]int, 2)}, nil
}

func (budget *RunBudget) Admission(class RunClass) (Admission, error) {
	if budget == nil || (class != RunInteractive && class != RunBackground) {
		return nil, ErrInvalidRunBudget
	}
	return runAdmission{budget: budget, class: class}, nil
}

type runAdmission struct {
	budget *RunBudget
	class  RunClass
}

func (admission runAdmission) TryAcquire() (func(), bool) {
	budget := admission.budget
	if budget == nil {
		return nil, false
	}
	budget.mu.Lock()
	classLimit := budget.limits.MaxInteractive
	if admission.class == RunBackground {
		classLimit = budget.limits.MaxBackground
	}
	if budget.active >= budget.limits.MaxActive || budget.byKind[admission.class] >= classLimit {
		budget.mu.Unlock()
		return nil, false
	}
	budget.active++
	budget.byKind[admission.class]++
	budget.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			budget.mu.Lock()
			budget.active--
			budget.byKind[admission.class]--
			budget.mu.Unlock()
		})
	}, true
}

package coreteam

import (
	"errors"
	"testing"
	"time"
)

func validExecution() Execution {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	return Execution{
		ExecutionID:    "11111111-1111-4111-8111-111111111111",
		PlanID:         "22222222-2222-4222-8222-222222222222",
		TaskID:         "33333333-3333-4333-8333-333333333333",
		ConfirmationID: "44444444-4444-4444-8444-444444444444",
		OwnerID:        "@team:example.test", AccountGeneration: 7,
		Status: ExecutionQueued, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func TestExecutionValidationAndTransitions(t *testing.T) {
	execution := validExecution()
	if err := execution.Validate(); err != nil {
		t.Fatal(err)
	}
	allowed := [][2]ExecutionStatus{
		{ExecutionQueued, ExecutionRunning},
		{ExecutionQueued, ExecutionCanceled},
		{ExecutionQueued, ExecutionTimedOut},
		{ExecutionRunning, ExecutionCleaningUp},
		{ExecutionRunning, ExecutionCompleted},
		{ExecutionRunning, ExecutionFailed},
		{ExecutionRunning, ExecutionCanceled},
		{ExecutionRunning, ExecutionTimedOut},
		{ExecutionCleaningUp, ExecutionCompleted},
		{ExecutionCleaningUp, ExecutionFailed},
		{ExecutionCleaningUp, ExecutionCanceled},
		{ExecutionCleaningUp, ExecutionTimedOut},
	}
	for _, transition := range allowed {
		if !CanTransitionExecution(transition[0], transition[1]) {
			t.Errorf("transition %s -> %s rejected", transition[0], transition[1])
		}
	}
	for _, transition := range [][2]ExecutionStatus{
		{ExecutionQueued, ExecutionCompleted},
		{ExecutionCleaningUp, ExecutionRunning},
		{ExecutionCompleted, ExecutionRunning},
		{ExecutionFailed, ExecutionCleaningUp},
		{"unknown", ExecutionRunning},
	} {
		if CanTransitionExecution(transition[0], transition[1]) {
			t.Errorf("transition %s -> %s accepted", transition[0], transition[1])
		}
	}
}

func TestTerminalExecutionRequiresVerifiedCleanup(t *testing.T) {
	execution := validExecution()
	execution.Status = ExecutionFailed
	execution.UpdatedAt = execution.UpdatedAt.Add(time.Minute)
	if !errors.Is(execution.Validate(), ErrInvalid) {
		t.Fatal("terminal execution without cleanup verification was accepted")
	}
	execution.CleanupVerifiedAt = execution.UpdatedAt
	if err := execution.Validate(); err != nil {
		t.Fatalf("verified terminal execution rejected: %v", err)
	}
	execution.Status = ExecutionCleaningUp
	if !errors.Is(execution.Validate(), ErrInvalid) {
		t.Fatal("nonterminal execution claimed cleanup verification")
	}
}

func TestExecutionValidationRejectsInvalidIdentityAndTime(t *testing.T) {
	for name, mutate := range map[string]func(*Execution){
		"execution id":           func(value *Execution) { value.ExecutionID = "execution" },
		"plan id":                func(value *Execution) { value.PlanID = "plan" },
		"task id":                func(value *Execution) { value.TaskID = "task" },
		"confirmation id":        func(value *Execution) { value.ConfirmationID = "confirmation" },
		"owner":                  func(value *Execution) { value.OwnerID = "@team\n:example.test" },
		"generation":             func(value *Execution) { value.AccountGeneration = 0 },
		"status":                 func(value *Execution) { value.Status = "unknown" },
		"revision":               func(value *Execution) { value.Revision = 0 },
		"created at":             func(value *Execution) { value.CreatedAt = time.Time{} },
		"updated before created": func(value *Execution) { value.UpdatedAt = value.CreatedAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			value := validExecution()
			mutate(&value)
			if !errors.Is(value.Validate(), ErrInvalid) {
				t.Fatalf("value unexpectedly valid: %#v", value)
			}
		})
	}
}

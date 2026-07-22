package scheduling

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRunBudgetEnforcesGlobalAndClassLimits(t *testing.T) {
	budget, err := NewRunBudget(RunBudgetLimits{MaxActive: 2, MaxInteractive: 2, MaxBackground: 1})
	if err != nil {
		t.Fatal(err)
	}
	interactive, _ := budget.Admission(RunInteractive)
	background, _ := budget.Admission(RunBackground)

	releaseBackground, ok := background.TryAcquire()
	if !ok || releaseBackground == nil {
		t.Fatal("first background run was not admitted")
	}
	if release, admitted := background.TryAcquire(); admitted || release != nil {
		t.Fatal("background class limit was not enforced")
	}
	releaseInteractive, ok := interactive.TryAcquire()
	if !ok || releaseInteractive == nil {
		t.Fatal("interactive run did not use the remaining global slot")
	}
	if release, admitted := interactive.TryAcquire(); admitted || release != nil {
		t.Fatal("global run limit was not enforced")
	}

	releaseBackground()
	releaseBackground()
	releaseSecondInteractive, ok := interactive.TryAcquire()
	if !ok || releaseSecondInteractive == nil {
		t.Fatal("idempotent release did not return capacity")
	}
	releaseInteractive()
	releaseSecondInteractive()
}

func TestRunBudgetNeverOversubscribesUnderConcurrency(t *testing.T) {
	budget, err := NewRunBudget(RunBudgetLimits{MaxActive: 2, MaxInteractive: 2, MaxBackground: 1})
	if err != nil {
		t.Fatal(err)
	}
	interactive, _ := budget.Admission(RunInteractive)
	background, _ := budget.Admission(RunBackground)

	start := make(chan struct{})
	releaseAll := make(chan struct{})
	var active atomic.Int32
	var activeBackground atomic.Int32
	var maximum atomic.Int32
	var maximumBackground atomic.Int32
	var wait sync.WaitGroup
	var attempted sync.WaitGroup
	attempted.Add(64)
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			admission := interactive
			isBackground := index%3 == 0
			if isBackground {
				admission = background
			}
			release, ok := admission.TryAcquire()
			if !ok {
				attempted.Done()
				return
			}
			current := active.Add(1)
			updateMaximum(&maximum, current)
			if isBackground {
				currentBackground := activeBackground.Add(1)
				updateMaximum(&maximumBackground, currentBackground)
			}
			attempted.Done()
			<-releaseAll
			if isBackground {
				activeBackground.Add(-1)
			}
			active.Add(-1)
			release()
		}(index)
	}
	close(start)
	attempted.Wait()
	if got := active.Load(); got != 2 {
		t.Fatalf("active runs after concurrent admission = %d, want 2", got)
	}
	close(releaseAll)
	wait.Wait()

	if got := maximum.Load(); got > 2 {
		t.Fatalf("maximum active runs = %d, want at most 2", got)
	}
	if got := maximumBackground.Load(); got > 1 {
		t.Fatalf("maximum background runs = %d, want at most 1", got)
	}
}

func TestRunBudgetRejectsInvalidConfigurationAndClass(t *testing.T) {
	for _, limits := range []RunBudgetLimits{
		{},
		{MaxActive: 1, MaxInteractive: 0, MaxBackground: 0},
		{MaxActive: 1, MaxInteractive: 2, MaxBackground: 0},
		{MaxActive: 1, MaxInteractive: 1, MaxBackground: 2},
	} {
		if _, err := NewRunBudget(limits); !errors.Is(err, ErrInvalidRunBudget) {
			t.Fatalf("limits %#v error = %v", limits, err)
		}
	}
	budget, _ := NewRunBudget(RunBudgetLimits{MaxActive: 1, MaxInteractive: 1})
	if _, err := budget.Admission("unknown"); !errors.Is(err, ErrInvalidRunBudget) {
		t.Fatalf("unknown class error = %v", err)
	}
}

func updateMaximum(maximum *atomic.Int32, candidate int32) {
	for {
		current := maximum.Load()
		if candidate <= current || maximum.CompareAndSwap(current, candidate) {
			return
		}
	}
}

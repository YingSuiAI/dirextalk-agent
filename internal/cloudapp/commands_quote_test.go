package cloudapp

import (
	"testing"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
)

func TestCreateQuoteCommandAllowsServerOwnedWorkerReleaseBinding(t *testing.T) {
	base := coordinatorPlan(time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)).PricingScope()
	scopes := make([]cloudquote.ScopeV1, 0, 3)
	for index, candidate := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		scope := base
		scope.Resource.CandidateID = candidate
		scope.Resource.InstanceType = []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index]
		scope.Resource.VCPU = uint32(2 << index)
		scope.Resource.MemoryMiB = uint64(8192 << index)
		scope.Resource.WorkerImageID = ""
		scope.Resource.WorkerImageDigest = ""
		scopes = append(scopes, scope)
	}
	command := CreateQuoteCommand{
		IdempotencyKey: "019b2d57-b3c0-7e65-a1d2-10c43de26719", Scopes: scopes,
		Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 730},
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("empty server-owned Worker release fields were rejected: %v", err)
	}
	if command.Scopes[0].Resource.WorkerImageID != "" || command.Scopes[0].Resource.WorkerImageDigest != "" {
		t.Fatal("command validation mutated caller scopes")
	}

	partial := command
	partial.Scopes = append([]cloudquote.ScopeV1(nil), command.Scopes...)
	partial.Scopes[0].Resource.WorkerImageID = validationWorkerImageID
	if err := partial.Validate(); err == nil {
		t.Fatal("partial caller Worker image binding was accepted")
	}
}

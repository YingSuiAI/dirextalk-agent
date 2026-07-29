package teamplan

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestPolicyDigestIsCanonicalAndPlanVerificationIsExact(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	digest, err := request.Policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	reordered := request.Policy
	reordered.AllowedRuntimeFamilies = append(
		[]RuntimeFamily(nil),
		request.Policy.AllowedRuntimeFamilies...,
	)
	slices.Reverse(reordered.AllowedRuntimeFamilies)
	reorderedDigest, err := reordered.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if reorderedDigest != digest {
		t.Fatalf(
			"semantically equal policy digest drifted: %s != %s",
			reorderedDigest,
			digest,
		)
	}
	plan, err := Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.PolicyRevision != digest {
		t.Fatalf(
			"Plan policy revision = %q, want %q",
			plan.PolicyRevision,
			digest,
		)
	}
	if err := verifyPlanPolicy(plan, reordered); err != nil {
		t.Fatalf("reordered policy verification error = %v", err)
	}

	tests := map[string]func(*Policy){
		"runtime allowlist": func(value *Policy) {
			value.AllowedRuntimeFamilies = []RuntimeFamily{RuntimeCodex}
		},
		"fixed overhead": func(value *Policy) {
			value.FixedWorkerOverheadMicros++
		},
		"safety margin": func(value *Policy) {
			value.SafetyMarginBasisPoints++
		},
		"worker ceiling": func(value *Policy) {
			value.MaxWorkers = 2
			value.MaxConcurrentWorkers = 2
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			changed := request.Policy
			changed.AllowedRuntimeFamilies = append(
				[]RuntimeFamily(nil),
				request.Policy.AllowedRuntimeFamilies...,
			)
			mutate(&changed)
			if err := verifyPlanPolicy(
				plan,
				changed,
			); !errors.Is(err, ErrPolicyChanged) {
				t.Fatalf(
					"verifyPlanPolicy() error = %v, want ErrPolicyChanged",
					err,
				)
			}
		})
	}
}

func TestPolicyDigestRejectsSubsecondDuration(t *testing.T) {
	t.Parallel()
	policy := validCompileRequest().Policy
	policy.MaxRoleDuration += time.Nanosecond
	if _, err := policy.Digest(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Policy.Digest() error = %v, want ErrInvalid", err)
	}
}

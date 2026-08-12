package cloudworker

import (
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimebounds"
	"github.com/google/uuid"
)

func TestEffectivePlanLimitsBindProfileAndPiRequestCeilings(t *testing.T) {
	t.Parallel()
	defaults := Limits{
		MaxRuntimeSeconds: 3600,
		MaxTokens:         1_000_000,
		MaxOutputBytes:    1 << 20,
	}
	tests := []struct {
		name       string
		profileMax int
		want       uint64
		wantErr    bool
	}{
		{name: "unspecified profile uses Pi cap", profileMax: 0, want: runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens},
		{name: "profile narrows default", profileMax: 2048, want: 2048},
		{name: "large profile uses Pi cap", profileMax: 1 << 20, want: runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens},
		{name: "profile below qualified minimum", profileMax: 511, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testModelExecutionSnapshot(test.profileMax)
			authorization, err := ModelAuthorizationFromSnapshot(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if authorization.MaximumOutputTokens != uint64(test.profileMax) {
				t.Fatalf("profile maximum = %d", authorization.MaximumOutputTokens)
			}
			limits, err := effectivePlanLimits(defaults, authorization)
			requestMaximum, requestErr := effectiveModelOutputTokens(authorization)
			if test.wantErr {
				if !errors.Is(err, ErrInvalid) || !errors.Is(requestErr, ErrInvalid) {
					t.Fatalf("effective limits errors = %v / %v, want ErrInvalid", err, requestErr)
				}
				return
			}
			if err != nil || requestErr != nil || limits.MaxTokens != defaults.MaxTokens ||
				requestMaximum != test.want {
				t.Fatalf("effective limits = %+v request_max=%d errors=%v/%v", limits, requestMaximum, err, requestErr)
			}
		})
	}
}

func TestModelAuthorizationDigestBindsProfileOutputLimit(t *testing.T) {
	t.Parallel()
	first, err := ModelAuthorizationFromSnapshot(testModelExecutionSnapshot(2048))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ModelAuthorizationFromSnapshot(testModelExecutionSnapshot(4096))
	if err != nil {
		t.Fatal(err)
	}
	if first.BindingDigest == second.BindingDigest ||
		first.CredentialBindingDigest == second.CredentialBindingDigest {
		t.Fatal("profile output-limit drift reused model authorization")
	}
}

func testModelExecutionSnapshot(maximum int) coremodel.ExecutionSnapshot {
	return coremodel.ExecutionSnapshot{
		ProfileID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-model-limit")).String(),
		Revision:  2, CredentialVersion: 4,
		Provider: coremodel.ProviderOpenAICompatible,
		BaseURL:  "https://model.example.test/v1", Model: "deepseek-test",
		APIKey: "test-secret", MaxOutputTokens: maximum,
	}
}

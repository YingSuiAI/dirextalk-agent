package cloudworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestLegacyModelAuthorizationRemainsReadableButCannotAuthorizeNewWork(t *testing.T) {
	t.Parallel()
	authorization := ModelAuthorization{
		ModelProfileID: uuid.NewString(), ModelProfileRevision: 2,
		Provider: "openai_compatible", Model: "gpt-test", Interface: "openai_compatible",
		MaximumOutputTokens: 4096, CredentialVersion: 4,
		CredentialBindingDigest: digestValue("legacy-credential"),
	}
	wantBinding := digestValue(struct {
		ModelProfileID          string
		ModelProfileRevision    uint64
		Provider                string
		Model                   string
		Interface               string
		MaximumOutputTokens     uint64
		CredentialVersion       uint64
		CredentialBindingDigest string
	}{authorization.ModelProfileID, authorization.ModelProfileRevision, authorization.Provider, authorization.Model,
		authorization.Interface, authorization.MaximumOutputTokens, authorization.CredentialVersion,
		authorization.CredentialBindingDigest})
	if err := authorization.Seal(); err != nil || authorization.BindingDigest != wantBinding {
		t.Fatalf("legacy binding=%s want=%s err=%v", authorization.BindingDigest, wantBinding, err)
	}
	legacyRaw, _ := json.Marshal(struct {
		ModelAuthorization modelAuthorizationPlanDigestV1
	}{
		ModelAuthorization: authorization.planDigestProjection().(modelAuthorizationPlanDigestV1),
	})
	projectedRaw, _ := json.Marshal(struct{ ModelAuthorization any }{
		ModelAuthorization: authorization.planDigestProjection(),
	})
	if !bytes.Equal(legacyRaw, projectedRaw) {
		t.Fatalf("legacy plan projection drifted: %s != %s", legacyRaw, projectedRaw)
	}
	if _, err := effectivePlanLimits(
		Limits{MaxRuntimeSeconds: 3600, MaxTokens: 1000, MaxOutputBytes: 1 << 20},
		authorization,
		RuntimeEstimate{MinimumSeconds: 600, ExpectedSeconds: 1200, MaximumSeconds: 1800},
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("legacy authorization created new work: %v", err)
	}
}

func TestEffectivePlanLimitsBindProfileAndPiRequestCeilings(t *testing.T) {
	t.Parallel()
	defaults := Limits{
		MaxRuntimeSeconds: 3600,
		MaxOutputBytes:    1 << 20,
	}
	tests := []struct {
		name       string
		profileMax int
		want       uint64
		wantErr    bool
	}{
		{name: "unspecified profile is not guessed", profileMax: 0, wantErr: true},
		{name: "profile narrows default", profileMax: 2048, want: 2048},
		{name: "profile above qualified runtime ceiling", profileMax: 1 << 20, wantErr: true},
		{name: "profile below qualified minimum", profileMax: 511, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testModelExecutionSnapshot(test.profileMax)
			authorization, err := ModelAuthorizationFromSnapshot(snapshot)
			if test.wantErr && errors.Is(err, ErrInvalid) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if authorization.MaximumOutputTokens != uint64(test.profileMax) {
				t.Fatalf("profile maximum = %d", authorization.MaximumOutputTokens)
			}
			limits, err := effectivePlanLimits(
				defaults,
				authorization,
				RuntimeEstimate{MinimumSeconds: 600, ExpectedSeconds: 1200, MaximumSeconds: 1800},
			)
			requestMaximum, requestErr := effectiveModelOutputTokens(authorization)
			if test.wantErr {
				if !errors.Is(err, ErrInvalid) || !errors.Is(requestErr, ErrInvalid) {
					t.Fatalf("effective limits errors = %v / %v, want ErrInvalid", err, requestErr)
				}
				return
			}
			if err != nil || requestErr != nil || limits.MaxTokens != 0 ||
				limits.MinimumRuntimeSeconds != 600 || limits.ExpectedRuntimeSeconds != 1200 || limits.MaxRuntimeSeconds != 1800 ||
				requestMaximum != test.want {
				t.Fatalf("effective limits = %+v request_max=%d errors=%v/%v", limits, requestMaximum, err, requestErr)
			}
		})
	}
}

func TestEffectivePlanLimitsRejectInvalidRuntimeEstimate(t *testing.T) {
	t.Parallel()
	authorization, err := ModelAuthorizationFromSnapshot(testModelExecutionSnapshot(4096))
	if err != nil {
		t.Fatal(err)
	}
	defaults := Limits{MaxRuntimeSeconds: 3600, MaxOutputBytes: 1 << 20}
	for _, test := range []struct {
		name     string
		estimate RuntimeEstimate
	}{
		{name: "below minimum", estimate: RuntimeEstimate{MinimumSeconds: 59, ExpectedSeconds: 120, MaximumSeconds: 300}},
		{name: "expected before minimum", estimate: RuntimeEstimate{MinimumSeconds: 600, ExpectedSeconds: 300, MaximumSeconds: 900}},
		{name: "maximum before expected", estimate: RuntimeEstimate{MinimumSeconds: 300, ExpectedSeconds: 900, MaximumSeconds: 600}},
		{name: "above policy", estimate: RuntimeEstimate{MinimumSeconds: 600, ExpectedSeconds: 1800, MaximumSeconds: 3601}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := effectivePlanLimits(defaults, authorization, test.estimate); !errors.Is(err, ErrInvalid) {
				t.Fatalf("estimate %+v error = %v, want ErrInvalid", test.estimate, err)
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

func TestModelAuthorizationDigestBindsProfileContextWindow(t *testing.T) {
	t.Parallel()
	firstSnapshot := testModelExecutionSnapshot(4096)
	secondSnapshot := firstSnapshot
	secondSnapshot.ContextWindow *= 2
	first, err := ModelAuthorizationFromSnapshot(firstSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ModelAuthorizationFromSnapshot(secondSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContextWindow != uint64(firstSnapshot.ContextWindow) ||
		first.BindingDigest == second.BindingDigest ||
		first.CredentialBindingDigest == second.CredentialBindingDigest {
		t.Fatal("profile context-window drift reused model authorization")
	}
}

func testModelExecutionSnapshot(maximum int) coremodel.ExecutionSnapshot {
	contextWindow := 65536
	if maximum > contextWindow {
		contextWindow = maximum * 2
	}
	return coremodel.ExecutionSnapshot{
		ProfileID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-model-limit")).String(),
		Revision:  2, CredentialVersion: 4,
		Provider: coremodel.ProviderOpenAICompatible,
		BaseURL:  "https://model.example.test/v1", Model: "deepseek-test",
		APIKey: "test-secret", MaxOutputTokens: maximum, ContextWindow: contextWindow,
	}
}

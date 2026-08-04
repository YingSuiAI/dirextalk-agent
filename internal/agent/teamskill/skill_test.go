package teamskill

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

const (
	testRequestID    = "61bf1ec0-2605-4d9a-a28c-84ec2f86b524"
	testConnectionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testGoal         = "Implement the bounded server change and verify it."
)

type policyResolverFunc func(
	context.Context,
	string,
) (teamplan.Policy, error)

func (function policyResolverFunc) ResolveTeamPolicy(
	ctx context.Context,
	ownerID string,
) (teamplan.Policy, error) {
	return function(ctx, ownerID)
}

func TestSkillPreparesServerBoundPlanWithoutExposingExecutionFacts(
	t *testing.T,
) {
	t.Parallel()
	policy := testPolicy()
	var captured PrepareRequest
	calls := 0
	skill, err := New(Dependencies{
		Policies: policyResolverFunc(func(
			_ context.Context,
			ownerID string,
		) (teamplan.Policy, error) {
			if ownerID != "owner-1" {
				t.Fatalf("policy owner = %q", ownerID)
			}
			return policy, nil
		}),
		Preparation: PreparationPortFunc(func(
			_ context.Context,
			request PrepareRequest,
		) (teamorchestration.PlanFact, error) {
			calls++
			captured = request
			return compilePlanFact(t, request, policy), nil
		}),
		TaskLifecycle: testPlanningTaskLifecycle(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindCallScope(context.Background(), CallScope{
		OwnerID:      "owner-1",
		ConnectionID: testConnectionID,
		Goal:         testGoal,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeapi.ToolRequest{
		RequestID:         testRequestID,
		OwnerID:           "owner-1",
		ConversationID:    "conversation-1",
		LatestUserMessage: testGoal,
	}
	tools, err := skill.Tools(ctx, request)
	if err != nil || len(tools) != 1 {
		t.Fatalf("Tools() = %#v, %v", tools, err)
	}
	tool := tools[0]
	if tool.Definition.Name != ToolPrepare {
		t.Fatalf("tool name = %q", tool.Definition.Name)
	}
	encodedSchema, err := json.Marshal(tool.Definition.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"owner_id",
		"connection_id",
		"provider",
		"region",
		"instance_type",
		"price",
		"credential",
		"approval",
		"runtime_image",
		"model_profile_id",
	} {
		if strings.Contains(string(encodedSchema), `"`+forbidden+`"`) {
			t.Fatalf(
				"Team tool schema exposes %q: %s",
				forbidden,
				encodedSchema,
			)
		}
	}
	roleSchema := schemaItems(
		schemaProperty(tool.Definition.InputSchema, "roles"),
	)
	families := schemaItems(
		schemaProperty(roleSchema, "preferred_families"),
	)
	if !reflect.DeepEqual(families["enum"], []string{"pi"}) {
		t.Fatalf("preferred runtime enum = %#v", families["enum"])
	}

	result, err := tool.Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "call-1",
			Name:           ToolPrepare,
			Arguments:      proposalArguments(t),
		},
	)
	if err != nil {
		t.Fatalf("Team plan tool error = %v", err)
	}
	if calls != 1 ||
		captured.OwnerID != request.OwnerID ||
		captured.ConnectionID != testConnectionID ||
		captured.Goal != testGoal {
		t.Fatalf("captured trusted request = %#v, calls=%d", captured, calls)
	}
	if len(result.RelatedTaskIDs) != 1 ||
		len(result.RelatedPlanIDs) != 1 ||
		result.RelatedPlanIDs[0] != uuid.NewSHA1(
			uuid.MustParse(testRequestID),
			[]byte("team-plan\x00owner-1"),
		).String() {
		t.Fatalf("related IDs = %#v, %#v", result.RelatedTaskIDs, result.RelatedPlanIDs)
	}
	for _, forbidden := range []string{
		"secret_ref",
		"credential",
		"account_id",
		"runtime_image",
		"pricing_snapshot",
		"compute_offer",
	} {
		if strings.Contains(result.Content, forbidden) {
			t.Fatalf("model result exposes %q: %s", forbidden, result.Content)
		}
	}
	var view map[string]any
	if json.Unmarshal([]byte(result.Content), &view) != nil ||
		view["signed_approval_required"] != true ||
		view["cloud_resources_started"] != false ||
		view["status"] != string(
			teamorchestration.PlanReadyForConfirmation,
		) {
		t.Fatalf("plan summary = %#v", view)
	}

	var invalid map[string]any
	if json.Unmarshal(proposalArguments(t), &invalid) != nil {
		t.Fatal("decode proposal fixture")
	}
	invalid["region"] = "us-east-1"
	raw, _ := json.Marshal(invalid)
	feedback, err := tool.Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "call-2",
			Name:           ToolPrepare,
			Arguments:      raw,
		},
	)
	if err != nil || !feedback.IsError || calls != 1 ||
		len(feedback.RelatedTaskIDs) != 0 ||
		len(feedback.RelatedPlanIDs) != 0 ||
		strings.Contains(feedback.Content, "us-east-1") ||
		!strings.Contains(feedback.Content, `"reason_code":"proposal_outside_policy"`) ||
		!strings.Contains(feedback.Content, "does not mean a Worker runtime is unavailable") ||
		!strings.Contains(feedback.Content, `"retry_allowed":false`) {
		t.Fatalf(
			"provider-field feedback = %#v, error=%v, calls=%d",
			feedback,
			err,
			calls,
		)
	}
}

func TestSkillReturnsTrustedLimitsAndAllowsOneBoundedCorrection(
	t *testing.T,
) {
	t.Parallel()
	policy := testPolicy()
	policy.MaxRoleDuration = time.Hour
	prepareCalls := 0
	skill, err := New(Dependencies{
		Policies: policyResolverFunc(func(
			context.Context,
			string,
		) (teamplan.Policy, error) {
			return policy, nil
		}),
		Preparation: PreparationPortFunc(func(
			_ context.Context,
			request PrepareRequest,
		) (teamorchestration.PlanFact, error) {
			prepareCalls++
			return compilePlanFact(t, request, policy), nil
		}),
		TaskLifecycle: testPlanningTaskLifecycle(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindCallScope(context.Background(), CallScope{
		OwnerID:      "owner-1",
		ConnectionID: testConnectionID,
		Goal:         testGoal,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeapi.ToolRequest{
		RequestID:         testRequestID,
		OwnerID:           "owner-1",
		ConversationID:    "conversation-1",
		LatestUserMessage: testGoal,
	}
	tools, err := skill.Tools(ctx, request)
	if err != nil || len(tools) != 1 {
		t.Fatalf("Tools() = %#v, %v", tools, err)
	}
	arguments := proposalDocument(t)
	duration := arguments["roles"].([]any)[0].(map[string]any)["duration"].(map[string]any)
	duration["maximum_seconds"] = 4200
	oversized, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	feedback, err := tools[0].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "call-1",
			Name:           ToolPrepare,
			Arguments:      oversized,
		},
	)
	if err != nil || !feedback.IsError || prepareCalls != 0 ||
		!strings.Contains(feedback.Content, `"reason_code":"proposal_outside_policy"`) ||
		!strings.Contains(feedback.Content, "does not mean a Worker runtime is unavailable") ||
		!strings.Contains(feedback.Content, `"retry_allowed":true`) ||
		!strings.Contains(feedback.Content, `"max_role_duration_seconds":3600`) ||
		!strings.Contains(feedback.Content, `"cloud_resources_started":false`) {
		t.Fatalf(
			"oversized proposal feedback = %#v, error=%v, calls=%d",
			feedback,
			err,
			prepareCalls,
		)
	}
	duration["maximum_seconds"] = 3600
	corrected, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tools[0].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "call-2",
			Name:           ToolPrepare,
			Arguments:      corrected,
		},
	)
	if err != nil || result.IsError || prepareCalls != 1 ||
		len(result.RelatedPlanIDs) != 1 {
		t.Fatalf(
			"corrected proposal result = %#v, error=%v, calls=%d",
			result,
			err,
			prepareCalls,
		)
	}
	feedback, err = tools[0].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "call-3",
			Name:           ToolPrepare,
			Arguments:      corrected,
		},
	)
	if err != nil || !feedback.IsError || prepareCalls != 1 ||
		!strings.Contains(feedback.Content, `"reason_code":"retry_exhausted"`) ||
		!strings.Contains(feedback.Content, `"retry_allowed":false`) {
		t.Fatalf(
			"exhausted retry feedback = %#v, error=%v, calls=%d",
			feedback,
			err,
			prepareCalls,
		)
	}
}

func TestSkillClosesUnplannedTaskAfterBoundedEligibilityFailures(
	t *testing.T,
) {
	t.Parallel()
	policy := testPolicy()
	prepareCalls := 0
	closeCalls := 0
	var closedRequest PrepareRequest
	var closedReason string
	skill, err := New(Dependencies{
		Policies: policyResolverFunc(func(
			context.Context,
			string,
		) (teamplan.Policy, error) {
			return policy, nil
		}),
		Preparation: PreparationPortFunc(func(
			context.Context,
			PrepareRequest,
		) (teamorchestration.PlanFact, error) {
			prepareCalls++
			return teamorchestration.PlanFact{}, teamplan.ErrNoRuntime
		}),
		TaskLifecycle: PlanningTaskLifecycleFunc(func(
			_ context.Context,
			request PrepareRequest,
			reasonCode string,
		) error {
			closeCalls++
			closedRequest = request
			closedReason = reasonCode
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindCallScope(context.Background(), CallScope{
		OwnerID:      "owner-1",
		ConnectionID: testConnectionID,
		Goal:         testGoal,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeapi.ToolRequest{
		RequestID:         testRequestID,
		OwnerID:           "owner-1",
		ConversationID:    "conversation-1",
		LatestUserMessage: testGoal,
	}
	tools, err := skill.Tools(ctx, request)
	if err != nil || len(tools) != 1 {
		t.Fatalf("Tools() = %#v, %v", tools, err)
	}
	first, err := tools[0].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "call-1",
			Name:           ToolPrepare,
			Arguments:      proposalArguments(t),
		},
	)
	if err != nil || !first.IsError ||
		!strings.Contains(first.Content, `"retry_allowed":true`) ||
		prepareCalls != 1 || closeCalls != 0 {
		t.Fatalf(
			"first failure=%#v error=%v prepare=%d close=%d",
			first,
			err,
			prepareCalls,
			closeCalls,
		)
	}
	second, err := tools[0].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "call-2",
			Name:           ToolPrepare,
			Arguments:      proposalArguments(t),
		},
	)
	if err != nil || !second.IsError ||
		!strings.Contains(second.Content, `"retry_allowed":false`) ||
		prepareCalls != 2 || closeCalls != 1 ||
		closedReason != "no_qualified_runtime" ||
		closedRequest.RequestID != request.RequestID ||
		closedRequest.OwnerID != request.OwnerID ||
		closedRequest.ConnectionID != testConnectionID ||
		closedRequest.Goal != testGoal {
		t.Fatalf(
			"terminal failure=%#v request=%#v reason=%q error=%v prepare=%d close=%d",
			second,
			closedRequest,
			closedReason,
			err,
			prepareCalls,
			closeCalls,
		)
	}
}

func TestProposalFailureFeedbackSeparatesMarketplaceAndCapacity(
	t *testing.T,
) {
	t.Parallel()
	reason, guidance, retryable, safe := proposalFailureFeedback(
		teamplan.ErrRuntimeRegistryUnavailable,
	)
	if !safe || retryable || reason != "runtime_registry_unavailable" ||
		!strings.Contains(guidance, "do not retry") ||
		!strings.Contains(guidance, "not compute capacity") {
		t.Fatalf(
			"registry feedback reason=%q guidance=%q retryable=%t safe=%t",
			reason,
			guidance,
			retryable,
			safe,
		)
	}
	reason, guidance, retryable, safe = proposalFailureFeedback(
		teamplan.ErrNoCompute,
	)
	if !safe || !retryable || reason != "no_qualified_compute" ||
		!strings.Contains(guidance, "compute offer") {
		t.Fatalf(
			"compute feedback reason=%q guidance=%q retryable=%t safe=%t",
			reason,
			guidance,
			retryable,
			safe,
		)
	}
	reason, guidance, retryable, safe = proposalFailureFeedback(
		teamplan.ErrRuntimeBudget,
	)
	if !safe || !retryable || reason != "runtime_output_budget_too_small" ||
		!strings.Contains(guidance, "512") ||
		!strings.Contains(guidance, "output_maximum") {
		t.Fatalf(
			"runtime budget feedback reason=%q guidance=%q retryable=%t safe=%t",
			reason,
			guidance,
			retryable,
			safe,
		)
	}
}

func TestSkillRejectsUntrustedScopeAndMismatchedGoal(t *testing.T) {
	t.Parallel()
	if _, err := BindCallScope(context.Background(), CallScope{
		OwnerID:      "owner-1",
		ConnectionID: testConnectionID,
		Goal:         "api_key=abcdefghijklmnopqrstuvwxyz",
	}); !errors.Is(err, ErrInvalidCallScope) {
		t.Fatalf("secret goal error = %v", err)
	}
	skill, err := New(Dependencies{
		Policies: policyResolverFunc(func(
			context.Context,
			string,
		) (teamplan.Policy, error) {
			return testPolicy(), nil
		}),
		Preparation: PreparationPortFunc(func(
			context.Context,
			PrepareRequest,
		) (teamorchestration.PlanFact, error) {
			t.Fatal("mismatched request reached preparation")
			return teamorchestration.PlanFact{}, nil
		}),
		TaskLifecycle: testPlanningTaskLifecycle(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindCallScope(context.Background(), CallScope{
		OwnerID:      "owner-1",
		ConnectionID: testConnectionID,
		Goal:         testGoal,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = skill.Tools(ctx, runtimeapi.ToolRequest{
		RequestID:         testRequestID,
		OwnerID:           "owner-1",
		ConversationID:    "conversation-1",
		LatestUserMessage: "different goal",
	})
	if !errors.Is(err, ErrInvocationScopeMismatch) {
		t.Fatalf("mismatched goal error = %v", err)
	}
}

func testPolicy() teamplan.Policy {
	return teamplan.Policy{
		MaxWorkers:                4,
		MaxConcurrentWorkers:      2,
		MaxRoleDuration:           2 * time.Hour,
		MaxVCPUPerWorker:          8,
		MaxMemoryMiBPerWorker:     16 * 1024,
		MaxDiskGiBPerWorker:       200,
		MaxPlanCostMicros:         100_000_000,
		SafetyMarginBasisPoints:   2000,
		FixedWorkerOverheadMicros: 10_000,
		AllowedRuntimeFamilies: []teamplan.RuntimeFamily{
			teamplan.RuntimePi,
		},
	}
}

func testPlanningTaskLifecycle() PlanningTaskLifecycle {
	return PlanningTaskLifecycleFunc(func(
		context.Context,
		PrepareRequest,
		string,
	) error {
		return nil
	})
}

func proposalArguments(t *testing.T) []byte {
	t.Helper()
	document := proposalDocument(t)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func proposalDocument(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"confidence": 90,
		"rationale":  "One isolated implementation Worker is sufficient.",
		"roles": []any{map[string]any{
			"role_id":    "implement",
			"title":      "Implement and verify",
			"objective":  "Implement the requested server change and run focused tests.",
			"work_class": "software.implementation",
			"required_capabilities": []string{
				"repository.read",
				"repository.write",
				"shell",
				"git",
				"test",
				"result.structured",
			},
			"preferred_families": []string{"pi"},
			"workspace":          "isolated_workspace",
			"duration": map[string]any{
				"minimum_seconds":  300,
				"expected_seconds": 900,
				"maximum_seconds":  1800,
			},
			"tokens": map[string]any{
				"input_minimum":   10_000,
				"input_expected":  30_000,
				"input_maximum":   80_000,
				"output_minimum":  2_000,
				"output_expected": 8_000,
				"output_maximum":  20_000,
			},
			"model_need": map[string]any{
				"minimum_quality":        "balanced",
				"minimum_context_tokens": 32_000,
				"vision":                 false,
			},
			"minimum_resources": map[string]any{
				"vcpu":       1,
				"memory_mib": 1024,
				"disk_gib":   20,
			},
		}},
	}
}

func compilePlanFact(
	t *testing.T,
	request PrepareRequest,
	policy teamplan.Policy,
) teamorchestration.PlanFact {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	requestID := uuid.MustParse(request.RequestID)
	goalHash := sha256.Sum256([]byte(strings.TrimSpace(request.Goal)))
	goalDigest := "sha256:" + hex.EncodeToString(goalHash[:])
	taskID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	input, err := taskinput.NewEmptyInput(
		request.OwnerID,
		taskID,
		goalDigest,
	)
	if err != nil {
		t.Fatalf("NewEmptyInput() error = %v", err)
	}
	inputBinding, err := input.Binding()
	if err != nil {
		t.Fatalf("TaskInput Binding() error = %v", err)
	}
	plan, err := teamplan.Compile(teamplan.CompileRequest{
		PlanID: uuid.NewSHA1(
			requestID,
			[]byte("team-plan\x00"+request.OwnerID),
		).String(),
		Revision:   1,
		OwnerID:    request.OwnerID,
		GoalDigest: goalDigest,
		TaskInput:  inputBinding,
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       request.ConnectionID,
			ConnectionRevision: 7,
			AccountID:          "123456789012",
		},
		Region:                "ap-southeast-3",
		CatalogRevision:       "sha256:" + strings.Repeat("1", 64),
		PricingSnapshotID:     "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		PricingSnapshotDigest: "sha256:" + strings.Repeat("2", 64),
		Currency:              "USD",
		QuotedAt:              now,
		ValidUntil:            now.Add(10 * time.Minute),
		Proposal:              request.Proposal,
		RuntimeReleases: []teamplan.RuntimeRelease{{
			ReleaseID:    "20000000-0000-4000-8000-000000000001",
			Family:       teamplan.RuntimePi,
			Version:      "0.83.0",
			SourceURL:    "https://github.com/earendil-works/pi",
			SourceCommit: strings.Repeat("a", 40),
			License:      "MIT",
			ImageDigest:  "sha256:" + strings.Repeat("3", 64),
			Adapter:      teamplan.AdapterPiV1,
			Capabilities: []teamplan.Capability{
				teamplan.CapabilityRepositoryRead,
				teamplan.CapabilityRepositoryWrite,
				teamplan.CapabilityShell,
				teamplan.CapabilityGit,
				teamplan.CapabilityTest,
				teamplan.CapabilityStructuredResults,
			},
			ModelInterfaces: []teamplan.ModelInterface{
				teamplan.ModelOpenAIResponses,
			},
			Suitability: []teamplan.Suitability{{
				WorkClass: teamplan.WorkSoftwareImplementation,
				Score:     100,
			}},
			Minimum: teamplan.ResourceEnvelope{
				VCPU: 1, MemoryMiB: 1024, DiskGiB: 20,
				Arch: recipe.ArchitectureAMD64,
			},
			Recommended: teamplan.ResourceEnvelope{
				VCPU: 2, MemoryMiB: 2048, DiskGiB: 30,
				Arch: recipe.ArchitectureAMD64,
			},
			ColdStart:   30 * time.Second,
			Trust:       teamplan.RuntimeTrustQualified,
			QualifiedAt: now,
		}},
		ModelOffers: []teamplan.ModelOffer{{
			ProfileID:              "openai-pi-worker",
			Provider:               "openai",
			Model:                  "gpt-5.3-codex",
			Interface:              teamplan.ModelOpenAIResponses,
			Quality:                teamplan.QualityBalanced,
			ContextTokens:          128_000,
			InputMicrosPerMillion:  2_000_000,
			OutputMicrosPerMillion: 8_000_000,
			CredentialRef:          "secret_ref:model/openai-pi-worker",
			Enabled:                true,
			CredentialReady:        true,
		}},
		ComputeOffers: []teamplan.ComputeOffer{{
			OfferID:        "30000000-0000-4000-8000-000000000001",
			Region:         "ap-southeast-3",
			InstanceType:   "t3.medium",
			Architecture:   recipe.ArchitectureAMD64,
			VCPU:           2,
			MemoryMiB:      4096,
			DiskGiB:        40,
			HourlyMicros:   80_000,
			PurchaseOption: "on_demand",
			CapacityPool:   "aws:ec2:standard",
			CapacityUnits:  1,
			AvailableUnits: 16,
			Available:      true,
		}},
		Policy: policy,
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return teamorchestration.PlanFact{
		TaskID:         taskID,
		Plan:           plan,
		PlanDigest:     digest,
		Status:         teamorchestration.PlanReadyForConfirmation,
		RecordRevision: 1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func schemaProperty(
	schema map[string]any,
	name string,
) map[string]any {
	properties := schema["properties"].(map[string]any)
	return properties[name].(map[string]any)
}

func schemaItems(schema map[string]any) map[string]any {
	return schema["items"].(map[string]any)
}

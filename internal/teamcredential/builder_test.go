package teamcredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

func TestBuilderCreatesLazySecretOnlyDeploymentCapability(t *testing.T) {
	now := time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC)
	request := credentialBuildFixture(t, now)
	builder, resolver := credentialBuilderFixture(t, now)

	first, err := builder.Build(request)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	second, err := builder.Build(request)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if resolver.calls != 0 {
		t.Fatalf("Build resolved %d credential values", resolver.calls)
	}
	if len(first.SecretRefs) != 1 ||
		first.SecretRefs[0] != request.Intent.ModelCredentialRef ||
		len(first.Bundles.InstallerSecrets) != 1 ||
		first.Bundles.InstallerRootTrust == nil ||
		first.Bundles.InstallerDelivery == nil {
		t.Fatalf("credential bundles=%+v", first)
	}
	staging := first.Bundles.InstallerSecrets[0]
	replayed := second.Bundles.InstallerSecrets[0]
	if staging.VersionID != replayed.VersionID ||
		first.Bundles.InstallerDelivery.TrustID !=
			second.Bundles.InstallerDelivery.TrustID ||
		staging.SlotID !=
			request.Prepared.Fact.Materialization.
				CredentialGrant.CredentialSlot ||
		staging.TargetPath !=
			request.Prepared.Fact.Materialization.
				CredentialTargetPath ||
		staging.FileMode != 0o400 ||
		staging.OwnerUID != workerServiceUID ||
		staging.OwnerGID != workerServiceGID {
		t.Fatalf(
			"non-deterministic or unsafe credential staging=%+v replay=%+v",
			staging,
			replayed,
		)
	}
	plan := first.Bundles.InstallerDelivery.SignedPlan.Plan
	if len(plan.Artifacts) != 0 ||
		len(plan.Commands) != 0 ||
		len(plan.Volumes) != 0 ||
		len(plan.Secrets) != 1 ||
		plan.Binding.AgentInstanceID !=
			request.Intent.AgentInstanceID ||
		plan.Binding.DeploymentID != request.Intent.DeploymentID ||
		plan.Binding.PlanHash != request.Intent.PlanDigest ||
		plan.Binding.ApprovalID != request.Intent.ApprovalID ||
		plan.Binding.RecipeDigest !=
			request.Prepared.Compiled.ManifestDigest {
		t.Fatalf("installer plan=%+v", plan)
	}
	serialized, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("provider-token-value")) {
		t.Fatal("credential plaintext entered compiled bundles")
	}
	var observed []byte
	if err := staging.Content.Materialize(
		context.Background(),
		func(secret []byte) error {
			observed = bytes.Clone(secret)
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if string(observed) != "provider-token-value" ||
		resolver.reference != "mounted:openai-codex" ||
		resolver.calls != 1 {
		t.Fatalf(
			"materialized=%q reference=%q calls=%d",
			observed,
			resolver.reference,
			resolver.calls,
		)
	}
	for index, value := range resolver.secret {
		if value != 0 {
			t.Fatalf("credential byte %d was not cleared", index)
		}
	}
	verified := 0
	if err := staging.Content.Commit(
		context.Background(),
		func() error {
			verified++
			return nil
		},
	); err != nil || verified != 1 {
		t.Fatalf("commit verified=%d error=%v", verified, err)
	}
}

func TestBuilderRejectsCredentialCatalogSubstitutionWithoutSecretRead(
	t *testing.T,
) {
	now := time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC)
	request := credentialBuildFixture(t, now)
	request.Intent.ModelCredentialRef = "secret_ref:model/substituted"
	builder, resolver := credentialBuilderFixture(t, now)

	if _, err := builder.Build(request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("catalog substitution error=%v", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("catalog substitution read %d secrets", resolver.calls)
	}
}

func TestBuilderRejectsLaunchAfterAuthorizationDeadline(t *testing.T) {
	now := time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC)
	request := credentialBuildFixture(t, now)
	request.Intent.LaunchNotAfter = now
	builder, resolver := credentialBuilderFixture(t, now)

	if _, err := builder.Build(request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired launch error=%v", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("expired launch read %d secrets", resolver.calls)
	}
}

func credentialBuilderFixture(
	t *testing.T,
	now time.Time,
) (*Builder, *credentialResolver) {
	t.Helper()
	profiles, err := modelapi.NewProfileCatalog([]modelapi.Profile{{
		ProfileID:       "openai-codex",
		Provider:        modelapi.ProviderOpenAICompatible,
		Model:           "gpt-codex",
		BaseURL:         "https://api.openai.example/v1",
		SecretRef:       "mounted:openai-codex",
		ContextWindow:   256_000,
		MaxOutputTokens: 64_000,
	}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := teampricing.NewModelOfferCatalog(
		teampricing.ModelOfferCatalogDocument{
			SchemaVersion: teampricing.ModelOfferCatalogSchemaV1,
			Currency:      "USD",
			Sources: []teampricing.ModelPriceSource{{
				SourceID: "openai-pricing",
				Digest:   credentialDigest("1"),
				CapturedAt: time.Date(
					2026,
					time.July,
					30,
					8,
					0,
					0,
					0,
					time.UTC,
				),
			}},
			Offers: []teampricing.ModelOfferEntry{{
				ProfileID:              "openai-codex",
				WorkerProvider:         "openai",
				Interface:              teamplan.ModelOpenAIResponses,
				Quality:                teamplan.QualityBalanced,
				InputMicrosPerMillion:  2_000_000,
				OutputMicrosPerMillion: 8_000_000,
				WorkerCredentialRef:    "secret_ref:model/openai-codex",
				Enabled:                true,
				SourceID:               "openai-pricing",
			}},
		},
		profiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &credentialResolver{
		secret: []byte("provider-token-value"),
	}
	credentials, err := teampricing.NewCatalogCredentialReadiness(
		catalog,
		resolver,
	)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Close)
	builder, err := NewBuilder(issuer, credentials, func() time.Time {
		return now
	})
	if err != nil {
		t.Fatal(err)
	}
	return builder, resolver
}

func credentialBuildFixture(
	t *testing.T,
	now time.Time,
) BuildRequest {
	t.Helper()
	agentID := uuid.NewString()
	executionID := uuid.NewString()
	planID := uuid.NewString()
	approvalID := uuid.NewString()
	taskID := uuid.NewString()
	stepID := uuid.NewString()
	deploymentID := uuid.NewString()
	workerID := uuid.NewString()
	roleID := "implement"
	roleDigest := credentialDigest("2")
	executionDigest := credentialDigest("3")
	planDigest := credentialDigest("4")
	contextBytes := []byte(`{"goal":"implement approved change"}`)
	contextDigest := digest(contextBytes)
	workspaceDigest := credentialDigest("5")
	workspaceSize := int64(4096)
	slot := "model-" + strings.Repeat("a", 16)
	runtimeTask := workerruntime.TaskV1{
		SchemaVersion:      workerruntime.TaskSchemaV1,
		TaskID:             taskID,
		RoleID:             roleID,
		Adapter:            workerruntime.AdapterCodexV1,
		RuntimeReleaseID:   uuid.NewString(),
		RuntimeVersion:     "1.0.0",
		RuntimeImageDigest: credentialDigest("6"),
		ContextDigest:      contextDigest,
		WorkspaceMode:      workerruntime.WorkspaceReadOnly,
		WorkspaceDigest:    workspaceDigest,
		Objective:          "Implement the approved change.",
		ModelProfileID:     "openai-codex",
		ModelProvider:      "openai",
		Model:              "gpt-codex",
		ModelInterface:     workerruntime.ModelOpenAIResponses,
		CredentialSlot:     slot,
	}
	runtimeDigest, err := runtimeTask.Digest()
	if err != nil {
		t.Fatal(err)
	}
	manifest := teaminput.ManifestV1{
		SchemaVersion:       teaminput.ManifestSchemaV1,
		ExecutionID:         executionID,
		ExecutionDigest:     executionDigest,
		PlanID:              planID,
		PlanDigest:          planDigest,
		TaskID:              taskID,
		TaskStepID:          stepID,
		RoleID:              roleID,
		RoleDigest:          roleDigest,
		DeploymentID:        deploymentID,
		ExpectedWorkerID:    workerID,
		ContextSnapshotID:   uuid.NewString(),
		ContextDigest:       contextDigest,
		WorkspaceMode:       workerruntime.WorkspaceReadOnly,
		WorkspaceSnapshotID: uuid.NewString(),
		WorkspaceDigest:     workspaceDigest,
		CredentialSlot:      slot,
		RuntimeTaskDigest:   runtimeDigest,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest(manifestBytes)
	contextObject := workerrunner.MaterializeObjectV1{
		ObjectName: "team-context-" +
			strings.TrimPrefix(contextDigest, "sha256:") + ".json",
		SHA256:      contextDigest,
		SizeBytes:   int64(len(contextBytes)),
		ContentType: "application/json",
	}
	workspaceObject := workerrunner.MaterializeObjectV1{
		ObjectName: "team-workspace-" +
			strings.TrimPrefix(workspaceDigest, "sha256:") + ".tar",
		SHA256:      workspaceDigest,
		SizeBytes:   workspaceSize,
		ContentType: "application/x-tar",
	}
	executionBundle := workerrunner.ExecutionBundleV1{
		SchemaVersion: 1,
		RecipeSHA256: strings.TrimPrefix(
			manifestDigest,
			"sha256:",
		),
		Actions: []workerrunner.ActionV1{
			{
				ID:             "materialize-input",
				Kind:           workerrunner.InputMaterializeActionKind,
				TimeoutSeconds: 300,
				Input: &workerrunner.InputMaterializeInputV1{
					Context:   contextObject,
					Workspace: &workspaceObject,
				},
			},
			{
				ID:             "execute-role",
				Kind:           workerrunner.RuntimeExecuteActionKind,
				TimeoutSeconds: 300,
				Runtime: &workerrunner.RuntimeExecuteInputV1{
					Task: runtimeTask,
				},
			},
		},
	}
	executionBytes, err := json.Marshal(executionBundle)
	if err != nil {
		t.Fatal(err)
	}
	grant := teaminput.CredentialGrantRequest{
		ExecutionID:            executionID,
		RoleID:                 roleID,
		DeploymentID:           deploymentID,
		ExpectedWorkerID:       workerID,
		CredentialSlot:         slot,
		ModelProfileID:         runtimeTask.ModelProfileID,
		ModelProvider:          runtimeTask.ModelProvider,
		Model:                  runtimeTask.Model,
		ModelInterface:         runtimeTask.ModelInterface,
		MaximumInputTokens:     10_000,
		MaximumOutputTokens:    2_000,
		MaximumDurationSeconds: 300,
	}
	grantBytes, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	grantDigest := digest(grantBytes)
	clear(grantBytes)
	contextTarget := path.Join(
		workerruntime.DefaultContextRoot,
		strings.TrimPrefix(contextDigest, "sha256:")+".json",
	)
	workspaceTarget := path.Join(
		workerruntime.DefaultWorkspaceRoot,
		strings.TrimPrefix(workspaceDigest, "sha256:"),
	)
	credentialTarget := path.Join(
		workerruntime.DefaultCredentialRoot,
		slot,
	)
	inputID, err := teaminput.InputID(executionID, roleID)
	if err != nil {
		t.Fatal(err)
	}
	materialization := teaminput.MaterializationV1{
		SchemaVersion:         teaminput.MaterializationSchemaV1,
		InputID:               inputID,
		OwnerID:               "owner-1",
		ExecutionID:           executionID,
		ExecutionDigest:       executionDigest,
		RoleID:                roleID,
		RoleDigest:            roleDigest,
		TaskID:                taskID,
		TaskStepID:            stepID,
		DeploymentID:          deploymentID,
		ExpectedWorkerID:      workerID,
		ContextSnapshotID:     manifest.ContextSnapshotID,
		ContextDigest:         contextDigest,
		WorkspaceSnapshotID:   manifest.WorkspaceSnapshotID,
		WorkspaceDigest:       workspaceDigest,
		Manifest:              manifest,
		ManifestDigest:        manifestDigest,
		RuntimeTask:           runtimeTask,
		RuntimeTaskDigest:     runtimeDigest,
		ExecutionBundleDigest: digest(executionBytes),
		CredentialGrant:       grant,
		CredentialGrantDigest: grantDigest,
		ContextTargetPath:     contextTarget,
		WorkspaceTargetPath:   workspaceTarget,
		CredentialTargetPath:  credentialTarget,
	}
	if err := materialization.Validate(); err != nil {
		t.Fatalf("invalid materialization fixture: %v", err)
	}
	prepared := teaminput.PreparedInput{
		Fact: teaminput.Fact{
			Materialization: materialization,
			Status:          teaminput.StatusMaterialized,
			RecordRevision:  1,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		Compiled: teaminput.CompiledInput{
			Manifest:              manifest,
			ManifestBytes:         manifestBytes,
			ManifestDigest:        manifestDigest,
			ContextBytes:          contextBytes,
			RuntimeTask:           runtimeTask,
			ExecutionBytes:        executionBytes,
			ExecutionBundleDigest: materialization.ExecutionBundleDigest,
			ContextObject:         contextObject,
			WorkspaceObject:       workspaceObject,
			CredentialGrant:       grant,
			CredentialGrantDigest: grantDigest,
			ContextTargetPath:     contextTarget,
			WorkspaceTargetPath:   workspaceTarget,
			CredentialTargetPath:  credentialTarget,
		},
	}
	intent := teamdispatch.IntentV1{
		SchemaVersion:             teamdispatch.SchemaV1,
		OperationID:               uuid.NewString(),
		AgentInstanceID:           agentID,
		OwnerID:                   materialization.OwnerID,
		ExecutionID:               executionID,
		ExecutionDigest:           executionDigest,
		PlanID:                    planID,
		PlanRevision:              1,
		PlanDigest:                planDigest,
		ApprovalID:                approvalID,
		LaunchAuthorizationID:     uuid.NewString(),
		LaunchAuthorizationDigest: credentialDigest("7"),
		RoleID:                    roleID,
		RoleDigest:                roleDigest,
		TaskID:                    taskID,
		TaskStepID:                stepID,
		DeploymentID:              deploymentID,
		ExpectedWorkerID:          workerID,
		ModelCredentialRef:        "secret_ref:model/openai-codex",
		MaximumApprovedCostMicros: 100_000,
		LaunchNotAfter:            now.Add(15 * time.Minute),
	}
	if err := intent.Validate(); err != nil {
		t.Fatalf("invalid intent fixture: %v", err)
	}
	return BuildRequest{Intent: intent, Prepared: prepared}
}

func credentialDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

type credentialResolver struct {
	secret    []byte
	reference string
	calls     int
}

func (resolver *credentialResolver) ResolveSecret(
	_ context.Context,
	reference string,
) ([]byte, error) {
	resolver.calls++
	resolver.reference = reference
	return resolver.secret, nil
}

var _ modelapi.SecretResolver = (*credentialResolver)(nil)

package teamprovision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

func TestBuildProjectsExactApprovedTeamWorkerGraph(t *testing.T) {
	t.Parallel()
	request := validTeamProvisionRequest(t)
	graph, err := Build(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Specs) != 4 {
		t.Fatalf("resource count = %d, want 4", len(graph.Specs))
	}
	wantTypes := []resource.Type{
		resource.TypeSG,
		resource.TypeENI,
		resource.TypeEIP,
		resource.TypeEC2,
	}
	for index, spec := range graph.Specs {
		if spec.Type != wantTypes[index] ||
			spec.AgentInstanceID !=
				request.Authorization.AgentInstanceID ||
			spec.OwnerID != request.Dispatch.Intent.OwnerID ||
			spec.TaskID != request.Dispatch.Intent.TaskID ||
			spec.DeploymentID !=
				request.Dispatch.Intent.DeploymentID ||
			spec.ApprovedPlanHash !=
				request.Authorization.PlanDigest ||
			spec.ApprovalID !=
				request.Authorization.ApprovalID ||
			spec.Retention != task.RetentionEphemeralAutoDestroy ||
			!spec.AutoDestroyApproved ||
			spec.Validate(request.Now) != nil {
			t.Fatalf("resource %d lost approved facts: %#v", index, spec)
		}
	}
	group, eni, eip, instance := graph.Specs[0], graph.Specs[1],
		graph.Specs[2], graph.Specs[3]
	if len(group.AWS.SecurityGroup.Ingress) != 0 ||
		!reflect.DeepEqual(
			group.AWS.SecurityGroup.Egress,
			[]resource.AWSNetworkRuleV1{
				{
					Protocol: "tcp",
					FromPort: 443,
					ToPort:   443,
					CIDRv4:   "0.0.0.0/0",
				},
				{
					Protocol: "udp",
					FromPort: 53,
					ToPort:   53,
					CIDRv4:   "169.254.169.253/32",
				},
			},
		) {
		t.Fatalf("security group broadened: %#v", group.AWS.SecurityGroup)
	}
	if !reflect.DeepEqual(eni.DependsOn, []string{group.ResourceID}) ||
		!reflect.DeepEqual(eip.DependsOn, []string{eni.ResourceID}) ||
		!reflect.DeepEqual(
			instance.DependsOn,
			[]string{eni.ResourceID, eip.ResourceID},
		) {
		t.Fatalf(
			"unexpected dependency graph: eni=%v eip=%v ec2=%v",
			eni.DependsOn,
			eip.DependsOn,
			instance.DependsOn,
		)
	}
	approvedRole := request.Authorization.Roles[0]
	ec2 := instance.AWS.Instance
	if ec2.ImageID != approvedRole.WorkerImage.ImageID ||
		ec2.ImageDigest != approvedRole.WorkerImage.ImageDigest ||
		ec2.InstanceType != approvedRole.InstanceType ||
		ec2.Architecture != approvedRole.Architecture ||
		ec2.InstanceProfileName != approvedRole.InstanceProfileName ||
		ec2.RootDeviceName != approvedRole.RootStorage.DeviceName ||
		uint64(ec2.RootVolumeGiB) !=
			approvedRole.RootStorage.SizeGiB ||
		ec2.RootKMSKeyID != approvedRole.RootStorage.KMSKeyID ||
		ec2.Market != resource.AWSMarketOnDemand ||
		!ec2.EBSOptimized ||
		ec2.Bootstrap.DeploymentID !=
			request.Dispatch.Intent.DeploymentID ||
		ec2.Bootstrap.WorkerID !=
			request.Dispatch.Intent.ExpectedWorkerID ||
		ec2.Bootstrap.EnrollmentExpectedRevision !=
			int64(request.Dispatch.ProvisioningWorkerRevision) ||
		ec2.Bootstrap.InstallerTrust == nil ||
		len(ec2.Bootstrap.InstallerArtifacts) != 0 ||
		len(ec2.Bootstrap.InstallerSecrets) != 1 {
		t.Fatalf("EC2 spec is not exact: %#v", ec2)
	}
	quoteDigest, err := request.FreshQuote.Digest()
	if err != nil ||
		graph.FreshQuoteDigest != quoteDigest ||
		graph.CreateAuthorization.ApprovalExpiresAt !=
			request.Authorization.LaunchNotAfter ||
		graph.CreateAuthorization.QuoteValidUntil !=
			request.FreshQuote.ValidUntil ||
		graph.ReconcileOnly {
		t.Fatalf("create authorization mismatch: %#v", graph)
	}
	replay, err := Build(request)
	if err != nil || !reflect.DeepEqual(graph, replay) {
		t.Fatalf("deterministic replay changed graph: err=%v", err)
	}
}

func TestBuildRejectsCrossLayerSubstitutionAndExpiry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*BuildRequest)
		want   error
	}{
		{
			name: "wrong phase",
			mutate: func(value *BuildRequest) {
				value.Dispatch.Phase = teamdispatch.PhaseActive
			},
			want: ErrInvalid,
		},
		{
			name: "authorization substitution",
			mutate: func(value *BuildRequest) {
				value.Authorization.Roles[0].InstanceType = "m7i.xlarge"
			},
			want: ErrFactMismatch,
		},
		{
			name: "fresh role exceeds approval",
			mutate: func(value *BuildRequest) {
				role := &value.FreshQuote.Roles[0]
				role.ComputeMaximumMicros++
				role.TotalMaximumMicros++
				value.FreshQuote.TotalMaximumMicros++
			},
			want: ErrFactMismatch,
		},
		{
			name: "recipe bundle substitution",
			mutate: func(value *BuildRequest) {
				value.Published.Recipe.SHA256[0] ^= 0xff
				value.Deployment.RecipeBundle =
					value.Published.Recipe
			},
			want: ErrFactMismatch,
		},
		{
			name: "model credential target substitution",
			mutate: func(value *BuildRequest) {
				value.Input.CredentialTargetPath += "-other"
			},
			want: ErrFactMismatch,
		},
		{
			name: "control endpoint substitution",
			mutate: func(value *BuildRequest) {
				value.Deployment.ControlPlaneEndpoint =
					"grpcs://other.example.com:443"
			},
			want: ErrFactMismatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validTeamProvisionRequest(t)
			test.mutate(&request)
			_, err := Build(request)
			if !errors.Is(err, test.want) {
				t.Fatalf("Build() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestBuildExpiredEvidenceIsReconciliationOnly(t *testing.T) {
	t.Parallel()
	request := validTeamProvisionRequest(t)
	request.Now = request.FreshQuote.ValidUntil
	graph, err := Build(request)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.ReconcileOnly ||
		request.Dispatch.ProvisioningStartedAt == nil ||
		!graph.CreateAuthorization.QuoteValidUntil.Equal(
			*request.Dispatch.ProvisioningStartedAt,
		) ||
		graph.CreateAuthorization.QuoteValidUntil.After(request.Now) {
		t.Fatalf(
			"expired evidence retained create authority: %#v",
			graph,
		)
	}
	if graph.Specs[3].AWS.Instance.Bootstrap.
		EnrollmentExpectedRevision !=
		int64(request.Dispatch.ProvisioningWorkerRevision) {
		t.Fatal("reconciliation changed frozen Worker revision")
	}
}

func TestBuildEnrolledWorkerIsReconciliationOnly(t *testing.T) {
	t.Parallel()
	request := validTeamProvisionRequest(t)
	request.Deployment.Revision++
	request.Deployment.State = worker.StateReady
	request.Deployment.WorkerID = request.Dispatch.Intent.ExpectedWorkerID
	request.Deployment.ProviderInstanceID = "i-0123456789abcdef0"
	request.Deployment.Enrollment.ConsumedAt = request.Now
	request.Deployment.SessionDigest = sha256.Sum256(
		[]byte("worker-session"),
	)
	request.Deployment.UpdatedAt = request.Now
	graph, err := Build(request)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.ReconcileOnly ||
		graph.Specs[3].AWS.Instance.Bootstrap.
			EnrollmentExpectedRevision !=
			int64(request.Dispatch.ProvisioningWorkerRevision) {
		t.Fatalf("enrolled Worker recovery graph=%#v", graph)
	}
}

func validTeamProvisionRequest(t *testing.T) BuildRequest {
	t.Helper()
	quotedAt := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	agentInstanceID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	approvalID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	plan := teamProvisionPlan(quotedAt)
	release := teamProvisionWorkerRelease(
		t,
		agentInstanceID,
		plan.ProviderScope.AccountID,
		plan.Region,
	)
	authorization, err := teamlaunch.NewAuthorizationV1(
		teamlaunch.BuildRequest{
			Plan:            plan,
			AgentInstanceID: agentInstanceID,
			ApprovalID:      approvalID,
			Network: teamlaunch.NetworkV1{
				ConnectivityMode: teamlaunch.
					ConnectivityDirectPublicTLSV1,
				VPCID:            "vpc-0123456789abcdef0",
				SubnetID:         "subnet-0123456789abcdef0",
				AvailabilityZone: "ap-northeast-3a",
				SecurityGroupMode: teamlaunch.
					SecurityGroupDedicatedNoIngress,
				PublicIPv4:    true,
				PublicInbound: false,
				ControlPlaneEndpoint: "grpcs://" +
					"worker-control.example.com:443",
				Egress: []teamlaunch.EgressRuleV1{
					{
						Protocol: "udp",
						FromPort: 53,
						ToPort:   53,
						CIDRv4:   "169.254.169.253/32",
					},
					{
						Protocol: "tcp",
						FromPort: 443,
						ToPort:   443,
						CIDRv4:   "0.0.0.0/0",
					},
				},
			},
			Retention: teamlaunch.RetentionV1{
				Class:                  teamlaunch.RetentionEphemeralAutoDestroy,
				AutoDestroy:            true,
				MaximumLifetimeSeconds: 2 * 60 * 60,
				DestroyGraceSeconds:    5 * 60,
			},
			LaunchNotBefore: quotedAt.Add(2 * time.Minute),
			LaunchNotAfter:  quotedAt.Add(2*time.Hour + 2*time.Minute),
			RoleSelections: []teamlaunch.RoleSelection{{
				RoleID:                    "implementation",
				RuntimeInstallationDigest: teamProvisionDigest("8"),
				RuntimeExecutableDigest:   teamProvisionDigest("7"),
				WorkerRelease:             release,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorizationDigest, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	now := authorization.LaunchNotBefore.Add(time.Minute)
	quote := teamlaunch.FreshQuoteV1{
		SchemaVersion:       teamlaunch.FreshQuoteSchemaV1,
		AuthorizationID:     authorization.AuthorizationID,
		AuthorizationDigest: authorizationDigest,
		PlanID:              authorization.PlanID,
		PlanRevision:        authorization.PlanRevision,
		PlanDigest:          authorization.PlanDigest,
		ProviderScope:       authorization.ProviderScope,
		Region:              authorization.Region,
		Currency:            authorization.Currency,
		SnapshotID:          "99999999-9999-4999-8999-999999999999",
		SnapshotDigest:      teamProvisionDigest("9"),
		CapturedAt:          authorization.LaunchNotBefore,
		ValidUntil: authorization.LaunchNotBefore.Add(
			15 * time.Minute,
		),
		MaximumQuoteAgeSeconds: authorization.MaximumQuoteAgeSeconds,
		Roles: []teamlaunch.FreshRoleQuoteV1{{
			RoleID:               "implementation",
			ComputeMaximumMicros: 400,
			ModelMaximumMicros:   500,
			FixedOverheadMicros:  100,
			TotalMaximumMicros:   1_000,
		}},
		TotalMaximumMicros: 1_000,
		HardBudgetMicros:   authorization.HardBudgetMicros,
	}
	if err := quote.ValidateAgainstAuthorization(
		authorization,
	); err != nil {
		t.Fatal(err)
	}

	executionID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	taskID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	stepID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	deploymentID := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	expectedWorkerID, err := workeridentity.DeriveWorkerID(deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	intent := teamdispatch.IntentV1{
		SchemaVersion:             teamdispatch.SchemaV1,
		OperationID:               "11111111-1111-4111-8111-111111111111",
		AgentInstanceID:           agentInstanceID,
		OwnerID:                   plan.OwnerID,
		ExecutionID:               executionID,
		ExecutionDigest:           teamProvisionDigest("1"),
		PlanID:                    plan.PlanID,
		PlanRevision:              plan.Revision,
		PlanDigest:                authorization.PlanDigest,
		ApprovalID:                approvalID,
		LaunchAuthorizationID:     authorization.AuthorizationID,
		LaunchAuthorizationDigest: authorizationDigest,
		RoleID:                    "implementation",
		RoleDigest:                teamProvisionDigest("2"),
		TaskID:                    taskID,
		TaskStepID:                stepID,
		DeploymentID:              deploymentID,
		ExpectedWorkerID:          expectedWorkerID,
		ModelCredentialRef:        "secret_ref:models/openai-code",
		MaximumApprovedCostMicros: authorization.Roles[0].
			MaximumApprovedCostMicros,
		LaunchNotAfter: authorization.LaunchNotAfter,
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	dispatch := teamdispatch.Fact{
		Intent:         intent,
		IntentDigest:   intentDigest,
		Phase:          teamdispatch.PhaseIntent,
		Outcome:        task.OutcomePending,
		RecordRevision: 1,
		CreatedAt:      authorization.LaunchNotBefore,
		UpdatedAt:      authorization.LaunchNotBefore,
	}
	if err := dispatch.Validate(); err != nil {
		t.Fatal(err)
	}

	contextDigest := teamProvisionDigest("3")
	workspaceDigest := teamProvisionDigest("4")
	credentialSlot := "model-credential"
	runtimeTask := workerruntime.TaskV1{
		SchemaVersion:      workerruntime.TaskSchemaV1,
		TaskID:             taskID,
		RoleID:             intent.RoleID,
		Adapter:            workerruntime.AdapterCodexV1,
		RuntimeReleaseID:   plan.Assignments[0].RuntimeReleaseID,
		RuntimeVersion:     plan.Assignments[0].RuntimeVersion,
		RuntimeImageDigest: plan.Assignments[0].RuntimeImageDigest,
		ContextDigest:      contextDigest,
		WorkspaceMode:      workerruntime.WorkspaceIsolated,
		WorkspaceDigest:    workspaceDigest,
		Objective:          plan.Assignments[0].Objective,
		ModelProfileID:     plan.Assignments[0].ModelProfileID,
		ModelProvider:      plan.Assignments[0].ModelProvider,
		Model:              plan.Assignments[0].Model,
		ModelInterface:     workerruntime.ModelOpenAIResponses,
		CredentialSlot:     credentialSlot,
		IncludePatch:       true,
	}
	runtimeDigest, err := runtimeTask.Digest()
	if err != nil {
		t.Fatal(err)
	}
	manifest := teaminput.ManifestV1{
		SchemaVersion:       teaminput.ManifestSchemaV1,
		ExecutionID:         executionID,
		ExecutionDigest:     intent.ExecutionDigest,
		PlanID:              plan.PlanID,
		PlanDigest:          authorization.PlanDigest,
		TaskID:              taskID,
		TaskStepID:          stepID,
		RoleID:              intent.RoleID,
		RoleDigest:          intent.RoleDigest,
		DeploymentID:        deploymentID,
		ExpectedWorkerID:    expectedWorkerID,
		ContextSnapshotID:   "22222222-2222-4222-8222-222222222222",
		ContextDigest:       contextDigest,
		WorkspaceMode:       workerruntime.WorkspaceIsolated,
		WorkspaceSnapshotID: "33333333-3333-4333-8333-333333333333",
		WorkspaceDigest:     workspaceDigest,
		CredentialSlot:      credentialSlot,
		RuntimeTaskDigest:   runtimeDigest,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	executionBytes := []byte(`{"schema_version":"test","actions":[]}`)
	credentialTarget := workerruntime.DefaultCredentialRoot +
		"/" + credentialSlot
	input := teaminput.CompiledInput{
		Manifest:              manifest,
		ManifestBytes:         manifestBytes,
		ManifestDigest:        teamProvisionContentDigest(manifestBytes),
		RuntimeTask:           runtimeTask,
		ExecutionBytes:        executionBytes,
		ExecutionBundleDigest: teamProvisionContentDigest(executionBytes),
		CredentialGrant: teaminput.CredentialGrantRequest{
			ExecutionID:            executionID,
			RoleID:                 intent.RoleID,
			DeploymentID:           deploymentID,
			ExpectedWorkerID:       expectedWorkerID,
			CredentialSlot:         credentialSlot,
			ModelProfileID:         plan.Assignments[0].ModelProfileID,
			ModelProvider:          plan.Assignments[0].ModelProvider,
			Model:                  plan.Assignments[0].Model,
			ModelInterface:         workerruntime.ModelOpenAIResponses,
			MaximumInputTokens:     80_000,
			MaximumOutputTokens:    20_000,
			MaximumDurationSeconds: 5 * 60,
		},
		CredentialTargetPath: credentialTarget,
	}

	issuer, err := installer.NewTrustIssuer(
		bytes.Repeat([]byte{0x74}, 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Close)
	versionID := "44444444-4444-4444-8444-444444444444"
	secretName := "dtx/" + agentInstanceID + "/deployments/" +
		deploymentID + "/" + credentialSlot
	secret := installer.SecretV1{
		SlotID:     credentialSlot,
		SecretRef:  intent.ModelCredentialRef,
		SecretName: secretName,
		VersionID:  versionID,
		TargetPath: credentialTarget,
		FileMode:   0o400,
		OwnerUID:   65532,
		OwnerGID:   65532,
	}
	binding := installer.BindingV1{
		AgentInstanceID: agentInstanceID,
		DeploymentID:    deploymentID,
		TaskID:          taskID,
		PlanHash:        authorization.PlanDigest,
		ApprovalID:      approvalID,
		RecipeDigest:    input.ManifestDigest,
	}
	delivery, err := issuer.Issue(
		installer.InstallerPlanV1{
			SchemaVersion: installer.PlanSchemaV1,
			Binding:       binding,
			SecretRefs:    []string{secret.SecretRef},
			Secrets:       []installer.SecretV1{secret},
			ExpiresAt: authorization.LaunchNotAfter.
				Add(30 * time.Minute).
				Format(time.RFC3339Nano),
		},
		installer.DaemonConfigV1{
			SchemaVersion: installer.DaemonConfigSchema,
			Binding:       binding,
			TargetRoot:    installer.PreinstalledArtifactRoot,
		},
		authorization.LaunchNotBefore,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := delivery.RootTrustMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := installerbootstrap.NewRootTrustMaterial(root)
	if err != nil {
		t.Fatal(err)
	}
	secretSource := installerbootstrap.SecretSourceV1{
		SchemaVersion: installerbootstrap.SecretSourceSchemaV1,
		SlotID:        secret.SlotID,
		SecretRef:     secret.SecretRef,
		SecretARN: "arn:aws:secretsmanager:" + plan.Region + ":" +
			plan.ProviderScope.AccountID + ":secret:" +
			secretName + "-abcdef",
		SecretName: secret.SecretName,
		VersionID:  secret.VersionID,
		KMSKeyARN: "arn:aws:kms:" + plan.Region + ":" +
			plan.ProviderScope.AccountID +
			":key/55555555-5555-4555-8555-555555555555",
		TargetPath:   secret.TargetPath,
		FileMode:     secret.FileMode,
		OwnerUID:     secret.OwnerUID,
		OwnerGID:     secret.OwnerGID,
		RecipeDigest: input.ManifestDigest,
	}
	bucket := "dtx-agent-test-artifacts"
	base := "s3://" + bucket + "/deployments/" + deploymentID + "/"
	recipeDigest, err := parseDigest(input.ManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, err := parseDigest(input.ExecutionBundleDigest)
	if err != nil {
		t.Fatal(err)
	}
	launchDigest := sha256.Sum256([]byte("launch"))
	secretAccess := "secret://aws-secretsmanager/" + credentialSlot
	access := worker.AccessScope{
		ArtifactPrefix:   base + "artifacts/",
		CheckpointPrefix: base + "checkpoints/",
		EvidencePrefix:   base + "evidence/",
		LogPrefix:        "cloudwatch://dtx-team/" + deploymentID,
		SecretRefs:       []string{secretAccess},
	}
	published := cloudexecution.PublishedBundles{
		Recipe: worker.BundleRef{
			S3Ref:  base + "bundles/recipe.cbor",
			SHA256: recipeDigest,
		},
		Execution: worker.BundleRef{
			S3Ref:  base + "bundles/execution.json",
			SHA256: executionDigest,
		},
		Launch: cloudexecution.BootstrapArtifact{
			Reference: base + "launch/config.json",
			SHA256:    launchDigest,
		},
		Access:             access,
		SecretBindings:     map[string]string{secret.SecretRef: secretAccess},
		InstallerRootTrust: &trust,
		InstallerArtifacts: []installerbootstrap.ArtifactSourceV1{},
		InstallerSecrets:   []installerbootstrap.SecretSourceV1{secretSource},
	}
	bootstrap := published.Launch
	bootstrap.EnrollmentMaterialRef = "identity://aws-sts/" +
		deploymentID
	enrollmentDigest := sha256.Sum256([]byte("enrollment-credential"))
	deployment := worker.Deployment{
		DeploymentID:         deploymentID,
		OwnerID:              intent.OwnerID,
		TaskID:               taskID,
		StepID:               stepID,
		ControlPlaneEndpoint: authorization.Network.ControlPlaneEndpoint,
		RecipeBundle:         published.Recipe,
		ExecutionBundle:      published.Execution,
		ExecutionTimeout:     5 * time.Minute,
		InstallerDelivery:    &delivery,
		InstallerCommandIDs:  []string{},
		State:                worker.StatePendingEnrollment,
		Outcome:              worker.OutcomePending,
		Access:               access,
		Enrollment: worker.Enrollment{
			CredentialDigest: enrollmentDigest,
			ExpiresAt:        now.Add(10 * time.Minute),
		},
		Revision:  1,
		CreatedAt: authorization.LaunchNotBefore,
		UpdatedAt: authorization.LaunchNotBefore,
	}
	quoteDigest, err := quote.Digest()
	if err != nil {
		t.Fatal(err)
	}
	frozenQuote := quote
	frozenQuote.Roles = append(
		[]teamlaunch.FreshRoleQuoteV1(nil),
		quote.Roles...,
	)
	provisioningStartedAt := now
	enrollmentExpires := deployment.Enrollment.ExpiresAt
	publishedEvidence, err := teamdispatch.NewPublishedEvidenceV1(
		intent,
		plan.ProviderScope.ConnectionID,
		published,
	)
	if err != nil {
		t.Fatal(err)
	}
	publishedEvidenceDigest, err := publishedEvidence.Digest()
	if err != nil {
		t.Fatal(err)
	}
	publishedAt := now
	dispatch.Phase = teamdispatch.PhaseProvisioning
	dispatch.PublishedEvidence = &publishedEvidence
	dispatch.PublishedEvidenceDigest = publishedEvidenceDigest
	dispatch.PublishedAt = &publishedAt
	dispatch.ProvisioningQuote = &frozenQuote
	dispatch.ProvisioningQuoteDigest = quoteDigest
	dispatch.ProvisioningStartedAt = &provisioningStartedAt
	dispatch.ProvisioningWorkerRevision = uint64(deployment.Revision)
	dispatch.ProvisioningEnrollmentExpires = &enrollmentExpires
	dispatch.RecordRevision++
	dispatch.UpdatedAt = provisioningStartedAt
	if err := dispatch.Validate(); err != nil {
		t.Fatal(err)
	}
	return BuildRequest{
		Dispatch:      dispatch,
		Authorization: authorization,
		FreshQuote:    quote,
		Input:         input,
		Published:     published,
		Bootstrap:     bootstrap,
		Deployment:    deployment,
		Now:           now,
	}
}

func teamProvisionPlan(quotedAt time.Time) teamplan.Plan {
	assignment := teamplan.WorkerAssignment{
		RoleID:    "implementation",
		Title:     "Implementation",
		Objective: "Implement and verify the approved change.",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityStructuredResults,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		RuntimeReleaseID:   "66666666-6666-4666-8666-666666666666",
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "0.1.0",
		RuntimeImageDigest: teamProvisionDigest("6"),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     "openai-code",
		ModelProvider:      "openai",
		Model:              "code-model",
		ModelInterface:     teamplan.ModelOpenAIResponses,
		ModelCredentialRef: "secret_ref:models/openai-code",
		ComputeOfferID:     "77777777-7777-4777-8777-777777777777",
		InstanceType:       "m7i.large",
		Resources: teamplan.ResourceEnvelope{
			VCPU:      2,
			MemoryMiB: 8192,
			DiskGiB:   40,
			Arch:      recipe.ArchitectureAMD64,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  time.Minute,
			Expected: 2 * time.Minute,
			Maximum:  5 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   10_000,
			InputExpected:  30_000,
			InputMaximum:   80_000,
			OutputMinimum:  2_000,
			OutputExpected: 8_000,
			OutputMaximum:  20_000,
		},
		ColdStart: 30 * time.Second,
	}
	return teamplan.Plan{
		SchemaVersion: teamplan.SchemaV1,
		PlanID:        "88888888-8888-4888-8888-888888888888",
		Revision:      1,
		OwnerID:       "owner-a",
		GoalDigest:    teamProvisionDigest("a"),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       "99999999-9999-4999-8999-999999999998",
			ConnectionRevision: 11,
			AccountID:          "123456789012",
		},
		Region:                "ap-northeast-3",
		CatalogRevision:       teamProvisionDigest("b"),
		PolicyRevision:        teamProvisionDigest("c"),
		PricingSnapshotID:     "99999999-9999-4999-8999-999999999997",
		PricingSnapshotDigest: teamProvisionDigest("d"),
		QuotedAt:              quotedAt,
		ValidUntil:            quotedAt.Add(teamplan.OfferSnapshotValidity),
		ProposalConfidence:    90,
		ProposalRationale:     "One bounded implementation Worker.",
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Assignments:           []teamplan.WorkerAssignment{assignment},
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  90 * time.Second,
			ExpectedWallTime: 150 * time.Second,
			MaximumWallTime:  330 * time.Second,
		},
		Cost: teamplan.CostEstimate{
			Currency:         "USD",
			MinimumMicros:    500,
			ExpectedMicros:   700,
			MaximumMicros:    1_000,
			HardBudgetMicros: 1_200,
			Roles: []teamplan.RoleCostEstimate{{
				RoleID:                "implementation",
				ComputeMinimumMicros:  100,
				ComputeExpectedMicros: 200,
				ComputeMaximumMicros:  400,
				ModelMinimumMicros:    300,
				ModelExpectedMicros:   400,
				ModelMaximumMicros:    500,
				TotalMinimumMicros:    500,
				TotalExpectedMicros:   700,
				TotalMaximumMicros:    1_000,
			}},
			Assumptions: []string{"on_demand_compute"},
			Exclusions:  []string{"third_party_paid_tools"},
		},
	}
}

func teamProvisionWorkerRelease(
	t *testing.T,
	agentInstanceID,
	accountID,
	region string,
) workerrelease.ReleaseV1 {
	t.Helper()
	image := workerami.ImageManifestV1{
		SchemaVersion:         workerami.ImageManifestSchemaV1,
		AgentInstanceID:       agentInstanceID,
		ImageID:               "ami-0123456789abcdef0",
		ImageName:             "dtx-worker-ami-0123456789abcdef0123",
		RootSnapshotID:        "snap-0123456789abcdef0",
		AccountID:             accountID,
		Region:                region,
		Architecture:          "amd64",
		BaseAMIID:             "ami-0abcdef0123456789",
		BaseAMIOwnerID:        "099720109477",
		RootDeviceName:        "/dev/sda1",
		ReleaseManifestDigest: teamProvisionDigest("e"),
		WorkerRootFSDigest:    teamProvisionDigest("f"),
		WorkerBinaryDigest:    teamProvisionDigest("1"),
		CreatedAt:             "2026-07-30T08:00:00Z",
	}
	evidence := awsprovider.WorkerAMIAttestationV1{
		SchemaVersion:         awsprovider.WorkerAMIAttestationSchemaV1,
		AgentInstanceID:       image.AgentInstanceID,
		AMIID:                 image.ImageID,
		RootSnapshotID:        image.RootSnapshotID,
		AccountID:             image.AccountID,
		Region:                image.Region,
		Architecture:          recipe.ArchitectureAMD64,
		ReleaseManifestDigest: image.ReleaseManifestDigest,
		WorkerRootFSDigest:    image.WorkerRootFSDigest,
		WorkerBinaryDigest:    image.WorkerBinaryDigest,
		ObservedAt: time.Date(
			2026,
			7,
			30,
			8,
			1,
			0,
			0,
			time.UTC,
		),
	}
	imageDigest, err := evidence.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(workerrelease.PublicationV1{
		SchemaVersion: workerrelease.PublicationSchemaV1,
		ImageManifest: image,
		ImageDigest:   imageDigest,
		Attestation:   evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := workerrelease.ParsePublicationJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return release
}

func teamProvisionDigest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}

func teamProvisionContentDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

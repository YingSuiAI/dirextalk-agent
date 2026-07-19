package cloudexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestLaunchApprovedPlanCreatesOneDurableWorkerAndReplaysTerminalOperation(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)

	first, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request)
	if err != nil {
		t.Fatalf("LaunchApprovedPlan() error = %v", err)
	}
	if first.State != StateActive || first.TaskID == "" || len(first.ResourceIDs) != 1 {
		t.Fatalf("operation = %#v", first)
	}
	if fixture.tasks.calls != 1 || fixture.bundles.calls != 1 || fixture.workers.calls != 1 || fixture.bootstraps.calls != 1 || fixture.resources.calls != 1 {
		t.Fatalf("side effects task=%d bundles=%d worker=%d bootstrap=%d resource=%d", fixture.tasks.calls, fixture.bundles.calls, fixture.workers.calls, fixture.bootstraps.calls, fixture.resources.calls)
	}
	approval := fixture.service.facts.(fakeFacts).approval
	if !fixture.resources.authorization.ApprovalExpiresAt.Equal(approval.ExpiresAt) || !fixture.resources.authorization.QuoteValidUntil.Equal(approval.QuoteValidUntil) {
		t.Fatalf("provider create authorization = %+v, approval expiry=%v quote expiry=%v", fixture.resources.authorization, approval.ExpiresAt, approval.QuoteValidUntil)
	}
	if !fixture.bootstraps.destroyedAfterCall {
		t.Fatal("enrollment credential was not wiped after bootstrap publication")
	}

	replayed, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request)
	if err != nil {
		t.Fatalf("replay error = %v", err)
	}
	if replayed.OperationID != first.OperationID || replayed.Revision != first.Revision {
		t.Fatalf("replay = %#v, first = %#v", replayed, first)
	}
	if fixture.tasks.calls != 1 || fixture.bundles.calls != 1 || fixture.workers.calls != 1 || fixture.bootstraps.calls != 1 || fixture.resources.calls != 1 {
		t.Fatal("terminal replay repeated a mutating side effect")
	}
}

func TestLaunchApprovedPlanFailsClosedBeforeMutationWithoutMatchingConnection(t *testing.T) {
	fixture := newLaunchFixture(t, time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC))
	fixture.connections.err = cloudapp.ErrNotFound
	_, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("error = %v, want ErrNotReady", err)
	}
	if fixture.tasks.calls+fixture.bundles.calls+fixture.workers.calls+fixture.bootstraps.calls+fixture.resources.calls != 0 {
		t.Fatal("a cloud mutation ran before connection verification")
	}
}

func TestPrepareApprovedPrivatePlanRejectsUnsignedControlTargetBeforeIntent(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)
	facts := fixture.service.facts.(fakeFacts)
	plan := facts.plan
	plan.Status, plan.Revision, plan.SchemaVersion = cloudapproval.PlanReadyForConfirmation, 1, cloudapproval.PlanSchemaV2
	plan.ResourceScope.Region = cloudquote.WorkerControlPrivateLinkRegion
	plan.ResourceScope.AvailabilityZones = []string{"ap-northeast-3a"}
	plan.NetworkScope = cloudapproval.NetworkScopeV1{
		VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
		SecurityGroupMode: cloudapproval.SecurityGroupCreateDedicated, EntryPoint: cloudapproval.EntryPointNone,
		RouteTableID: "rtb-0123456789abcdef0", ControlPlaneEndpoint: "grpcs://worker-control.y1.dirextalk.ai:443",
		PrivateConnectivity: cloudapproval.PrivateConnectivityNoNATEndpointsV1,
	}
	plan.ServiceOperations = privateEndpointOperationScope()
	var err error
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := cloudapproval.NewApprovalV1(plan, facts.approval.ApprovalID, strings.Repeat("d", 48), "device-1", now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status, plan.Revision = cloudapproval.PlanApproved, 2
	fixture.service.facts = fakeFacts{plan: plan, approval: approval}
	fixture.request.ControlPlaneTarget = "grpcs://different.example.com:443"

	if _, err := fixture.service.PrepareApprovedPlan(context.Background(), fixture.caller, fixture.request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
	if fixture.service.operations.(*memoryOperations).value != nil {
		t.Fatal("mismatched control target reached durable intent mutation")
	}
}

func TestCompileBundlesNeverFallsBackToUnknownAction(t *testing.T) {
	value := launchRecipe(time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC))
	value.Install.Steps[0].Action = "shell.run"
	err := validateExecutionRecipe(value)
	if !errors.Is(err, ErrUnsupportedRecipe) {
		t.Fatalf("error = %v, want ErrUnsupportedRecipe", err)
	}
}

func TestCompileBundlesCarriesStableCapabilityWithoutLeaseGrant(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	value := launchRecipe(now)
	value.Sources[0].ID = "service-release"
	root := installer.PreinstalledArtifactRoot
	value.Install.Installer = &recipe.InstallerCapabilityV1{
		Artifacts: []recipe.InstallerArtifactV1{{Name: "service-installer", SourceID: "service-release", SizeBytes: 32, TargetPath: root + "/service-installer"}},
		Commands:  []recipe.InstallerCommandV1{{CommandID: "install-service", Argv: []string{root + "/service-installer", "install"}, WorkingDirectory: root, TimeoutSeconds: 5, ArtifactRefs: []string{"service-installer"}}},
	}
	value.Install.Steps[0] = recipe.InstallStepV1{ID: "install", Summary: "Install exact service", TimeoutSeconds: 5, Action: installer.ActionExecute, Checkpoint: "done", Inputs: []recipe.ActionInputV1{{Name: "command_id", Kind: recipe.ActionInputConfig, Ref: "install-service"}}}
	recipeDigest, err := value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	binding := installer.BindingV1{AgentInstanceID: uuid.NewString(), DeploymentID: uuid.NewString(), TaskID: uuid.NewString(), PlanHash: testDigest("1"), ApprovalID: uuid.NewString(), RecipeDigest: recipeDigest}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x75}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding,
		Artifacts: []installer.ArtifactV1{{Name: "service-installer", SHA256: value.Sources[0].ArtifactDigest, SizeBytes: 32, TargetPath: root + "/service-installer"}},
		Commands:  []installer.CommandV1{{CommandID: "install-service", Argv: []string{root + "/service-installer", "install"}, WorkingDirectory: root, TimeoutSeconds: 5, ArtifactRefs: []string{"service-installer"}}},
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
	}, installer.DaemonConfigV1{SchemaVersion: installer.DaemonConfigSchema, Binding: binding, TargetRoot: root}, now)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compileBundles(value, &delivery, now)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.InstallerDelivery == nil || compiled.InstallerDelivery.TrustID != delivery.TrustID || len(compiled.InstallerCommandIDs) != 1 || compiled.InstallerCommandIDs[0] != "install-service" || compiled.InstallerRootTrust == nil {
		t.Fatalf("compiled installer capability is incomplete: %+v", compiled)
	}
	if bytes.Contains(compiled.ExecutionBytes, []byte("lease_grant")) || !bytes.Contains(compiled.ExecutionBytes, []byte(`"command_id":"install-service"`)) ||
		!bytes.Contains(compiled.ExecutionBytes, []byte(`"trust_id":"`+delivery.TrustID+`"`)) {
		t.Fatal("execution bundle omitted stable delivery or embedded lease grant")
	}
}

func TestInstallerResolutionUsesArtifactURLNotResearchEvidenceURL(t *testing.T) {
	now := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	configureInstallerLaunch(t, fixture, issuer, now, time.Hour, 5*time.Minute, cloudapproval.RetentionScopeV1{
		Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 60, MaxLifetimeSeconds: 86_400,
	})
	value := fixture.service.recipes.(fakeRecipes).value
	value.Sources[0].ArtifactURL = "https://artifacts.example.com/sha256/" + strings.TrimPrefix(value.Sources[0].ArtifactDigest, "sha256:") + "/service-installer"
	digest, err := value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	facts := fixture.service.facts.(fakeFacts)
	plan := facts.plan
	plan.Status, plan.Revision, plan.Recipe.Digest = cloudapproval.PlanReadyForConfirmation, 1, digest
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := cloudapproval.NewApprovalV1(plan, facts.approval.ApprovalID, strings.Repeat("f", 48), "device-1", now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status, plan.Revision = cloudapproval.PlanApproved, 2
	fixture.service.facts = fakeFacts{plan: plan, approval: approval}
	fixture.service.recipes = fakeRecipes{value: value}
	resolver := &capturingArtifactResolver{}
	fixture.service.artifactResolver = resolver
	if _, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request); err != nil {
		t.Fatal(err)
	}
	if len(resolver.requests) != 1 || resolver.requests[0].SourceURL != value.Sources[0].ArtifactURL || resolver.requests[0].SourceURL == value.Sources[0].URL {
		t.Fatalf("artifact resolution request = %+v", resolver.requests)
	}
}

func TestLaunchInstallerCapabilityOutlivesShortApprovalAndHonorsEphemeralLifetime(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name               string
		maxLifetimeSeconds uint64
		wantExpiry         time.Time
	}{
		{name: "approval expiry is not capability expiry", maxLifetimeSeconds: uint64((24 * time.Hour) / time.Second), wantExpiry: now.Add(2*time.Hour + 30*time.Minute)},
		{name: "ephemeral lifetime caps capability", maxLifetimeSeconds: uint64((45 * time.Minute) / time.Second), wantExpiry: now.Add(45 * time.Minute)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLaunchFixture(t, now)
			issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x76}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer issuer.Close()
			configureInstallerLaunch(t, fixture, issuer, now, 2*time.Hour, 5*time.Minute, cloudapproval.RetentionScopeV1{
				Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 60, MaxLifetimeSeconds: test.maxLifetimeSeconds,
			})

			operation, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request)
			if err != nil {
				t.Fatalf("LaunchApprovedPlan() error = %v", err)
			}
			if operation.InstallerDelivery == nil {
				t.Fatal("launch omitted installer capability")
			}
			expiresAt, err := time.Parse(time.RFC3339Nano, operation.InstallerDelivery.SignedPlan.Plan.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			if !expiresAt.Equal(test.wantExpiry) {
				t.Fatalf("capability expiry = %v, want %v", expiresAt, test.wantExpiry)
			}
			approval := fixture.service.facts.(fakeFacts).approval
			if !expiresAt.After(approval.ExpiresAt) {
				t.Fatalf("capability expiry %v was incorrectly bounded by approval expiry %v", expiresAt, approval.ExpiresAt)
			}
		})
	}
}

func TestInstallerCapabilityExpiryHasSevenDayHardLimitAndFailsClosedWhenExpired(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	value := launchRecipe(now)
	value.Install.TimeoutSeconds = uint32((8 * 24 * time.Hour) / time.Second)
	plan := cloudapproval.PlanV1{RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionManaged}}

	expiresAt, err := installerCapabilityExpiry(value, plan, Operation{Intent: Intent{RecordedAt: now}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(7 * 24 * time.Hour); !expiresAt.Equal(want) {
		t.Fatalf("capability expiry = %v, want seven-day ceiling %v", expiresAt, want)
	}

	plan.RetentionScope = cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, MaxLifetimeSeconds: 60}
	_, err = installerCapabilityExpiry(value, plan, Operation{Intent: Intent{RecordedAt: now.Add(-time.Minute)}}, now)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("expired ephemeral lifetime error = %v, want ErrNotReady", err)
	}
}

func TestAWSResourcePlanUsesOnlyApprovedExistingSecurityGroup(t *testing.T) {
	fixture := newLaunchFixture(t, time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC))
	plan := fixture.service.facts.(fakeFacts).plan
	connection := fixture.connections.value
	recipeValue := fixture.service.recipes.(fakeRecipes).value
	operation := Operation{
		Intent: Intent{Launch: fixture.request, ConnectionID: connection.ConnectionID, ApprovedPlanHash: fixture.service.facts.(fakeFacts).approval.PlanHash, DeploymentID: uuid.NewString()},
		State:  StateBootstrapReady, TaskID: uuid.NewString(), Bootstrap: BootstrapArtifact{SHA256: sha256.Sum256([]byte("launch"))},
		CreatedAt: time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 7, 16, 10, 0, 1, 0, time.UTC),
	}
	operation.Bootstrap.Reference = "s3://agent-bucket/deployments/" + operation.DeploymentID + "/launch/config.json"
	builder, err := NewAWSResourcePlanBuilder(plan.AgentInstanceID, "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := builder.Build(plan, connection, recipeValue, operation)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(specs) != 2 || specs[0].Type != resource.TypeENI || specs[1].Type != resource.TypeEC2 {
		t.Fatalf("specs = %#v", specs)
	}
	if specs[0].AWS.NetworkInterface.ExistingSecurityGroupID != plan.NetworkScope.SecurityGroupID || len(specs[0].DependsOn) != 0 {
		t.Fatal("approved existing security group was replaced by an unapproved owned group")
	}
	if len(specs[1].DependsOn) != 1 || specs[1].DependsOn[0] != specs[0].ResourceID {
		t.Fatal("instance is not bound to its exclusive ENI")
	}
}

func TestAWSResourcePlanBuildsExactNoNATEndpointGraphBeforeWorker(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)
	plan := fixture.service.facts.(fakeFacts).plan
	plan.SchemaVersion = cloudapproval.PlanSchemaV2
	plan.ResourceScope.Region = cloudquote.WorkerControlPrivateLinkRegion
	plan.ResourceScope.AvailabilityZones = []string{"ap-northeast-3a"}
	plan.NetworkScope = cloudapproval.NetworkScopeV1{
		VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
		SecurityGroupMode: cloudapproval.SecurityGroupCreateDedicated, EntryPoint: cloudapproval.EntryPointNone,
		RouteTableID: "rtb-0123456789abcdef0", ControlPlaneEndpoint: "grpcs://worker-control.y1.dirextalk.ai:443",
		PrivateConnectivity: cloudapproval.PrivateConnectivityNoNATEndpointsV1,
	}
	plan.ServiceOperations = privateEndpointOperationScope()
	connection := fixture.connections.value
	connection.Region = cloudquote.WorkerControlPrivateLinkRegion
	operation := Operation{
		Intent: Intent{Launch: fixture.request, ConnectionID: connection.ConnectionID, ApprovedPlanHash: fixture.service.facts.(fakeFacts).approval.PlanHash, DeploymentID: uuid.NewString()},
		State:  StateBootstrapReady, TaskID: uuid.NewString(), Bootstrap: BootstrapArtifact{SHA256: sha256.Sum256([]byte("launch"))},
		CreatedAt: now, UpdatedAt: now.Add(time.Second),
	}
	operation.Launch.ControlPlaneTarget = plan.NetworkScope.ControlPlaneEndpoint
	operation.Bootstrap.Reference = "s3://agent-bucket/deployments/" + operation.DeploymentID + "/launch/config.json"
	builder, err := NewAWSResourcePlanBuilder(plan.AgentInstanceID, "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := builder.Build(plan, connection, fixture.service.recipes.(fakeRecipes).value, operation)
	if err != nil {
		t.Fatal(err)
	}
	wantTypes := []resource.Type{resource.TypeSG, resource.TypeSG, resource.TypeSecurityGroupRule, resource.TypeEndpoint, resource.TypeEndpoint, resource.TypeEndpoint, resource.TypeENI, resource.TypeEC2}
	if len(specs) != len(wantTypes) {
		t.Fatalf("spec count = %d, want %d: %#v", len(specs), len(wantTypes), specs)
	}
	for index, want := range wantTypes {
		if specs[index].Type != want {
			t.Fatalf("spec[%d].Type = %q, want %q", index, specs[index].Type, want)
		}
	}
	workerGroup, endpointGroup, rule := specs[0], specs[1], specs[2]
	if len(endpointGroup.AWS.SecurityGroup.Egress) != 0 || !slices.Equal(rule.DependsOn, []string{workerGroup.ResourceID, endpointGroup.ResourceID}) ||
		rule.AWS.SecurityGroupRule.FromPort != 443 || rule.AWS.SecurityGroupRule.ToPort != 443 {
		t.Fatalf("endpoint security topology = group %#v rule %#v", endpointGroup, rule)
	}
	gateway, secrets, workerControl, eni, instance := specs[3], specs[4], specs[5], specs[6], specs[7]
	if gateway.AWS.Endpoint.EndpointType != resource.AWSVPCEndpointTypeGateway ||
		!slices.Equal(gateway.AWS.Endpoint.RouteTableIDs, []string{plan.NetworkScope.RouteTableID}) || len(gateway.DependsOn) != 0 {
		t.Fatalf("gateway endpoint = %#v", gateway)
	}
	if secrets.AWS.Endpoint.EndpointType != resource.AWSVPCEndpointTypeInterface || secrets.AWS.Endpoint.SubnetID != plan.NetworkScope.SubnetID ||
		!secrets.AWS.Endpoint.PrivateDNSEnabled || !slices.Equal(secrets.DependsOn, []string{endpointGroup.ResourceID}) {
		t.Fatalf("Secrets Manager endpoint = %#v", secrets)
	}
	if workerControl.AWS.Endpoint.ServiceName != "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0" || workerControl.AWS.Endpoint.EndpointType != resource.AWSVPCEndpointTypeInterface ||
		!workerControl.AWS.Endpoint.PrivateDNSEnabled || !slices.Equal(workerControl.DependsOn, []string{endpointGroup.ResourceID}) {
		t.Fatalf("Worker Control endpoint = %#v", workerControl)
	}
	if !slices.Equal(eni.DependsOn, []string{workerGroup.ResourceID}) ||
		!slices.Equal(instance.DependsOn, []string{eni.ResourceID, gateway.ResourceID, secrets.ResourceID, workerControl.ResourceID}) ||
		instance.AWS.Instance.Bootstrap.ControlPlaneEndpoint != plan.NetworkScope.ControlPlaneEndpoint {
		t.Fatalf("Worker endpoint readiness graph: eni=%#v instance=%#v", eni, instance)
	}
}

func privateEndpointOperationScope() *cloudapproval.ServiceOperationScopeV1 {
	return &cloudapproval.ServiceOperationScopeV1{PrivateEndpoints: []cloudapproval.PrivateEndpointOperationSpecV1{
		{OperationKey: "worker-s3-gateway", Service: cloudapproval.PrivateEndpointServiceS3, EndpointType: cloudapproval.PrivateEndpointTypeGateway},
		{OperationKey: "worker-secretsmanager-interface", Service: cloudapproval.PrivateEndpointServiceSecretsManager, EndpointType: cloudapproval.PrivateEndpointTypeInterface,
			SecurityGroupSource: cloudapproval.EndpointSecurityGroupEndpointDedicatedFromWorker, PrivateDNSEnabled: true, MonthlyHours: 730, DataMiBPerMonth: 1},
		{OperationKey: "worker-worker-control-interface", Service: cloudapproval.PrivateEndpointServiceWorkerControl, ServiceName: "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0", EndpointType: cloudapproval.PrivateEndpointTypeInterface,
			SecurityGroupSource: cloudapproval.EndpointSecurityGroupEndpointDedicatedFromWorker, PrivateDNSEnabled: true, MonthlyHours: 730, DataMiBPerMonth: 1},
	}}
}

func TestAWSResourcePlanRejectsUnimplementedPublicEntryPoint(t *testing.T) {
	fixture := newLaunchFixture(t, time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC))
	plan := fixture.service.facts.(fakeFacts).plan
	plan.NetworkScope.EntryPoint = cloudapproval.EntryPointALB
	plan.NetworkScope.PublicExposure = true
	plan.NetworkScope.IngressPorts = []uint32{443}
	plan.NetworkScope.Hostname = "service.example.test"
	plan.NetworkScope.TLSRequired = true
	plan.NetworkScope.AuthenticationRequired = true
	connection := fixture.connections.value
	operation := Operation{
		Intent: Intent{Launch: fixture.request, ConnectionID: connection.ConnectionID, ApprovedPlanHash: fixture.service.facts.(fakeFacts).approval.PlanHash, DeploymentID: uuid.NewString()},
		State:  StateBootstrapReady, TaskID: uuid.NewString(), Bootstrap: BootstrapArtifact{SHA256: sha256.Sum256([]byte("launch"))},
	}
	operation.Bootstrap.Reference = "s3://agent-bucket/deployments/" + operation.DeploymentID + "/launch/config.json"
	builder, err := NewAWSResourcePlanBuilder(plan.AgentInstanceID, "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Build(plan, connection, fixture.service.recipes.(fakeRecipes).value, operation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unimplemented public entry point error = %v, want ErrInvalid", err)
	}
}

func TestAWSResourcePlanRejectsWorkerPublicIPv4(t *testing.T) {
	fixture := newLaunchFixture(t, time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC))
	plan := fixture.service.facts.(fakeFacts).plan
	plan.NetworkScope.SecurityGroupMode = cloudapproval.SecurityGroupCreateDedicated
	plan.NetworkScope.SecurityGroupID = ""
	plan.NetworkScope.PublicIPv4 = true
	connection := fixture.connections.value
	operation := Operation{
		Intent: Intent{Launch: fixture.request, ConnectionID: connection.ConnectionID, ApprovedPlanHash: fixture.service.facts.(fakeFacts).approval.PlanHash, DeploymentID: uuid.NewString()},
		State:  StateBootstrapReady, TaskID: uuid.NewString(), Bootstrap: BootstrapArtifact{SHA256: sha256.Sum256([]byte("launch"))},
		CreatedAt: time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 7, 16, 10, 0, 1, 0, time.UTC),
	}
	operation.Bootstrap.Reference = "s3://agent-bucket/deployments/" + operation.DeploymentID + "/launch/config.json"
	builder, err := NewAWSResourcePlanBuilder(plan.AgentInstanceID, "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Build(plan, connection, fixture.service.recipes.(fakeRecipes).value, operation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("public Worker error = %v, want ErrInvalid", err)
	}
}

func TestAWSResourcePlanCreatesSeparateEncryptedEBSForPersistentRecipeSlot(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)
	plan, recipeValue, approval := bindPersistentVolume(t, fixture)
	connection := fixture.connections.value
	operation := Operation{
		Intent: Intent{Launch: fixture.request, ConnectionID: connection.ConnectionID, ApprovedPlanHash: approval.PlanHash, DeploymentID: uuid.NewString()},
		State:  StateBootstrapReady, TaskID: uuid.NewString(), Bootstrap: BootstrapArtifact{SHA256: sha256.Sum256([]byte("launch"))},
		CreatedAt: time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 7, 17, 10, 0, 1, 0, time.UTC),
	}
	operation.Bootstrap.Reference = "s3://agent-bucket/deployments/" + operation.DeploymentID + "/launch/config.json"
	bindOperationInstallerVolume(t, &operation, plan, approval, now)
	builder, err := NewAWSResourcePlanBuilder(plan.AgentInstanceID, "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := builder.Build(plan, connection, recipeValue, operation)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 3 || specs[0].Type != resource.TypeENI || specs[1].Type != resource.TypeEBS || specs[2].Type != resource.TypeEC2 {
		t.Fatalf("persistent slot topology = %+v", specs)
	}
	volume := specs[1]
	if volume.AWS.Volume == nil || volume.AWS.Volume.SlotID != "knowledge" || volume.AWS.Volume.KMSKeyID == "" ||
		volume.AWS.Volume.DeviceName != "/dev/sdf" || volume.AWS.Volume.MountPath != "/srv/knowledge" ||
		volume.AWS.Volume.Disposition != resource.AWSVolumeDeleteWithDeployment {
		t.Fatalf("data EBS lost approved scope: %+v", volume.AWS.Volume)
	}
	instance := specs[2]
	if instance.AWS.Instance.RootVolumeGiB != uint32(plan.ResourceScope.DiskGiB) || len(instance.AWS.Instance.DataVolumes) != 1 ||
		instance.AWS.Instance.DataVolumes[0].ResourceID != volume.ResourceID || !reflect.DeepEqual(instance.DependsOn, []string{specs[0].ResourceID, volume.ResourceID}) {
		t.Fatalf("persistent slot was not a separate EC2 dependency: %+v", instance)
	}
	replayed, err := builder.Build(plan, connection, recipeValue, operation)
	if err != nil || !reflect.DeepEqual(replayed, specs) {
		t.Fatalf("restart did not reconstruct deterministic volume intents: equal=%v err=%v", reflect.DeepEqual(replayed, specs), err)
	}
}

func TestInstallerDeliveryCarriesOnlySignedNonSecretVolumeBinding(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	configureInstallerLaunch(t, fixture, issuer, now, time.Hour, 5*time.Minute, cloudapproval.RetentionScopeV1{
		Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 60, MaxLifetimeSeconds: 86_400,
	})
	_, _, _ = bindPersistentVolume(t, fixture)
	value := fixture.service.recipes.(fakeRecipes).value
	value.Install.Installer.Commands[0].VolumeSlotRefs = []string{"knowledge"}
	fixture.service.recipes = fakeRecipes{value: value}
	plan := fixture.service.facts.(fakeFacts).plan
	plan.Status, plan.Revision = cloudapproval.PlanReadyForConfirmation, 1
	plan.Recipe.Digest, err = value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	facts := fixture.service.facts.(fakeFacts)
	approval, err := cloudapproval.NewApprovalV1(plan, facts.approval.ApprovalID, strings.Repeat("e", 48), "device-1", now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status, plan.Revision = cloudapproval.PlanApproved, 2
	fixture.service.facts = fakeFacts{plan: plan, approval: approval}

	operation, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	delivery := operation.InstallerDelivery
	if delivery == nil || len(delivery.SignedPlan.Plan.Volumes) != 1 || len(delivery.SignedPlan.Plan.Commands) != 1 ||
		operation.InstallerRootTrust == nil || len(operation.InstallerRootTrust.ArtifactManifest.Manifest.Volumes) != 1 {
		t.Fatalf("installer delivery omitted volume binding: %+v", delivery)
	}
	volume := delivery.SignedPlan.Plan.Volumes[0]
	command := delivery.SignedPlan.Plan.Commands[0]
	if volume.Name != "knowledge" || volume.DeviceName != "/dev/sdf" || volume.MountPath != "/srv/knowledge" ||
		len(command.VolumeRefs) != 1 || command.VolumeRefs[0] != "knowledge" {
		t.Fatalf("installer volume capability mismatch: volume=%+v command=%+v", volume, command)
	}
}

func TestLaunchApprovedPlanStopsBeforeAWSArtifactMutationWhenBootstrapSecretIsNotReady(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	configureInstallerSecretLaunch(t, fixture, issuer, now, "secret_ref:bootstrap/"+uuid.NewString())
	resolver := &fakeInstallerSecretResolver{err: ErrNotReady}
	fixture.service.secretResolver = resolver

	if _, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request); !errors.Is(err, ErrNotReady) {
		t.Fatalf("error=%v", err)
	}
	if resolver.calls != 1 || fixture.bundles.calls+fixture.workers.calls+fixture.bootstraps.calls+fixture.resources.calls != 0 {
		t.Fatalf("unresolved secret reached AWS mutation: resolve=%d bundles=%d workers=%d bootstrap=%d resources=%d",
			resolver.calls, fixture.bundles.calls, fixture.workers.calls, fixture.bootstraps.calls, fixture.resources.calls)
	}
}

func TestLaunchApprovedPlanStagesUploadedBootstrapSecretForArtifactPublisher(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reference := "secret_ref:bootstrap/" + uuid.NewString()
	configureInstallerSecretLaunch(t, fixture, issuer, now, reference)
	content := &fakeInstallerSecretContent{}
	resolver := &fakeInstallerSecretResolver{content: content}
	fixture.service.secretResolver = resolver

	// The generic fake publisher intentionally does not manufacture a signed
	// AWS SecretSource. Reaching it with the resolved content is the boundary
	// under test; production publication/read-back is covered in awsartifact.
	if _, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request); err == nil {
		t.Fatal("fake publisher unexpectedly produced a complete signed secret source")
	}
	if fixture.bundles.calls != 1 || resolver.calls != 1 || content.materializeCalls != 1 || content.commitCalls != 1 ||
		len(fixture.bundles.compiled.InstallerSecrets) != 1 || fixture.bundles.compiled.InstallerSecrets[0].SecretRef != reference {
		t.Fatalf("staging resolve=%d bundle=%d materialize=%d commit=%d secrets=%#v", resolver.calls, fixture.bundles.calls,
			content.materializeCalls, content.commitCalls, fixture.bundles.compiled.InstallerSecrets)
	}
}

func bindPersistentVolume(t *testing.T, fixture launchFixture) (cloudapproval.PlanV1, recipe.RecipeV1, cloudapproval.ApprovalV1) {
	t.Helper()
	recipeValue := fixture.service.recipes.(fakeRecipes).value
	recipeValue.VolumeSlots = []recipe.VolumeSlotRequirementV1{{
		SlotID: "knowledge", Purpose: "persistent knowledge index", MountPath: "/srv/knowledge", Persistent: true, EncryptionRequired: true,
	}}
	digest, err := recipeValue.Digest()
	if err != nil {
		t.Fatal(err)
	}
	facts := fixture.service.facts.(fakeFacts)
	plan := facts.plan
	plan.Status, plan.Revision = cloudapproval.PlanReadyForConfirmation, 1
	plan.Recipe.Digest = digest
	kmsAlias, err := awsfoundation.KMSAliasForAgent(plan.AgentInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	plan.ResourceScope.VolumeScopes = []cloudapproval.VolumeScopeV1{{
		SlotID: "knowledge", SizeGiB: 80, VolumeType: "gp3", IOPS: 3_000, ThroughputMiBPS: 125,
		Encrypted: true, KMSKeyID: kmsAlias, DeviceName: "/dev/sdf", MountPath: "/srv/knowledge",
		Persistent: true, Disposition: cloudapproval.VolumeDeleteWithDeployment,
	}}
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := cloudapproval.NewApprovalV1(plan, facts.approval.ApprovalID, strings.Repeat("f", 48), "device-1", plan.Quote.ValidUntil.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status, plan.Revision = cloudapproval.PlanApproved, 2
	fixture.service.facts = fakeFacts{plan: plan, approval: approval}
	fixture.service.recipes = fakeRecipes{value: recipeValue}
	return plan, recipeValue, approval
}

func bindOperationInstallerVolume(t *testing.T, operation *Operation, plan cloudapproval.PlanV1, approval cloudapproval.ApprovalV1, now time.Time) {
	t.Helper()
	if operation == nil || len(plan.ResourceScope.VolumeScopes) != 1 {
		t.Fatal("volume operation fixture is incomplete")
	}
	volume := plan.ResourceScope.VolumeScopes[0]
	binding := installer.BindingV1{
		AgentInstanceID: plan.AgentInstanceID, DeploymentID: operation.DeploymentID, TaskID: operation.TaskID,
		PlanHash: approval.PlanHash, ApprovalID: approval.ApprovalID, RecipeDigest: plan.Recipe.Digest,
	}
	artifact := installer.ArtifactV1{
		Name: "installer", SHA256: testDigest("a"), SizeBytes: 32, TargetPath: installer.PreinstalledArtifactRoot + "/installer",
	}
	installerPlan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding, Artifacts: []installer.ArtifactV1{artifact},
		Volumes: []installer.VolumeV1{{
			Name: volume.SlotID, DeviceName: volume.DeviceName, MountPath: volume.MountPath, ReadOnly: volume.ReadOnly,
			Persistent: volume.Persistent, Disposition: string(volume.Disposition), SizeGiB: volume.SizeGiB,
		}},
		Commands: []installer.CommandV1{{
			CommandID: "install", Argv: []string{artifact.TargetPath}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 30, ArtifactRefs: []string{artifact.Name}, VolumeRefs: []string{volume.SlotID},
		}},
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x58}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(installerPlan, installer.DaemonConfigV1{
		SchemaVersion: installer.DaemonConfigSchema, Binding: binding, TargetRoot: installer.PreinstalledArtifactRoot,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	root, err := delivery.RootTrustMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	material, err := installerbootstrap.NewRootTrustMaterial(root)
	if err != nil {
		t.Fatal(err)
	}
	operation.InstallerRootTrust = &material
	operation.InstallerArtifacts = []installerbootstrap.ArtifactSourceV1{{
		SchemaVersion: installerbootstrap.ArtifactSourceSchemaV1, Name: artifact.Name, Bucket: "agent-bucket",
		Key: "deployments/" + operation.DeploymentID + "/artifacts/" + artifact.Name, VersionID: "version-1",
		KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555",
		SHA256:    artifact.SHA256, SizeBytes: artifact.SizeBytes, TargetPath: artifact.TargetPath, RecipeDigest: binding.RecipeDigest,
	}}
}

type launchFixture struct {
	service     *Service
	caller      cloudapp.MutationScope
	request     LaunchRequest
	tasks       *fakeTasks
	bundles     *fakeBundles
	workers     *fakeWorkers
	bootstraps  *fakeBootstraps
	resources   *fakeResources
	connections *fakeConnections
}

func newLaunchFixture(t *testing.T, now time.Time) launchFixture {
	t.Helper()
	agentID, ownerID, planID := uuid.NewString(), "owner-1", uuid.NewString()
	connectionID, approvalID := uuid.NewString(), uuid.NewString()
	value := launchRecipe(now)
	digest, err := value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: agentID, OwnerID: ownerID, PlanID: planID,
		Revision: 1, Status: cloudapproval.PlanReadyForConfirmation, ConnectionID: connectionID,
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: value.RecipeID, Digest: digest, Maturity: value.Maturity},
		Quote:  cloudapproval.QuoteBindingV1{QuoteID: uuid.NewString(), Digest: testDigest("b"), CandidateID: "recommended", ValidUntil: now.Add(15 * time.Minute)},
		ResourceScope: cloudapproval.ResourceScopeV1{
			Region: "us-east-1", AvailabilityZones: []string{"us-east-1a"}, InstanceType: "m7i.large", InstanceCount: 1,
			Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 8192, DiskGiB: 40, VolumeType: "gp3",
			VolumeEncrypted: true, PurchaseOption: cloudapproval.PurchaseOnDemand,
			WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: testDigest("c"),
		},
		NetworkScope:   cloudapproval.NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: cloudapproval.EntryPointNone},
		RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
	}
	scopeDigest, err := plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.ScopeDigest = scopeDigest
	approval, err := cloudapproval.NewApprovalV1(plan, approvalID, strings.Repeat("c", 48), "device-1", now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status, plan.Revision = cloudapproval.PlanApproved, 2

	tasks := &fakeTasks{task: task.Task{TaskID: uuid.NewString(), OwnerID: ownerID}}
	bundles, workers, bootstraps, resources := &fakeBundles{}, &fakeWorkers{}, &fakeBootstraps{}, &fakeResources{}
	connections := &fakeConnections{value: cloudapp.Connection{ConnectionID: connectionID, OwnerID: ownerID, AccountID: "123456789012", Region: "us-east-1", ControlRoleARN: "arn:aws:iam::123456789012:role/control", FoundationStack: "stack", Status: "active", Revision: 1}}
	operations := &memoryOperations{}
	service, err := NewService(
		agentID, fakeFacts{plan: plan, approval: approval}, connections, fakeRecipes{value: value}, tasks,
		bundles, workers, bootstraps, fakeResourcePlans{}, resources, operations, func() time.Time { return now },
		WithInstallerArtifactResolver(fakeArtifactResolver{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return launchFixture{
		service: service, caller: cloudapp.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
		request: LaunchRequest{IdempotencyKey: uuid.NewString(), OwnerID: ownerID, PlanID: planID, ApprovalID: approvalID, ControlPlaneTarget: "grpcs://agent.example.com:7443"},
		tasks:   tasks, bundles: bundles, workers: workers, bootstraps: bootstraps, resources: resources, connections: connections,
	}
}

func configureInstallerLaunch(t *testing.T, fixture launchFixture, issuer *installer.TrustIssuer, now time.Time, installTimeout, approvalTTL time.Duration, retention cloudapproval.RetentionScopeV1) {
	t.Helper()
	value := fixture.service.recipes.(fakeRecipes).value
	value.Sources[0].ID = "service-release"
	value.Install.TimeoutSeconds = uint32(installTimeout / time.Second)
	root := installer.PreinstalledArtifactRoot
	value.Install.Installer = &recipe.InstallerCapabilityV1{
		Artifacts: []recipe.InstallerArtifactV1{{Name: "service-installer", SourceID: "service-release", SizeBytes: 32, TargetPath: root + "/service-installer"}},
		Commands: []recipe.InstallerCommandV1{{
			CommandID: "install-service", Argv: []string{root + "/service-installer", "install"}, WorkingDirectory: root,
			TimeoutSeconds: 5, ArtifactRefs: []string{"service-installer"},
		}},
	}
	value.Install.Steps[0] = recipe.InstallStepV1{
		ID: "install", Summary: "Install exact service", TimeoutSeconds: 5, Action: installer.ActionExecute, Checkpoint: "done",
		Inputs: []recipe.ActionInputV1{{Name: "command_id", Kind: recipe.ActionInputConfig, Ref: "install-service"}},
	}
	digest, err := value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	facts := fixture.service.facts.(fakeFacts)
	plan := facts.plan
	plan.Status, plan.Revision = cloudapproval.PlanReadyForConfirmation, 1
	plan.Recipe.Digest = digest
	plan.RetentionScope = retention
	scopeDigest, err := plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.ScopeDigest = scopeDigest
	approval, err := cloudapproval.NewApprovalV1(plan, facts.approval.ApprovalID, strings.Repeat("d", 48), "device-1", now.Add(approvalTTL))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status, plan.Revision = cloudapproval.PlanApproved, 2
	fixture.service.facts = fakeFacts{plan: plan, approval: approval}
	fixture.service.recipes = fakeRecipes{value: value}
	fixture.service.installerTrust = issuer
}

func configureInstallerSecretLaunch(t *testing.T, fixture launchFixture, issuer *installer.TrustIssuer, now time.Time, reference string) {
	t.Helper()
	configureInstallerLaunch(t, fixture, issuer, now, time.Minute, 10*time.Minute, cloudapproval.RetentionScopeV1{
		Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400,
	})
	value := fixture.service.recipes.(fakeRecipes).value
	value.SecretSlots = []recipe.SecretSlotRequirementV1{{
		SlotID: "model-token", Purpose: "model token", Delivery: recipe.SecretDeliveryFile,
		TargetPath: "/etc/dirextalk-service-secrets/model-token", FileMode: 0o400,
	}}
	value.Install.Installer.Commands[0].SecretSlotRefs = []string{"model-token"}
	digest, err := value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	facts := fixture.service.facts.(fakeFacts)
	plan := facts.plan
	plan.Status, plan.Revision = cloudapproval.PlanReadyForConfirmation, 1
	plan.Recipe.Digest = digest
	plan.SecretScope = []cloudapproval.SecretReferenceV1{{SecretRef: reference, Purpose: "model token", Delivery: recipe.SecretDeliveryFile}}
	scopeDigest, err := plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.ScopeDigest = scopeDigest
	approval, err := cloudapproval.NewApprovalV1(plan, facts.approval.ApprovalID, strings.Repeat("e", 48), "device-1", now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status, plan.Revision = cloudapproval.PlanApproved, 2
	fixture.service.facts = fakeFacts{plan: plan, approval: approval}
	fixture.service.recipes = fakeRecipes{value: value}
}

func launchRecipe(now time.Time) recipe.RecipeV1 {
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: uuid.NewString(), Name: "Validation Worker", Maturity: recipe.MaturityExperimental,
		Sources:      []recipe.SourceV1{{URL: "https://example.com/worker", Version: "v0.1.0", Commit: "abcdef0123456789", ArtifactDigest: testDigest("a"), ContentDigest: testDigest("d"), License: "Apache-2.0", RetrievedAt: now, Official: true}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 1, MinMemoryMiB: 1024, MinDiskGiB: 8, Architecture: recipe.ArchitectureAMD64},
		Install:      recipe.InstallContractV1{TimeoutSeconds: 30, CheckpointNames: []string{"done"}, Steps: []recipe.InstallStepV1{{ID: "smoke", Summary: "Validate typed Worker", TimeoutSeconds: 5, Action: "worker.noop", Checkpoint: "done"}}},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
		},
		Lifecycle: recipe.LifecycleContractV1{Start: "worker.start", Stop: "worker.stop", Maintenance: "worker.maintenance", Restart: "worker.restart", Upgrade: "worker.upgrade", Rollback: "worker.rollback", Backup: "worker.backup", Restore: "worker.restore", Destroy: "worker.destroy"},
	}
}

type fakeFacts struct {
	plan     cloudapproval.PlanV1
	approval cloudapproval.ApprovalV1
}

func (facts fakeFacts) LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return facts.plan, nil
}
func (facts fakeFacts) LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error) {
	return facts.approval, nil
}

type fakeConnections struct {
	value cloudapp.Connection
	err   error
}

func (connections *fakeConnections) LoadConnection(context.Context, string, string) (cloudapp.Connection, error) {
	return connections.value, connections.err
}

type fakeRecipes struct{ value recipe.RecipeV1 }

func (recipes fakeRecipes) ResolveRecipe(context.Context, string, string, string) (recipe.RecipeV1, error) {
	return recipes.value, nil
}

type fakeTasks struct {
	task  task.Task
	calls int
}

func (tasks *fakeTasks) Create(context.Context, task.MutationScope, task.CreateCommand) (task.Task, error) {
	tasks.calls++
	return tasks.task, nil
}

type fakeBundles struct {
	calls    int
	compiled CompiledBundles
}

type fakeInstallerSecretResolver struct {
	content InstallerSecretContent
	err     error
	calls   int
}

func (resolver *fakeInstallerSecretResolver) Resolve(context.Context, InstallerSecretResolveRequest) (InstallerSecretContent, error) {
	resolver.calls++
	return resolver.content, resolver.err
}

type fakeInstallerSecretContent struct {
	materializeCalls int
	commitCalls      int
}

func (content *fakeInstallerSecretContent) Materialize(_ context.Context, write func([]byte) error) error {
	content.materializeCalls++
	value := []byte("secret-canary")
	defer clear(value)
	return write(value)
}

func (content *fakeInstallerSecretContent) Commit(_ context.Context, verify func() error) error {
	content.commitCalls++
	return verify()
}

type fakeArtifactResolver struct{}

func (fakeArtifactResolver) Resolve(context.Context, InstallerArtifactResolveRequest) (InstallerArtifactContent, error) {
	return &fakeArtifactContent{reader: bytes.NewReader(bytes.Repeat([]byte{0x61}, 32))}, nil
}

type capturingArtifactResolver struct {
	requests []InstallerArtifactResolveRequest
}

func (resolver *capturingArtifactResolver) Resolve(_ context.Context, request InstallerArtifactResolveRequest) (InstallerArtifactContent, error) {
	resolver.requests = append(resolver.requests, request)
	return &fakeArtifactContent{reader: bytes.NewReader(bytes.Repeat([]byte{0x61}, 32))}, nil
}

type fakeArtifactContent struct {
	reader  *bytes.Reader
	cleaned bool
}

func (content *fakeArtifactContent) Open(context.Context) (io.ReadSeekCloser, error) {
	if content.cleaned {
		return nil, ErrNotReady
	}
	return &readSeekCloser{Reader: content.reader}, nil
}

func (content *fakeArtifactContent) Cleanup() error {
	content.cleaned = true
	return nil
}

type readSeekCloser struct{ *bytes.Reader }

func (*readSeekCloser) Close() error { return nil }

func (publisher *fakeBundles) PublishBundles(ctx context.Context, connection cloudapp.Connection, deploymentID string, compiled CompiledBundles, _ []string) (PublishedBundles, error) {
	publisher.calls++
	publisher.compiled = compiled
	for _, secret := range compiled.InstallerSecrets {
		if secret.Content == nil {
			return PublishedBundles{}, ErrNotReady
		}
		if err := secret.Content.Materialize(ctx, func([]byte) error { return nil }); err != nil {
			return PublishedBundles{}, err
		}
		if err := secret.Content.Commit(ctx, func() error { return nil }); err != nil {
			return PublishedBundles{}, err
		}
	}
	recipeBytes, executionBytes := compiled.RecipeBytes, compiled.ExecutionBytes
	recipeDigest, executionDigest := sha256.Sum256(recipeBytes), sha256.Sum256(executionBytes)
	base := "s3://agent-bucket/workers/" + deploymentID + "/"
	var installerArtifacts []installerbootstrap.ArtifactSourceV1
	if compiled.InstallerRootTrust != nil {
		for _, artifact := range compiled.InstallerRootTrust.ArtifactManifest.Manifest.Artifacts {
			installerArtifacts = append(installerArtifacts, installerbootstrap.ArtifactSourceV1{
				SchemaVersion: installerbootstrap.ArtifactSourceSchemaV1, Name: artifact.Name, Bucket: "agent-bucket",
				Key: "deployments/" + deploymentID + "/artifacts/" + artifact.Name, VersionID: "version-1",
				KMSKeyARN: "arn:aws:kms:" + connection.Region + ":" + connection.AccountID + ":key/11111111-2222-4333-8444-555555555555",
				SHA256:    artifact.SHA256, SizeBytes: artifact.SizeBytes, TargetPath: artifact.TargetPath,
				RecipeDigest: compiled.InstallerRootTrust.ArtifactManifest.Manifest.Binding.RecipeDigest,
			})
		}
	}
	return PublishedBundles{
		Recipe: worker.BundleRef{S3Ref: base + "recipe.cbor", SHA256: recipeDigest}, Execution: worker.BundleRef{S3Ref: base + "execution.json", SHA256: executionDigest},
		Launch: BootstrapArtifact{Reference: base + "launch/config.json", SHA256: sha256.Sum256([]byte("launch"))},
		Access: worker.AccessScope{ArtifactPrefix: base + "artifacts/", CheckpointPrefix: base + "checkpoints/", EvidencePrefix: base + "evidence/", LogPrefix: "cloudwatch://worker-log/" + deploymentID}, SecretBindings: map[string]string{},
		InstallerRootTrust: cloneInstallerRootTrust(compiled.InstallerRootTrust),
		InstallerArtifacts: installerArtifacts,
	}, nil
}

type fakeCredential struct {
	value     []byte
	destroyed bool
}

func (credential *fakeCredential) Reveal() []byte { return bytes.Clone(credential.value) }
func (credential *fakeCredential) Destroy() {
	clear(credential.value)
	credential.destroyed = true
}

type fakeWorkers struct{ calls int }

func (workers *fakeWorkers) CreateDeployment(_ context.Context, _ WorkerCreateMutation, request worker.CreateDeploymentRequest) (worker.Deployment, SensitiveCredential, error) {
	workers.calls++
	return worker.Deployment{DeploymentID: request.DeploymentID, TaskID: request.TaskID, StepID: request.StepID, Revision: 1}, &fakeCredential{value: bytes.Repeat([]byte{0x42}, 48)}, nil
}

type fakeBootstraps struct {
	calls              int
	destroyedAfterCall bool
}

func (publisher *fakeBootstraps) PublishBootstrap(_ context.Context, _ cloudapp.Connection, request BootstrapRequest) (BootstrapArtifact, error) {
	publisher.calls++
	publisher.destroyedAfterCall = len(request.EnrollmentCredential) == 48
	result := request.Launch
	result.EnrollmentMaterialRef = "secret://aws/" + request.DeploymentID
	return result, nil
}

type fakeResourcePlans struct{}

func (fakeResourcePlans) Build(_ cloudapproval.PlanV1, _ cloudapp.Connection, _ recipe.RecipeV1, operation Operation) ([]resource.ProvisionSpec, error) {
	return []resource.ProvisionSpec{{ResourceID: deterministicID(operation.DeploymentID, "ec2")}}, nil
}

type fakeResources struct {
	calls         int
	authorization resource.ProviderCreateAuthorization
}

func (resources *fakeResources) Provision(_ context.Context, _ cloudapp.Connection, spec resource.ProvisionSpec, authorization resource.ProviderCreateAuthorization) (resource.ResourceV1, error) {
	resources.calls++
	resources.authorization = authorization
	return resource.ResourceV1{ResourceID: spec.ResourceID}, nil
}

type memoryOperations struct{ value *Operation }

func (repository *memoryOperations) Begin(_ context.Context, intent Intent) (Operation, bool, error) {
	if repository.value != nil {
		if repository.value.RequestHash != intent.RequestHash {
			return Operation{}, false, ErrRevisionConflict
		}
		return *repository.value, false, nil
	}
	value := Operation{Intent: intent, State: StateIntent, Revision: 1, CreatedAt: intent.RecordedAt, UpdatedAt: intent.RecordedAt}
	repository.value = &value
	return value, true, nil
}
func (repository *memoryOperations) Save(_ context.Context, value Operation, expected int64) (Operation, error) {
	if repository.value == nil || repository.value.Revision != expected {
		return Operation{}, ErrRevisionConflict
	}
	value.Revision++
	repository.value = &value
	return value, nil
}
func (repository *memoryOperations) GetByPlan(context.Context, string, string) (Operation, error) {
	if repository.value == nil {
		return Operation{}, ErrNotReady
	}
	return *repository.value, nil
}
func (repository *memoryOperations) ListRecoverable(context.Context, int) ([]Operation, error) {
	if repository.value == nil || repository.value.State == StateActive {
		return nil, nil
	}
	return []Operation{*repository.value}, nil
}

func testDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }

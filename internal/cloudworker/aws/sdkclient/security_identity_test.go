package sdkclient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestFindStackByIntentRequiresPagedOriginalCreationEvent(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent := sdkSecurityPlanAndIntent(t, now)
	stackID := sdkSecurityStackID(intent.StackName)
	createdAt := now.Add(time.Second)
	stack := sdkSecurityStack(plan, intent, stackID, createdAt)
	root := sdkSecurityRootCreateEvent(intent, stackID, createdAt)
	pages := map[string]*cloudformation.DescribeStackEventsOutput{
		"": {
			StackEvents: []cftypes.StackEvent{{
				EventId: awssdk.String("event-worker-instance"), StackId: awssdk.String(stackID), StackName: awssdk.String(intent.StackName),
				Timestamp: awssdk.Time(createdAt.Add(time.Second)), ClientRequestToken: awssdk.String(intent.ClientToken),
				LogicalResourceId: awssdk.String(cloudaws.LogicalID(cloudaws.ResourceEC2)), PhysicalResourceId: awssdk.String("i-0123456789abcdef0"),
				ResourceType: awssdk.String("AWS::EC2::Instance"), ResourceStatus: cftypes.ResourceStatusCreateInProgress,
			}},
			NextToken: awssdk.String("page-2"),
		},
		"page-2": {StackEvents: []cftypes.StackEvent{root}},
	}
	client, cfn := sdkSecurityClient(t, now.Add(2*time.Second), stack, pages, nil)
	reference, found, err := client.FindStackByIntent(context.Background(), cloudaws.FindStackRequest{
		Identity: plan.Identity, Intent: intent, MutationDispatchedAt: now, MutationDeadline: now.Add(30 * time.Second),
	})
	if err != nil || !found || reference.ProviderID != stackID || reference.ClientToken != intent.ClientToken ||
		reference.CreationIdentity.StackID != stackID || reference.CreationIdentity.CreationEventID != awssdk.ToString(root.EventId) ||
		!reference.CreationIdentity.CreationTime.Equal(createdAt) {
		t.Fatalf("creation proof=%+v found=%t err=%v", reference, found, err)
	}
	cfn.mu.Lock()
	defer cfn.mu.Unlock()
	if len(cfn.eventInputs) != 2 || awssdk.ToString(cfn.eventInputs[0].StackName) != stackID ||
		awssdk.ToString(cfn.eventInputs[1].StackName) != stackID || awssdk.ToString(cfn.eventInputs[1].NextToken) != "page-2" {
		t.Fatalf("DescribeStackEvents was not exact-ID paginated: %+v", cfn.eventInputs)
	}
}

func TestGraphStateFailsClosedOnTerminalProvisioningFailure(t *testing.T) {
	for _, status := range []cftypes.StackStatus{
		cftypes.StackStatusCreateFailed,
		cftypes.StackStatusRollbackFailed,
		cftypes.StackStatusRollbackComplete,
		cftypes.StackStatusUpdateFailed,
		cftypes.StackStatusUpdateRollbackFailed,
		cftypes.StackStatusUpdateRollbackComplete,
	} {
		if state, err := graphState(status); err != nil || state != cloudaws.GraphFailed {
			t.Fatalf("terminal stack status %s state=%s err=%v", status, state, err)
		}
	}
	for _, status := range []cftypes.StackStatus{
		cftypes.StackStatusCreateInProgress,
		cftypes.StackStatusRollbackInProgress,
		cftypes.StackStatusUpdateRollbackInProgress,
	} {
		if state, err := graphState(status); err != nil || state != cloudaws.GraphProvisioning {
			t.Fatalf("in-progress stack status %s state=%s err=%v", status, state, err)
		}
	}
}

func TestObserveTerminalRollbackWithoutIAMResourcesReadsNamesAsAbsent(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent := sdkSecurityPlanAndIntent(t, now)
	stackID := sdkSecurityStackID(intent.StackName)
	stack := sdkSecurityStack(plan, intent, stackID, now.Add(time.Second))
	stack.StackStatus = cftypes.StackStatusRollbackComplete
	iamFake := &securityIAMFake{roleMissing: true, profileMissing: true}
	client, cfn := sdkSecurityClient(t, now.Add(2*time.Second), stack, nil, iamFake)
	cfn.emptyStackResources = true
	policy, err := plan.Network.SecurityGroupPolicy()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := client.ObserveGraph(context.Background(), cloudaws.ObserveGraphRequest{
		Identity: plan.Identity, Plan: plan, PlanDigest: plan.Digest, InfrastructureDigest: plan.InfrastructureDigest,
		IntentDigest: intent.IntentDigest, ClientToken: intent.ClientToken, StackProviderID: stackID,
		ExpectedResourceProviderIDs: map[cloudaws.ResourceKind]string{cloudaws.ResourceStack: stackID},
		ExpectedTags:                cloudaws.RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest),
		SecurityGroupPolicy:         policy,
	})
	if err != nil || graph.State != cloudaws.GraphFailed || len(graph.Resources) != len(cloudaws.AllResourceKinds()) {
		t.Fatalf("terminal rollback graph=%+v err=%v", graph, err)
	}
	for _, kind := range []cloudaws.ResourceKind{cloudaws.ResourceIAMRole, cloudaws.ResourceInstanceProfile} {
		for _, resource := range graph.Resources {
			if resource.Kind == kind && resource.Exists {
				t.Fatalf("%s was not observed absent: %+v", kind, resource)
			}
		}
	}
}

func TestFindStackByIntentFailsClosedOnReplacementVisibilityAndPagination(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent := sdkSecurityPlanAndIntent(t, now)
	stackID := sdkSecurityStackID(intent.StackName)
	createdAt := now.Add(time.Second)
	stack := sdkSecurityStack(plan, intent, stackID, createdAt)

	t.Run("same name and tags but different create token", func(t *testing.T) {
		replacement := sdkSecurityRootCreateEvent(intent, stackID, createdAt)
		replacement.ClientRequestToken = awssdk.String("replacement-create-token")
		client, _ := sdkSecurityClient(t, now.Add(2*time.Second), stack,
			map[string]*cloudformation.DescribeStackEventsOutput{"": {StackEvents: []cftypes.StackEvent{replacement}}}, nil)
		if _, found, err := client.FindStackByIntent(context.Background(), cloudaws.FindStackRequest{
			Identity: plan.Identity, Intent: intent, MutationDispatchedAt: now, MutationDeadline: now.Add(30 * time.Second),
		}); found || !errors.Is(err, cloudaws.ErrOwnershipMismatch) {
			t.Fatalf("same-name replacement accepted: found=%t err=%v", found, err)
		}
	})

	t.Run("copied token but creation is outside dispatch window", func(t *testing.T) {
		lateCreation := now.Add(2 * time.Minute)
		lateStack := sdkSecurityStack(plan, intent, stackID, lateCreation)
		lateEvent := sdkSecurityRootCreateEvent(intent, stackID, lateCreation)
		client, _ := sdkSecurityClient(t, lateCreation.Add(time.Second), lateStack,
			map[string]*cloudformation.DescribeStackEventsOutput{"": {StackEvents: []cftypes.StackEvent{lateEvent}}}, nil)
		if _, found, err := client.FindStackByIntent(context.Background(), cloudaws.FindStackRequest{
			Identity: plan.Identity, Intent: intent, MutationDispatchedAt: now, MutationDeadline: now.Add(30 * time.Second),
		}); found || !errors.Is(err, cloudaws.ErrOwnershipMismatch) {
			t.Fatalf("late copied-token replacement accepted: found=%t err=%v", found, err)
		}
	})

	t.Run("creation event not yet visible", func(t *testing.T) {
		client, _ := sdkSecurityClient(t, now.Add(2*time.Second), stack,
			map[string]*cloudformation.DescribeStackEventsOutput{"": {}}, nil)
		if _, found, err := client.FindStackByIntent(context.Background(), cloudaws.FindStackRequest{
			Identity: plan.Identity, Intent: intent, MutationDispatchedAt: now, MutationDeadline: now.Add(30 * time.Second),
		}); found || !errors.Is(err, cloudaws.ErrCloudReadback) {
			t.Fatalf("incomplete event visibility accepted: found=%t err=%v", found, err)
		}
	})

	t.Run("repeated page token", func(t *testing.T) {
		client, _ := sdkSecurityClient(t, now.Add(2*time.Second), stack, map[string]*cloudformation.DescribeStackEventsOutput{
			"":     {NextToken: awssdk.String("loop")},
			"loop": {NextToken: awssdk.String("loop")},
		}, nil)
		if _, found, err := client.FindStackByIntent(context.Background(), cloudaws.FindStackRequest{
			Identity: plan.Identity, Intent: intent, MutationDispatchedAt: now, MutationDeadline: now.Add(30 * time.Second),
		}); found || !errors.Is(err, cloudaws.ErrCloudReadback) {
			t.Fatalf("pagination loop accepted: found=%t err=%v", found, err)
		}
	})
}

func TestCreateStackRevalidatesAuthorizationBeforeMutationHTTP(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent := sdkSecurityPlanAndIntent(t, now)
	clientNow := intent.Authorization.QuoteExpiresAt
	client, cfn := sdkSecurityClient(t, clientNow, cftypes.Stack{}, nil, nil)
	policy, err := plan.Network.SecurityGroupPolicy()
	if err != nil {
		t.Fatal(err)
	}
	request := cloudaws.CreateStackRequest{
		Identity: plan.Identity, Plan: plan, Intent: intent, ExpectedResources: cloudaws.AllResourceKinds(),
		ResourceTags:         cloudaws.RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest),
		MutationDispatchedAt: now, MutationDeadline: now.Add(30 * time.Second),
		SecurityGroupPolicy: policy, InstanceCount: 1,
	}
	if _, err := client.CreateStack(context.Background(), request); !errors.Is(err, cloudaws.ErrInvalid) {
		t.Fatalf("expired authorization result=%v", err)
	}
	cfn.mu.Lock()
	defer cfn.mu.Unlock()
	if cfn.createCalls != 0 {
		t.Fatalf("expired authorization emitted %d CreateStack HTTP calls", cfn.createCalls)
	}
}

func TestIAMImmutableIDsFenceTagObserveAndDelete(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent := sdkSecurityPlanAndIntent(t, now)
	stackID := sdkSecurityStackID(intent.StackName)
	stack := sdkSecurityStack(plan, intent, stackID, now.Add(time.Second))
	roleID := "AROA1234567890ABCDEFG"
	profileID := "AIPA1234567890ABCDEFG"
	tags := cloudaws.RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest)

	t.Run("resolve and tag exact identities", func(t *testing.T) {
		iamFake := sdkSecurityIAM(plan, roleID, profileID, tags, nil)
		client, _ := sdkSecurityClient(t, now.Add(2*time.Second), stack, nil, iamFake)
		proof, err := client.ResolveIAMResourceIdentities(context.Background(), cloudaws.ResolveIAMResourceIdentitiesRequest{
			Identity: plan.Identity, Plan: plan, PlanDigest: plan.Digest, InfrastructureDigest: plan.InfrastructureDigest,
			IntentDigest: intent.IntentDigest, StackProviderID: stackID, ExpectedTags: tags,
		})
		if err != nil || proof.IAMRoleID != roleID || proof.InstanceProfileID != profileID {
			t.Fatalf("IAM proof=%+v err=%v", proof, err)
		}
		if err := client.EnsureResourceIdentity(context.Background(), sdkSecurityEnsureIdentityRequest(plan, intent, stackID, roleID, profileID, tags)); err != nil {
			t.Fatal(err)
		}
		iamFake.mu.Lock()
		defer iamFake.mu.Unlock()
		if iamFake.tagCalls != 1 || !containsTags(iamTagMap(iamFake.profileTags), tags) {
			t.Fatalf("exact profile identity was not tagged once: calls=%d tags=%v", iamFake.tagCalls, iamFake.profileTags)
		}
	})

	t.Run("unknown tag retry rejects same-name profile replacement", func(t *testing.T) {
		iamFake := sdkSecurityIAM(plan, roleID, profileID, tags, nil)
		iamFake.tagErrors = []error{errors.New("tag response lost")}
		client, _ := sdkSecurityClient(t, now.Add(2*time.Second), stack, nil, iamFake)
		ensure := sdkSecurityEnsureIdentityRequest(plan, intent, stackID, roleID, profileID, tags)
		if err := client.EnsureResourceIdentity(context.Background(), ensure); !errors.Is(err, cloudaws.ErrResponseUnknown) {
			t.Fatalf("first unknown tag = %v, want response unknown", err)
		}

		iamFake.mu.Lock()
		replacementID := "AIPAQRSTUVWXYZ1234567"
		iamFake.profile.InstanceProfileId = awssdk.String(replacementID)
		iamFake.mu.Unlock()
		if err := client.EnsureResourceIdentity(context.Background(), ensure); !errors.Is(err, cloudaws.ErrOwnershipMismatch) {
			t.Fatalf("same-name replacement retry = %v, want ownership mismatch", err)
		}
		iamFake.mu.Lock()
		defer iamFake.mu.Unlock()
		if iamFake.tagCalls != 1 {
			t.Fatalf("same-name replacement reached a second TagInstanceProfile call: %d", iamFake.tagCalls)
		}
	})

	for _, replacement := range []struct {
		name       string
		roleID     string
		profileID  string
		deleteKind cloudaws.ResourceKind
		expectedID string
	}{
		{name: "role same-name replacement", roleID: "AROAQRSTUVWXYZ1234567", profileID: profileID, deleteKind: cloudaws.ResourceIAMRole, expectedID: roleID},
		{name: "profile same-name replacement", roleID: roleID, profileID: "AIPAQRSTUVWXYZ1234567", deleteKind: cloudaws.ResourceInstanceProfile, expectedID: profileID},
	} {
		t.Run(replacement.name, func(t *testing.T) {
			iamFake := sdkSecurityIAM(plan, replacement.roleID, replacement.profileID, tags, tags)
			client, cfn := sdkSecurityClient(t, now.Add(2*time.Second), stack, nil, iamFake)
			ensure := sdkSecurityEnsureIdentityRequest(plan, intent, stackID, roleID, profileID, tags)
			if err := client.EnsureResourceIdentity(context.Background(), ensure); !errors.Is(err, cloudaws.ErrOwnershipMismatch) {
				t.Fatalf("same-name replacement reached tag path: %v", err)
			}
			iamFake.mu.Lock()
			if iamFake.tagCalls != 0 {
				t.Fatalf("same-name replacement was tagged %d times", iamFake.tagCalls)
			}
			iamFake.mu.Unlock()

			policy, _ := plan.Network.SecurityGroupPolicy()
			deleteRequest := cloudaws.DeleteResourceRequest{
				Identity: plan.Identity, Plan: plan, PlanDigest: plan.Digest, InfrastructureDigest: plan.InfrastructureDigest,
				IntentDigest: intent.IntentDigest, Kind: replacement.deleteKind, LogicalID: cloudaws.LogicalID(replacement.deleteKind),
				ResourceProviderID: replacement.expectedID, ExpectedTags: tags, SecurityGroupPolicy: policy, MutationToken: "delete-exact-resource",
				ExpectedResourceProviderIDs: map[cloudaws.ResourceKind]string{
					cloudaws.ResourceStack: stackID, cloudaws.ResourceIAMRole: roleID, cloudaws.ResourceInstanceProfile: profileID,
				},
			}
			if err := client.DeleteResource(context.Background(), deleteRequest); !errors.Is(err, cloudaws.ErrOwnershipMismatch) {
				t.Fatalf("same-name replacement reached delete path: %v", err)
			}
			cfn.mu.Lock()
			deletes := cfn.deleteCalls
			cfn.mu.Unlock()
			if deletes != 0 {
				t.Fatalf("same-name replacement emitted %d DeleteStack calls", deletes)
			}
		})
	}
}

func TestDeleteStackUsesLedgerBoundARNAndRejectsSameNameReplacement(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent := sdkSecurityPlanAndIntent(t, now)
	stackID := sdkSecurityStackID(intent.StackName)
	tags := cloudaws.RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest)
	policy, _ := plan.Network.SecurityGroupPolicy()
	request := cloudaws.DeleteResourceRequest{
		Identity: plan.Identity, Plan: plan, PlanDigest: plan.Digest, InfrastructureDigest: plan.InfrastructureDigest,
		IntentDigest: intent.IntentDigest, Kind: cloudaws.ResourceStack, LogicalID: cloudaws.LogicalID(cloudaws.ResourceStack),
		ResourceProviderID: stackID, ExpectedResourceProviderIDs: map[cloudaws.ResourceKind]string{cloudaws.ResourceStack: stackID},
		ExpectedTags: tags, SecurityGroupPolicy: policy, MutationToken: "delete-exact-stack",
	}

	t.Run("exact ARN", func(t *testing.T) {
		stack := sdkSecurityStack(plan, intent, stackID, now.Add(time.Second))
		client, cfn := sdkSecurityClient(t, now.Add(2*time.Second), stack, nil, nil)
		if err := client.DeleteResource(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		cfn.mu.Lock()
		defer cfn.mu.Unlock()
		if len(cfn.describeInputs) == 0 || awssdk.ToString(cfn.describeInputs[0].StackName) != stackID ||
			len(cfn.deleteInputs) != 1 || awssdk.ToString(cfn.deleteInputs[0].StackName) != stackID {
			t.Fatalf("stack calls were not exact ARN bound: describe=%+v delete=%+v", cfn.describeInputs, cfn.deleteInputs)
		}
	})

	t.Run("same name replacement", func(t *testing.T) {
		replacementID := "arn:aws:cloudformation:us-east-1:123456789012:stack/" + intent.StackName + "/22222222-2222-4222-8222-222222222222"
		replacement := sdkSecurityStack(plan, intent, replacementID, now.Add(time.Second))
		client, cfn := sdkSecurityClient(t, now.Add(2*time.Second), replacement, nil, nil)
		if err := client.DeleteResource(context.Background(), request); !errors.Is(err, cloudaws.ErrOwnershipMismatch) {
			t.Fatalf("same-name replacement delete=%v, want ownership mismatch", err)
		}
		cfn.mu.Lock()
		defer cfn.mu.Unlock()
		if cfn.deleteCalls != 0 {
			t.Fatalf("same-name replacement emitted %d DeleteStack calls", cfn.deleteCalls)
		}
	})
}

func sdkSecurityEnsureIdentityRequest(plan cloudaws.Plan, intent cloudaws.DispatchIntent, stackID, roleID, profileID string, tags map[string]string) cloudaws.EnsureResourceIdentityRequest {
	return cloudaws.EnsureResourceIdentityRequest{
		Identity: plan.Identity, Plan: plan, PlanDigest: plan.Digest, InfrastructureDigest: plan.InfrastructureDigest,
		IntentDigest: intent.IntentDigest, StackProviderID: stackID, Kind: cloudaws.ResourceInstanceProfile,
		LogicalID: cloudaws.LogicalID(cloudaws.ResourceInstanceProfile), ExpectedTags: tags,
		ExpectedResourceProviderIDs: map[cloudaws.ResourceKind]string{
			cloudaws.ResourceIAMRole: roleID, cloudaws.ResourceInstanceProfile: profileID,
		}, MutationToken: "tag-exact-profile",
	}
}

func sdkSecurityPlanAndIntent(t *testing.T, now time.Time) (cloudaws.Plan, cloudaws.DispatchIntent) {
	t.Helper()
	identity := cloudaws.ExecutionIdentity{
		OwnerID: "owner-1", AccountID: "123456789012", AccountGeneration: 3, Region: "us-east-1",
		ExecutionID: "11111111-1111-4111-8111-111111111111", TaskID: "22222222-2222-4222-8222-222222222222",
		TaskAttempt: 2, LeaseEpoch: 7, ProviderID: "credential-revision-7", Generation: 1,
	}
	identity.LaunchIdentity = cloudaws.DeriveLaunchIdentity(identity)
	plan, err := cloudaws.SealPlan(cloudaws.Plan{
		Identity: identity, Recipe: cloudaws.RecipePiTask, Adapter: cloudaws.AdapterPiJSON, Digest: sdkSecurityDigest("9"),
		AMIID: "ami-0123456789abcdef0", AMIDigest: sdkSecurityDigest("a"), WorkerDigest: sdkSecurityDigest("b"),
		PiDigest: sdkSecurityDigest("c"), HostNetworkPolicySHA256: sdkSecurityDigest("8"), Architecture: "amd64", InstanceType: "c7i.large",
		RootVolumeGiB: 32, RootDeviceName: "/dev/xvda", RootVolumeType: "gp3", RootVolumeIOPS: 3000, RootVolumeThroughput: 125,
		RootKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
		VPCID:         "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
		ControlPlaneEndpoint: "https://control.example.com:443", ControlPlaneServerName: "control.example.com",
		ControlPlaneTrustBundleSHA256: sdkSecurityDigest("4"), ModelRelayServerName: "api.openai.com",
		ModelRelayTrustBundleSHA256: sdkSecurityDigest("6"), WorkspaceMode: cloudaws.WorkspaceWrite,
		ExecutionSHA256: sdkSecurityDigest("5"), TaskSHA256: sdkSecurityDigest("6"), InputManifestDigest: sdkSecurityDigest("1"),
		ModelAuthorizationDigest: sdkSecurityDigest("2"), ArtifactBindingDigest: sdkSecurityDigest("3"),
		S3Grants: []cloudaws.S3ObjectGrant{
			{Access: cloudaws.S3ReadExactVersion, Bucket: "dirextalk-input", Key: "tasks/input.tar", VersionID: "version-1"},
			{Access: cloudaws.S3WritePrefix, Bucket: "dirextalk-output", Key: "executions/11111111/"},
		}, ArtifactRetentionSeconds: 86400,
		Network: cloudaws.NetworkPolicy{
			DNSResolverCIDRs: []string{"10.0.0.2/32"}, TLSProxyCIDRs: []string{"10.0.0.9/32"},
			AllowedFQDNs:     []string{"api.openai.com", "s3.us-east-1.amazonaws.com"},
			OutboundProxyURL: "https://proxy.example.test:443", OutboundProxyServerName: "proxy.example.test",
			OutboundProxyTrustBundleSHA256: sdkSecurityDigest("7"),
		}, DestroyDeadline: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := cloudaws.AuthorizationBinding{
		AuthorizedQuoteDigest: sdkSecurityDigest("d"), FreshQuoteDigest: sdkSecurityDigest("d"),
		ExpectedConfirmationDigest: sdkSecurityDigest("e"), ConfirmationDigest: sdkSecurityDigest("e"),
		FreshQuotedAt: now.Add(-10 * time.Second), QuoteExpiresAt: now.Add(5 * time.Minute), ConfirmedAt: now.Add(-time.Second),
		MaximumQuoteAgeSeconds: 300,
	}
	intent, err := cloudaws.NewDispatchIntent(plan, authorization, now)
	if err != nil {
		t.Fatal(err)
	}
	return plan, intent
}

func sdkSecurityDigest(character string) string {
	value := ""
	for len(value) < 64 {
		value += character
	}
	return value[:64]
}

func sdkSecurityStackID(name string) string {
	return "arn:aws:cloudformation:us-east-1:123456789012:stack/" + name + "/11111111-1111-4111-8111-111111111111"
}

func sdkSecurityStack(plan cloudaws.Plan, intent cloudaws.DispatchIntent, stackID string, createdAt time.Time) cftypes.Stack {
	return cftypes.Stack{
		StackId: awssdk.String(stackID), StackName: awssdk.String(intent.StackName), CreationTime: awssdk.Time(createdAt),
		StackStatus: cftypes.StackStatusCreateInProgress,
		Tags:        sdkCFNTags(cloudaws.RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest)),
	}
}

func sdkSecurityRootCreateEvent(intent cloudaws.DispatchIntent, stackID string, createdAt time.Time) cftypes.StackEvent {
	return cftypes.StackEvent{
		EventId: awssdk.String("event-root-create-in-progress"), StackId: awssdk.String(stackID), StackName: awssdk.String(intent.StackName),
		Timestamp: awssdk.Time(createdAt), ClientRequestToken: awssdk.String(intent.ClientToken),
		LogicalResourceId: awssdk.String(intent.StackName), PhysicalResourceId: awssdk.String(stackID),
		ResourceType: awssdk.String("AWS::CloudFormation::Stack"), ResourceStatus: cftypes.ResourceStatusCreateInProgress,
	}
}

func sdkSecurityClient(t *testing.T, now time.Time, stack cftypes.Stack, pages map[string]*cloudformation.DescribeStackEventsOutput, iamFake *securityIAMFake) (*Client, *securityCFNFake) {
	t.Helper()
	if iamFake == nil {
		iamFake = &securityIAMFake{}
	}
	cfn := &securityCFNFake{stack: stack, eventPages: pages}
	client, err := newClient(Config{AccountID: "123456789012", AccountGeneration: 3, Region: "us-east-1", ProviderID: "credential-revision-7"},
		&securitySTSFake{account: "123456789012"}, cfn, securityEC2Fake{}, iamFake, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return client, cfn
}

func sdkSecurityIAM(plan cloudaws.Plan, roleID, profileID string, roleTags, profileTags map[string]string) *securityIAMFake {
	role := iamtypes.Role{RoleName: awssdk.String(plan.IAMRoleName), RoleId: awssdk.String(roleID),
		Arn: awssdk.String("arn:aws:iam::123456789012:role/" + plan.IAMRoleName)}
	profile := iamtypes.InstanceProfile{InstanceProfileName: awssdk.String(plan.InstanceProfileName), InstanceProfileId: awssdk.String(profileID),
		Arn:   awssdk.String("arn:aws:iam::123456789012:instance-profile/" + plan.InstanceProfileName),
		Roles: []iamtypes.Role{{RoleName: awssdk.String(plan.IAMRoleName), RoleId: awssdk.String(roleID)}}}
	return &securityIAMFake{role: role, profile: profile, roleTags: sdkIAMTags(roleTags), profileTags: sdkIAMTags(profileTags)}
}

type securitySTSFake struct{ account string }

func (fake *securitySTSFake) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: awssdk.String(fake.account)}, nil
}

type securityCFNFake struct {
	mu                  sync.Mutex
	stack               cftypes.Stack
	eventPages          map[string]*cloudformation.DescribeStackEventsOutput
	eventInputs         []cloudformation.DescribeStackEventsInput
	createCalls         int
	deleteCalls         int
	describeInputs      []cloudformation.DescribeStacksInput
	deleteInputs        []cloudformation.DeleteStackInput
	emptyStackResources bool
}

func (fake *securityCFNFake) CreateStack(context.Context, *cloudformation.CreateStackInput, ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.createCalls++
	return &cloudformation.CreateStackOutput{StackId: fake.stack.StackId}, nil
}

func (fake *securityCFNFake) DescribeStacks(_ context.Context, input *cloudformation.DescribeStacksInput, _ ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.describeInputs = append(fake.describeInputs, *input)
	if fake.stack.StackId == nil {
		return &cloudformation.DescribeStacksOutput{}, nil
	}
	return &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{fake.stack}}, nil
}

func (fake *securityCFNFake) DescribeStackEvents(_ context.Context, input *cloudformation.DescribeStackEventsInput, _ ...func(*cloudformation.Options)) (*cloudformation.DescribeStackEventsOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.eventInputs = append(fake.eventInputs, *input)
	output, ok := fake.eventPages[awssdk.ToString(input.NextToken)]
	if !ok || output == nil {
		return nil, errors.New("unexpected DescribeStackEvents page")
	}
	copy := *output
	copy.StackEvents = append([]cftypes.StackEvent(nil), output.StackEvents...)
	return &copy, nil
}

func (fake *securityCFNFake) DescribeStackResources(context.Context, *cloudformation.DescribeStackResourcesInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStackResourcesOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.emptyStackResources {
		return &cloudformation.DescribeStackResourcesOutput{}, nil
	}
	physical := map[cloudaws.ResourceKind]string{
		cloudaws.ResourceSecurityGroup: "sg-0123456789abcdef0", cloudaws.ResourceIAMRole: awssdk.ToString(fake.stack.StackName) + "-role",
		cloudaws.ResourceInstanceProfile: awssdk.ToString(fake.stack.StackName) + "-profile", cloudaws.ResourceENI: "eni-0123456789abcdef0",
		cloudaws.ResourceEIP: "eipalloc-0123456789abcdef0", cloudaws.ResourceEC2: "i-0123456789abcdef0",
	}
	// Plan names use the deterministic stack name as their prefix.
	resources := make([]cftypes.StackResource, 0, len(cfnResourceTypes))
	for kind, resourceType := range cfnResourceTypes {
		resources = append(resources, cftypes.StackResource{
			StackId: fake.stack.StackId, LogicalResourceId: awssdk.String(cloudaws.LogicalID(kind)),
			PhysicalResourceId: awssdk.String(physical[kind]), ResourceType: awssdk.String(resourceType),
		})
	}
	return &cloudformation.DescribeStackResourcesOutput{StackResources: resources}, nil
}

func (fake *securityCFNFake) DeleteStack(_ context.Context, input *cloudformation.DeleteStackInput, _ ...func(*cloudformation.Options)) (*cloudformation.DeleteStackOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.deleteCalls++
	fake.deleteInputs = append(fake.deleteInputs, *input)
	return &cloudformation.DeleteStackOutput{}, nil
}

type securityEC2Fake struct{}

func (securityEC2Fake) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{}, nil
}
func (securityEC2Fake) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{}, nil
}
func (securityEC2Fake) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}
func (securityEC2Fake) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{}, nil
}
func (securityEC2Fake) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

type securityIAMFake struct {
	mu              sync.Mutex
	role            iamtypes.Role
	profile         iamtypes.InstanceProfile
	roleTags        []iamtypes.Tag
	profileTags     []iamtypes.Tag
	tagErrors       []error
	applyUnknownTag bool
	tagCalls        int
	roleMissing     bool
	profileMissing  bool
}

func (fake *securityIAMFake) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.roleMissing {
		return nil, &iamtypes.NoSuchEntityException{}
	}
	copy := fake.role
	return &iam.GetRoleOutput{Role: &copy}, nil
}
func (fake *securityIAMFake) ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return &iam.ListRoleTagsOutput{Tags: append([]iamtypes.Tag(nil), fake.roleTags...)}, nil
}
func (fake *securityIAMFake) GetInstanceProfile(context.Context, *iam.GetInstanceProfileInput, ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.profileMissing {
		return nil, &iamtypes.NoSuchEntityException{}
	}
	copy := fake.profile
	copy.Roles = append([]iamtypes.Role(nil), fake.profile.Roles...)
	return &iam.GetInstanceProfileOutput{InstanceProfile: &copy}, nil
}
func (fake *securityIAMFake) ListInstanceProfileTags(context.Context, *iam.ListInstanceProfileTagsInput, ...func(*iam.Options)) (*iam.ListInstanceProfileTagsOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return &iam.ListInstanceProfileTagsOutput{Tags: append([]iamtypes.Tag(nil), fake.profileTags...)}, nil
}
func (fake *securityIAMFake) TagInstanceProfile(_ context.Context, input *iam.TagInstanceProfileInput, _ ...func(*iam.Options)) (*iam.TagInstanceProfileOutput, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.tagCalls++
	var tagErr error
	if len(fake.tagErrors) != 0 {
		tagErr = fake.tagErrors[0]
		fake.tagErrors = fake.tagErrors[1:]
	}
	if tagErr == nil || fake.applyUnknownTag {
		fake.profileTags = append([]iamtypes.Tag(nil), input.Tags...)
	}
	return &iam.TagInstanceProfileOutput{}, tagErr
}

func iamTagMap(tags []iamtypes.Tag) map[string]string {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		result[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
	}
	return result
}

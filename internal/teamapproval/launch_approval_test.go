package teamapproval

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestV2ChallengeSignsPlanAndExactLaunchAuthorization(t *testing.T) {
	plan := approvalTestPlan()
	issuedAt := plan.QuotedAt.Add(time.Minute)
	authorization := approvalTestLaunchAuthorization(t, plan, issuedAt)
	challenge, err := NewChallengeV2(
		plan,
		authorization,
		authorization.AgentInstanceID,
		authorization.ApprovalID,
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"cloud-device-1234567890abcdef12345678",
		issuedAt,
	)
	if err != nil {
		t.Fatalf("NewChallengeV2() error = %v", err)
	}
	publicKey, privateKey := approvalTestKey()
	signature := signLaunchChallenge(t, challenge, privateKey)
	if err := VerifyWithLaunch(
		challenge,
		signature,
		plan,
		authorization,
		publicKey,
		issuedAt.Add(time.Second),
	); err != nil {
		t.Fatalf("VerifyWithLaunch() error = %v", err)
	}
	if err := Verify(
		challenge,
		signature,
		plan,
		publicKey,
		issuedAt.Add(time.Second),
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf(
			"legacy Verify() error = %v, want ErrSignatureInvalid",
			err,
		)
	}
	digest, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if challenge.LaunchAuthorizationID != authorization.AuthorizationID ||
		challenge.LaunchAuthorizationDigest != digest ||
		signature.LaunchAuthorizationID != authorization.AuthorizationID ||
		signature.LaunchAuthorizationDigest != digest {
		t.Fatalf(
			"launch authorization was not repeated exactly: challenge=%+v signature=%+v",
			challenge,
			signature,
		)
	}
}

func TestV2ApprovalRejectsLaunchAuthorizationOrEnvelopeDrift(t *testing.T) {
	plan := approvalTestPlan()
	issuedAt := plan.QuotedAt.Add(time.Minute)
	authorization := approvalTestLaunchAuthorization(t, plan, issuedAt)
	challenge, err := NewChallengeV2(
		plan,
		authorization,
		authorization.AgentInstanceID,
		authorization.ApprovalID,
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"cloud-device-1234567890abcdef12345678",
		issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := approvalTestKey()
	signature := signLaunchChallenge(t, challenge, privateKey)

	driftedAuthorization := authorization
	driftedAuthorization.Roles[0].WorkerImage.ImageID =
		"ami-0fedcba9876543210"
	if err := VerifyWithLaunch(
		challenge,
		signature,
		plan,
		driftedAuthorization,
		publicKey,
		issuedAt.Add(time.Second),
	); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf(
			"launch drift error = %v, want ErrPlanChanged",
			err,
		)
	}

	driftedSignature := signature
	driftedSignature.LaunchAuthorizationDigest =
		"sha256:" + strings.Repeat("f", 64)
	if err := VerifyWithLaunch(
		challenge,
		driftedSignature,
		plan,
		authorization,
		publicKey,
		issuedAt.Add(time.Second),
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf(
			"signature envelope drift error = %v, want ErrSignatureInvalid",
			err,
		)
	}
}

func TestV2SigningPayloadBindsEveryLaunchDigest(t *testing.T) {
	plan := approvalTestPlan()
	issuedAt := plan.QuotedAt.Add(time.Minute)
	firstAuthorization := approvalTestLaunchAuthorization(t, plan, issuedAt)
	first, err := NewChallengeV2(
		plan,
		firstAuthorization,
		firstAuthorization.AgentInstanceID,
		firstAuthorization.ApprovalID,
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"cloud-device-1234567890abcdef12345678",
		issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondAuthorization := firstAuthorization
	secondAuthorization.Network.VPCID = "vpc-0fedcba9876543210"
	secondDigest, err := secondAuthorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.LaunchAuthorizationDigest = secondDigest
	firstPayload, err := first.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	secondPayload, err := second.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstPayload) == string(secondPayload) {
		t.Fatal("launch authorization drift did not change signing payload")
	}
}

func signLaunchChallenge(
	t *testing.T,
	challenge ChallengeV1,
	privateKey ed25519.PrivateKey,
) SignatureV1 {
	t.Helper()
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	return SignatureV1{
		SchemaVersion:             SignatureSchemaV2,
		ApprovalID:                challenge.ApprovalID,
		ChallengeID:               challenge.ChallengeID,
		PlanID:                    challenge.PlanID,
		PlanRevision:              challenge.PlanRevision,
		PlanDigest:                challenge.PlanDigest,
		LaunchAuthorizationID:     challenge.LaunchAuthorizationID,
		LaunchAuthorizationDigest: challenge.LaunchAuthorizationDigest,
		SignerKeyID:               challenge.SignerKeyID,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, payload),
		),
	}
}

func approvalTestLaunchAuthorization(
	t *testing.T,
	plan teamplan.Plan,
	issuedAt time.Time,
) teamlaunch.AuthorizationV1 {
	t.Helper()
	const (
		agentInstanceID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		approvalID      = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	)
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	authorizationID, err := teamlaunch.AuthorizationID(
		plan.PlanID,
		plan.Revision,
		approvalID,
	)
	if err != nil {
		t.Fatal(err)
	}
	foundation, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: agentInstanceID,
		Partition:       "aws",
		AccountID:       plan.ProviderScope.AccountID,
		Region:          plan.Region,
	})
	if err != nil {
		t.Fatal(err)
	}
	kmsAlias, err := awsfoundation.KMSAliasForAgent(agentInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	authorization := teamlaunch.AuthorizationV1{
		SchemaVersion:   teamlaunch.SchemaV1,
		AuthorizationID: authorizationID,
		AgentInstanceID: agentInstanceID,
		OwnerID:         plan.OwnerID,
		PlanID:          plan.PlanID,
		PlanRevision:    plan.Revision,
		PlanDigest:      planDigest,
		ApprovalID:      approvalID,
		ProviderScope:   plan.ProviderScope,
		Region:          plan.Region,
		Network: teamlaunch.NetworkV1{
			ConnectivityMode:     teamlaunch.ConnectivityDirectPublicTLSV1,
			VPCID:                "vpc-0123456789abcdef0",
			SubnetID:             "subnet-0123456789abcdef0",
			AvailabilityZone:     "ap-northeast-3a",
			SecurityGroupMode:    teamlaunch.SecurityGroupDedicatedNoIngress,
			PublicIPv4:           true,
			ControlPlaneEndpoint: "grpcs://worker-control.demo2.dirextalk.ai:7443",
			Egress: []teamlaunch.EgressRuleV1{
				{
					Protocol: "tcp",
					FromPort: 443,
					ToPort:   443,
					CIDRv4:   "0.0.0.0/0",
				},
				{
					Protocol: "tcp",
					FromPort: 7443,
					ToPort:   7443,
					CIDRv4:   "0.0.0.0/0",
				},
				{
					Protocol: "udp",
					FromPort: 53,
					ToPort:   53,
					CIDRv4:   "169.254.169.253/32",
				},
			},
		},
		Retention: teamlaunch.RetentionV1{
			Class:                  teamlaunch.RetentionEphemeralAutoDestroy,
			AutoDestroy:            true,
			MaximumLifetimeSeconds: 2 * 60 * 60,
			DestroyGraceSeconds:    5 * 60,
		},
		WorkerCount:                  plan.WorkerCount,
		MaxConcurrentBillableWorkers: plan.MaxConcurrentWorkers,
		Currency:                     plan.Cost.Currency,
		HardBudgetMicros:             plan.Cost.HardBudgetMicros,
		RequiresFreshQuote:           true,
		MaximumQuoteAgeSeconds:       15 * 60,
		LaunchNotBefore:              plan.QuotedAt.Add(30 * time.Second),
		LaunchNotAfter:               plan.QuotedAt.Add(30 * time.Minute),
		Roles: []teamlaunch.RoleLaunchV1{{
			RoleID:                    plan.Assignments[0].RoleID,
			RuntimeReleaseID:          plan.Assignments[0].RuntimeReleaseID,
			RuntimeImageDigest:        plan.Assignments[0].RuntimeImageDigest,
			RuntimeInstallationDigest: "sha256:" + strings.Repeat("6", 64),
			RuntimeExecutableDigest:   "sha256:" + strings.Repeat("7", 64),
			ComputeOfferID:            plan.Assignments[0].ComputeOfferID,
			InstanceType:              plan.Assignments[0].InstanceType,
			Architecture:              recipe.ArchitectureAMD64,
			VCPU:                      plan.Assignments[0].Resources.VCPU,
			MemoryMiB:                 plan.Assignments[0].Resources.MemoryMiB,
			PurchaseOption:            teamlaunch.PurchaseOnDemand,
			InstanceProfileName:       foundation.WorkerProfileName,
			EBSOptimized:              true,
			RequireIMDSv2:             true,
			MetadataResponseHopLimit:  1,
			ShutdownBehavior:          teamlaunch.ShutdownTerminate,
			RootStorage: teamlaunch.RootStorageV1{
				DeviceName:          "/dev/sda1",
				SizeGiB:             plan.Assignments[0].Resources.DiskGiB,
				VolumeType:          "gp3",
				IOPS:                3000,
				ThroughputMiBPS:     125,
				KMSKeyID:            kmsAlias,
				Encrypted:           true,
				DeleteOnTermination: true,
			},
			WorkerImage: teamlaunch.WorkerImageV1{
				PublicationDigest:     "sha256:" + strings.Repeat("8", 64),
				AgentInstanceID:       agentInstanceID,
				AccountID:             plan.ProviderScope.AccountID,
				Region:                plan.Region,
				Architecture:          recipe.ArchitectureAMD64,
				ImageID:               "ami-0123456789abcdef0",
				ImageDigest:           "sha256:" + strings.Repeat("9", 64),
				RootSnapshotID:        "snap-0123456789abcdef0",
				ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64),
				WorkerRootFSDigest:    "sha256:" + strings.Repeat("b", 64),
				WorkerBinaryDigest:    "sha256:" + strings.Repeat("c", 64),
				ObservedAt:            issuedAt.Add(-time.Hour),
			},
			MaximumApprovedCostMicros: plan.Cost.Roles[0].TotalMaximumMicros,
		}},
	}
	if err := authorization.ValidateAgainst(plan); err != nil {
		t.Fatalf("launch authorization fixture is invalid: %v", err)
	}
	return authorization
}

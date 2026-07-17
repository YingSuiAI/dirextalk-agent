package entrypoint

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPlanAndChallengeBindApprovedExternalHealthEntry(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 123456789, time.UTC)
	plan, err := NewPlanV1("11111111-1111-4111-8111-111111111111", 1, PlanReadyForApproval, validScope(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan validation failed: %v", err)
	}

	challenge, err := NewChallengeV1(
		plan,
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
		"44444444-4444-4444-8444-444444444444",
		"device-0123456789abcdef01234567",
		now,
		now.Add(4*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(challenge.SigningCBOR) {
		t.Fatal("challenge did not retain exact signing payload")
	}

	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := SignatureV1{
		ApprovalID:        challenge.ApprovalID,
		ChallengeID:       challenge.ChallengeID,
		EntryPlanID:       challenge.EntryPlanID,
		EntryPlanRevision: challenge.EntryPlanRevision,
		PlanHash:          challenge.PlanHash,
		ScopeDigest:       challenge.ScopeDigest,
		SignerKeyID:       challenge.SignerKeyID,
		ExpiresAt:         challenge.ExpiresAt,
		Signature:         ed25519.Sign(privateKey, payload),
	}
	if err := VerifyDeviceSignature(challenge, signature, privateKey.Public().(ed25519.PublicKey), now.Add(time.Minute)); err != nil {
		t.Fatalf("valid device signature rejected: %v", err)
	}

	operation := OperationV1{
		Challenge: challenge, Status: StatusApproved, Signature: &signature, Revision: 1,
		CreatedAt: now, UpdatedAt: now.Add(time.Second), ApprovedAt: ptr(now.Add(time.Second)),
	}
	if err := operation.Validate(); err != nil {
		t.Fatalf("approved operation validation failed: %v", err)
	}
}

func TestScopeDigestNormalizesOrderAndBindsAllSensitiveEntryFields(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	left := validScope(now)
	right := validScope(now)
	right.ALB.PublicSubnets[0], right.ALB.PublicSubnets[1] = right.ALB.PublicSubnets[1], right.ALB.PublicSubnets[0]
	right.Certificate.SubjectAlternativeNames[0], right.Certificate.SubjectAlternativeNames[1] = right.Certificate.SubjectAlternativeNames[1], right.Certificate.SubjectAlternativeNames[0]
	leftDigest, err := ScopeDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := ScopeDigest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("equivalent reordered scope digests differ: %s != %s", leftDigest, rightDigest)
	}

	for name, change := range map[string]func(*ScopeV1){
		"worker resource": func(value *ScopeV1) { value.Worker.WorkerResourceID = "99999999-9999-4999-8999-999999999999" },
		"worker readback": func(value *ScopeV1) { value.Worker.ReadBack.TagDigest = digest('b') },
		"certificate": func(value *ScopeV1) {
			value.Certificate.CertificateARN = "arn:aws:acm:ap-south-1:123456789012:certificate/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"subnet":      func(value *ScopeV1) { value.ALB.PublicSubnets[0].SubnetID = "subnet-abcdef12" },
		"health path": func(value *ScopeV1) { value.Health.Path = "/ready" },
		"health evidence": func(value *ScopeV1) {
			value.Health.EvidenceDigest = digest('c')
			value.Recipe.HealthContractDigest = digest('c')
		},
		"auth contract": func(value *ScopeV1) {
			value.Authentication.ContractDigest = digest('d')
			value.Recipe.AuthenticationContractDigest = digest('d')
		},
		"cost": func(value *ScopeV1) { value.Cost.TrafficEstimateMicros++ },
		"retention": func(value *ScopeV1) {
			value.Retention.DestroyDeadline = value.Retention.DestroyDeadline.Add(-time.Minute)
			value.Worker.Retention.DestroyDeadline = value.Retention.DestroyDeadline
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := validScope(now)
			change(&changed)
			changedDigest, err := ScopeDigest(changed)
			if err != nil {
				t.Fatalf("changed scope validation failed: %v", err)
			}
			if changedDigest == leftDigest {
				t.Fatal("sensitive scope drift did not change digest")
			}
		})
	}
}

func TestScopeRejectsUnsafeTargetDerivationAndIncompleteIndependentEvidence(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	for name, change := range map[string]func(*ScopeV1){
		"unsupported entry kind":         func(value *ScopeV1) { value.Kind = "cloudfront" },
		"EIP source":                     func(value *ScopeV1) { value.ALB.TargetSource = TargetSourceEIP },
		"endpoint source":                func(value *ScopeV1) { value.ALB.TargetSource = TargetSourceVPCEndpoint },
		"worker URL source":              func(value *ScopeV1) { value.ALB.TargetSource = TargetSourceWorkerURL },
		"worker log source":              func(value *ScopeV1) { value.ALB.TargetSource = TargetSourceWorkerLog },
		"direct public IPv4":             func(value *ScopeV1) { value.ALB.WorkerPublicIPv4 = true },
		"EIP requested":                  func(value *ScopeV1) { value.ALB.EIPRequested = true },
		"worker unsuccessful":            func(value *ScopeV1) { value.Worker.ExecutionOutcome = WorkerOutcomeFailed },
		"worker readback absent":         func(value *ScopeV1) { value.Worker.ReadBack.Exists = false },
		"readback before worker success": func(value *ScopeV1) { value.Worker.ReadBack.ObservedAt = value.Worker.SucceededAt.Add(-time.Second) },
		"certificate not issued":         func(value *ScopeV1) { value.Certificate.Status = CertificateStatusPendingValidation },
		"certificate wrong region":       func(value *ScopeV1) { value.Certificate.Region = "us-east-1" },
		"subnet is not public":           func(value *ScopeV1) { value.ALB.PublicSubnets[0].Public = false },
		"only one subnet":                func(value *ScopeV1) { value.ALB.PublicSubnets = value.ALB.PublicSubnets[:1] },
		"same subnet AZ": func(value *ScopeV1) {
			value.ALB.PublicSubnets[1].AvailabilityZone = value.ALB.PublicSubnets[0].AvailabilityZone
		},
		"non-approved TLS policy":    func(value *ScopeV1) { value.ALB.TLSPolicy = "ELBSecurityPolicy-TLS13-1-3-2021-06" },
		"non-approved ingress CIDR":  func(value *ScopeV1) { value.ALB.IngressCIDRs = []string{"10.0.0.0/8"} },
		"authenticated health route": func(value *ScopeV1) { value.Health.NoCredentialRoute = false },
		"wrong health recipe digest": func(value *ScopeV1) { value.Health.EvidenceDigest = digest('e') },
		"no service authentication":  func(value *ScopeV1) { value.Authentication.Required = false },
	} {
		t.Run(name, func(t *testing.T) {
			value := validScope(now)
			change(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("unsafe or incomplete scope was accepted")
			}
		})
	}
}

func TestChallengeRejectsTamperingAndExpiry(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	plan, err := NewPlanV1("11111111-1111-4111-8111-111111111111", 1, PlanReadyForApproval, validScope(now))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewChallengeV1(plan, "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "device-0123456789abcdef01234567", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytesOf(7, ed25519.SeedSize))
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature := SignatureV1{ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID, EntryPlanID: challenge.EntryPlanID, EntryPlanRevision: challenge.EntryPlanRevision, PlanHash: challenge.PlanHash, ScopeDigest: challenge.ScopeDigest, SignerKeyID: challenge.SignerKeyID, ExpiresAt: challenge.ExpiresAt, Signature: ed25519.Sign(privateKey, payload)}

	if err := VerifyDeviceSignature(challenge, signature, privateKey.Public().(ed25519.PublicKey), challenge.ExpiresAt); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("expiry error = %v, want ErrApprovalExpired", err)
	}
	tampered := signature
	tampered.ScopeDigest = digest('f')
	if err := VerifyDeviceSignature(challenge, tampered, privateKey.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("tampered scope error = %v, want ErrApprovalRequired", err)
	}
	tampered = signature
	tampered.Signature = append([]byte(nil), signature.Signature...)
	tampered.Signature[0] ^= 0xff
	if err := VerifyDeviceSignature(challenge, tampered, privateKey.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("tampered signature error = %v, want ErrApprovalRequired", err)
	}
}

func TestChallengeCannotOutliveEntryQuote(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	plan, err := NewPlanV1("11111111-1111-4111-8111-111111111111", 1, PlanReadyForApproval, validScope(now))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewChallengeV1(plan, "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "device-0123456789abcdef01234567", now, plan.Scope.Cost.ValidUntil)
	if err == nil {
		t.Fatal("challenge outliving quote was accepted")
	}
}

func TestOperationRequiresSignatureAfterApproval(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	plan, err := NewPlanV1("11111111-1111-4111-8111-111111111111", 1, PlanReadyForApproval, validScope(now))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewChallengeV1(plan, "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "device-0123456789abcdef01234567", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	operation := OperationV1{Challenge: challenge, Status: StatusActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := operation.Validate(); err == nil {
		t.Fatal("active operation without approval signature was accepted")
	}
	operation.Status = StatusAwaitingApproval
	if err := operation.Validate(); err != nil {
		t.Fatalf("awaiting approval operation rejected: %v", err)
	}
	operation.ErrorSummary = strings.Repeat("x", 513)
	if err := operation.Validate(); err == nil {
		t.Fatal("oversized error summary was accepted")
	}
}

func validScope(now time.Time) ScopeV1 {
	deadline := now.Add(30 * time.Minute)
	return ScopeV1{
		SchemaVersion:   ScopeSchemaV1,
		Kind:            EntryKindALB,
		AgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		OwnerID:         "owner-0123456789abcdef",
		ConnectionID:    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Region:          "ap-south-1",
		Worker: WorkerReadBackScopeV1{
			DeploymentID:           "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
			DeploymentRevision:     3,
			TaskID:                 "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
			OriginalPlanID:         "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			OriginalPlanHash:       digest('1'),
			OriginalApprovalID:     "ffffffff-ffff-4fff-8fff-ffffffffffff",
			WorkerResourceID:       "12121212-1212-4212-8212-121212121212",
			WorkerResourceRevision: 5,
			WorkerSpecDigest:       digest('2'),
			InstanceID:             "i-12345678",
			VPCID:                  "vpc-12345678",
			SubnetID:               "subnet-12345678",
			SecurityGroupID:        "sg-12345678",
			ExecutionOutcome:       WorkerOutcomeSucceeded,
			SucceededAt:            now,
			ReadBack: AWSReadBackV1{
				Observed: true, Exists: true, State: EC2InstanceRunning, ObservedAt: now.Add(time.Second), TagDigest: digest('3'),
			},
			Retention: RetentionScopeV1{Class: RetentionEphemeral, AutoDestroy: true, DestroyDeadline: deadline},
		},
		Recipe: RecipeHealthBindingV1{RecipeDigest: digest('4'), HealthContractDigest: digest('5'), AuthenticationContractDigest: digest('6')},
		Certificate: CertificateScopeV1{
			CertificateARN:          "arn:aws:acm:ap-south-1:123456789012:certificate/12345678-1234-4234-8234-1234567890ab",
			Region:                  "ap-south-1",
			Hostname:                "api.example.com",
			SubjectAlternativeNames: []string{"api.example.com", "*.example.com"},
			Status:                  CertificateStatusIssued,
			ReadBackDigest:          digest('7'),
			ObservedAt:              now.Add(2 * time.Second),
		},
		ALB: ALBScopeV1{
			Scheme:           ALBSchemeInternetFacing,
			ListenerPort:     HTTPSPort,
			ListenerProtocol: ListenerProtocolHTTPS,
			TLSPolicy:        TLSPolicyTLS13_2021_06,
			IngressCIDRs:     []string{"0.0.0.0/0"},
			TargetProtocol:   TargetProtocolHTTP,
			TargetPort:       8080,
			TargetSource:     TargetSourceApprovedWorkerReadBack,
			WorkerPublicIPv4: false,
			EIPRequested:     false,
			PublicSubnets: []PublicSubnetScopeV1{
				{SubnetID: "subnet-23456789", VPCID: "vpc-12345678", AvailabilityZone: "ap-south-1a", Public: true, ReadBackDigest: digest('8'), ObservedAt: now.Add(2 * time.Second)},
				{SubnetID: "subnet-3456789a", VPCID: "vpc-12345678", AvailabilityZone: "ap-south-1b", Public: true, ReadBackDigest: digest('9'), ObservedAt: now.Add(2 * time.Second)},
			},
		},
		Health:         HealthRouteScopeV1{Path: "/health/ready", ExpectedStatusCode: 200, EvidenceDigest: digest('5'), NoCredentialRoute: true},
		Authentication: AuthenticationScopeV1{Required: true, ContractDigest: digest('6')},
		Cost: EntryCostScopeV1{
			QuoteID: "56565656-5656-4565-8565-565656565656", QuoteDigest: digest('a'), Currency: "USD", QuotedAt: now, ValidUntil: now.Add(15 * time.Minute),
			ALBHourlyEstimateMicros: 12000, LCUHourlyEstimateMicros: 9000, EstimatedLCUMilliUnits: 1000,
			EstimatedEgressMiB: 1024, TrafficEstimateMicros: 1000, MaximumLaunchAmountMicros: 30000, AssumptionsDigest: digest('b'),
		},
		Retention: RetentionScopeV1{Class: RetentionEphemeral, AutoDestroy: true, DestroyDeadline: deadline},
	}
}

func digest(value byte) string { return "sha256:" + strings.Repeat(string(value), 64) }

func bytesOf(value byte, count int) []byte { return []byte(strings.Repeat(string(value), count)) }

func ptr(value time.Time) *time.Time { return &value }

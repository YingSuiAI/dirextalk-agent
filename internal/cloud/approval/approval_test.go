package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

func TestPlanHashCanonicalizesScopesAndBindsOwnership(t *testing.T) {
	left := validPlan()
	right := left
	right.Status = PlanApproved
	right.ResourceScope.AvailabilityZones = []string{"us-east-1b", "us-east-1a"}
	right.SecretScope = []SecretReferenceV1{left.SecretScope[1], left.SecretScope[0]}
	right.IntegrationScope = []IntegrationScopeV1{left.IntegrationScope[1], left.IntegrationScope[0]}

	leftHash, err := left.Hash()
	if err != nil {
		t.Fatal(err)
	}
	rightHash, err := right.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if leftHash != rightHash {
		t.Fatalf("set/status projection changed immutable plan hash: %s != %s", leftHash, rightHash)
	}

	right.OwnerID = "owner-2"
	if _, err := right.Hash(); err == nil {
		t.Fatal("owner scope drift did not require a new quote")
	}
	right.Quote.ScopeDigest, err = right.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := right.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if changed == leftHash {
		t.Fatal("owner change did not change plan hash")
	}
}

func TestApprovalSigningPayloadBindsEveryHighRiskScope(t *testing.T) {
	plan := validPlan()
	approval, err := NewApprovalV1(plan, "approval-1", "challenge-1", "device-key-1", plan.Quote.ValidUntil.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := approval.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*ApprovalV1)
	}{
		{"approval", func(a *ApprovalV1) { a.ApprovalID = "approval-2" }},
		{"agent instance", func(a *ApprovalV1) { a.AgentInstanceID = "agent-instance-2" }},
		{"owner", func(a *ApprovalV1) { a.OwnerID = "owner-2" }},
		{"plan", func(a *ApprovalV1) { a.PlanID = "plan-2" }},
		{"plan hash", func(a *ApprovalV1) { a.PlanHash = digest("6") }},
		{"connection", func(a *ApprovalV1) { a.ConnectionID = "connection-2" }},
		{"quote identity", func(a *ApprovalV1) { a.QuoteID = "quote-2" }},
		{"quote", func(a *ApprovalV1) { a.QuoteDigest = digest("9") }},
		{"quote scope", func(a *ApprovalV1) { a.QuoteScopeDigest = digest("7") }},
		{"quote candidate", func(a *ApprovalV1) { a.QuoteCandidateID = "performance" }},
		{"quote validity", func(a *ApprovalV1) { a.QuoteValidUntil = a.QuoteValidUntil.Add(-time.Second) }},
		{"revision", func(a *ApprovalV1) { a.PlanRevision++ }},
		{"recipe", func(a *ApprovalV1) { a.RecipeDigest = digest("8") }},
		{"resource", func(a *ApprovalV1) { a.ResourceScope.DiskGiB++ }},
		{"network", func(a *ApprovalV1) { a.NetworkScope.SubnetID = "subnet-0bbbbbbbbbbbbbbbb" }},
		{"secret", func(a *ApprovalV1) { a.SecretScope[0].Purpose = "different purpose" }},
		{"integration", func(a *ApprovalV1) { a.IntegrationScope[0].Name = "different integration" }},
		{"retention", func(a *ApprovalV1) { a.RetentionScope.GracePeriodSeconds++ }},
		{"challenge", func(a *ApprovalV1) { a.ChallengeID = "challenge-2" }},
		{"signer", func(a *ApprovalV1) { a.SignerKeyID = "device-key-2" }},
		{"expiry", func(a *ApprovalV1) { a.ExpiresAt = a.ExpiresAt.Add(-time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := approval
			changed.SecretScope = append([]SecretReferenceV1(nil), approval.SecretScope...)
			changed.IntegrationScope = append([]IntegrationScopeV1(nil), approval.IntegrationScope...)
			test.mutate(&changed)
			payload, err := changed.SigningPayload()
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) == string(baseline) {
				t.Fatalf("%s mutation did not change signing payload", test.name)
			}
		})
	}
}

func TestApprovalVerifyAndCurrentPlanBinding(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := validPlan()
	approval, err := NewApprovalV1(plan, "approval-1", "challenge-1", "device-key-1", now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := approval.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	approval.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if err := approval.Verify(publicKey, now); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := approval.ValidateAgainstPlan(plan, now); err != nil {
		t.Fatalf("ValidateAgainstPlan() error = %v", err)
	}
	if err := approval.VerifyForPlan(publicKey, plan, now); err != nil {
		t.Fatalf("VerifyForPlan() error = %v", err)
	}

	drifted := plan
	drifted.RetentionScope.GracePeriodSeconds++
	if err := approval.ValidateAgainstPlan(drifted, now); err == nil {
		t.Fatal("ValidateAgainstPlan() accepted retention drift")
	}
	drifted = plan
	drifted.NetworkScope.SecurityGroupMode, drifted.NetworkScope.SecurityGroupID = SecurityGroupCreateDedicated, ""
	if err := approval.ValidateAgainstPlan(drifted, now); err == nil {
		t.Fatal("ValidateAgainstPlan() accepted security group ownership drift")
	}
	drifted = plan
	drifted.NetworkScope.PublicIPv4 = !drifted.NetworkScope.PublicIPv4
	if err := approval.ValidateAgainstPlan(drifted, now); err == nil {
		t.Fatal("ValidateAgainstPlan() accepted public IPv4 drift")
	}
	if err := approval.Verify(publicKey, approval.ExpiresAt); err == nil {
		t.Fatal("Verify() accepted an expired approval")
	}
}

func TestApprovalContractContainsNoPrivateKeyField(t *testing.T) {
	typeOf := reflect.TypeOf(ApprovalV1{})
	for i := 0; i < typeOf.NumField(); i++ {
		name := strings.ToLower(typeOf.Field(i).Name + " " + typeOf.Field(i).Tag.Get("json"))
		if strings.Contains(name, "private") || strings.Contains(name, "secret_key") {
			t.Fatalf("ApprovalV1 exposes private signing material through %s", typeOf.Field(i).Name)
		}
	}
}

func TestPlanAndApprovalGoldenVectors(t *testing.T) {
	planJSON := readGolden(t, "testdata/v1/plan.json")
	var plan PlanV1
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, validPlan()) {
		t.Fatal("plan.json no longer matches the Go PlanV1 vector")
	}
	planCBOR, err := plan.CanonicalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(planCBOR), readGolden(t, "testdata/v1/plan.cbor.hex"); got != want {
		t.Fatalf("plan CBOR differs from language-neutral golden")
	}
	planHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := NewApprovalV1(plan, "approval-1", "challenge-1", readGolden(t, "testdata/v1/approval-key-id.txt"), time.Date(2026, time.July, 16, 8, 5, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := approval.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	payloadHash := sha256.Sum256(payload)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), payload)
	if want := readGolden(t, "testdata/v1/plan.hash"); planHash != want {
		t.Fatalf("plan hash = %q, want golden %q", planHash, want)
	}
	if got, want := hex.EncodeToString(payload), readGolden(t, "testdata/v1/approval-signing-payload.cbor.hex"); got != want {
		t.Fatal("signing payload differs from language-neutral golden")
	}
	if got, want := hex.EncodeToString(payloadHash[:]), readGolden(t, "testdata/v1/approval-signing-payload.sha256"); got != want {
		t.Fatalf("payload SHA-256 = %q, want golden %q", got, want)
	}
	if got, want := base64.RawURLEncoding.EncodeToString(signature), readGolden(t, "testdata/v1/approval-signature.base64url"); got != want {
		t.Fatalf("signature = %q, want golden %q", got, want)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if got, want := base64.RawURLEncoding.EncodeToString(publicKey), readGolden(t, "testdata/v1/approval-public-key.raw.base64url"); got != want {
		t.Fatalf("raw public key = %q, want golden %q", got, want)
	}
	spki := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, publicKey...)
	if got, want := base64.StdEncoding.EncodeToString(spki), readGolden(t, "testdata/v1/approval-public-key.spki.base64"); got != want {
		t.Fatalf("SPKI public key = %q, want golden %q", got, want)
	}
	publicKeyHash := sha256.Sum256(publicKey)
	if got, want := "cloud-device-"+hex.EncodeToString(publicKeyHash[:])[:24], readGolden(t, "testdata/v1/approval-key-id.txt"); got != want {
		t.Fatalf("approval key ID = %q, want golden %q", got, want)
	}
}

func validPlan() PlanV1 {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := PlanV1{
		SchemaVersion:   PlanSchemaV1,
		AgentInstanceID: "agent-instance-1",
		OwnerID:         "owner-1",
		PlanID:          "plan-1",
		Revision:        7,
		Status:          PlanReadyForConfirmation,
		ConnectionID:    "connection-1",
		Recipe:          RecipeBindingV1{RecipeID: "recipe-1", Digest: digest("a"), Maturity: recipe.MaturityExperimental},
		Quote:           QuoteBindingV1{QuoteID: "quote-1", Digest: digest("b"), ValidUntil: now.Add(15 * time.Minute), CandidateID: "recommended"},
		ResourceScope: ResourceScopeV1{
			Region: "us-east-1", AvailabilityZones: []string{"us-east-1a", "us-east-1b"}, InstanceType: "m7i.xlarge", Architecture: recipe.ArchitectureAMD64,
			InstanceCount: 1, VCPU: 4, MemoryMiB: 16384, DiskGiB: 80, VolumeType: "gp3", VolumeEncrypted: true, PurchaseOption: PurchaseOnDemand,
			WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: digest("c"),
		},
		NetworkScope: NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupMode: SecurityGroupExisting, SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: EntryPointNone},
		SecretScope: []SecretReferenceV1{
			{SecretRef: "secret_ref:plan-1/model-token", Purpose: "model access", Delivery: recipe.SecretDeliveryFile},
			{SecretRef: "secret_ref:plan-1/registry-token", Purpose: "registry access", Delivery: recipe.SecretDeliveryFile},
		},
		IntegrationScope: []IntegrationScopeV1{{Kind: IntegrationMCP, Name: "service tools"}, {Kind: IntegrationWeb, Name: "service ui"}},
		RetentionScope:   RetentionScopeV1{Class: RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
	}
	scopeDigest, err := plan.PricingScopeDigest()
	if err != nil {
		panic(err)
	}
	plan.Quote.ScopeDigest = scopeDigest
	return plan
}

func digest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }

func readGolden(t *testing.T, name string) string {
	t.Helper()
	value, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(value))
}

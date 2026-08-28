package cloudworker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func compatibilityPlan(t *testing.T) Plan {
	t.Helper()
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	store := &intrinsicStore{}
	service, err := NewServiceWithAWSBindingResolver(store, intrinsicDefaults(now),
		FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: time.Minute, Now: func() time.Time { return now }},
		AWSBindingResolverFunc(func(context.Context) (AWSBinding, error) { return intrinsicAWSBinding(), nil }),
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	enableCredentialProposalDependencies(t, service, nil)
	if _, err = service.Propose(context.Background(), credentialProposalCommand()); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 {
		t.Fatalf("offers=%d", len(store.commands))
	}
	return store.commands[0].Plan
}

func TestPersistedPlanAcceptsReleasedUnboundDigestEncodingsOnly(t *testing.T) {
	legacy := compatibilityPlan(t)
	legacyPermission, err := BindingForPlan(legacy)
	if err != nil || string(legacyPermission.PermissionDigest) != legacy.ModelAuthorization.BindingDigest {
		t.Fatalf("legacy binding=%+v err=%v", legacyPermission, err)
	}
	loadedLegacy := legacy
	if err = loadedLegacy.ValidatePersisted(); err != nil || loadedLegacy.IsV185NilGitHubEncoding() {
		t.Fatalf("legacy load err=%v v185=%v", err, loadedLegacy.IsV185NilGitHubEncoding())
	}

	deployed := legacy
	deployed.v185NilGitHubDigest = true
	if err = deployed.sealAuthorizationBasis(); err != nil {
		t.Fatal(err)
	}
	deployed.Quote.BasisDigest = deployed.AuthorizationBasisDigest
	if err = deployed.Quote.Seal(); err != nil {
		t.Fatal(err)
	}
	if err = deployed.Seal(); err != nil {
		t.Fatal(err)
	}
	deployedPermission, err := BindingForPlan(deployed)
	if err != nil || deployedPermission.PermissionDigest == legacyPermission.PermissionDigest {
		t.Fatalf("deployed binding=%+v err=%v", deployedPermission, err)
	}
	loadedDeployed := deployed
	loadedDeployed.v185NilGitHubDigest = false
	if err = loadedDeployed.ValidatePersisted(); err != nil || !loadedDeployed.IsV185NilGitHubEncoding() {
		t.Fatalf("deployed load err=%v v185=%v", err, loadedDeployed.IsV185NilGitHubEncoding())
	}
	loadedPermission, err := BindingForPlan(loadedDeployed)
	if err != nil || !loadedPermission.Equal(deployedPermission) {
		t.Fatalf("deployed confirmation changed: binding=%+v err=%v", loadedPermission, err)
	}

	tampered := deployed
	tampered.v185NilGitHubDigest = false
	tampered.GitHubBinding = &GitHubBinding{OwnerID: deployed.OwnerID, AccountGeneration: deployed.AccountGeneration, ConfigRevision: 1, CredentialVersion: 1}
	if err = tampered.ValidatePersisted(); err == nil {
		t.Fatal("accepted a binding added to an unbound deployed plan")
	}
}

func TestPersistedBoundPlanNeverUsesUnboundCompatibility(t *testing.T) {
	bound := compatibilityPlan(t)
	bound.GitHubBinding = &GitHubBinding{OwnerID: bound.OwnerID, AccountGeneration: bound.AccountGeneration, ConfigRevision: 3, CredentialVersion: 5}
	if err := bound.sealAuthorizationBasis(); err != nil {
		t.Fatal(err)
	}
	bound.Quote.BasisDigest = bound.AuthorizationBasisDigest
	if err := bound.Quote.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := bound.Seal(); err != nil {
		t.Fatal(err)
	}
	loaded := bound
	if err := loaded.ValidatePersisted(); err != nil || loaded.IsV185NilGitHubEncoding() {
		t.Fatalf("bound load err=%v historical=%v", err, loaded.IsV185NilGitHubEncoding())
	}
	loaded.GitHubBinding.CredentialVersion++
	if err := loaded.ValidatePersisted(); err == nil {
		t.Fatal("accepted a rotated bound GitHub credential")
	}
}

type releasedProposalFixture struct {
	PublicPlan  json.RawMessage `json:"public_plan"`
	PrivatePlan struct {
		Objective     string         `json:"objective"`
		InputManifest InputManifest  `json:"input_manifest"`
		GitHubBinding *GitHubBinding `json:"github_binding"`
	} `json:"private_plan"`
	ProposalRequestDigest string         `json:"proposal_request_digest"`
	ProposalCommand       ProposeCommand `json:"proposal_command"`
}

func releasedProposalPlan(t *testing.T, name string) (Plan, releasedProposalFixture) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "store", "postgres", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var fixture releasedProposalFixture
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var plan Plan
	if err = json.Unmarshal(fixture.PublicPlan, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Objective, plan.InputManifest, plan.GitHubBinding = fixture.PrivatePlan.Objective, fixture.PrivatePlan.InputManifest, fixture.PrivatePlan.GitHubBinding
	if err = plan.ValidatePersisted(); err != nil {
		t.Fatalf("%s plan: %v", name, err)
	}
	return plan, fixture
}

func TestProposalReplayDigestsMatchReleasedFixtures(t *testing.T) {
	legacyPlan, legacyFixture := releasedProposalPlan(t, "v184-unbound.json")
	_, deployedFixture := releasedProposalPlan(t, "v185-unbound.json")
	boundPlan, boundFixture := releasedProposalPlan(t, "v185-bound.json")
	legacy, deployed := proposalRequestDigests(legacyPlan, legacyFixture.ProposalCommand.ComputeRequirements)
	if legacy != legacyFixture.ProposalRequestDigest || deployed != deployedFixture.ProposalRequestDigest {
		t.Fatalf("unbound replay digests legacy=%q deployed=%q", legacy, deployed)
	}
	bound, alternate := proposalRequestDigests(boundPlan, boundFixture.ProposalCommand.ComputeRequirements)
	if bound != boundFixture.ProposalRequestDigest || alternate != "" {
		t.Fatalf("bound replay digest=%q alternate=%q", bound, alternate)
	}
}

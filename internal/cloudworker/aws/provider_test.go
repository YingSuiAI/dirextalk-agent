package aws

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestPlanAndDispatchAreDeterministicAndNetworkIsClosed(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan := testPlan(t, now)
	reordered := plan
	reordered.InfrastructureDigest = ""
	reordered.Network.DNSResolverCIDRs = []string{"10.0.0.53/32", "10.0.0.2/32"}
	reordered.Network.TLSProxyCIDRs = []string{"10.0.0.10/32", "10.0.0.9/32"}
	reordered.Network.AllowedFQDNs = []string{"s3.us-east-1.amazonaws.com", "api.openai.com"}
	reordered, err := SealPlan(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if plan.InfrastructureDigest != reordered.InfrastructureDigest {
		t.Fatalf("canonical infrastructure digest changed with order: %s != %s", plan.InfrastructureDigest, reordered.InfrastructureDigest)
	}
	authorization := testAuthorization(now)
	first, err := NewDispatchIntent(plan, authorization, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDispatchIntent(plan, authorization, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.ClientToken != second.ClientToken || first.IntentDigest != second.IntentDigest || first.StackName != second.StackName {
		t.Fatal("dispatch identity changed across controller restart")
	}
	if len(plan.Digest) != 64 || len(plan.InfrastructureDigest) != 64 || len(first.IntentDigest) != 64 {
		t.Fatalf("digest is not Core canonical lowercase 64-hex: plan=%q infrastructure=%q intent=%q", plan.Digest, plan.InfrastructureDigest, first.IntentDigest)
	}
	policy, err := plan.Network.SecurityGroupPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Ingress) != 0 || policy.SecurityGroupEnforcesFQDN || policy.FQDNEnforcement != "controlled_tls_proxy" {
		t.Fatalf("unsafe security-group policy: %+v", policy)
	}
	for _, rule := range policy.Egress {
		if rule.CIDRv4 == "0.0.0.0/0" || (rule.FromPort != 53 && rule.FromPort != 443) {
			t.Fatalf("unexpected egress rule: %+v", rule)
		}
	}

	unsafe := plan
	unsafe.InfrastructureDigest = ""
	unsafe.Network.TLSProxyCIDRs = []string{"0.0.0.0/0"}
	if _, err := SealPlan(unsafe); err == nil {
		t.Fatal("unbounded TLS egress accepted")
	}
	unsafe = plan
	unsafe.InfrastructureDigest = ""
	unsafe.Network.AllowedFQDNs = []string{"*.example.com"}
	if _, err := SealPlan(unsafe); err == nil {
		t.Fatal("wildcard FQDN accepted")
	}
}

func TestProxyAndHostPolicyDriftChangeInfrastructureAndTamperFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan := testPlan(t, now)

	proxyDrift := plan
	proxyDrift.Network.OutboundProxyURL = "https://proxy-2.example.test:443"
	proxyDrift.Network.OutboundProxyServerName = "proxy-2.example.test"
	proxyDrift.Network.OutboundProxyBindingDigest = ""
	proxyDrift.IAMRoleName, proxyDrift.InstanceProfileName, proxyDrift.BootstrapDigest, proxyDrift.InfrastructureDigest = "", "", "", ""
	proxyDrift, err := SealPlan(proxyDrift)
	if err != nil {
		t.Fatal(err)
	}
	if proxyDrift.InfrastructureDigest == plan.InfrastructureDigest || proxyDrift.BootstrapDigest == plan.BootstrapDigest || proxyDrift.Network.OutboundProxyBindingDigest == plan.Network.OutboundProxyBindingDigest {
		t.Fatal("outbound proxy drift reused infrastructure authorization")
	}

	hostDrift := plan
	hostDrift.HostNetworkPolicySHA256 = testDigest("f")
	hostDrift.IAMRoleName, hostDrift.InstanceProfileName, hostDrift.BootstrapDigest, hostDrift.InfrastructureDigest = "", "", "", ""
	hostDrift, err = SealPlan(hostDrift)
	if err != nil {
		t.Fatal(err)
	}
	if hostDrift.InfrastructureDigest == plan.InfrastructureDigest || hostDrift.BootstrapDigest == plan.BootstrapDigest {
		t.Fatal("host network policy drift reused infrastructure authorization")
	}

	kmsDrift := plan
	kmsDrift.RootKMSKeyARN = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222"
	kmsDrift.IAMRoleName, kmsDrift.InstanceProfileName, kmsDrift.BootstrapDigest, kmsDrift.InfrastructureDigest = "", "", "", ""
	kmsDrift, err = SealPlan(kmsDrift)
	if err != nil {
		t.Fatal(err)
	}
	if kmsDrift.InfrastructureDigest == plan.InfrastructureDigest ||
		kmsDrift.BootstrapDigest == plan.BootstrapDigest {
		t.Fatal("artifact KMS drift reused bootstrap or infrastructure authorization")
	}

	relayTrustDrift := plan
	relayTrustDrift.ModelRelayTrustBundleSHA256 = testDigest("0")
	relayTrustDrift.IAMRoleName, relayTrustDrift.InstanceProfileName, relayTrustDrift.BootstrapDigest, relayTrustDrift.InfrastructureDigest = "", "", "", ""
	relayTrustDrift, err = SealPlan(relayTrustDrift)
	if err != nil {
		t.Fatal(err)
	}
	if relayTrustDrift.InfrastructureDigest == plan.InfrastructureDigest ||
		relayTrustDrift.BootstrapDigest == plan.BootstrapDigest {
		t.Fatal("model relay CA drift reused bootstrap or infrastructure authorization")
	}

	tampered := plan
	tampered.Network.OutboundProxyBindingDigest = testDigest("0")
	if tampered.Validate() == nil {
		t.Fatal("tampered proxy binding passed sealed plan validation")
	}
}

func TestDispatchRejectsQuoteConfirmationAndFreshnessDriftBeforeMutation(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan := testPlan(t, now)
	authorization := testAuthorization(now)

	tests := []struct {
		name   string
		mutate func(*AuthorizationBinding)
	}{
		{name: "fresh quote differs from authorized", mutate: func(binding *AuthorizationBinding) { binding.FreshQuoteDigest = testDigest("f") }},
		{name: "confirmation readback differs from expected", mutate: func(binding *AuthorizationBinding) { binding.ConfirmationDigest = testDigest("f") }},
		{name: "fresh quote too old", mutate: func(binding *AuthorizationBinding) { binding.FreshQuotedAt = now.Add(-10 * time.Minute) }},
		{name: "quote expired", mutate: func(binding *AuthorizationBinding) { binding.QuoteExpiresAt = now }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := authorization
			test.mutate(&binding)
			if _, err := NewDispatchIntent(plan, binding, now); err == nil {
				t.Fatal("authorization drift accepted")
			}
		})
	}

	intent, err := NewDispatchIntent(plan, authorization, now)
	if err != nil {
		t.Fatal(err)
	}
	intent.Authorization.FreshQuoteDigest = testDigest("f")
	intent.IntentDigest = intent.expectedDigest()
	ledger := NewMemoryLedger()
	cloud := newFakeCloud(plan, intent, func() time.Time { return now })
	provider, _ := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }))
	if _, err := provider.Ensure(context.Background(), plan, intent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("provider accepted tampered authorization: %v", err)
	}
	if cloud.createCalls != 0 {
		t.Fatal("provider crossed mutation boundary before authorization validation")
	}

	validIntent, err := NewDispatchIntent(plan, authorization, now)
	if err != nil {
		t.Fatal(err)
	}
	late := now.Add(6 * time.Minute)
	lateLedger := NewMemoryLedger()
	lateCloud := newFakeCloud(plan, validIntent, func() time.Time { return late })
	lateProvider, _ := NewProvider(lateCloud, lateLedger, WithClock(func() time.Time { return late }))
	if _, err := lateProvider.Ensure(context.Background(), plan, validIntent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired quote reached provider boundary: %v", err)
	}
	if lateCloud.createCalls != 0 {
		t.Fatal("provider mutated AWS after quote expiry")
	}
}

func TestAuthorizationExpiryBetweenClaimAndDispatchIsDurablyFenced(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	cloud.onVerify = func() { now = intent.Authorization.QuoteExpiresAt }
	if _, err := provider.Ensure(context.Background(), plan, intent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("authorization expiring during provider read-back was accepted: %v", err)
	}
	stored, getErr := ledger.Get(context.Background(), plan.Identity)
	if getErr != nil || stored.State != LifecycleFailed || !stored.CreateMutation.DispatchedAt.IsZero() || cloud.createCalls != 0 {
		t.Fatalf("expired dispatch was not durably fenced: state=%s dispatched=%s creates=%d err=%v",
			stored.State, stored.CreateMutation.DispatchedAt, cloud.createCalls, getErr)
	}
}

func TestEnsureCreatesExactlyOnceAndPersistsEveryResource(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	if record, err := NewLedgerRecord(plan, intent, now); err != nil {
		t.Fatalf("new ledger record: %v", err)
	} else if err := record.Validate(); err != nil {
		t.Fatalf("ledger record validate: %v", err)
	}

	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil {
		t.Fatalf("ensure failed (create_calls=%d verify_calls=%d): %v", cloud.createCalls, cloud.verifyCalls, err)
	}
	if graph.State != GraphActive || cloud.createCalls != 1 {
		t.Fatalf("unexpected ensure result: state=%s creates=%d", graph.State, cloud.createCalls)
	}
	if _, err := provider.Ensure(context.Background(), plan, intent); err != nil {
		t.Fatal(err)
	}
	if cloud.createCalls != 1 {
		t.Fatalf("idempotent ensure created %d stacks", cloud.createCalls)
	}
	if cloud.lastCreate.SSMEnabled || len(cloud.lastCreate.SecurityGroupPolicy.Ingress) != 0 ||
		cloud.lastCreate.InstanceCount != 1 {
		t.Fatalf("create request escaped closed topology: %+v", cloud.lastCreate)
	}
	record, err := ledger.Get(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != LifecycleActive || len(record.Resources) != len(AllResourceKinds()) {
		t.Fatalf("ledger not active: %+v", record)
	}
	if record.StackCreationIdentity.StackID != record.StackProviderID ||
		record.StackCreationIdentity.ClientRequestToken != intent.ClientToken ||
		record.StackCreationIdentity.CreationEventID == "" ||
		record.Resources[ResourceIAMRole].ProviderID != cloud.providerID(ResourceIAMRole) ||
		record.Resources[ResourceInstanceProfile].ProviderID != cloud.providerID(ResourceInstanceProfile) {
		t.Fatalf("immutable AWS identities were not persisted: stack=%+v role=%q profile=%q", record.StackCreationIdentity,
			record.Resources[ResourceIAMRole].ProviderID, record.Resources[ResourceInstanceProfile].ProviderID)
	}
	for _, kind := range AllResourceKinds() {
		entry := record.Resources[kind]
		if entry.ProviderID == "" || entry.State != ResourceActive {
			t.Fatalf("resource %s not independently bound: %+v", kind, entry)
		}
	}
	cloud.assertEveryOperationScoped(t)
}

func TestConcurrentStackCreationEvidenceBindingPreservesFirstObservation(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	record, err := NewLedgerRecord(plan, intent, now)
	if err != nil {
		t.Fatal(err)
	}
	record.State = LifecycleCreateStarted
	record.CreateMutation = MutationRecord{
		Token:        "create-mutation-11111111",
		StartedAt:    now,
		LeaseUntil:   now.Add(time.Second),
		DispatchedAt: now,
		Attempts:     1,
	}
	if _, err = ledger.CreateIntent(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	first := cloud.stackReferenceLocked()
	second := first
	second.CreationIdentity.ObservedAt = first.CreationIdentity.ObservedAt.Add(time.Millisecond)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, reference := range []StackReference{first, second} {
		go func(reference StackReference) {
			<-start
			errs <- provider.bindStackReference(context.Background(), plan.Identity, reference, LifecycleProvisioning)
		}(reference)
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("same create operation conflicted during concurrent read-back: %v", err)
		}
	}

	stored, err := ledger.Get(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.StackCreationIdentity.sameOperation(first.CreationIdentity) {
		t.Fatalf("bound a different create operation: %+v", stored.StackCreationIdentity)
	}
	if stored.StackCreationIdentity.ObservedAt != first.CreationIdentity.ObservedAt &&
		stored.StackCreationIdentity.ObservedAt != second.CreationIdentity.ObservedAt {
		t.Fatalf("did not preserve the first successful observation time: %s", stored.StackCreationIdentity.ObservedAt)
	}
}

func TestIAMSameNameReplacementIDFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, _, cloud, provider := testProvider(t, &now)
	if _, err := provider.Ensure(context.Background(), plan, intent); err != nil {
		t.Fatal(err)
	}
	cloud.mu.Lock()
	replacement := cloud.resources[ResourceIAMRole]
	replacement.ProviderID = "AROAQRSTUVWXYZ1234567"
	cloud.resources[ResourceIAMRole] = replacement
	cloud.mu.Unlock()
	if _, err := provider.Observe(context.Background(), plan.Identity); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("same-name IAM role replacement was accepted: %v", err)
	}
}

func TestPreparePersistsIntentWithoutAWSMutationAndEnsureConsumesItOnce(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	identity, err := provider.Prepare(context.Background(), plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Equal(plan.Identity) || cloud.createCalls != 0 || cloud.mutationCalls != 0 || cloud.verifyCalls != 0 {
		t.Fatalf("prepare crossed AWS boundary: identity=%+v create=%d mutation=%d verify=%d", identity, cloud.createCalls, cloud.mutationCalls, cloud.verifyCalls)
	}
	record, err := ledger.Get(context.Background(), identity)
	if err != nil || record.State != LifecycleIntentRecorded || record.Intent.IntentDigest != intent.IntentDigest {
		t.Fatalf("prepared ledger=%+v err=%v", record, err)
	}
	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil || graph.State != GraphActive || cloud.createCalls != 1 {
		t.Fatalf("ensure after prepare: graph=%s create=%d err=%v", graph.State, cloud.createCalls, err)
	}
	if _, err := provider.Ensure(context.Background(), plan, intent); err != nil || cloud.createCalls != 1 {
		t.Fatalf("prepared intent replay created again: create=%d err=%v", cloud.createCalls, err)
	}
}

func TestEnsureFailsClosedAfterCleanupWasRequested(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	cloud.holdDelete[ResourceEC2] = true
	if _, err = provider.Destroy(context.Background(), plan.Identity, graph); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("destroy = %v, want pending", err)
	}
	record, err := ledger.Get(context.Background(), plan.Identity)
	if err != nil || record.State != LifecycleDestroying || record.CleanupRequestedAt.IsZero() {
		t.Fatalf("cleanup intent was not durable: record=%+v err=%v", record, err)
	}
	if _, err = provider.Ensure(context.Background(), plan, intent); !errors.Is(err, ErrDestroyRequested) {
		t.Fatalf("ensure after cleanup = %v, want destroy requested", err)
	}
	if cloud.createCalls != 1 {
		t.Fatalf("cleanup race created %d stacks", cloud.createCalls)
	}
}

func TestUnknownCreateResponseUsesReadbackAndNeverCreatesAgain(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	cloud.createErr = ErrResponseUnknown
	cloud.applyUnknownCreate = true

	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	if graph.State != GraphActive || cloud.createCalls != 1 || cloud.findCalls == 0 {
		t.Fatalf("unknown create was not reconciled: graph=%s creates=%d finds=%d", graph.State, cloud.createCalls, cloud.findCalls)
	}
	if _, err := provider.Ensure(context.Background(), plan, intent); err != nil {
		t.Fatal(err)
	}
	if cloud.createCalls != 1 {
		t.Fatal("unknown response caused duplicate create")
	}
	record, _ := ledger.Get(context.Background(), plan.Identity)
	if record.CreateMutation.UncertainAt.IsZero() {
		t.Fatal("unknown mutation was not durably recorded")
	}
}

func TestUnknownInstanceProfileIdentityRetriesOnlyAfterDurableDeadline(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	cloud.profileUntagged = true
	cloud.identityErrors = []error{ErrResponseUnknown}

	graph, err := provider.Ensure(context.Background(), plan, intent)
	if !errors.Is(err, ErrReconcilePending) || graph.State != GraphProvisioning {
		t.Fatalf("unknown profile tag = %s, %v; want provisioning/pending", graph.State, err)
	}
	stored, err := ledger.Get(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	profile := stored.Resources[ResourceInstanceProfile]
	if profile.IdentityState != ResourceIdentityUncertain || profile.IdentityMutation.CompletedAt.IsZero() ||
		!profile.IdentityMutation.LeaseUntil.Equal(profile.IdentityMutation.CompletedAt.Add(time.Second)) ||
		!profile.IdentityMutation.LeaseUntil.After(now) || profile.IdentityMutation.Attempts != 1 {
		t.Fatalf("unknown profile tag did not persist a bounded retry fence: %+v", profile)
	}
	if cloud.createCalls != 1 || cloud.identityCalls != 1 {
		t.Fatalf("first attempt created/tagged unexpected counts: create=%d tag=%d", cloud.createCalls, cloud.identityCalls)
	}

	// Recreate the provider to prove the retry deadline is ledger state rather
	// than an in-memory timer. No call before that exact deadline may re-tag.
	restarted, err := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }), WithMutationLease(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now = profile.IdentityMutation.LeaseUntil.Add(-time.Nanosecond)
	if graph, err = restarted.Ensure(context.Background(), plan, intent); !errors.Is(err, ErrReconcilePending) || graph.State != GraphProvisioning {
		t.Fatalf("pre-deadline retry = %s, %v; want provisioning/pending", graph.State, err)
	}
	if cloud.identityCalls != 1 || cloud.createCalls != 1 {
		t.Fatalf("pre-deadline call repeated mutation: create=%d tag=%d", cloud.createCalls, cloud.identityCalls)
	}

	now = profile.IdentityMutation.LeaseUntil
	graph, err = restarted.Ensure(context.Background(), plan, intent)
	if err != nil || graph.State != GraphActive {
		t.Fatalf("post-deadline exact retry = %s, %v; want active", graph.State, err)
	}
	stored, err = ledger.Get(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	profile = stored.Resources[ResourceInstanceProfile]
	if profile.IdentityState != ResourceIdentityVerified || profile.IdentityMutation.Attempts != 2 ||
		cloud.identityCalls != 2 || cloud.createCalls != 1 {
		t.Fatalf("identity retry did not converge exactly once: profile=%+v create=%d tag=%d", profile, cloud.createCalls, cloud.identityCalls)
	}
	if len(cloud.identityRequests) != 2 || cloud.identityRequests[0].CleanupOnly || cloud.identityRequests[1].CleanupOnly ||
		cloud.identityRequests[0].MutationToken != cloud.identityRequests[1].MutationToken {
		t.Fatalf("provisioning retry changed identity fence: %+v", cloud.identityRequests)
	}
}

func TestPreTagCancelEstablishesCleanupOnlyIdentityAndDestroysExactGraph(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	cloud.profileUntagged = true
	cloud.identityErrors = []error{ErrResponseUnknown}

	observed, err := provider.Ensure(context.Background(), plan, intent)
	if !errors.Is(err, ErrReconcilePending) || observed.State != GraphProvisioning {
		t.Fatalf("unknown profile tag = %s, %v; want provisioning/pending", observed.State, err)
	}
	stored, err := ledger.Get(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	retryAt := stored.Resources[ResourceInstanceProfile].IdentityMutation.LeaseUntil

	pending, err := provider.Destroy(context.Background(), plan.Identity, observed)
	if !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("pre-deadline cancellation = %v, want pending", err)
	}
	if pending.State != GraphDestroying {
		t.Fatalf("durable cleanup fence leaked provider provisioning state: %s", pending.State)
	}
	stored, getErr := ledger.Get(context.Background(), plan.Identity)
	if getErr != nil || stored.State != LifecycleDestroying || stored.CleanupRequestedAt.IsZero() {
		t.Fatalf("cleanup fence was not durable: state=%s requested=%s err=%v", stored.State, stored.CleanupRequestedAt, getErr)
	}
	if cloud.identityCalls != 1 || len(cloud.deleteRequests) != 0 {
		t.Fatalf("pre-deadline cleanup mutated cloud: tags=%d deletes=%d", cloud.identityCalls, len(cloud.deleteRequests))
	}

	// A restarted cleanup controller may establish the previously untagged
	// profile identity, but only with the durable cleanup fence reflected in the
	// adapter request and only after the unknown-call deadline.
	restarted, err := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }), WithMutationLease(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now = retryAt
	destroyed, err := restarted.Destroy(context.Background(), plan.Identity, pending)
	if err != nil || destroyed.State != GraphVerifiedDestroyed {
		t.Fatalf("cleanup-only identity recovery = %s, %v; want verified_destroyed", destroyed.State, err)
	}
	stored, err = ledger.Get(context.Background(), plan.Identity)
	if err != nil || stored.State != LifecycleVerifiedDestroyed || cloud.createCalls != 1 || cloud.identityCalls != 2 {
		t.Fatalf("cleanup-only recovery did not converge once: state=%s create=%d tag=%d err=%v", stored.State, cloud.createCalls, cloud.identityCalls, err)
	}
	if len(cloud.identityRequests) != 2 || cloud.identityRequests[0].CleanupOnly || !cloud.identityRequests[1].CleanupOnly ||
		cloud.identityRequests[0].MutationToken != cloud.identityRequests[1].MutationToken {
		t.Fatalf("cleanup retry was not fenced as cleanup-only: %+v", cloud.identityRequests)
	}
	for _, kind := range AllResourceKinds() {
		if cloud.deleteCalls[kind] != 1 || stored.Resources[kind].State != ResourceVerifiedDestroyed {
			t.Fatalf("%s was not exactly deleted and verified: deletes=%d state=%s", kind, cloud.deleteCalls[kind], stored.Resources[kind].State)
		}
	}
}

func TestLeaseReclaimReusesOriginalDispatchAndInstance(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil {
		t.Fatal(err)
	}

	reclaimedPlan := plan
	reclaimedPlan.Identity.TaskAttempt++
	reclaimedPlan.Identity.LeaseEpoch++
	reclaimedPlan.Identity.LaunchIdentity = DeriveLaunchIdentity(reclaimedPlan.Identity)
	reclaimedPlan.InfrastructureDigest = ""
	reclaimedPlan, err = SealPlan(reclaimedPlan)
	if err != nil {
		t.Fatal(err)
	}
	reclaimedIntent, err := NewDispatchIntent(reclaimedPlan, testAuthorization(now), now)
	if err != nil {
		t.Fatal(err)
	}
	reclaimedGraph, err := provider.Ensure(context.Background(), reclaimedPlan, reclaimedIntent)
	if err != nil {
		t.Fatalf("lease reclaim did not resume original dispatch: %v", err)
	}
	if reclaimedGraph.StackProviderID != graph.StackProviderID || !reclaimedGraph.Identity.Equal(plan.Identity) {
		t.Fatalf("lease reclaim returned a replacement graph: before=%+v after=%+v", graph.Identity, reclaimedGraph.Identity)
	}
	if cloud.createCalls != 1 {
		t.Fatalf("lease reclaim created %d stacks", cloud.createCalls)
	}
	stored, err := ledger.GetByExecution(context.Background(), LookupFor(reclaimedPlan.Identity))
	if err != nil || !stored.Identity.Equal(plan.Identity) {
		t.Fatalf("execution lookup did not return original launch: record=%+v err=%v", stored.Identity, err)
	}
	if _, err := provider.Destroy(context.Background(), stored.Identity, graph); err != nil {
		t.Fatalf("original launch cleanup failed: %v", err)
	}
	if cloud.createCalls != 1 {
		t.Fatal("cleanup caused a second create")
	}
}

func TestUnknownCreateWithoutProviderObjectRemainsReadbackOnly(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	cloud.createErr = ErrResponseUnknown

	if _, err := provider.Ensure(context.Background(), plan, intent); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("unknown create = %v, want reconcile pending", err)
	}
	if _, err := provider.Ensure(context.Background(), plan, intent); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("second unknown create = %v, want reconcile pending", err)
	}
	if cloud.createCalls != 1 {
		t.Fatalf("readback-only fence performed %d creates", cloud.createCalls)
	}
	record, _ := ledger.Get(context.Background(), plan.Identity)
	if record.State != LifecycleCreateUncertain {
		t.Fatalf("unexpected ledger state: %s", record.State)
	}
}

func TestCancellationFencesBlockedCreateAndCleansLateSuccess(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	cloud.createArrived = make(chan struct{}, 1)
	cloud.createRelease = make(chan struct{})
	type ensureResult struct {
		graph ObservedGraph
		err   error
	}
	result := make(chan ensureResult, 1)
	go func() {
		graph, err := provider.Ensure(context.Background(), plan, intent)
		result <- ensureResult{graph: graph, err: err}
	}()
	select {
	case <-cloud.createArrived:
	case <-time.After(2 * time.Second):
		t.Fatal("CreateStack did not reach the bounded external call")
	}

	// This is the cancellation/lease-reclaim race: cleanup wins while the one
	// authorized CreateStack call is still in flight and not yet provider-visible.
	observed, err := provider.Observe(context.Background(), plan.Identity)
	if err != nil || observed.State != GraphProvisioning {
		t.Fatalf("pre-cancel observation = %s, %v", observed.State, err)
	}
	if _, err = provider.Destroy(context.Background(), plan.Identity, observed); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("cleanup did not wait for in-flight create: %v", err)
	}
	stored, err := ledger.Get(context.Background(), plan.Identity)
	if err != nil || stored.State != LifecycleDestroying || stored.CleanupRequestedAt.IsZero() {
		t.Fatalf("create fence was not durable: state=%s cleanup=%v err=%v", stored.State, stored.CleanupRequestedAt, err)
	}
	for _, entry := range stored.Resources {
		if entry.State == ResourceVerifiedDestroyed {
			t.Fatal("in-flight create was hidden by an early destroyed tombstone")
		}
	}

	close(cloud.createRelease)
	select {
	case ensured := <-result:
		if !errors.Is(ensured.err, ErrDestroyRequested) {
			t.Fatalf("late create resumed provisioning: graph=%s err=%v", ensured.graph.State, ensured.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bounded CreateStack did not return")
	}
	cloud.createArrived, cloud.createRelease = nil, nil

	observed, err = provider.Observe(context.Background(), plan.Identity)
	if err != nil || observed.State != GraphDestroying {
		t.Fatalf("late successful stack was not rediscovered: state=%s err=%v", observed.State, err)
	}
	destroyed, err := provider.Destroy(context.Background(), plan.Identity, observed)
	if err != nil || destroyed.State != GraphVerifiedDestroyed {
		t.Fatalf("late successful stack did not clean: state=%s err=%v", destroyed.State, err)
	}
	stored, err = ledger.Get(context.Background(), plan.Identity)
	if err != nil || stored.State != LifecycleVerifiedDestroyed || cloud.createCalls != 1 {
		t.Fatalf("cleanup closed with wrong state/create count: state=%s creates=%d err=%v", stored.State, cloud.createCalls, err)
	}
}

func TestUnknownCreateNeedsBoundedDeadlineAndVisibilityQualification(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	cloud.createErr = ErrResponseUnknown
	if _, err := provider.Ensure(context.Background(), plan, intent); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("unknown create = %v, want pending", err)
	}
	stored, err := ledger.Get(context.Background(), plan.Identity)
	if err != nil || stored.CreateMutation.DispatchedAt.IsZero() || stored.CreateMutation.CompletedAt.IsZero() ||
		stored.CreateMutation.LeaseUntil.Sub(stored.CreateMutation.StartedAt) != time.Second {
		t.Fatalf("bounded create deadline was not durable: mutation=%+v err=%v", stored.CreateMutation, err)
	}
	observed, err := provider.Observe(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Destroy(context.Background(), plan.Identity, observed); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("pre-deadline cleanup = %v, want pending", err)
	}
	stored, _ = ledger.Get(context.Background(), plan.Identity)
	if stored.State == LifecycleVerifiedDestroyed || stored.CreateAbsence.Observations != 0 {
		t.Fatalf("pre-deadline absence qualified: state=%s proof=%+v", stored.State, stored.CreateAbsence)
	}

	now = stored.CreateMutation.LeaseUntil
	if graph, err := provider.Observe(context.Background(), plan.Identity); err != nil || graph.State != GraphDestroying {
		t.Fatalf("first post-deadline read = %s, %v", graph.State, err)
	}
	stored, _ = ledger.Get(context.Background(), plan.Identity)
	if stored.State == LifecycleVerifiedDestroyed || stored.CreateAbsence.Observations != 1 {
		t.Fatalf("single absence incorrectly closed cleanup: state=%s proof=%+v", stored.State, stored.CreateAbsence)
	}

	// A brand-new provider proves the qualification evidence is durable and not
	// an in-memory sleep/window. The fake clock advances; wall time does not.
	restarted, _ := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }), WithMutationLease(time.Second))
	now = now.Add(createVisibilityQualificationWindow - time.Nanosecond)
	if graph, err := restarted.Observe(context.Background(), plan.Identity); err != nil || graph.State != GraphDestroying {
		t.Fatalf("short visibility window = %s, %v", graph.State, err)
	}
	stored, _ = ledger.Get(context.Background(), plan.Identity)
	if stored.State == LifecycleVerifiedDestroyed {
		t.Fatal("visibility qualification used an arbitrary short delay")
	}
	now = now.Add(time.Nanosecond)
	qualified, err := restarted.Observe(context.Background(), plan.Identity)
	if err != nil || qualified.State != GraphVerifiedDestroyed {
		t.Fatalf("qualified absence = %s, %v", qualified.State, err)
	}
	stored, err = ledger.Get(context.Background(), plan.Identity)
	if err != nil || stored.State != LifecycleVerifiedDestroyed || stored.CreateAbsence.Observations < createAbsenceRequiredObservations ||
		stored.VerifiedDestroyedAt.IsZero() || !stored.TombstoneAuditUntil.After(stored.VerifiedDestroyedAt) {
		t.Fatalf("qualified tombstone was not durable: state=%s proof=%+v err=%v", stored.State, stored.CreateAbsence, err)
	}
}

func TestReaperAuditsTombstoneAndCleansLateUnknownCreate(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	cloud.createErr = ErrResponseUnknown
	if _, err := provider.Ensure(context.Background(), plan, intent); !errors.Is(err, ErrReconcilePending) {
		t.Fatal(err)
	}
	observed, err := provider.Observe(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Destroy(context.Background(), plan.Identity, observed); !errors.Is(err, ErrReconcilePending) {
		t.Fatal(err)
	}
	stored, _ := ledger.Get(context.Background(), plan.Identity)
	now = stored.CreateMutation.LeaseUntil
	if _, err = provider.Observe(context.Background(), plan.Identity); err != nil {
		t.Fatal(err)
	}
	now = now.Add(createVisibilityQualificationWindow)
	if graph, err := provider.Observe(context.Background(), plan.Identity); err != nil || graph.State != GraphVerifiedDestroyed {
		t.Fatalf("initial tombstone = %s, %v", graph.State, err)
	}

	// The original unknown call becomes visible only after initial qualification.
	// This is not a second CreateStack call; the tombstone audit must reopen the
	// same dispatch and destroy all eight exact resources.
	now = now.Add(verifiedTombstoneAuditInterval)
	cloud.mu.Lock()
	cloud.createLocked()
	cloud.mu.Unlock()
	restarted, _ := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }), WithMutationLease(time.Second))
	reaper, _ := NewReaper(restarted, ledger, WithReaperClock(func() time.Time { return now }))
	report, err := reaper.Sweep(context.Background())
	if err != nil || report.VerifiedDestroyed != 1 {
		t.Fatalf("late-create tombstone audit failed: report=%+v err=%v", report, err)
	}
	stored, err = ledger.Get(context.Background(), plan.Identity)
	if err != nil || stored.State != LifecycleVerifiedDestroyed || cloud.createCalls != 1 {
		t.Fatalf("late create leaked or duplicated: state=%s creates=%d err=%v", stored.State, cloud.createCalls, err)
	}
	for _, kind := range AllResourceKinds() {
		if cloud.deleteCalls[kind] != 1 || stored.Resources[kind].State != ResourceVerifiedDestroyed {
			t.Fatalf("late %s cleanup not verified: deletes=%d state=%s", kind, cloud.deleteCalls[kind], stored.Resources[kind].State)
		}
	}
}

func TestDestroyRejectsSameNameReplacementBeforeMutation(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, _, cloud, provider := testProvider(t, &now)
	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	cloud.mu.Lock()
	replaced := cloud.resources[ResourceEC2]
	replacementIdentity := plan.Identity
	replacementIdentity.Generation++
	replaced.LaunchIdentity = DeriveLaunchIdentity(replacementIdentity)
	replaced.Generation = replacementIdentity.Generation
	replaced.Tags[TagLaunchIdentity] = replaced.LaunchIdentity
	replaced.Tags[TagGeneration] = "2"
	cloud.resources[ResourceEC2] = replaced
	cloud.mu.Unlock()

	if _, err := provider.Destroy(context.Background(), plan.Identity, graph); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("replacement destroy = %v, want ownership mismatch", err)
	}
	if len(cloud.deleteRequests) != 0 {
		t.Fatalf("replacement was mutated: %+v", cloud.deleteRequests)
	}
}

func TestEveryReadRevalidatesProviderIdentityAndClosedTopology(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, _, cloud, provider := testProvider(t, &now)
	if _, err := provider.Ensure(context.Background(), plan, intent); err != nil {
		t.Fatal(err)
	}
	cloud.mu.Lock()
	readsBefore := cloud.readCalls
	wrong := ProviderIdentityObservation{AccountID: plan.Identity.AccountID, AccountGeneration: plan.Identity.AccountGeneration + 1, Region: plan.Identity.Region, ProviderID: plan.Identity.ProviderID, ObservedAt: now}
	cloud.identityOverride = &wrong
	cloud.mu.Unlock()
	if _, err := provider.Observe(context.Background(), plan.Identity); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("provider replacement read = %v, want identity mismatch", err)
	}
	cloud.mu.Lock()
	if cloud.readCalls != readsBefore {
		cloud.mu.Unlock()
		t.Fatal("cloud graph was read after provider identity mismatch")
	}
	cloud.identityOverride = nil
	cloud.topologyMutator = func(proof *TopologyProof) { proof.SSMEnabled = true }
	cloud.mu.Unlock()
	if _, err := provider.Observe(context.Background(), plan.Identity); !errors.Is(err, ErrCloudReadback) {
		t.Fatalf("SSM topology drift = %v, want readback failure", err)
	}
}

func TestUnknownDeleteResponseIsReadBackAndCanConverge(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	cloud.deleteUnknown[ResourceEC2] = true
	cloud.applyUnknownDelete[ResourceEC2] = true

	destroyed, err := provider.Destroy(context.Background(), plan.Identity, graph)
	if err != nil {
		t.Fatal(err)
	}
	if destroyed.State != GraphVerifiedDestroyed {
		t.Fatalf("destroy state = %s", destroyed.State)
	}
	record, _ := ledger.Get(context.Background(), plan.Identity)
	if record.State != LifecycleVerifiedDestroyed || !allEntriesDestroyed(record.Resources) {
		t.Fatal("verified_destroyed was published before every resource read back absent")
	}
	for _, kind := range AllResourceKinds() {
		if cloud.deleteCalls[kind] != 1 {
			t.Fatalf("delete calls for %s = %d", kind, cloud.deleteCalls[kind])
		}
	}
	cloud.assertEveryOperationScoped(t)
}

func TestDestroyedCASConflictForcesFreshExactReadback(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan := testPlan(t, now)
	intent, err := NewDispatchIntent(plan, testAuthorization(now), now)
	if err != nil {
		t.Fatal(err)
	}
	baseLedger := NewMemoryLedger()
	cloud := newFakeCloud(plan, intent, func() time.Time { return now })
	ledger := &conflictingDestroyedLedger{ResourceLedger: baseLedger}
	provider, err := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }), WithMutationLease(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Ensure(context.Background(), plan, intent); err != nil {
		t.Fatal(err)
	}
	if err := provider.requestCleanup(context.Background(), plan.Identity); err != nil {
		t.Fatal(err)
	}
	cloud.mu.Lock()
	cloud.removeLocked(ResourceEC2)
	cloud.mu.Unlock()
	record, err := ledger.Get(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := provider.observeResource(context.Background(), record, record.Resources[ResourceEC2])
	if err != nil || observation.Exists {
		t.Fatalf("initial absence=%+v err=%v", observation, err)
	}
	cloud.mu.Lock()
	readsBefore := cloud.readCalls
	cloud.mu.Unlock()
	ledger.arm = true
	ledger.onConflict = func() {
		cloud.mu.Lock()
		defer cloud.mu.Unlock()
		reappeared := cloud.resources[ResourceEC2]
		reappeared.Exists = true
		reappeared.ObservedAt = now
		cloud.resources[ResourceEC2] = reappeared
	}

	destroyed, err := provider.markResourceDestroyed(context.Background(), record, ResourceEC2, observation)
	if err != nil || destroyed {
		t.Fatalf("stale absence closed resource: destroyed=%t err=%v", destroyed, err)
	}
	stored, err := baseLedger.Get(context.Background(), plan.Identity)
	if err != nil || stored.Resources[ResourceEC2].State == ResourceVerifiedDestroyed || stored.Resources[ResourceEC2].Mutation.Attempts != 1 {
		t.Fatalf("stale absence overwrote the latest mutation fence: entry=%+v err=%v", stored.Resources[ResourceEC2], err)
	}
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if !ledger.fired || cloud.readCalls != readsBefore+1 {
		t.Fatalf("CAS loss did not force one fresh exact read: fired=%t reads=%d want=%d", ledger.fired, cloud.readCalls, readsBefore+1)
	}
}

func TestUnknownDeleteThatStillExistsNeverBlindlyRetries(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	cloud.deleteUnknown[ResourceEC2] = true

	if _, err := provider.Destroy(context.Background(), plan.Identity, graph); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("destroy = %v, want pending", err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		observed, observeErr := provider.Observe(context.Background(), plan.Identity)
		if observeErr != nil {
			t.Fatal(observeErr)
		}
		if _, destroyErr := provider.Destroy(context.Background(), plan.Identity, observed); !errors.Is(destroyErr, ErrReconcilePending) {
			t.Fatalf("retry %d = %v, want pending", attempt, destroyErr)
		}
	}
	if cloud.deleteCalls[ResourceEC2] != 1 {
		t.Fatalf("uncertain delete was repeated %d times", cloud.deleteCalls[ResourceEC2])
	}
	record, _ := ledger.Get(context.Background(), plan.Identity)
	if record.Resources[ResourceEC2].State != ResourceDestroyUncertain || record.State == LifecycleVerifiedDestroyed {
		t.Fatalf("unknown resource state was lost: %+v", record.Resources[ResourceEC2])
	}

	// After the mutation lease expires, Destroy performs another exact
	// ownership-validated read-back and may safely retry the same deterministic
	// delete token. A second unknown response remains non-terminal.
	now = now.Add(2 * time.Second)
	observed, err := provider.Observe(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Destroy(context.Background(), plan.Identity, observed); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("post-lease destroy = %v, want pending", err)
	}
	if cloud.deleteCalls[ResourceEC2] != 2 {
		t.Fatalf("post-lease exact read-back did not retry delete: calls=%d", cloud.deleteCalls[ResourceEC2])
	}
	if len(cloud.deleteRequests) < 2 || cloud.deleteRequests[0].MutationToken != cloud.deleteRequests[1].MutationToken {
		t.Fatalf("delete retry changed deterministic token: %+v", cloud.deleteRequests)
	}

	// A later retry whose response is still unknown but whose read-back proves
	// absence may close cleanup; all other resources are then deleted normally.
	now = now.Add(2 * time.Second)
	cloud.applyUnknownDelete[ResourceEC2] = true
	observed, err = provider.Observe(context.Background(), plan.Identity)
	if err != nil {
		t.Fatal(err)
	}
	destroyed, err := provider.Destroy(context.Background(), plan.Identity, observed)
	if err != nil || destroyed.State != GraphVerifiedDestroyed {
		t.Fatalf("verified retry did not converge: state=%s err=%v", destroyed.State, err)
	}
	record, err = ledger.Get(context.Background(), plan.Identity)
	if err != nil || record.State != LifecycleVerifiedDestroyed || !allEntriesDestroyed(record.Resources) {
		t.Fatalf("cleanup did not close after exact absence: state=%s err=%v", record.State, err)
	}
}

func TestAcceptedAsyncDeleteConvergesAfterReaperRestart(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	graph, err := provider.Ensure(context.Background(), plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	cloud.holdDelete[ResourceEC2] = true
	if _, err := provider.Destroy(context.Background(), plan.Identity, graph); !errors.Is(err, ErrReconcilePending) {
		t.Fatalf("async destroy = %v, want pending", err)
	}
	record, _ := ledger.Get(context.Background(), plan.Identity)
	if record.Resources[ResourceEC2].State != ResourceDestroyAccepted || record.State == LifecycleVerifiedDestroyed {
		t.Fatalf("accepted async delete published a terminal state: %+v", record.Resources[ResourceEC2])
	}
	cloud.mu.Lock()
	cloud.removeLocked(ResourceEC2)
	cloud.holdDelete[ResourceEC2] = false
	cloud.mu.Unlock()

	restartedProvider, _ := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }))
	restarted, _ := NewReaper(restartedProvider, ledger, WithReaperClock(func() time.Time { return now }))
	if report, err := restarted.Sweep(context.Background()); err != nil || report.VerifiedDestroyed != 1 {
		t.Fatalf("restart sweep did not converge: report=%+v err=%v", report, err)
	}
	record, _ = ledger.Get(context.Background(), plan.Identity)
	if record.State != LifecycleVerifiedDestroyed || cloud.deleteCalls[ResourceEC2] != 1 {
		t.Fatalf("restart state=%s ec2 deletes=%d", record.State, cloud.deleteCalls[ResourceEC2])
	}
}

func TestReaperRestartAndConcurrentSweepConverge(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, ledger, cloud, provider := testProvider(t, &now)
	if _, err := provider.Ensure(context.Background(), plan, intent); err != nil {
		t.Fatal(err)
	}
	now = plan.DestroyDeadline.Add(time.Second)
	cloud.deleteArrived = make(chan struct{}, 1)
	cloud.deleteRelease = make(chan struct{})

	firstProvider, _ := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }))
	secondProvider, _ := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }))
	firstReaper, _ := NewReaper(firstProvider, ledger, WithReaperClock(func() time.Time { return now }))
	secondReaper, _ := NewReaper(secondProvider, ledger, WithReaperClock(func() time.Time { return now }))
	type result struct {
		report ReapReport
		err    error
	}
	results := make(chan result, 2)
	go func() {
		report, err := firstReaper.Sweep(context.Background())
		results <- result{report, err}
	}()
	select {
	case <-cloud.deleteArrived:
	case <-time.After(2 * time.Second):
		t.Fatal("first reaper did not reach mutation")
	}
	go func() {
		report, err := secondReaper.Sweep(context.Background())
		results <- result{report, err}
	}()
	// Let the losing sweep observe the in-flight CAS claim before the winner
	// completes. It may report pending, but it cannot issue a duplicate delete.
	time.Sleep(20 * time.Millisecond)
	close(cloud.deleteRelease)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent sweep failed: report=%+v err=%v", result.report, result.err)
		}
	}
	cloud.deleteArrived, cloud.deleteRelease = nil, nil

	// A brand-new Reaper instance proves no in-memory lease or cursor is needed
	// to converge after restart.
	restartedProvider, _ := NewProvider(cloud, ledger, WithClock(func() time.Time { return now }))
	restarted, _ := NewReaper(restartedProvider, ledger, WithReaperClock(func() time.Time { return now }))
	if report, err := restarted.Sweep(context.Background()); err != nil {
		t.Fatalf("restart sweep failed: report=%+v err=%v", report, err)
	}
	record, _ := ledger.Get(context.Background(), plan.Identity)
	if record.State != LifecycleVerifiedDestroyed {
		t.Fatalf("restart did not converge: %s", record.State)
	}
	for _, kind := range AllResourceKinds() {
		if cloud.deleteCalls[kind] != 1 {
			t.Fatalf("concurrent delete calls for %s = %d", kind, cloud.deleteCalls[kind])
		}
	}
}

func testPlan(t *testing.T, now time.Time) Plan {
	t.Helper()
	identity := ExecutionIdentity{
		OwnerID: "owner-1", AccountID: "123456789012", AccountGeneration: 3, Region: "us-east-1",
		ExecutionID: "11111111-1111-4111-8111-111111111111", TaskID: "22222222-2222-4222-8222-222222222222",
		TaskAttempt: 2, LeaseEpoch: 7, ProviderID: "aws-credential-revision-7", Generation: 1,
	}
	identity.LaunchIdentity = DeriveLaunchIdentity(identity)
	plan, err := SealPlan(Plan{
		Identity: identity, Recipe: RecipePiTask, Adapter: AdapterPiJSON,
		Digest: testDigest("9"),
		AMIID:  "ami-0123456789abcdef0", AMIDigest: testDigest("a"), WorkerDigest: testDigest("b"), PiDigest: testDigest("c"), HostNetworkPolicySHA256: testDigest("8"), Architecture: "amd64",
		InstanceType: "c7i.large", RootVolumeGiB: 32, RootDeviceName: "/dev/xvda", RootVolumeType: "gp3", RootVolumeIOPS: 3000,
		RootVolumeThroughput: 125, RootKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
		VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", ControlPlaneEndpoint: "https://control.example.com:443",
		ControlPlaneServerName: "control.example.com", ControlPlaneTrustBundleSHA256: testDigest("4"),
		ModelRelayServerName: "api.openai.com", ModelRelayTrustBundleSHA256: testDigest("6"),
		WorkspaceMode: WorkspaceWrite, ExecutionSHA256: testDigest("5"), TaskSHA256: testDigest("6"),
		InputManifestDigest: testDigest("1"), ModelAuthorizationDigest: testDigest("2"), ArtifactBindingDigest: testDigest("3"),
		S3Grants: []S3ObjectGrant{{Access: S3ReadExactVersion, Bucket: "dirextalk-input", Key: "tasks/input.tar", VersionID: "version-1"},
			{Access: S3WritePrefix, Bucket: "dirextalk-output", Key: "executions/11111111/"}}, ArtifactRetentionSeconds: 86400,
		Network: NetworkPolicy{
			DNSResolverCIDRs: []string{"10.0.0.2/32", "10.0.0.53/32"}, TLSProxyCIDRs: []string{"10.0.0.9/32", "10.0.0.10/32"},
			AllowedFQDNs:     []string{"api.openai.com", "s3.us-east-1.amazonaws.com"},
			OutboundProxyURL: "https://proxy.example.test:443", OutboundProxyServerName: "proxy.example.test",
			OutboundProxyTrustBundleSHA256: testDigest("7"),
		},
		DestroyDeadline: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testDigest(character string) string {
	value := ""
	for len(value) < 64 {
		value += character
	}
	return value[:64]
}

func testProvider(t *testing.T, now *time.Time) (Plan, DispatchIntent, *MemoryLedger, *fakeCloud, *Provider) {
	t.Helper()
	plan := testPlan(t, *now)
	intent, err := NewDispatchIntent(plan, testAuthorization(*now), *now)
	if err != nil {
		t.Fatal(err)
	}
	ledger := NewMemoryLedger()
	cloud := newFakeCloud(plan, intent, func() time.Time { return *now })
	provider, err := NewProvider(cloud, ledger, WithClock(func() time.Time { return *now }), WithMutationLease(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return plan, intent, ledger, cloud, provider
}

func testAuthorization(now time.Time) AuthorizationBinding {
	return AuthorizationBinding{
		AuthorizedQuoteDigest: testDigest("d"), FreshQuoteDigest: testDigest("d"),
		ExpectedConfirmationDigest: testDigest("e"), ConfirmationDigest: testDigest("e"),
		FreshQuotedAt: now.Add(-10 * time.Second), QuoteExpiresAt: now.Add(5 * time.Minute), ConfirmedAt: now.Add(-time.Second),
		MaximumQuoteAgeSeconds: 300,
	}
}

type fakeCloud struct {
	mu                 sync.Mutex
	plan               Plan
	intent             DispatchIntent
	now                func() time.Time
	created            bool
	resources          map[ResourceKind]ResourceObservation
	createErr          error
	applyUnknownCreate bool
	profileUntagged    bool
	identityErrors     []error
	applyUnknownTag    bool
	identityCalls      int
	identityRequests   []EnsureResourceIdentityRequest
	deleteUnknown      map[ResourceKind]bool
	applyUnknownDelete map[ResourceKind]bool
	holdDelete         map[ResourceKind]bool
	deleteCalls        map[ResourceKind]int
	createCalls        int
	findCalls          int
	verifyCalls        int
	readCalls          int
	mutationCalls      int
	lastCreate         CreateStackRequest
	deleteRequests     []DeleteResourceRequest
	deleteArrived      chan struct{}
	deleteRelease      chan struct{}
	createArrived      chan struct{}
	createRelease      chan struct{}
	identityOverride   *ProviderIdentityObservation
	topologyMutator    func(*TopologyProof)
	onVerify           func()
}

type conflictingDestroyedLedger struct {
	ResourceLedger
	arm        bool
	fired      bool
	onConflict func()
}

func (ledger *conflictingDestroyedLedger) CompareAndSwap(ctx context.Context, next LedgerRecord, expectedRevision uint64) (LedgerRecord, error) {
	if ledger.arm && !ledger.fired && next.Resources[ResourceEC2].State == ResourceVerifiedDestroyed {
		current, err := ledger.ResourceLedger.Get(ctx, next.Identity)
		if err != nil {
			return LedgerRecord{}, err
		}
		concurrent := current.clone()
		entry := concurrent.Resources[ResourceEC2]
		entry.Mutation.Token = mutationToken(concurrent.Intent.IntentDigest, ResourceEC2)
		entry.Mutation.Attempts++
		concurrent.Resources[ResourceEC2] = entry
		concurrent.Revision = current.Revision + 1
		if _, err := ledger.ResourceLedger.CompareAndSwap(ctx, concurrent, current.Revision); err != nil {
			return LedgerRecord{}, err
		}
		ledger.fired = true
		if ledger.onConflict != nil {
			ledger.onConflict()
		}
		return LedgerRecord{}, ErrConflict
	}
	return ledger.ResourceLedger.CompareAndSwap(ctx, next, expectedRevision)
}

func newFakeCloud(plan Plan, intent DispatchIntent, now func() time.Time) *fakeCloud {
	return &fakeCloud{
		plan: plan, intent: intent, now: now, resources: make(map[ResourceKind]ResourceObservation),
		deleteUnknown: make(map[ResourceKind]bool), applyUnknownDelete: make(map[ResourceKind]bool),
		holdDelete: make(map[ResourceKind]bool), deleteCalls: make(map[ResourceKind]int),
	}
}

func (cloud *fakeCloud) VerifyProviderIdentity(_ context.Context, request ProviderIdentityRequest) (ProviderIdentityObservation, error) {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if !request.Identity.Equal(cloud.plan.Identity) {
		return ProviderIdentityObservation{}, ErrIdentityMismatch
	}
	cloud.verifyCalls++
	if cloud.onVerify != nil {
		hook := cloud.onVerify
		cloud.onVerify = nil
		hook()
	}
	if cloud.identityOverride != nil {
		return *cloud.identityOverride, nil
	}
	return ProviderIdentityObservation{AccountID: request.Identity.AccountID, AccountGeneration: request.Identity.AccountGeneration,
		Region: request.Identity.Region, ProviderID: request.Identity.ProviderID, ObservedAt: cloud.now().UTC()}, nil
}

func (cloud *fakeCloud) CreateStack(ctx context.Context, request CreateStackRequest) (StackReference, error) {
	cloud.mu.Lock()
	cloud.requireIdentity(request.Identity)
	if request.Validate() != nil || request.Plan.Digest != cloud.plan.Digest || request.Intent.IntentDigest != cloud.intent.IntentDigest {
		cloud.mu.Unlock()
		return StackReference{}, ErrInvalid
	}
	cloud.createCalls++
	cloud.mutationCalls++
	cloud.lastCreate = request
	arrived, release := cloud.createArrived, cloud.createRelease
	cloud.mu.Unlock()
	if arrived != nil {
		select {
		case arrived <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
			return StackReference{}, ErrResponseUnknown
		}
	}
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if cloud.createErr == nil || cloud.applyUnknownCreate {
		cloud.createLocked()
	}
	if cloud.createErr != nil {
		return StackReference{}, cloud.createErr
	}
	return cloud.stackReferenceLocked(), nil
}

func (cloud *fakeCloud) FindStackByIntent(_ context.Context, request FindStackRequest) (StackReference, bool, error) {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	cloud.requireIdentity(request.Identity)
	cloud.findCalls++
	cloud.readCalls++
	if request.Intent.IntentDigest != cloud.intent.IntentDigest {
		return StackReference{}, false, ErrIdentityMismatch
	}
	if !cloud.created {
		return StackReference{}, false, nil
	}
	return cloud.stackReferenceLocked(), true, nil
}

func (cloud *fakeCloud) ObserveGraph(_ context.Context, request ObserveGraphRequest) (ObservedGraph, error) {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	cloud.requireIdentity(request.Identity)
	cloud.readCalls++
	if request.PlanDigest != cloud.plan.Digest || request.InfrastructureDigest != cloud.plan.InfrastructureDigest || request.IntentDigest != cloud.intent.IntentDigest || request.ClientToken != cloud.intent.ClientToken ||
		!containsTags(request.ExpectedTags, RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)) {
		return ObservedGraph{}, ErrIdentityMismatch
	}
	stackID := cloud.providerID(ResourceStack)
	if request.StackProviderID != "" && request.StackProviderID != stackID {
		return ObservedGraph{}, ErrOwnershipMismatch
	}
	return cloud.graphLocked(), nil
}

func (cloud *fakeCloud) ObserveResource(_ context.Context, request ObserveResourceRequest) (ResourceObservation, error) {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	cloud.requireIdentity(request.Identity)
	cloud.readCalls++
	if request.PlanDigest != cloud.plan.Digest || request.InfrastructureDigest != cloud.plan.InfrastructureDigest || request.IntentDigest != cloud.intent.IntentDigest || request.LogicalID != LogicalID(request.Kind) ||
		request.ResourceProviderID != cloud.providerID(request.Kind) || !containsTags(request.ExpectedTags, RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)) {
		return ResourceObservation{}, ErrIdentityMismatch
	}
	observation := cloud.resources[request.Kind]
	if request.Kind == ResourceInstanceProfile && observation.Exists && !containsTags(observation.Tags, request.ExpectedTags) {
		return ResourceObservation{}, ErrCloudReadback
	}
	return observation, nil
}

func (cloud *fakeCloud) ResolveIAMResourceIdentities(_ context.Context, request ResolveIAMResourceIdentitiesRequest) (IAMResourceIdentityProof, error) {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	cloud.requireIdentity(request.Identity)
	cloud.readCalls++
	if !cloud.created || request.PlanDigest != cloud.plan.Digest || request.InfrastructureDigest != cloud.plan.InfrastructureDigest ||
		request.IntentDigest != cloud.intent.IntentDigest || request.StackProviderID != cloud.providerID(ResourceStack) ||
		!containsTags(request.ExpectedTags, RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)) {
		return IAMResourceIdentityProof{}, ErrIdentityMismatch
	}
	return IAMResourceIdentityProof{
		Identity: cloud.plan.Identity, PlanDigest: cloud.plan.Digest, InfrastructureDigest: cloud.plan.InfrastructureDigest,
		IntentDigest: cloud.intent.IntentDigest, StackProviderID: cloud.providerID(ResourceStack),
		IAMRoleName: cloud.plan.IAMRoleName, IAMRoleID: cloud.providerID(ResourceIAMRole),
		InstanceProfileName: cloud.plan.InstanceProfileName, InstanceProfileID: cloud.providerID(ResourceInstanceProfile),
		ObservedAt: cloud.now().UTC(),
	}, nil
}

func (cloud *fakeCloud) EnsureResourceIdentity(_ context.Context, request EnsureResourceIdentityRequest) error {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	cloud.requireIdentity(request.Identity)
	cloud.mutationCalls++
	if request.Kind != ResourceInstanceProfile || request.LogicalID != LogicalID(ResourceInstanceProfile) || request.StackProviderID != cloud.providerID(ResourceStack) ||
		request.PlanDigest != cloud.plan.Digest || request.InfrastructureDigest != cloud.plan.InfrastructureDigest || request.IntentDigest != cloud.intent.IntentDigest ||
		request.ExpectedResourceProviderIDs[ResourceIAMRole] != cloud.providerID(ResourceIAMRole) ||
		request.ExpectedResourceProviderIDs[ResourceInstanceProfile] != cloud.providerID(ResourceInstanceProfile) ||
		request.MutationToken == "" || !containsTags(request.ExpectedTags, RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)) {
		return ErrIdentityMismatch
	}
	cloud.identityCalls++
	cloud.identityRequests = append(cloud.identityRequests, request)
	var mutationErr error
	if len(cloud.identityErrors) != 0 {
		mutationErr = cloud.identityErrors[0]
		cloud.identityErrors = cloud.identityErrors[1:]
	}
	if mutationErr == nil || errors.Is(mutationErr, ErrResponseUnknown) && cloud.applyUnknownTag {
		profile := cloud.resources[ResourceInstanceProfile]
		profile.Tags = RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)
		profile.ObservedAt = cloud.now().UTC()
		cloud.resources[ResourceInstanceProfile] = profile
	}
	return mutationErr
}

func (cloud *fakeCloud) DeleteResource(_ context.Context, request DeleteResourceRequest) error {
	cloud.mu.Lock()
	cloud.requireIdentity(request.Identity)
	if request.PlanDigest != cloud.plan.Digest || request.InfrastructureDigest != cloud.plan.InfrastructureDigest || request.IntentDigest != cloud.intent.IntentDigest || request.LogicalID != LogicalID(request.Kind) ||
		request.ResourceProviderID != cloud.providerID(request.Kind) || request.ExpectedResourceProviderIDs[ResourceStack] != cloud.providerID(ResourceStack) ||
		!containsTags(request.ExpectedTags, RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)) || request.MutationToken == "" {
		cloud.mu.Unlock()
		return ErrIdentityMismatch
	}
	cloud.deleteCalls[request.Kind]++
	cloud.mutationCalls++
	cloud.deleteRequests = append(cloud.deleteRequests, request)
	arrived, release := cloud.deleteArrived, cloud.deleteRelease
	cloud.mu.Unlock()
	if arrived != nil && request.Kind == ResourceEC2 {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
	}
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if cloud.deleteUnknown[request.Kind] {
		if cloud.applyUnknownDelete[request.Kind] {
			cloud.removeLocked(request.Kind)
		}
		return ErrResponseUnknown
	}
	if !cloud.holdDelete[request.Kind] {
		cloud.removeLocked(request.Kind)
	}
	return nil
}

func (cloud *fakeCloud) createLocked() {
	cloud.created = true
	tags := RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)
	for _, kind := range allResourceKinds {
		resourceTags := cloneMap(tags)
		if kind == ResourceInstanceProfile && cloud.profileUntagged {
			resourceTags = map[string]string{}
		}
		cloud.resources[kind] = ResourceObservation{
			Kind: kind, LogicalID: LogicalID(kind), ProviderID: cloud.providerID(kind), Exists: true, Tags: resourceTags,
			LaunchIdentity: cloud.plan.Identity.LaunchIdentity, Generation: cloud.plan.Identity.Generation, ObservedAt: cloud.now().UTC(),
		}
	}
}

func (cloud *fakeCloud) removeLocked(kind ResourceKind) {
	observation := cloud.resources[kind]
	observation.Exists = false
	observation.ObservedAt = cloud.now().UTC()
	cloud.resources[kind] = observation
}

func (cloud *fakeCloud) graphLocked() ObservedGraph {
	policy, _ := cloud.plan.Network.SecurityGroupPolicy()
	resources := make([]ResourceObservation, 0, len(allResourceKinds))
	state := GraphVerifiedDestroyed
	allExist := cloud.created
	identityPending := false
	expectedTags := RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)
	for _, kind := range allResourceKinds {
		observation, ok := cloud.resources[kind]
		if !ok {
			observation = ResourceObservation{Kind: kind, LogicalID: LogicalID(kind), ObservedAt: cloud.now().UTC()}
		}
		observation.ObservedAt = cloud.now().UTC()
		observation.Tags = cloneMap(observation.Tags)
		if kind == ResourceInstanceProfile && observation.Exists && !containsTags(observation.Tags, expectedTags) {
			identityPending = true
			observation.Exists = false
			observation.Tags = nil
		}
		resources = append(resources, observation)
		if observation.Exists {
			state = GraphDestroying
		} else {
			allExist = false
		}
	}
	if allExist {
		state = GraphActive
	} else if cloud.created && identityPending {
		state = GraphProvisioning
	}
	stackID := ""
	if cloud.created {
		stackID = cloud.providerID(ResourceStack)
	}
	graph := ObservedGraph{
		Identity: cloud.plan.Identity, PlanDigest: cloud.plan.Digest, InfrastructureDigest: cloud.plan.InfrastructureDigest, IntentDigest: cloud.intent.IntentDigest,
		StackProviderID: stackID, State: state, Resources: resources,
		Topology: TopologyProof{EC2InstanceCount: 1, Ingress: []NetworkRule{}, Egress: slices.Clone(policy.Egress),
			SSMEnabled: false, FQDNEnforcement: policy.FQDNEnforcement, FQDNPolicyDigest: policy.FQDNPolicyDigest},
		ObservedAt: cloud.now().UTC(),
	}
	if cloud.topologyMutator != nil {
		cloud.topologyMutator(&graph.Topology)
	}
	return graph
}

func (cloud *fakeCloud) stackReferenceLocked() StackReference {
	creationTime := cloud.lastCreate.MutationDispatchedAt
	if creationTime.IsZero() {
		creationTime = cloud.intent.RecordedAt
	}
	return StackReference{ProviderID: cloud.providerID(ResourceStack), InfrastructureDigest: cloud.plan.InfrastructureDigest, IntentDigest: cloud.intent.IntentDigest, ClientToken: cloud.intent.ClientToken,
		CreationIdentity: StackCreationIdentity{StackID: cloud.providerID(ResourceStack), StackName: cloud.intent.StackName, ClientRequestToken: cloud.intent.ClientToken,
			CreationEventID: "event-create-11111111", CreationTime: creationTime, ObservedAt: cloud.now().UTC()},
		Tags: RequiredTags(cloud.plan.Identity, cloud.plan.Digest, cloud.plan.InfrastructureDigest, cloud.intent.IntentDigest)}
}

func (cloud *fakeCloud) providerID(kind ResourceKind) string {
	switch kind {
	case ResourceEC2:
		return "i-0123456789abcdef0"
	case ResourceEBS:
		return "vol-0123456789abcdef0"
	case ResourceENI:
		return "eni-0123456789abcdef0"
	case ResourceEIP:
		return "eipalloc-0123456789abcdef0"
	case ResourceSecurityGroup:
		return "sg-0123456789abcdef0"
	case ResourceIAMRole:
		return "AROA1234567890ABCDEFG"
	case ResourceInstanceProfile:
		return "AIPA1234567890ABCDEFG"
	case ResourceStack:
		return "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-pi/11111111"
	default:
		return ""
	}
}

func (cloud *fakeCloud) requireIdentity(identity ExecutionIdentity) {
	if !identity.Equal(cloud.plan.Identity) {
		panic("fake AWS request omitted or changed immutable execution identity")
	}
}

func (cloud *fakeCloud) assertEveryOperationScoped(t *testing.T) {
	t.Helper()
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if cloud.verifyCalls < cloud.readCalls+cloud.mutationCalls {
		t.Fatalf("provider identity checks=%d, AWS operations=%d", cloud.verifyCalls, cloud.readCalls+cloud.mutationCalls)
	}
}

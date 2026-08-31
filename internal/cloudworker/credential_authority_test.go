package cloudworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimebounds"
	"github.com/google/uuid"
)

type limitRecordingQuoter struct {
	base FakeQuoter
	last QuoteRequest
}

func (quoter *limitRecordingQuoter) Quote(ctx context.Context, request QuoteRequest) (Quote, error) {
	quoter.last = request
	return quoter.base.Quote(ctx, request)
}

type proposalAWSBindingResolver struct {
	binding AWSBinding
	err     error
	calls   int
}

type capacityReuseResolver struct {
	err          error
	calls        int
	resolveCalls int
	selection    WorkerReuseSelection
	found        bool
}

func (resolver *capacityReuseResolver) ResolveIdleWorker(context.Context, string, uint64, AWSBinding, ComputeRequirements, *ServiceSpec) (WorkerReuseSelection, bool, error) {
	resolver.resolveCalls++
	return resolver.selection, resolver.found, nil
}

func (resolver *capacityReuseResolver) CheckCreateWorkerCapacity(context.Context, string, uint64, AWSBinding) error {
	resolver.calls++
	return resolver.err
}

func enableCredentialProposalDependencies(t *testing.T, service *Service, reuse *capacityReuseResolver) {
	t.Helper()
	if reuse == nil {
		reuse = &capacityReuseResolver{}
	}
	if err := service.EnablePersistentWorkerReuse(reuse); err != nil {
		t.Fatal(err)
	}
	if err := service.EnableDynamicComputeSelection(intrinsicComputeSelector{compute: ComputeSpec{InstanceType: "t3.small", Architecture: "x86_64", VCPU: 2, MemoryGiB: 2, RootDeviceName: "/dev/xvda", VolumeGiB: 20, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125}}); err != nil {
		t.Fatal(err)
	}
}

func (resolver *proposalAWSBindingResolver) ResolveCurrentAWSBinding(context.Context) (AWSBinding, error) {
	resolver.calls++
	return resolver.binding, resolver.err
}

func credentialProposalCommand() ProposeCommand {
	return ProposeCommand{
		OwnerID: "@owner:example.test", AccountGeneration: 7,
		IdempotencyKey: uuid.NewString(), ConversationID: uuid.NewString(), TurnID: uuid.NewString(),
		TurnLeaseID: uuid.NewString(), TurnLeaseEpoch: 2, ExpectedTurnRevision: 1,
		Objective: "run an exact cloud task", ObjectiveSummary: "run an exact cloud task",
		UserPromptDigest: digestValue("credential-authority-prompt"),
		ProposalReason:   ProposalReasonLocalBudgetExceeded,
		LocalBudgetEvidence: &LocalBudgetEvidence{
			BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-project-execution"),
		},
		InputManifest:       InputManifest{Schema: InputManifestSchema, Items: []InputManifestItem{}},
		WorkspaceMode:       WorkspaceNone,
		ComputeRequirements: ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 2, DiskGiB: 20, EstimatedRuntimeMinutes: 60},
		ModelAuthorization: ModelAuthorization{
			ModelProfileID: uuid.NewString(), ModelProfileRevision: 2,
			Provider: "openai_compatible", Model: "gpt-test", Interface: "openai_compatible",
			CredentialVersion: 4, CredentialBindingDigest: digestValue("model-credential"),
		},
	}
}

func TestServiceProposalRevalidatesCurrentAWSBinding(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	current := intrinsicAWSBinding()
	current.CredentialRevision++
	resolver := &proposalAWSBindingResolver{binding: current}
	store := &intrinsicStore{}
	service, err := NewServiceWithAWSBindingResolver(
		store, defaults,
		FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }},
		resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	enableCredentialProposalDependencies(t, service, nil)
	offer, err := service.Propose(context.Background(), credentialProposalCommand())
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 || len(store.commands) != 1 || offer.Plan.AWS != current ||
		offer.Plan.AWS == intrinsicAWSBinding() || offer.Plan.AuthorizationBasisDigest == "" {
		t.Fatalf("proposal did not bind current credential: calls=%d plan=%+v", resolver.calls, offer.Plan)
	}
}

func TestServiceProposalFailsClosedWhenCredentialAuthorityIsStale(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	resolver := &proposalAWSBindingResolver{binding: intrinsicAWSBinding(), err: ErrStaleAuthorization}
	store := &intrinsicStore{}
	service, err := NewServiceWithAWSBindingResolver(
		store, defaults,
		FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }},
		resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	enableCredentialProposalDependencies(t, service, nil)
	if _, err = service.Propose(context.Background(), credentialProposalCommand()); !errors.Is(err, ErrStaleAuthorization) {
		t.Fatalf("stale credential authority err=%v", err)
	}
	if resolver.calls != 1 || len(store.commands) != 0 {
		t.Fatalf("stale credential authority persisted an offer: calls=%d commands=%d", resolver.calls, len(store.commands))
	}
}

func TestServiceChecksWorkerCapacityBeforeQuote(t *testing.T) {
	now := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	store := &intrinsicStore{}
	quoter := &limitRecordingQuoter{base: FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }}}
	service, err := NewServiceWithAWSBindingResolver(store, defaults, quoter, &proposalAWSBindingResolver{binding: intrinsicAWSBinding()}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	capacityErr := errors.New("worker pool is full")
	reuse := &capacityReuseResolver{err: capacityErr}
	enableCredentialProposalDependencies(t, service, reuse)
	if _, err = service.Propose(context.Background(), credentialProposalCommand()); !errors.Is(err, capacityErr) {
		t.Fatalf("proposal error=%v", err)
	}
	if reuse.calls != 1 || quoter.last.OwnerID != "" || len(store.commands) != 0 {
		t.Fatalf("capacity failure crossed quote/store boundary: calls=%d quote=%+v offers=%d", reuse.calls, quoter.last, len(store.commands))
	}
}

func TestServiceRetainedWorkerQuoteMatchesWorkloadLifetime(t *testing.T) {
	for _, test := range []struct {
		name         string
		workloadKind WorkloadKind
		service      *ServiceSpec
		wantAmount   int64
		wantMaximum  int64
	}{
		{name: "finite job", workloadKind: WorkloadJob, wantAmount: 12_000, wantMaximum: 15_000},
		{name: "persistent service with hostname", workloadKind: WorkloadService, service: &ServiceSpec{WorkloadID: "web", Port: 8080, HealthPath: "/health", Hostname: "app.example.test"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
			store := &intrinsicStore{}
			service, err := NewServiceWithAWSBindingResolver(store, intrinsicDefaults(now), FakeQuoter{
				AmountMicros: 12_000, MaximumAuthorizedMicros: 15_000, ComputeMicrosPerHour: 29_200,
				TTL: 5 * time.Minute, Now: func() time.Time { return now },
			}, &proposalAWSBindingResolver{binding: intrinsicAWSBinding()}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			reuse := &capacityReuseResolver{found: true, selection: WorkerReuseSelection{WorkerID: uuid.NewString(), Compute: ComputeSpec{
				InstanceType: "t3.small", Architecture: "x86_64", VCPU: 2, MemoryGiB: 2,
				RootDeviceName: "/dev/xvda", VolumeGiB: 20, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125,
			}}}
			enableCredentialProposalDependencies(t, service, reuse)
			command := credentialProposalCommand()
			command.WorkloadKind, command.Service = test.workloadKind, test.service
			offer, err := service.Propose(context.Background(), command)
			if err != nil {
				t.Fatal(err)
			}
			if !offer.Plan.PersistentWorkerReuse || offer.Execution.State != StateQueued || offer.Plan.Quote.ComputeMicrosPerHour != 29_200 ||
				offer.Plan.Quote.AmountMicros != test.wantAmount || offer.Plan.Quote.MaximumAuthorizedCostMicros != test.wantMaximum {
				t.Fatalf("retained Worker offer=%+v execution=%+v", offer.Plan, offer.Execution)
			}
		})
	}
}

func TestServiceRejectsRetainedGPUBelowRequiredAcceleratorMemory(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := &intrinsicStore{}
	quoter := &limitRecordingQuoter{base: FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }}}
	service, err := NewServiceWithAWSBindingResolver(store, intrinsicDefaults(now), quoter,
		&proposalAWSBindingResolver{binding: intrinsicAWSBinding()}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	reuse := &capacityReuseResolver{found: true, selection: WorkerReuseSelection{WorkerID: uuid.NewString(), Compute: ComputeSpec{
		InstanceType: "g6f.2xlarge", Architecture: "x86_64", AcceleratorType: AcceleratorGPU, AcceleratorName: "L4", AcceleratorMemoryMiB: 5724,
		VCPU: 8, MemoryGiB: 32, RootDeviceName: "/dev/xvda", VolumeGiB: 120, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125,
	}}}
	enableCredentialProposalDependencies(t, service, reuse)
	command := credentialProposalCommand()
	command.ComputeRequirements = ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 16, MinAcceleratorMemoryGiB: 20,
		DiskGiB: 100, EstimatedRuntimeMinutes: 60, AcceleratorType: AcceleratorGPU}
	if _, err = service.Propose(context.Background(), command); !errors.Is(err, ErrInvalid) {
		t.Fatalf("undersized retained GPU proposal err=%v, want invalid", err)
	}
	if len(store.commands) != 0 || quoter.last.OwnerID != "" {
		t.Fatalf("undersized retained GPU crossed quote/store boundary: quote=%+v offers=%d", quoter.last, len(store.commands))
	}
}

func TestProposeIntrinsicPublicationTracksCredentialReadinessWithoutRestart(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	resolver := &proposalAWSBindingResolver{binding: intrinsicAWSBinding(), err: ErrStaleAuthorization}
	service, err := NewServiceWithAWSBindingResolver(
		&intrinsicStore{}, defaults,
		FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }},
		resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	enableCredentialProposalDependencies(t, service, nil)
	intrinsic, err := NewProposeIntrinsic(service, &intrinsicOwner{owner: IntrinsicOwnerContext{OwnerID: "@owner:example.test", AccountGeneration: 7}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := coreconversation.TurnLease{Turn: coreconversation.Turn{ID: uuid.NewString()}, LeaseID: uuid.NewString(), Epoch: 1}
	if tools, resolveErr := intrinsic.ResolveIntrinsicTools(context.Background(), lease); resolveErr != nil || len(tools) != 0 {
		t.Fatalf("unready tools=%v err=%v", tools, resolveErr)
	}
	resolver.err = nil
	if tools, resolveErr := intrinsic.ResolveIntrinsicTools(context.Background(), lease); resolveErr != nil || len(tools) != 1 || tools[0].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName {
		t.Fatalf("ready tools=%v err=%v", tools, resolveErr)
	}
	resolver.err = ErrStaleAuthorization
	if tools, resolveErr := intrinsic.ResolveIntrinsicTools(context.Background(), lease); resolveErr != nil || len(tools) != 0 {
		t.Fatalf("revoked tools=%v err=%v", tools, resolveErr)
	}
}

func TestServiceProposalBindsAuthorizationTokenCeilingBeforeSingleQuote(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	defaults.Limits.MaxTokens = 1_000_000
	resolver := &proposalAWSBindingResolver{binding: intrinsicAWSBinding()}
	store := &intrinsicStore{}
	quoter := &limitRecordingQuoter{base: FakeQuoter{
		AmountMicros: 1000, MaximumAuthorizedMicros: 2000,
		TTL: 5 * time.Minute, Now: func() time.Time { return now },
	}}
	service, err := NewServiceWithAWSBindingResolver(
		store, defaults, quoter, resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	enableCredentialProposalDependencies(t, service, nil)
	command := credentialProposalCommand()
	command.ModelAuthorization.MaximumOutputTokens = 0
	offer, err := service.Propose(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	want := runtimebounds.OpenAICompatibleMaximumAuthorizedOutputTokens
	if offer.Plan.Limits.MaxTokens != want || quoter.last.Limits.MaxTokens != want ||
		offer.Plan.Quote.BasisDigest != offer.Plan.AuthorizationBasisDigest ||
		offer.Execution.PlanDigest != offer.Plan.Digest ||
		offer.Execution.ExecutionDigest != offer.Plan.ExecutionDigest {
		t.Fatalf("bound offer drift: plan=%+v quote_request=%+v execution=%+v", offer.Plan, quoter.last, offer.Execution)
	}

}

func TestServiceProposalRejectsUnqualifiedEffectiveTokenLimitBeforeAuthorityOrQuote(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	resolver := &proposalAWSBindingResolver{binding: intrinsicAWSBinding()}
	store := &intrinsicStore{}
	quoter := &limitRecordingQuoter{base: FakeQuoter{
		AmountMicros: 1000, MaximumAuthorizedMicros: 2000,
		TTL: 5 * time.Minute, Now: func() time.Time { return now },
	}}
	service, err := NewServiceWithAWSBindingResolver(store, defaults, quoter, resolver, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	enableCredentialProposalDependencies(t, service, nil)
	command := credentialProposalCommand()
	command.ModelAuthorization.MaximumOutputTokens = 511
	if _, err = service.Propose(context.Background(), command); !errors.Is(err, ErrInvalid) {
		t.Fatalf("proposal error = %v, want ErrInvalid", err)
	}
	if resolver.calls != 0 || len(store.commands) != 0 || quoter.last.OwnerID != "" {
		t.Fatalf("invalid output limit crossed a side-effect boundary: resolver=%d store=%d quote=%+v", resolver.calls, len(store.commands), quoter.last)
	}
}

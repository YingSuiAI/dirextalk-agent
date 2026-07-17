package resource

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type fakeResourceRepository struct {
	mu        sync.Mutex
	resources map[string]ResourceV1
	managed   map[string]ManagedServiceV1
}

func newFakeResourceRepository() *fakeResourceRepository {
	return &fakeResourceRepository{resources: make(map[string]ResourceV1), managed: make(map[string]ManagedServiceV1)}
}

func (repository *fakeResourceRepository) CreateIntent(_ context.Context, resource ResourceV1) (ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if existing, exists := repository.resources[resource.ResourceID]; exists {
		return existing.clone(), nil
	}
	repository.resources[resource.ResourceID] = resource.clone()
	return resource.clone(), nil
}

func (repository *fakeResourceRepository) Get(_ context.Context, resourceID string) (ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	resource, exists := repository.resources[resourceID]
	if !exists {
		return ResourceV1{}, ErrNotFound
	}
	return resource.clone(), nil
}

func (repository *fakeResourceRepository) ListDeployment(_ context.Context, deploymentID string) ([]ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.list(func(resource ResourceV1) bool { return resource.DeploymentID == deploymentID }), nil
}

func (repository *fakeResourceRepository) ListByAgent(_ context.Context, agentInstanceID string) ([]ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.list(func(resource ResourceV1) bool { return resource.AgentInstanceID == agentInstanceID }), nil
}

func (repository *fakeResourceRepository) list(include func(ResourceV1) bool) []ResourceV1 {
	result := make([]ResourceV1, 0)
	for _, resource := range repository.resources {
		if include(resource) {
			result = append(result, resource.clone())
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID < result[j].ResourceID })
	return result
}

func (repository *fakeResourceRepository) Save(_ context.Context, resource ResourceV1, expectedRevision int64) (ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, exists := repository.resources[resource.ResourceID]
	if !exists {
		return ResourceV1{}, ErrNotFound
	}
	if current.Revision != expectedRevision || resource.Revision != expectedRevision+1 {
		return ResourceV1{}, ErrRevisionConflict
	}
	repository.resources[resource.ResourceID] = resource.clone()
	return resource.clone(), nil
}

func (repository *fakeResourceRepository) AcceptManaged(_ context.Context, deploymentID string, managed ManagedServiceV1, expected map[string]int64) ([]ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for resourceID, revision := range expected {
		resource, exists := repository.resources[resourceID]
		if !exists || resource.DeploymentID != deploymentID || resource.Revision != revision {
			return nil, ErrRevisionConflict
		}
	}
	result := make([]ResourceV1, 0, len(expected))
	for resourceID := range expected {
		resource := repository.resources[resourceID]
		resource.State = StateRetainedManaged
		resource.Retention = task.RetentionManaged
		resource.DestroyDeadline = time.Time{}
		resource.AutoDestroyApproved = false
		resource.Tags[TagRetention] = string(task.RetentionManaged)
		resource.Tags[TagDestroyDeadline] = "managed"
		resource.Revision++
		resource.UpdatedAt = managed.UpdatedAt
		repository.resources[resourceID] = resource.clone()
		result = append(result, resource.clone())
	}
	repository.managed[deploymentID] = managed
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID < result[j].ResourceID })
	return result, nil
}

func (repository *fakeResourceRepository) ImportOrphan(_ context.Context, resource ResourceV1) (ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.resources[resource.ResourceID]; exists {
		return ResourceV1{}, ErrAlreadyExists
	}
	repository.resources[resource.ResourceID] = resource.clone()
	return resource.clone(), nil
}

type fakeProvider struct {
	mu                sync.Mutex
	resources         map[string]ProviderObservation
	byToken           map[string]string
	createCount       int
	readCount         int
	responseLost      bool
	hiddenFinds       int
	hiddenAllFinds    int
	findBarrier       chan struct{}
	findArrivals      int
	ambiguousByToken  map[string][]string
	blockedDelete     map[string]bool
	deleteOrder       []string
	beforeCreate      func(ProviderCreateRequest) error
	omitEmbedded      bool
	ignoreOwnerFilter bool
	now               time.Time
}

func newFakeProvider(now time.Time) *fakeProvider {
	return &fakeProvider{
		resources: make(map[string]ProviderObservation), byToken: make(map[string]string),
		ambiguousByToken: make(map[string][]string), blockedDelete: make(map[string]bool), now: now,
	}
}

func (provider *fakeProvider) Create(_ context.Context, request ProviderCreateRequest) (ProviderObservation, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.beforeCreate != nil {
		if err := provider.beforeCreate(request); err != nil {
			return ProviderObservation{}, err
		}
	}
	provider.createCount++
	providerID := fmt.Sprintf("%s-%d", request.Type, provider.createCount)
	observation := ProviderObservation{ProviderID: providerID, Type: request.Type, Exists: true, Tags: cloneMap(request.Tags), ObservedAt: provider.now}
	if request.Type == TypeEC2 && request.AWS != nil && request.AWS.Instance != nil && !provider.omitEmbedded {
		rootID, rootDigest, err := EmbeddedRootVolumeFacts(request.ResourceID, request.AWS.Instance)
		if err != nil {
			return ProviderObservation{}, err
		}
		rootTags := cloneMap(request.Tags)
		rootTags[TagResourceID] = rootID
		rootTags[TagEmbeddedParentResourceID] = request.ResourceID
		rootProviderID := fmt.Sprintf("ebs-root-%d", provider.createCount)
		root := ProviderObservation{ProviderID: rootProviderID, Type: TypeEBS, Exists: true, Tags: rootTags, ObservedAt: provider.now}
		root.Tags["dirextalk_spec_digest"] = rootDigest
		observation.Embedded = []ProviderObservation{root}
		provider.resources[rootProviderID] = root
	}
	provider.resources[providerID] = observation
	provider.byToken[request.ClientToken] = providerID
	if provider.responseLost {
		provider.responseLost = false
		return ProviderObservation{}, errors.New("simulated provider response loss")
	}
	return observation, nil
}

func TestProvisionTypedEC2TracksRootEBSBeforeLaunchAndMirrorsItForReaper(t *testing.T) {
	fixture := newResourceFixture(t)
	eni, err := fixture.service.Provision(context.Background(), fixture.spec(TypeENI, "worker-eni"), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	instanceAWS := testTypedEC2AWS(fixture.deploymentID)
	instanceDigest, err := instanceAWS.Digest(TypeEC2)
	if err != nil {
		t.Fatal(err)
	}
	instanceSpec := fixture.spec(TypeEC2, "exclusive-worker", eni.ResourceID)
	instanceSpec.AWS, instanceSpec.SpecDigest = instanceAWS, instanceDigest
	rootID, _, err := EmbeddedRootVolumeFacts(instanceSpec.ResourceID, instanceAWS.Instance)
	if err != nil {
		t.Fatal(err)
	}
	fixture.provider.beforeCreate = func(request ProviderCreateRequest) error {
		if request.Type != TypeEC2 {
			return nil
		}
		parent, parentErr := fixture.repository.Get(context.Background(), request.ResourceID)
		root, rootErr := fixture.repository.Get(context.Background(), rootID)
		if parentErr != nil || rootErr != nil || parent.State != StateProvisioning || root.State != StateProvisioning ||
			parent.Intent.ClientToken == "" || parent.Intent.ProviderCreateStartedAt.IsZero() || root.Intent.ClientToken != parent.Intent.ClientToken {
			return errors.New("RunInstances reached provider before parent and root-volume intents were durable")
		}
		return nil
	}
	instance, err := fixture.service.Provision(context.Background(), instanceSpec, fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	root, err := fixture.repository.Get(context.Background(), rootID)
	if err != nil {
		t.Fatal(err)
	}
	if instance.State != StateActive || root.State != StateActive || root.Type != TypeEBS || root.ProviderID == "" ||
		root.Tags[TagResourceID] != rootID || root.Tags[TagEmbeddedParentResourceID] != instance.ResourceID ||
		!slicesEqual(instance.DependsOn, []string{eni.ResourceID, rootID}) {
		t.Fatalf("root EBS ledger is incomplete: instance=%+v root=%+v", instance, root)
	}
	manifest := fixture.mirror.manifests[fixture.deploymentID]
	if len(manifest.Resources) != 3 {
		t.Fatalf("root EBS missing from Reaper manifest: %+v", manifest)
	}
	manifest.DestroyDeadline = fixture.now.Add(-time.Minute)
	for index := range manifest.Resources {
		manifest.Resources[index].DestroyDeadline = manifest.DestroyDeadline
		manifest.Resources[index].Tags[TagDestroyDeadline] = manifest.DestroyDeadline.Format(time.RFC3339)
	}
	fixture.mirror.manifests[fixture.deploymentID] = manifest
	reaper, err := NewReaper(fixture.provider, fixture.mirror)
	if err != nil {
		t.Fatal(err)
	}
	reaper.now = func() time.Time { return fixture.now }
	report, err := reaper.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.VerifiedDestroyed != 3 || report.Blocked != 0 {
		t.Fatalf("Reaper did not independently verify root EBS destruction: %+v", report)
	}
	instanceDelete, rootDelete := -1, -1
	for index, providerID := range fixture.provider.deleteOrder {
		if providerID == instance.ProviderID {
			instanceDelete = index
		}
		if providerID == root.ProviderID {
			rootDelete = index
		}
	}
	if instanceDelete < 0 || rootDelete < 0 || instanceDelete >= rootDelete {
		t.Fatalf("root EBS destroy order=%v", fixture.provider.deleteOrder)
	}
}

func TestProvisionTypedEC2FailsClosedWhenRootEBSCannotBeReadBack(t *testing.T) {
	fixture := newResourceFixture(t)
	eni, err := fixture.service.Provision(context.Background(), fixture.spec(TypeENI, "worker-eni"), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	instanceAWS := testTypedEC2AWS(fixture.deploymentID)
	instanceDigest, err := instanceAWS.Digest(TypeEC2)
	if err != nil {
		t.Fatal(err)
	}
	spec := fixture.spec(TypeEC2, "exclusive-worker", eni.ResourceID)
	spec.AWS, spec.SpecDigest = instanceAWS, instanceDigest
	rootID, _, err := EmbeddedRootVolumeFacts(spec.ResourceID, instanceAWS.Instance)
	if err != nil {
		t.Fatal(err)
	}
	fixture.provider.omitEmbedded = true
	created, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
	if !errors.Is(err, ErrReadBack) || created.State != StateProvisioning {
		t.Fatalf("missing root EBS read-back must fail closed: resource=%+v err=%v", created, err)
	}
	root, err := fixture.repository.Get(context.Background(), rootID)
	if err != nil {
		t.Fatal(err)
	}
	if root.State != StateProvisioning || root.ProviderID != "" {
		t.Fatalf("unverified root EBS became active: %+v", root)
	}
	if manifest, exists := fixture.mirror.manifests[fixture.deploymentID]; exists {
		for _, item := range manifest.Resources {
			if (item.ResourceID == spec.ResourceID || item.ResourceID == rootID) && (item.State == StateActive || item.ProviderID != "") {
				t.Fatalf("unverified EC2/root facts reached the active manifest: %+v", manifest)
			}
		}
	}
}

func testTypedEC2AWS(deploymentID string) *AWSResourceSpecV1 {
	return &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, Instance: &AWSEC2InstanceSpecV1{Architecture: recipe.ArchitectureAMD64,
		ImageID: "ami-0123456789abcdef0", ImageDigest: "sha256:" + repeatHex('a'), InstanceType: "t3.large",
		InstanceProfileName: "dtx-agent-example-worker", UserDataArtifactRef: "s3://dtx-artifacts/deployments/" + deploymentID + "/launch/config.json",
		UserDataArtifactDigest: "sha256:" + repeatHex('b'), Bootstrap: AWSWorkerBootstrapSpecV1{
			DeploymentID: deploymentID, WorkerID: uuid.NewString(), ControlPlaneEndpoint: "grpcs://agent.example.com:7443", EnrollmentExpectedRevision: 1,
		},
		RootDeviceName: "/dev/sda1", RootVolumeGiB: 24, RootKMSKeyID: "alias/dtx-worker", Market: AWSMarketOnDemand, EBSOptimized: true,
	}}
}

func (provider *fakeProvider) FindByClientToken(_ context.Context, _ Type, _ string, token string) (ProviderObservation, bool, error) {
	provider.mu.Lock()
	if provider.findBarrier != nil && len(provider.byToken) == 0 {
		barrier := provider.findBarrier
		provider.findArrivals++
		if provider.findArrivals == 2 {
			close(barrier)
			provider.findBarrier = nil
		}
		provider.mu.Unlock()
		<-barrier
		return ProviderObservation{}, false, nil
	}
	defer provider.mu.Unlock()
	if provider.hiddenFinds > 0 {
		provider.hiddenFinds--
		return ProviderObservation{}, false, nil
	}
	if candidates := provider.ambiguousByToken[token]; len(candidates) > 1 {
		return ProviderObservation{}, false, ErrReadBack
	} else if len(candidates) == 1 {
		return provider.resources[candidates[0]], true, nil
	}
	providerID, found := provider.byToken[token]
	if !found {
		return ProviderObservation{}, false, nil
	}
	return provider.resources[providerID], true, nil
}

func (provider *fakeProvider) FindAllByClientToken(_ context.Context, _ Type, _ string, token string) ([]ProviderObservation, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.hiddenAllFinds > 0 {
		provider.hiddenAllFinds--
		return nil, nil
	}
	providerIDs := append([]string(nil), provider.ambiguousByToken[token]...)
	if len(providerIDs) == 0 {
		if providerID := provider.byToken[token]; providerID != "" {
			providerIDs = append(providerIDs, providerID)
		}
	}
	result := make([]ProviderObservation, 0, len(providerIDs))
	for _, providerID := range providerIDs {
		result = append(result, provider.resources[providerID])
	}
	return result, nil
}

func TestProvisionDoesNotRepeatAmbiguousEIPOrSnapshotCreateWhileTagsAreDelayed(t *testing.T) {
	for _, kind := range []Type{TypeEIP, TypeSnapshot} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := newResourceFixture(t)
			fixture.provider.responseLost = true
			fixture.provider.hiddenFinds = 3
			fixture.provider.hiddenAllFinds = 2
			spec := fixture.spec(kind, "delayed-provider-tags")

			first, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
			if !errors.Is(err, ErrCreateAmbiguous) || first.State != StateProvisioning || fixture.provider.createCount != 1 {
				t.Fatalf("first ambiguous create resource=%+v error=%v creates=%d", first, err, fixture.provider.createCount)
			}
			second, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
			if !errors.Is(err, ErrCreateAmbiguous) || second.State != StateProvisioning || fixture.provider.createCount != 1 {
				t.Fatalf("delayed retry resource=%+v error=%v creates=%d", second, err, fixture.provider.createCount)
			}
			active, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
			if err != nil || active.State != StateActive || fixture.provider.createCount != 1 {
				t.Fatalf("visible reconciliation resource=%+v error=%v creates=%d", active, err, fixture.provider.createCount)
			}
		})
	}
}

func TestProvisionFencesConcurrentEIPAndSnapshotCreatesAcrossRepositoryCAS(t *testing.T) {
	for _, kind := range []Type{TypeEIP, TypeSnapshot} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := newResourceFixture(t)
			fixture.provider.findBarrier = make(chan struct{})
			spec := fixture.spec(kind, "concurrent-provider-create")
			type result struct {
				resource ResourceV1
				err      error
			}
			results := make(chan result, 2)
			for range 2 {
				go func() {
					created, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
					results <- result{resource: created, err: err}
				}()
			}
			for range 2 {
				value := <-results
				if value.err != nil && !errors.Is(value.err, ErrCreateAmbiguous) {
					t.Fatalf("concurrent Provision() resource=%+v error=%v", value.resource, value.err)
				}
			}
			if fixture.provider.createCount != 1 {
				t.Fatalf("concurrent provider creates=%d, want exactly one", fixture.provider.createCount)
			}
			active, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
			if err != nil || active.State != StateActive || fixture.provider.createCount != 1 {
				t.Fatalf("fenced reconciliation resource=%+v error=%v creates=%d", active, err, fixture.provider.createCount)
			}
			stored, err := fixture.repository.Get(context.Background(), spec.ResourceID)
			if err != nil || stored.Intent.ProviderCreateStartedAt.IsZero() {
				t.Fatalf("durable provider-create fence missing: resource=%+v error=%v", stored, err)
			}
		})
	}
}

func TestProvisionPersistsAndReapsEveryAmbiguousEIPAndSnapshotMatch(t *testing.T) {
	for _, kind := range []Type{TypeEIP, TypeSnapshot} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := newResourceFixture(t)
			spec := fixture.spec(kind, "ambiguous-provider-matches")
			token := clientToken("create", spec.AgentInstanceID, spec.DeploymentID, spec.ResourceID, spec.SpecDigest)
			providerIDs := []string{string(kind) + "-candidate-a", string(kind) + "-candidate-b"}
			for _, providerID := range providerIDs {
				fixture.provider.resources[providerID] = ProviderObservation{
					ProviderID: providerID, Type: kind, Exists: true, Tags: spec.mandatoryTags(), ObservedAt: fixture.now,
				}
			}
			fixture.provider.ambiguousByToken[token] = append([]string(nil), providerIDs...)
			fixture.provider.hiddenAllFinds = 1

			provisioning, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
			if !errors.Is(err, ErrCreateAmbiguous) || provisioning.State != StateProvisioning || fixture.provider.createCount != 0 ||
				provisioning.Intent.ProviderCreateStartedAt.IsZero() || len(provisioning.ProviderCandidateIDs) != 0 {
				t.Fatalf("temporarily hidden ambiguous matches were not durably fenced: resource=%+v error=%v creates=%d", provisioning, err, fixture.provider.createCount)
			}
			provisioning, err = fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
			if !errors.Is(err, ErrCreateAmbiguous) || provisioning.State != StateProvisioning || fixture.provider.createCount != 0 ||
				!slicesEqual(provisioning.ProviderCandidateIDs, providerIDs) {
				t.Fatalf("visible ambiguous matches were not all recorded: resource=%+v error=%v creates=%d", provisioning, err, fixture.provider.createCount)
			}
			manifest, exists := fixture.mirror.manifests[fixture.deploymentID]
			if !exists || len(manifest.Resources) != 1 || !slicesEqual(manifest.Resources[0].ProviderCandidateIDs, providerIDs) {
				t.Fatalf("candidate cleanup evidence was not mirrored: %+v", manifest)
			}

			manifest.DestroyDeadline = fixture.now.Add(-time.Minute)
			manifest.Resources[0].DestroyDeadline = manifest.DestroyDeadline
			manifest.Resources[0].Tags[TagDestroyDeadline] = manifest.DestroyDeadline.Format(time.RFC3339)
			fixture.mirror.manifests[fixture.deploymentID] = manifest
			reaper, err := NewReaper(fixture.provider, fixture.mirror)
			if err != nil {
				t.Fatal(err)
			}
			reaper.now = func() time.Time { return fixture.now }
			report, err := reaper.Sweep(context.Background())
			if err != nil || report.VerifiedDestroyed != 1 || report.Blocked != 0 || !slicesEqual(fixture.provider.deleteOrder, providerIDs) {
				t.Fatalf("ambiguous candidate cleanup report=%+v error=%v deletes=%v", report, err, fixture.provider.deleteOrder)
			}
			for _, providerID := range providerIDs {
				if fixture.provider.resources[providerID].Exists {
					t.Fatalf("candidate %s remains billable after verified cleanup", providerID)
				}
			}
		})
	}
}

func (provider *fakeProvider) ReadBack(_ context.Context, kind Type, providerID, _ string) (ProviderObservation, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.readCount++
	observation, exists := provider.resources[providerID]
	if !exists {
		return ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: provider.now}, nil
	}
	observation.ObservedAt = provider.now
	return observation, nil
}

func (provider *fakeProvider) Delete(_ context.Context, _ Type, providerID, _ string, _ map[string]string) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.deleteOrder = append(provider.deleteOrder, providerID)
	if provider.blockedDelete[providerID] {
		return errors.New("AccessDenied: simulated test denial")
	}
	observation := provider.resources[providerID]
	observation.Exists = false
	observation.ObservedAt = provider.now
	provider.resources[providerID] = observation
	return nil
}

func (provider *fakeProvider) ListOwned(_ context.Context, agentInstanceID, ownerID string) ([]ProviderObservation, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	result := make([]ProviderObservation, 0)
	for _, observation := range provider.resources {
		if observation.Exists && observation.Tags[TagAgentInstanceID] == agentInstanceID && (provider.ignoreOwnerFilter || observation.Tags[TagOwnerID] == ownerID) {
			result = append(result, observation)
		}
	}
	return result, nil
}

type fakeMirror struct {
	mu        sync.Mutex
	manifests map[string]Manifest
	failNext  bool
	failAtPut int
	puts      int
}

func newFakeMirror() *fakeMirror { return &fakeMirror{manifests: make(map[string]Manifest)} }

func (mirror *fakeMirror) Put(_ context.Context, manifest Manifest) error {
	mirror.mu.Lock()
	defer mirror.mu.Unlock()
	mirror.puts++
	if mirror.failNext || mirror.failAtPut == mirror.puts {
		mirror.failNext = false
		return errors.New("simulated DynamoDB outage")
	}
	mirror.manifests[manifest.ManifestID] = manifest.clone()
	return nil
}

func (mirror *fakeMirror) ListExpired(_ context.Context, _ time.Time) ([]Manifest, error) {
	mirror.mu.Lock()
	defer mirror.mu.Unlock()
	result := make([]Manifest, 0, len(mirror.manifests))
	for _, manifest := range mirror.manifests {
		result = append(result, manifest.clone())
	}
	return result, nil
}

type resourceFixture struct {
	service      *Service
	repository   *fakeResourceRepository
	provider     *fakeProvider
	mirror       *fakeMirror
	now          time.Time
	agentID      string
	taskID       string
	deploymentID string
	ownerID      string
	approvalID   string
}

func newResourceFixture(t *testing.T) resourceFixture {
	t.Helper()
	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	repository := newFakeResourceRepository()
	provider := newFakeProvider(now)
	mirror := newFakeMirror()
	service, err := NewService(repository, provider, mirror)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	return resourceFixture{
		service: service, repository: repository, provider: provider, mirror: mirror, now: now,
		agentID: uuid.NewString(), taskID: uuid.NewString(), deploymentID: uuid.NewString(), ownerID: "owner-1",
		approvalID: uuid.NewString(),
	}
}

func (fixture resourceFixture) spec(kind Type, logicalName string, dependencies ...string) ProvisionSpec {
	return ProvisionSpec{
		ResourceID: uuid.NewString(), AgentInstanceID: fixture.agentID, OwnerID: fixture.ownerID,
		TaskID: fixture.taskID, DeploymentID: fixture.deploymentID, Type: kind, LogicalName: logicalName,
		Region: "us-west-2", SpecDigest: "sha256:" + repeatHex('a'), ApprovedPlanHash: "sha256:" + repeatHex('b'),
		ApprovalID: fixture.approvalID, DependsOn: dependencies, Retention: task.RetentionEphemeralAutoDestroy,
		DestroyDeadline: fixture.now.Add(30 * time.Minute), AutoDestroyApproved: true,
	}
}

func (fixture resourceFixture) createAuthorization() ProviderCreateAuthorization {
	return ProviderCreateAuthorization{
		ApprovalExpiresAt: fixture.now.Add(10 * time.Minute),
		QuoteValidUntil:   fixture.now.Add(15 * time.Minute),
	}
}

func TestProvisionPersistsIntentReconcilesLostResponseAndMirrorsBeforeActive(t *testing.T) {
	fixture := newResourceFixture(t)
	spec := fixture.spec(TypeEBS, "data-volume")
	fixture.provider.responseLost = true
	fixture.provider.beforeCreate = func(request ProviderCreateRequest) error {
		stored, err := fixture.repository.Get(context.Background(), request.ResourceID)
		if err != nil {
			return err
		}
		if stored.State != StateProvisioning || stored.Intent.Operation != MutationCreate || stored.Intent.ClientToken != request.ClientToken || stored.Intent.ProviderCreateStartedAt.IsZero() {
			return errors.New("provider called before durable mutation intent")
		}
		return nil
	}
	fixture.mirror.failAtPut = 2
	resource, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
	if err == nil || resource.State != StateProvisioning || resource.ProviderID == "" {
		t.Fatalf("mirror failure must leave reconciled resource provisioning: resource=%+v err=%v", resource, err)
	}
	stored, _ := fixture.repository.Get(context.Background(), spec.ResourceID)
	if stored.State != StateProvisioning {
		t.Fatalf("active was exposed before mirror: %+v", stored)
	}
	active, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	if active.State != StateActive || fixture.provider.createCount != 1 || fixture.provider.readCount < 2 {
		t.Fatalf("response loss created a duplicate resource: active=%+v creates=%d", active, fixture.provider.createCount)
	}
	manifest := fixture.mirror.manifests[fixture.deploymentID]
	if len(manifest.Resources) != 1 || manifest.Resources[0].State != StateActive || !manifest.AutoDestroyApproved {
		t.Fatalf("active manifest was not mirrored: %+v", manifest)
	}
	for _, key := range []string{TagAgentInstanceID, TagOwnerID, TagTaskID, TagDeploymentID, TagResourceID, TagRetention, TagDestroyDeadline, TagApprovedPlanHash, TagApprovalID} {
		if active.Tags[key] == "" {
			t.Errorf("mandatory tag %s missing", key)
		}
	}
}

func TestProvisionChecksFreshnessOnlyBeforeFirstProviderMutation(t *testing.T) {
	t.Run("expired approval blocks a new provider fact", func(t *testing.T) {
		fixture := newResourceFixture(t)
		authorization := fixture.createAuthorization()
		authorization.ApprovalExpiresAt = fixture.now

		created, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEC2, "expired-worker"), authorization)
		if !errors.Is(err, ErrCreateAuthorizationExpired) || created.State != StateProvisioning {
			t.Fatalf("Provision() resource=%+v error=%v, want provisioning intent and expired authorization", created, err)
		}
		if fixture.provider.createCount != 0 {
			t.Fatalf("expired approval reached provider Create %d times", fixture.provider.createCount)
		}
	})

	t.Run("existing provider fact reconciles after expiry", func(t *testing.T) {
		fixture := newResourceFixture(t)
		clock := fixture.now
		fixture.service.now = func() time.Time { return clock }
		spec := fixture.spec(TypeEC2, "recoverable-worker")
		authorization := fixture.createAuthorization()
		fixture.mirror.failAtPut = 2

		provisioning, err := fixture.service.Provision(context.Background(), spec, authorization)
		if err == nil || provisioning.State != StateProvisioning || provisioning.ProviderID == "" || fixture.provider.createCount != 1 {
			t.Fatalf("first Provision() resource=%+v error=%v creates=%d", provisioning, err, fixture.provider.createCount)
		}

		clock = authorization.QuoteValidUntil.Add(time.Second)
		active, err := fixture.service.Provision(context.Background(), spec, authorization)
		if err != nil {
			t.Fatalf("reconcile existing provider fact after expiry: %v", err)
		}
		if active.State != StateActive || fixture.provider.createCount != 1 || fixture.provider.readCount < 2 {
			t.Fatalf("reconcile resource=%+v creates=%d reads=%d", active, fixture.provider.createCount, fixture.provider.readCount)
		}
	})
}

func TestDestroyUsesReverseDependenciesAndBlocksUntilReadBack(t *testing.T) {
	fixture := newResourceFixture(t)
	volume, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEBS, "volume"), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	instance, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEC2, "worker", volume.ResourceID), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	fixture.provider.blockedDelete[instance.ProviderID] = true
	result, err := fixture.service.Destroy(context.Background(), DestroyRequest{DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, ApprovalID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Blocked || len(fixture.provider.deleteOrder) != 1 || fixture.provider.deleteOrder[0] != instance.ProviderID {
		t.Fatalf("partial destroy did not stop at dependent: result=%+v order=%v", result, fixture.provider.deleteOrder)
	}
	states := statesByID(result.Resources)
	if states[instance.ResourceID] != StateDestroyBlocked || states[volume.ResourceID] != StateDestroyBlocked {
		t.Fatalf("blocked states not retained: %v", states)
	}

	fixture.provider.blockedDelete[instance.ProviderID] = false
	result, err = fixture.service.Destroy(context.Background(), DestroyRequest{DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, ApprovalID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if result.Blocked {
		t.Fatalf("retry remained blocked: %+v", result)
	}
	order := fixture.provider.deleteOrder
	if len(order) != 3 || order[1] != instance.ProviderID || order[2] != volume.ProviderID {
		t.Fatalf("destroy order must be dependent before dependency: %v", order)
	}
	for _, resource := range result.Resources {
		if resource.State != StateVerifiedDestroyed || resource.ReadBack.Exists {
			t.Fatalf("destroy was not independently read back: %+v", resource)
		}
	}
}

func TestEndpointAndSnapshotDestroyBeforeTheirDependencies(t *testing.T) {
	fixture := newResourceFixture(t)
	group, err := fixture.service.Provision(context.Background(), fixture.spec(TypeSG, "endpoint-security-group"), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	endpointAWS := &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, Endpoint: &AWSVPCEndpointSpecV1{
		VPCID: "vpc-0123456789abcdef0", ServiceName: "com.amazonaws.us-west-2.s3",
		SubnetIDs: []string{"subnet-0123456789abcdef0"}, PrivateDNSEnabled: true,
	}}
	endpointSpec := fixture.spec(TypeEndpoint, "private-s3-endpoint", group.ResourceID)
	endpointSpec.AWS = endpointAWS
	endpointSpec.SpecDigest, err = endpointAWS.Digest(TypeEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := fixture.service.Provision(context.Background(), endpointSpec, fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}

	volume, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEBS, "data-volume"), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	snapshotAWS := &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, Snapshot: &AWSEBSSnapshotSpecV1{
		Description: "checkpoint before destroy", Disposition: AWSSnapshotDeleteWithDeployment,
	}}
	snapshotSpec := fixture.spec(TypeSnapshot, "destroy-checkpoint", volume.ResourceID)
	snapshotSpec.AWS = snapshotAWS
	snapshotSpec.SpecDigest, err = snapshotAWS.Digest(TypeSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := fixture.service.Provision(context.Background(), snapshotSpec, fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}

	result, err := fixture.service.Destroy(context.Background(), DestroyRequest{DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, ApprovalID: uuid.NewString()})
	if err != nil || result.Blocked {
		t.Fatalf("destroy endpoint/snapshot graph: result=%+v err=%v", result, err)
	}
	position := make(map[string]int, len(fixture.provider.deleteOrder))
	for index, providerID := range fixture.provider.deleteOrder {
		position[providerID] = index
	}
	if position[endpoint.ProviderID] >= position[group.ProviderID] || position[snapshot.ProviderID] >= position[volume.ProviderID] {
		t.Fatalf("dependency destroy order = %v", fixture.provider.deleteOrder)
	}
	for _, item := range result.Resources {
		if item.State != StateVerifiedDestroyed || item.ReadBack.Exists {
			t.Fatalf("destroy was not independently verified: %+v", item)
		}
	}
}

func TestPublicEntrypointDestroyUsesClosedDependencyGraphAndRejectsManaged(t *testing.T) {
	t.Run("destroys entry resources before exact dependencies", func(t *testing.T) {
		fixture := newResourceFixture(t)
		worker, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEC2, "exclusive-worker"), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		workerSecurityGroup, err := fixture.service.Provision(context.Background(), fixture.spec(TypeSG, "worker-security-group"), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		albSecurityGroup, err := fixture.service.Provision(context.Background(), fixture.spec(TypeSG, "entry-security-group"), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		loadBalancer, err := fixture.service.Provision(context.Background(), fixture.spec(TypeALB, "public-entry", albSecurityGroup.ResourceID), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		targetGroup, err := fixture.service.Provision(context.Background(), fixture.spec(TypeTargetGroup, "worker-target", worker.ResourceID), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		listener, err := fixture.service.Provision(context.Background(), fixture.spec(TypeListener, "https-listener", loadBalancer.ResourceID, targetGroup.ResourceID), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		bridge, err := fixture.service.Provision(context.Background(), fixture.spec(TypeSecurityGroupRule, "worker-ingress-bridge", albSecurityGroup.ResourceID, workerSecurityGroup.ResourceID), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}

		result, err := fixture.service.Destroy(context.Background(), DestroyRequest{DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, ApprovalID: uuid.NewString()})
		if err != nil || result.Blocked {
			t.Fatalf("Destroy() result=%+v error=%v", result, err)
		}
		position := make(map[string]int, len(fixture.provider.deleteOrder))
		for index, providerID := range fixture.provider.deleteOrder {
			position[providerID] = index
		}
		for _, pair := range [][2]string{
			{listener.ProviderID, loadBalancer.ProviderID}, {listener.ProviderID, targetGroup.ProviderID},
			{targetGroup.ProviderID, worker.ProviderID}, {loadBalancer.ProviderID, albSecurityGroup.ProviderID},
			{bridge.ProviderID, albSecurityGroup.ProviderID}, {bridge.ProviderID, workerSecurityGroup.ProviderID},
		} {
			if position[pair[0]] >= position[pair[1]] {
				t.Fatalf("entry destroy order=%v: %s must precede %s", fixture.provider.deleteOrder, pair[0], pair[1])
			}
		}
		for _, item := range result.Resources {
			if item.State != StateVerifiedDestroyed || item.ReadBack.Exists {
				t.Fatalf("entry resource not independently verified destroyed: %+v", item)
			}
		}
	})

	t.Run("managed entry remains fail closed", func(t *testing.T) {
		fixture := newResourceFixture(t)
		entry, err := fixture.service.Provision(context.Background(), fixture.spec(TypeALB, "managed-public-entry"), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		contract := ManagedContractV1{
			DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, AcceptanceApprovalID: uuid.NewString(),
			Currency: "USD", CostAlertAmountMinor: 5_000, MonitorRef: "monitor://service/health",
			MaintenanceRef: "runbook://service/maintenance", RestartRef: "runbook://service/restart",
			BackupRef: "runbook://service/backup", RestoreRef: "runbook://service/restore",
			UpgradeRef: "runbook://service/upgrade", RollbackRef: "runbook://service/rollback",
			DestroyRef: "runbook://service/destroy", AcceptedAt: fixture.now,
		}
		if _, _, err := fixture.service.AcceptManaged(context.Background(), contract); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.Destroy(context.Background(), DestroyRequest{DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, ApprovalID: uuid.NewString()}); !errors.Is(err, ErrManaged) {
			t.Fatalf("managed entry destroy error = %v, want ErrManaged", err)
		}
		if len(fixture.provider.deleteOrder) != 0 || !fixture.provider.resources[entry.ProviderID].Exists {
			t.Fatalf("managed entry reached provider delete: order=%v observation=%+v", fixture.provider.deleteOrder, fixture.provider.resources[entry.ProviderID])
		}
	})
}

func TestManagedAcceptanceRequiresCompleteContractAndDisablesReaper(t *testing.T) {
	fixture := newResourceFixture(t)
	resource, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEC2, "service"), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	contract := ManagedContractV1{
		DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, AcceptanceApprovalID: uuid.NewString(),
		Currency: "USD", CostAlertAmountMinor: 5_000, MonitorRef: "monitor://service/health",
		MaintenanceRef: "runbook://service/maintenance", RestartRef: "runbook://service/restart",
		BackupRef: "runbook://service/backup", RestoreRef: "runbook://service/restore",
		UpgradeRef: "runbook://service/upgrade", RollbackRef: "runbook://service/rollback",
		DestroyRef: "runbook://service/destroy", AcceptedAt: fixture.now,
	}
	missing := contract
	missing.BackupRef = ""
	if _, _, err := fixture.service.AcceptManaged(context.Background(), missing); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incomplete managed contract accepted: %v", err)
	}
	managed, resources, err := fixture.service.AcceptManaged(context.Background(), contract)
	if err != nil {
		t.Fatal(err)
	}
	if managed.State != "active" || len(resources) != 1 || resources[0].State != StateRetainedManaged || resources[0].DestroyDeadline != (time.Time{}) {
		t.Fatalf("unexpected managed state: managed=%+v resources=%+v", managed, resources)
	}
	manifest := fixture.mirror.manifests[fixture.deploymentID]
	if !manifest.Managed || manifest.AutoDestroyApproved || manifest.Retention != task.RetentionManaged {
		t.Fatalf("managed manifest could be reaped: %+v", manifest)
	}
	reaper, err := NewReaper(fixture.provider, fixture.mirror)
	if err != nil {
		t.Fatal(err)
	}
	reaper.now = func() time.Time { return fixture.now.Add(24 * time.Hour) }
	report, err := reaper.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.SkippedManaged != 1 || len(fixture.provider.deleteOrder) != 0 || !fixture.provider.resources[resource.ProviderID].Exists {
		t.Fatalf("reaper touched a managed resource: report=%+v order=%v", report, fixture.provider.deleteOrder)
	}
}

func TestManagedAndDestroyTransitionsFenceEachOther(t *testing.T) {
	t.Run("managed blocks destroy", func(t *testing.T) {
		fixture := newResourceFixture(t)
		created, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEC2, "managed-service"), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		contract := ManagedContractV1{
			DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, AcceptanceApprovalID: uuid.NewString(),
			Currency: "USD", CostAlertAmountMinor: 5_000, MonitorRef: "monitor://service/health",
			MaintenanceRef: "runbook://service/maintenance", RestartRef: "runbook://service/restart",
			BackupRef: "runbook://service/backup", RestoreRef: "runbook://service/restore",
			UpgradeRef: "runbook://service/upgrade", RollbackRef: "runbook://service/rollback",
			DestroyRef: "runbook://service/destroy", AcceptedAt: fixture.now,
		}
		if _, _, err := fixture.service.AcceptManaged(context.Background(), contract); err != nil {
			t.Fatal(err)
		}
		_, err = fixture.service.Destroy(context.Background(), DestroyRequest{DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, ApprovalID: uuid.NewString()})
		if !errors.Is(err, ErrManaged) || len(fixture.provider.deleteOrder) != 0 || !fixture.provider.resources[created.ProviderID].Exists {
			t.Fatalf("managed destroy = %v, deletes=%v", err, fixture.provider.deleteOrder)
		}
	})

	t.Run("destroy schedule blocks managed acceptance", func(t *testing.T) {
		fixture := newResourceFixture(t)
		if _, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEC2, "ephemeral-service"), fixture.createAuthorization()); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.ScheduleDestroy(context.Background(), fixture.deploymentID, fixture.ownerID); err != nil {
			t.Fatal(err)
		}
		contract := ManagedContractV1{
			DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, AcceptanceApprovalID: uuid.NewString(),
			Currency: "USD", CostAlertAmountMinor: 5_000, MonitorRef: "monitor://service/health",
			MaintenanceRef: "runbook://service/maintenance", RestartRef: "runbook://service/restart",
			BackupRef: "runbook://service/backup", RestoreRef: "runbook://service/restore",
			UpgradeRef: "runbook://service/upgrade", RollbackRef: "runbook://service/rollback",
			DestroyRef: "runbook://service/destroy", AcceptedAt: fixture.now,
		}
		if _, _, err := fixture.service.AcceptManaged(context.Background(), contract); !errors.Is(err, ErrInvalid) {
			t.Fatalf("scheduled resource became managed: %v", err)
		}
	})
}

func TestAgentLossReaperDeletesOnlyApprovedExpiredEphemeral(t *testing.T) {
	fixture := newResourceFixture(t)
	resource, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEC2, "ephemeral-worker"), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixture.mirror.manifests[fixture.deploymentID]
	manifest.DestroyDeadline = fixture.now.Add(-time.Minute)
	manifest.Resources[0].DestroyDeadline = manifest.DestroyDeadline
	manifest.Resources[0].Tags[TagDestroyDeadline] = manifest.DestroyDeadline.Format(time.RFC3339)
	fixture.mirror.manifests[fixture.deploymentID] = manifest

	reaper, err := NewReaper(fixture.provider, fixture.mirror)
	if err != nil {
		t.Fatal(err)
	}
	reaper.now = func() time.Time { return fixture.now }
	report, err := reaper.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.VerifiedDestroyed != 1 || report.Blocked != 0 || fixture.provider.resources[resource.ProviderID].Exists {
		t.Fatalf("approved expired resource was not reaped: %+v", report)
	}
	readback := fixture.mirror.manifests[fixture.deploymentID].Resources[0]
	if readback.State != StateVerifiedDestroyed || readback.ReadBack.Exists {
		t.Fatalf("reaper did not persist verified read-back: %+v", readback)
	}

	// An otherwise identical manifest without the plan-bound approval is never deleted.
	unapproved := manifest.clone()
	unapproved.ManifestID = uuid.NewString()
	unapproved.DeploymentID = unapproved.ManifestID
	unapproved.AutoDestroyApproved = false
	unapproved.Resources[0].DeploymentID = unapproved.DeploymentID
	unapproved.Resources[0].State = StateActive
	unapproved.Resources[0].ProviderID = "unapproved-provider"
	fixture.provider.resources["unapproved-provider"] = ProviderObservation{ProviderID: "unapproved-provider", Type: TypeEC2, Exists: true, Tags: unapproved.Resources[0].Tags, ObservedAt: fixture.now}
	fixture.mirror.manifests[unapproved.ManifestID] = unapproved
	report, err = reaper.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.SkippedNotApproved != 1 || !fixture.provider.resources["unapproved-provider"].Exists {
		t.Fatalf("unapproved manifest was reaped: %+v", report)
	}
}

func TestRecoverOwnedImportsOnlyCompletelyTaggedOrphans(t *testing.T) {
	fixture := newResourceFixture(t)
	spec := fixture.spec(TypeSnapshot, "snapshot")
	tags := spec.mandatoryTags()
	orphanID := "snap-orphan"
	fixture.provider.resources[orphanID] = ProviderObservation{ProviderID: orphanID, Type: TypeSnapshot, Exists: true, Tags: tags, ObservedAt: fixture.now}
	foreignTags := cloneMap(tags)
	foreignTags[TagAgentInstanceID] = uuid.NewString()
	fixture.provider.resources["snap-foreign"] = ProviderObservation{ProviderID: "snap-foreign", Type: TypeSnapshot, Exists: true, Tags: foreignTags, ObservedAt: fixture.now}
	crossOwnerTags := cloneMap(tags)
	crossOwnerTags[TagOwnerID] = "other-owner"
	fixture.provider.resources["snap-other-owner"] = ProviderObservation{ProviderID: "snap-other-owner", Type: TypeSnapshot, Exists: true, Tags: crossOwnerTags, ObservedAt: fixture.now}
	imported, err := fixture.service.RecoverOwned(context.Background(), fixture.agentID, fixture.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != 1 || imported[0].ProviderID != orphanID || imported[0].State != StateOrphaned {
		t.Fatalf("unexpected recovered resources: %+v", imported)
	}
}

func TestRecoverOwnedRejectsCrossOwnerObservationEvenIfProviderReturnsIt(t *testing.T) {
	fixture := newResourceFixture(t)
	tags := fixture.spec(TypeSnapshot, "snapshot").mandatoryTags()
	tags[TagOwnerID] = "other-owner"
	fixture.provider.ignoreOwnerFilter = true // simulate a broken provider-side filter.
	fixture.provider.resources["snap-other-owner"] = ProviderObservation{
		ProviderID: "snap-other-owner", Type: TypeSnapshot, Exists: true, Tags: tags, ObservedAt: fixture.now,
	}
	imported, err := fixture.service.RecoverOwned(context.Background(), fixture.agentID, fixture.ownerID)
	if err != nil || len(imported) != 0 {
		t.Fatalf("cross-owner observation was adopted: imported=%+v err=%v", imported, err)
	}
}

func repeatHex(value byte) string {
	buffer := make([]byte, 64)
	for index := range buffer {
		buffer[index] = value
	}
	return string(buffer)
}

func statesByID(resources []ResourceV1) map[string]State {
	result := make(map[string]State, len(resources))
	for _, resource := range resources {
		result[resource.ResourceID] = resource.State
	}
	return result
}

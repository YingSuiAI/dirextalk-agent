package resource

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestRetireManagedPreparationOriginalRecoversProviderAndStoreResponseLoss(t *testing.T) {
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID, operationID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	sourceID := uuid.NewString()
	deadline := now.Add(time.Hour)
	source := ResourceV1{
		ResourceID: sourceID, AgentInstanceID: agentID, OwnerID: "owner-managed-retire", TaskID: taskID,
		DeploymentID: deploymentID, Type: TypeEBS, LogicalName: "source", Region: "us-west-2",
		SpecDigest: managedPreparationTestDigest("a"), ApprovedPlanHash: managedPreparationTestDigest("b"),
		ApprovalID: uuid.NewString(), ProviderID: "vol-0123456789abcdef0",
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true,
		Tags:  managedPreparationTestTags(agentID, taskID, deploymentID, sourceID, deadline),
		State: StateActive, ReadBack: ReadBackEvidence{
			Exists: true, ProviderID: "vol-0123456789abcdef0", ObservedAt: now, TagDigest: managedPreparationTestDigest("c"),
		},
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	source.Tags[TagOwnerID] = source.OwnerID
	source.Tags[TagApprovedPlanHash], source.Tags[TagApprovalID] = source.ApprovedPlanHash, source.ApprovalID
	base := newFakeResourceRepository()
	base.resources[sourceID] = source
	repository := &managedPreparationFakeRepository{
		fakeResourceRepository: base, operationID: operationID, loseCompleteResponse: true,
	}
	provider := &lostDeleteProvider{fakeProvider: newFakeProvider(now.Add(10 * time.Minute)), loseResponse: true}
	provider.resources[source.ProviderID] = ProviderObservation{
		ProviderID: source.ProviderID, Type: source.Type, Exists: true, Tags: cloneMap(source.Tags), ObservedAt: now,
	}
	mirror := newFakeMirror()
	service, err := NewService(repository, provider, mirror)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now.Add(10 * time.Minute) }
	request := ManagedPreparationRetireRequest{
		OperationID: operationID, OwnerID: source.OwnerID, DeploymentID: deploymentID, ResourceID: sourceID,
	}
	if _, err := service.RetireManagedPreparationOriginal(context.Background(), request); err == nil {
		t.Fatal("lost durable completion response was not surfaced")
	}
	retired, err := service.RetireManagedPreparationOriginal(context.Background(), request)
	if err != nil || retired.State != StateVerifiedDestroyed || retired.ReadBack.Exists {
		t.Fatalf("retirement replay=%+v error=%v", retired, err)
	}
	if provider.deleteCalls != 1 || repository.completeCalls != 1 {
		t.Fatalf("response-loss replay duplicated mutation: deletes=%d completes=%d", provider.deleteCalls, repository.completeCalls)
	}
	manifest := mirror.manifests[deploymentID]
	if len(manifest.Resources) != 1 || manifest.Resources[0].State != StateVerifiedDestroyed {
		t.Fatalf("final retirement manifest=%+v", manifest)
	}
}

func TestManagedPreparationManifestOriginFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID, operationID, resourceID :=
		uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	deadline := now.Add(time.Hour)
	item := ResourceV1{
		ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: "owner-origin-manifest",
		TaskID: taskID, DeploymentID: deploymentID, Type: TypeSnapshot, LogicalName: "snapshot",
		Region: "us-west-2", SpecDigest: managedPreparationTestDigest("a"),
		ApprovedPlanHash: managedPreparationTestDigest("b"), ApprovalID: operationID,
		IntentOrigin: IntentOriginManagedPreparation, OriginScopeDigest: managedPreparationTestDigest("c"),
		ProviderID: "snap-0123456789abcdef0", Retention: task.RetentionEphemeralAutoDestroy,
		DestroyDeadline: deadline, AutoDestroyApproved: true, State: StateActive,
		ReadBack: ReadBackEvidence{
			Exists: true, ProviderID: "snap-0123456789abcdef0", ObservedAt: now, TagDigest: managedPreparationTestDigest("d"),
		},
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	item.Tags = managedPreparationTestTags(agentID, taskID, deploymentID, resourceID, deadline)
	item.Tags[TagOwnerID], item.Tags[TagApprovedPlanHash], item.Tags[TagApprovalID] = item.OwnerID, item.ApprovedPlanHash, item.ApprovalID
	item.Tags[TagIntentOrigin], item.Tags[TagOriginScopeDigest] = string(item.IntentOrigin), item.OriginScopeDigest
	manifest, err := manifestFrom([]ResourceV1{item}, true, now)
	if err != nil || manifest.ValidateResourceApprovalScope() != nil {
		t.Fatalf("valid managed-preparation origin manifest=%+v error=%v", manifest, err)
	}
	manifest.Resources[0].Tags[TagOriginScopeDigest] = managedPreparationTestDigest("e")
	if err := manifest.ValidateResourceApprovalScope(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered managed-preparation origin error=%v", err)
	}
	manifest.Resources[0].Tags[TagOriginScopeDigest] = item.OriginScopeDigest
	manifest.Resources[0].IntentOrigin = IntentOrigin("unknown")
	if err := manifest.ValidateResourceApprovalScope(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown managed-preparation origin error=%v", err)
	}
}

type managedPreparationFakeRepository struct {
	*fakeResourceRepository
	operationID          string
	loseCompleteResponse bool
	completeCalls        int
}

func (repository *managedPreparationFakeRepository) CommitManagedPreparationSwap(
	context.Context,
	ManagedPreparationSwapRequest,
	time.Time,
) (ManagedPreparationSwapRecord, ResourceV1, error) {
	return ManagedPreparationSwapRecord{}, ResourceV1{}, ErrInvalid
}

func (repository *managedPreparationFakeRepository) BeginManagedPreparationRetire(
	_ context.Context,
	request ManagedPreparationRetireRequest,
	at time.Time,
) (ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	item, found := repository.resources[request.ResourceID]
	if !found || request.OperationID != repository.operationID || item.OwnerID != request.OwnerID ||
		item.DeploymentID != request.DeploymentID {
		return ResourceV1{}, ErrRevisionConflict
	}
	token := "managed-preparation-retire:" + request.OperationID
	switch item.State {
	case StateActive:
		item.State = StateDestroying
		item.Intent = MutationIntent{Operation: MutationDestroy, ClientToken: token, RecordedAt: at}
		item.ReadBack = ReadBackEvidence{}
		item.Revision++
		item.UpdatedAt = at
		repository.resources[item.ResourceID] = item
	case StateDestroying, StateVerifiedDestroyed:
		if item.Intent.ClientToken != token {
			return ResourceV1{}, ErrRevisionConflict
		}
	default:
		return ResourceV1{}, ErrRevisionConflict
	}
	return item.clone(), nil
}

func (repository *managedPreparationFakeRepository) CompleteManagedPreparationRetire(
	_ context.Context,
	request ManagedPreparationRetireRequest,
	evidence ReadBackEvidence,
	at time.Time,
) (ResourceV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	item := repository.resources[request.ResourceID]
	if item.State != StateDestroying || evidence.Exists || evidence.ProviderID != item.ProviderID {
		return ResourceV1{}, ErrRevisionConflict
	}
	repository.completeCalls++
	item.State = StateVerifiedDestroyed
	item.ReadBack = evidence
	item.Revision++
	item.UpdatedAt = at
	repository.resources[item.ResourceID] = item
	if repository.loseCompleteResponse {
		repository.loseCompleteResponse = false
		return ResourceV1{}, errors.New("simulated resource-store completion response loss")
	}
	return item.clone(), nil
}

type lostDeleteProvider struct {
	*fakeProvider
	loseResponse bool
	deleteCalls  int
}

func (provider *lostDeleteProvider) Delete(ctx context.Context, kind Type, providerID, region string, tags map[string]string) error {
	provider.deleteCalls++
	err := provider.fakeProvider.Delete(ctx, kind, providerID, region, tags)
	if err == nil && provider.loseResponse {
		provider.loseResponse = false
		return errors.New("simulated provider delete response loss")
	}
	return err
}

func managedPreparationTestTags(agentID, taskID, deploymentID, resourceID string, deadline time.Time) map[string]string {
	return map[string]string{
		TagAgentInstanceID: agentID, TagTaskID: taskID, TagDeploymentID: deploymentID, TagResourceID: resourceID,
		TagRetention: string(task.RetentionEphemeralAutoDestroy), TagDestroyDeadline: deadline.Format(time.RFC3339),
	}
}

func managedPreparationTestDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }

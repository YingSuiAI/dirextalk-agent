package cloudworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestInputStagerRejectsBeforeConfirmationAndSourceDriftWithoutUpload(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, execution, prerequisite, source := stagingFixture(t, now)
	ledger := NewMemoryStagingLedger()
	objects := &stagingObjectFake{now: &now}
	reader := &stagingSourceFake{read: source}
	stager, _ := NewInputStager(reader, objects, ledger, func() time.Time { return now })

	future := prerequisite
	future.ConfirmedAt = now.Add(time.Second)
	if _, err := stager.Stage(context.Background(), plan, execution, future); !errors.Is(err, ErrStaleAuthorization) || objects.putCalls != 0 {
		t.Fatalf("pre-confirmation staging crossed AWS boundary: calls=%d err=%v", objects.putCalls, err)
	}

	reader.read.SourceRevision++
	if _, err := stager.Stage(context.Background(), plan, execution, prerequisite); !errors.Is(err, ErrInvalid) || objects.putCalls != 0 {
		t.Fatalf("source drift crossed AWS boundary: calls=%d err=%v", objects.putCalls, err)
	}
	records, err := ledger.ListExecution(context.Background(), plan.OwnerID, plan.AccountGeneration, plan.ExecutionID)
	if err != nil || len(records) != 1 || records[0].State != StagingIntentRecorded || records[0].MutationAttempts != 0 {
		t.Fatalf("drift did not retain a no-mutation intent: records=%+v err=%v", records, err)
	}
}

func TestInputStagerPersistsIntentBeforePutAndReusesExactVersion(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, execution, prerequisite, source := stagingFixture(t, now)
	ledger := NewMemoryStagingLedger()
	objects := &stagingObjectFake{now: &now, versionOnPut: "version-1"}
	objects.beforePut = func(identity StagingObjectIdentity) {
		record, err := ledger.Get(context.Background(), identity)
		if err != nil || record.State != StagingPutStarted || record.MutationAttempts != 1 || record.Revision != 2 {
			t.Fatalf("PutObject preceded durable intent: record=%+v err=%v", record, err)
		}
	}
	stager, _ := NewInputStager(&stagingSourceFake{read: source}, objects, ledger, func() time.Time { return now })

	manifest, err := stager.Stage(context.Background(), plan, execution, prerequisite)
	if err != nil || len(manifest.Items) != 1 || manifest.Items[0].S3VersionID != "version-1" || objects.putCalls != 1 {
		t.Fatalf("stage result=%+v calls=%d err=%v", manifest, objects.putCalls, err)
	}
	if _, err := stager.Stage(context.Background(), plan, execution, prerequisite); err != nil || objects.putCalls != 1 {
		t.Fatalf("restart did not reuse exact version: calls=%d err=%v", objects.putCalls, err)
	}
}

func TestInputStagerUnknownPutIsReadbackOnlyAndNeverCreatesSecondVersion(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, execution, prerequisite, source := stagingFixture(t, now)

	t.Run("unknown response with created version binds by identity", func(t *testing.T) {
		ledger := NewMemoryStagingLedger()
		objects := &stagingObjectFake{now: &now, versionOnPut: "version-unknown", putUnknown: true}
		stager, _ := NewInputStager(&stagingSourceFake{read: source}, objects, ledger, func() time.Time { return now })
		manifest, err := stager.Stage(context.Background(), plan, execution, prerequisite)
		if err != nil || manifest.Items[0].S3VersionID != "version-unknown" || objects.putCalls != 1 || objects.findCalls == 0 {
			t.Fatalf("unknown readback failed: manifest=%+v puts=%d finds=%d err=%v", manifest, objects.putCalls, objects.findCalls, err)
		}
		if _, err := stager.Stage(context.Background(), plan, execution, prerequisite); err != nil || objects.putCalls != 1 {
			t.Fatalf("restart repeated unknown PutObject: calls=%d err=%v", objects.putCalls, err)
		}
	})

	t.Run("unknown response without object never retries", func(t *testing.T) {
		localNow := now
		ledger := NewMemoryStagingLedger()
		objects := &stagingObjectFake{now: &localNow, putUnknown: true}
		stager, _ := NewInputStager(&stagingSourceFake{read: source}, objects, ledger, func() time.Time { return localNow })
		if _, err := stager.Stage(context.Background(), plan, execution, prerequisite); !errors.Is(err, ErrStagingPending) || objects.putCalls != 1 {
			t.Fatalf("first unknown response: calls=%d err=%v", objects.putCalls, err)
		}
		localNow = localNow.Add(time.Minute)
		if _, err := stager.Stage(context.Background(), plan, execution, prerequisite); !errors.Is(err, ErrStagingPending) || objects.putCalls != 1 {
			t.Fatalf("expired mutation lease repeated PutObject: calls=%d err=%v", objects.putCalls, err)
		}
		if err := stager.Cleanup(context.Background(), plan); err != nil {
			t.Fatalf("fresh absent inventory did not clean unknown put: %v", err)
		}
		records, _ := ledger.ListExecution(context.Background(), plan.OwnerID, plan.AccountGeneration, plan.ExecutionID)
		if len(records) != 1 || records[0].State != StagingVerifiedDestroyed || records[0].MutationAttempts != 1 {
			t.Fatalf("unknown put cleanup=%+v", records)
		}
	})
}

func TestInputStagerCleanupDeletesExactVersionAndTerminalRecordCannotRegress(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, execution, prerequisite, source := stagingFixture(t, now)
	ledger := NewMemoryStagingLedger()
	objects := &stagingObjectFake{now: &now, versionOnPut: "version-delete", deleteUnknown: true}
	stager, _ := NewInputStager(&stagingSourceFake{read: source}, objects, ledger, func() time.Time { return now })
	if _, err := stager.Stage(context.Background(), plan, execution, prerequisite); err != nil {
		t.Fatal(err)
	}
	if err := stager.Cleanup(context.Background(), plan); err != nil || objects.deleteCalls != 1 || objects.deletedVersion != "version-delete" {
		t.Fatalf("exact cleanup calls=%d version=%q err=%v", objects.deleteCalls, objects.deletedVersion, err)
	}
	records, _ := ledger.ListExecution(context.Background(), plan.OwnerID, plan.AccountGeneration, plan.ExecutionID)
	if len(records) != 1 || records[0].State != StagingVerifiedDestroyed {
		t.Fatalf("cleanup record=%+v", records)
	}
	next := records[0]
	next.State, next.VersionID, next.DeleteAttempts, next.Revision, next.UpdatedAt = StagingVersionBound, "version-delete", 0, next.Revision+1, now.Add(time.Second)
	if _, err := ledger.CompareAndSwap(context.Background(), next, records[0].Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("terminal staging record regressed: %v", err)
	}
}

func stagingFixture(t *testing.T, now time.Time) (Plan, Execution, LaunchPrerequisite, SourceRead) {
	t.Helper()
	content := []byte("input-data")
	inputID, sourceRef := uuid.NewString(), uuid.NewString()
	manifest := InputManifest{Schema: InputManifestSchema, Items: []InputManifestItem{{
		InputID: inputID, Kind: "file", Name: "input.txt", MountPath: "input/input.txt", MediaType: "text/plain",
		SizeBytes: uint64(len(content)), SHA256: digestBytesForTest(content), SourceRef: sourceRef, SourceRevision: 3,
	}}}
	store := &intrinsicStore{}
	service, err := NewService(store, intrinsicDefaults(now), FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	model := ModelAuthorization{ModelProfileID: uuid.NewString(), ModelProfileRevision: 2, Provider: "openai_compatible", BaseURL: "https://api.openai.com/v1", Model: "gpt-test", Interface: "openai_compatible", MaximumOutputTokens: 4096, ContextWindow: 65536, CredentialVersion: 4, CredentialBindingDigest: digestValue("credential")}
	offer, err := service.Propose(context.Background(), ProposeCommand{
		OwnerID: "@owner:example.test", AccountGeneration: 7, IdempotencyKey: uuid.NewString(), ConversationID: uuid.NewString(), TurnID: uuid.NewString(),
		TurnLeaseID: uuid.NewString(), TurnLeaseEpoch: 2, ExpectedTurnRevision: 1, Objective: "edit input", ObjectiveSummary: "edit input",
		UserPromptDigest: digestValue("prompt"), ProposalReason: ProposalReasonExplicitUserCloud, InputManifest: manifest, WorkspaceMode: WorkspaceWrite,
		ModelAuthorization: model,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := BindingForPlan(offer.Plan)
	if err != nil {
		t.Fatal(err)
	}
	prerequisite := LaunchPrerequisite{ConfirmationBindingDigest: string(binding.Digest), ConfirmationRevision: 3,
		ConfirmedAt: now.Add(-time.Second), TaskAttempt: 1, LeaseEpoch: 1, AccountGeneration: offer.Plan.AccountGeneration}
	return offer.Plan, offer.Execution, prerequisite, SourceRead{SourceRef: sourceRef, SourceRevision: 3, SizeBytes: uint64(len(content)), MediaType: "text/plain", Body: &testReadSeekCloser{Reader: *bytes.NewReader(content)}}
}

func digestBytesForTest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

type testReadSeekCloser struct{ bytes.Reader }

func (reader *testReadSeekCloser) Close() error { return nil }

type stagingSourceFake struct{ read SourceRead }

func (source *stagingSourceFake) OpenSource(context.Context, SourceRequest) (SourceRead, error) {
	content, err := io.ReadAll(source.read.Body)
	if err != nil {
		return SourceRead{}, err
	}
	_, _ = source.read.Body.Seek(0, io.SeekStart)
	copy := source.read
	copy.Body = &testReadSeekCloser{Reader: *bytes.NewReader(content)}
	return copy, nil
}

type stagingObjectFake struct {
	now            *time.Time
	versionOnPut   string
	putUnknown     bool
	deleteUnknown  bool
	version        string
	identity       StagingObjectIdentity
	beforePut      func(StagingObjectIdentity)
	putCalls       int
	findCalls      int
	observeCalls   int
	deleteCalls    int
	deletedVersion string
}

func (store *stagingObjectFake) PutVersion(_ context.Context, request StagingPutRequest) (StagingObjectObservation, error) {
	store.putCalls++
	if store.beforePut != nil {
		store.beforePut(request.Identity)
	}
	store.identity = request.Identity
	if store.versionOnPut != "" {
		store.version = store.versionOnPut
	}
	observation := StagingObjectObservation{Identity: request.Identity, VersionID: store.version, Exists: store.version != "", ObservedAt: store.now.UTC()}
	if store.putUnknown {
		return StagingObjectObservation{}, ErrStagingResponseUnknown
	}
	return observation, nil
}

func (store *stagingObjectFake) FindVersion(_ context.Context, identity StagingObjectIdentity) (StagingObjectObservation, bool, error) {
	store.findCalls++
	if store.version == "" {
		return StagingObjectObservation{}, false, nil
	}
	return StagingObjectObservation{Identity: identity, VersionID: store.version, Exists: true, ObservedAt: store.now.UTC()}, true, nil
}

func (store *stagingObjectFake) ObserveVersion(_ context.Context, request StagingVersionRequest) (StagingObjectObservation, error) {
	store.observeCalls++
	exists := store.version != "" && request.VersionID == store.version
	return StagingObjectObservation{Identity: request.Identity, VersionID: request.VersionID, Exists: exists, ObservedAt: store.now.UTC()}, nil
}

func (store *stagingObjectFake) DeleteVersion(_ context.Context, request StagingVersionRequest) error {
	store.deleteCalls++
	store.deletedVersion = request.VersionID
	if request.VersionID == store.version {
		store.version = ""
	}
	if store.deleteUnknown {
		return ErrStagingResponseUnknown
	}
	return nil
}

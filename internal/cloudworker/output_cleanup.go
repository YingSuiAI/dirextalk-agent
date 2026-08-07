package cloudworker

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type OutputJournalManager struct {
	ledger  OutputJournalLedger
	objects OutputVersionStoreFactory
	now     func() time.Time
}

func NewOutputJournalManager(ledger OutputJournalLedger, objects OutputVersionStoreFactory, clocks ...func() time.Time) (*OutputJournalManager, error) {
	if ledger == nil || objects == nil {
		return nil, ErrInvalid
	}
	clock := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &OutputJournalManager{ledger: ledger, objects: objects, now: clock}, nil
}

// Authorize durably binds one task attempt/lease to the exact execution S3
// prefix before the provider is allowed to create the Worker. It performs no
// AWS call and is idempotent across controller restart and lease reclaim.
func (manager *OutputJournalManager) Authorize(ctx context.Context, plan Plan, task coretask.Task) error {
	if manager == nil || ctx == nil || manager.ledger == nil || manager.objects == nil {
		return ErrInvalid
	}
	identity, err := outputJournalIdentity(plan, task)
	if err != nil {
		return err
	}
	now := manager.now().UTC()
	if !validOutputTime(now) {
		return ErrInvalid
	}
	_, err = manager.ledger.EnsureJournal(ctx, OutputJournalRecord{
		Identity: identity, State: OutputJournalApproved, Revision: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	return err
}

// Cleanup runs only after Worker sessions are fenced and the ephemeral AWS
// graph is verified destroyed. Each invocation starts with a fresh inventory,
// so an uncertain PutObject or DeleteObject is resolved by readback before any
// mutation is retried. The only versions allowed to remain are exact artifacts
// already accepted into the durable retention authority.
func (manager *OutputJournalManager) Cleanup(ctx context.Context, plan Plan, accepted []Artifact) error {
	if manager == nil || ctx == nil || manager.ledger == nil || manager.objects == nil {
		return ErrInvalid
	}
	identity, err := outputExecutionIdentity(plan)
	if err != nil {
		return err
	}
	retained, err := acceptedOutputVersions(identity, accepted)
	if err != nil {
		return err
	}
	journals, err := manager.ledger.ListJournals(ctx, identity)
	if err != nil {
		return err
	}
	if len(journals) == 0 {
		if len(retained) != 0 {
			return ErrConflict
		}
		return nil
	}
	if err = manager.markJournalsCleaning(ctx, journals); err != nil {
		return err
	}
	objects, err := manager.objects.StoreForOutput(ctx, identity)
	if err != nil || objects == nil {
		return errors.Join(ErrOutputCleanupPending, err)
	}
	first, err := manager.inventory(ctx, objects, identity)
	if err != nil {
		return errors.Join(ErrOutputCleanupPending, err)
	}
	if err = manager.reconcileRetained(ctx, objects, retained, first); err != nil {
		return err
	}
	for key, observation := range first {
		if _, keep := retained[key]; keep {
			continue
		}
		record, discoverErr := manager.discover(ctx, observation)
		if discoverErr != nil {
			return discoverErr
		}
		if record.State == OutputVersionRetained {
			return ErrStaleAuthorization
		}
		if record.State == OutputVersionVerifiedDeleted {
			// A version that was proven absent and is now visible again violates
			// immutable version identity/readback and must never be deleted under
			// stale authority.
			return ErrStaleAuthorization
		}
		record, err = manager.markDeleteStarted(ctx, record)
		if err != nil {
			return err
		}
		if deleteErr := objects.DeleteExact(ctx, record.Observation.Identity); deleteErr != nil {
			if markErr := manager.markDeleteUncertain(ctx, record); markErr != nil {
				return markErr
			}
		}
	}

	// Readback is mandatory even when every DeleteObject returned success. It
	// resolves response-unknown calls and catches versions uploaded before the
	// already-verified IAM/instance destruction became visible to S3.
	second, err := manager.inventory(ctx, objects, identity)
	if err != nil {
		return errors.Join(ErrOutputCleanupPending, err)
	}
	if err = manager.reconcileRetained(ctx, objects, retained, second); err != nil {
		return err
	}
	if err = manager.recordSecondInventory(ctx, second, retained); err != nil {
		return err
	}
	if err = manager.verifyAbsentVersions(ctx, identity, second); err != nil {
		return err
	}
	for key := range second {
		if _, keep := retained[key]; !keep {
			return ErrOutputCleanupPending
		}
	}
	journals, err = manager.ledger.ListJournals(ctx, identity)
	if err != nil {
		return err
	}
	return manager.markJournalsVerified(ctx, journals)
}

func (manager *OutputJournalManager) inventory(ctx context.Context, objects OutputVersionStore, identity OutputExecutionIdentity) (map[string]OutputVersionObservation, error) {
	cursor := OutputInventoryCursor{}
	seenCursors := make(map[OutputInventoryCursor]struct{})
	result := make(map[string]OutputVersionObservation)
	for {
		if _, duplicate := seenCursors[cursor]; duplicate {
			return nil, ErrConflict
		}
		seenCursors[cursor] = struct{}{}
		request := OutputInventoryRequest{Identity: identity, Cursor: cursor}
		page, err := objects.InventoryPage(ctx, request)
		if err != nil || page.Validate(request) != nil {
			return nil, errors.Join(ErrOutputCleanupPending, err)
		}
		for _, observation := range page.Versions {
			key := outputVersionKey(observation.Identity)
			if _, duplicate := result[key]; duplicate {
				return nil, ErrConflict
			}
			result[key] = observation
		}
		if page.NextCursor.empty() {
			return result, nil
		}
		cursor = page.NextCursor
	}
}

func acceptedOutputVersions(identity OutputExecutionIdentity, artifacts []Artifact) (map[string]ArtifactRetentionIdentity, error) {
	result := make(map[string]ArtifactRetentionIdentity, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Retention == nil || artifact.Retention.Validate() != nil || artifact.Status != ArtifactVerified {
			return nil, ErrInvalid
		}
		retention := *artifact.Retention
		if retention.OwnerID != identity.OwnerID || retention.AccountID != identity.AccountID ||
			retention.AccountGeneration != identity.AccountGeneration || retention.Region != identity.Region ||
			retention.CredentialID != identity.CredentialID || retention.CredentialRevision != identity.CredentialRevision ||
			retention.ProviderID != identity.ProviderID || retention.ExecutionID != identity.ExecutionID ||
			retention.PlanID != identity.PlanID || retention.PlanDigest != identity.PlanDigest ||
			retention.Claim.Bucket != identity.Bucket || retention.KeyPrefix != identity.KeyPrefix ||
			retention.KMSKeyARN != identity.KMSKeyARN || retention.Claim.Name == "result.json" {
			return nil, ErrStaleAuthorization
		}
		version := OutputVersionIdentity{OutputExecutionIdentity: identity, Key: retention.Claim.Key, VersionID: retention.Claim.VersionID}
		if version.Validate() != nil {
			return nil, ErrInvalid
		}
		key := outputVersionKey(version)
		if _, duplicate := result[key]; duplicate {
			return nil, ErrConflict
		}
		result[key] = retention
	}
	return result, nil
}

func (manager *OutputJournalManager) reconcileRetained(ctx context.Context, objects OutputVersionStore, retained map[string]ArtifactRetentionIdentity, live map[string]OutputVersionObservation) error {
	for key, retention := range retained {
		listed, found := live[key]
		if !found || listed.Identity.DeleteMarker || listed.SizeBytes != retention.Claim.SizeBytes {
			return ErrOutputCleanupPending
		}
		exact, err := objects.ObserveExact(ctx, listed.Identity)
		if err != nil || exact.Validate(listed.Identity) != nil {
			return errors.Join(ErrOutputCleanupPending, err)
		}
		if !exact.Exists || exact.SizeBytes != retention.Claim.SizeBytes || exact.MediaType != retention.Claim.MediaType ||
			exact.SHA256 != retention.Claim.SHA256 || exact.KMSKeyARN != retention.KMSKeyARN || exact.BucketKeyEnabled {
			return ErrStaleAuthorization
		}
		record, err := manager.discover(ctx, listed)
		if err != nil {
			return err
		}
		if record.State == OutputVersionRetained {
			continue
		}
		if record.State != OutputVersionDiscovered {
			return ErrStaleAuthorization
		}
		now := manager.now().UTC()
		next := record
		next.State, next.Revision, next.UpdatedAt = OutputVersionRetained, record.Revision+1, now
		if _, err = manager.ledger.CompareAndSwapVersion(ctx, next, record.Revision); err != nil {
			return err
		}
	}
	return nil
}

func (manager *OutputJournalManager) discover(ctx context.Context, observation OutputVersionObservation) (OutputVersionRecord, error) {
	return manager.ledger.DiscoverVersion(ctx, OutputVersionRecord{
		Observation: observation, State: OutputVersionDiscovered, Revision: 1,
		CreatedAt: observation.ObservedAt, UpdatedAt: observation.ObservedAt,
	})
}

func (manager *OutputJournalManager) markDeleteStarted(ctx context.Context, record OutputVersionRecord) (OutputVersionRecord, error) {
	if record.State != OutputVersionDiscovered && record.State != OutputVersionDeleteStarted && record.State != OutputVersionDeleteUncertain {
		return OutputVersionRecord{}, ErrConflict
	}
	now := manager.now().UTC()
	next := record
	next.State, next.DeleteAttempts = OutputVersionDeleteStarted, record.DeleteAttempts+1
	next.Revision, next.UpdatedAt = record.Revision+1, now
	return manager.ledger.CompareAndSwapVersion(ctx, next, record.Revision)
}

func (manager *OutputJournalManager) markDeleteUncertain(ctx context.Context, record OutputVersionRecord) error {
	if record.State != OutputVersionDeleteStarted {
		return ErrConflict
	}
	next := record
	next.State, next.Revision, next.UpdatedAt = OutputVersionDeleteUncertain, record.Revision+1, manager.now().UTC()
	_, err := manager.ledger.CompareAndSwapVersion(ctx, next, record.Revision)
	return err
}

func (manager *OutputJournalManager) recordSecondInventory(ctx context.Context, live map[string]OutputVersionObservation, retained map[string]ArtifactRetentionIdentity) error {
	for key, observation := range live {
		record, err := manager.discover(ctx, observation)
		if err != nil {
			return err
		}
		if _, keep := retained[key]; keep {
			if record.State != OutputVersionRetained {
				return ErrStaleAuthorization
			}
			continue
		}
		if record.State == OutputVersionRetained || record.State == OutputVersionVerifiedDeleted {
			return ErrStaleAuthorization
		}
	}
	return nil
}

func (manager *OutputJournalManager) verifyAbsentVersions(ctx context.Context, identity OutputExecutionIdentity, live map[string]OutputVersionObservation) error {
	records, err := manager.ledger.ListVersions(ctx, identity)
	if err != nil {
		return err
	}
	for _, record := range records {
		key := outputVersionKey(record.Observation.Identity)
		_, exists := live[key]
		if record.State == OutputVersionRetained {
			if !exists {
				return ErrOutputCleanupPending
			}
			continue
		}
		if exists {
			continue
		}
		if record.State == OutputVersionVerifiedDeleted {
			continue
		}
		now := manager.now().UTC()
		next := record
		next.State, next.Revision, next.UpdatedAt, next.VerifiedDeletedAt =
			OutputVersionVerifiedDeleted, record.Revision+1, now, now
		if _, err = manager.ledger.CompareAndSwapVersion(ctx, next, record.Revision); err != nil {
			return err
		}
	}
	return nil
}

func (manager *OutputJournalManager) markJournalsCleaning(ctx context.Context, journals []OutputJournalRecord) error {
	for _, record := range journals {
		if record.Validate() != nil {
			return ErrConflict
		}
		now := manager.now().UTC()
		next := record
		next.State, next.InventoryAttempts = OutputJournalCleaning, record.InventoryAttempts+1
		next.VerifiedCleanAt = time.Time{}
		next.Revision, next.UpdatedAt = record.Revision+1, now
		if _, err := manager.ledger.CompareAndSwapJournal(ctx, next, record.Revision); err != nil {
			return err
		}
	}
	return nil
}

func (manager *OutputJournalManager) markJournalsVerified(ctx context.Context, journals []OutputJournalRecord) error {
	for _, record := range journals {
		if record.State == OutputJournalVerifiedClean {
			continue
		}
		if record.State != OutputJournalCleaning {
			return ErrConflict
		}
		now := manager.now().UTC()
		next := record
		next.State, next.VerifiedCleanAt = OutputJournalVerifiedClean, now
		next.Revision, next.UpdatedAt = record.Revision+1, now
		if _, err := manager.ledger.CompareAndSwapJournal(ctx, next, record.Revision); err != nil {
			return err
		}
	}
	return nil
}

var _ ControllerOutputJournal = (*OutputJournalManager)(nil)

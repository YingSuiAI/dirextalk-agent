package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// NewCoreExtensionLifecycleHandler returns the production task handler for
// confirmation-bound install/update/uninstall tasks. The worker supplies the
// already-claimed lease; this handler consumes the exact confirmation and
// lets CompleteLifecycle perform the single fenced terminal transition.
func NewCoreExtensionLifecycleHandler(s *CoreExtensionStore) coreruntime.TaskHandler {
	return NewCoreExtensionLifecycleHandlerWithPromoter(s, nil)
}

// NewCoreExtensionLifecycleHandlerWithPromoter adds the post-confirmation
// runner publication boundary. The promoter is deliberately outside the SQL
// store so staging and runner publication remain separate idempotent effects.
func NewCoreExtensionLifecycleHandlerWithPromoter(s *CoreExtensionStore, promoter coreextension.LifecycleArtifactPromoter) coreruntime.TaskHandler {
	return func(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
		if s == nil || s.store == nil || task.Spec.Kind != coretask.TaskKindExtension || task.Spec.Payload.Extension == nil || task.Status != coretask.StatusRunning || task.Lease == nil {
			return coreruntime.ManagedOutcome{Err: coretask.ErrInvalid}
		}
		p := task.Spec.Payload.Extension
		if p.Operation != coretask.ExtensionOperationInstall && p.Operation != coretask.ExtensionOperationUpdate && p.Operation != coretask.ExtensionOperationUninstall || !coretask.ValidUUID(p.ConfirmationID) {
			return coreruntime.ManagedOutcome{Err: coretask.ErrConflict}
		}
		confirmationStore := NewCoreConfirmationStore(s.store)
		confirmation, err := confirmationStore.Get(ctx, p.ConfirmationID)
		if err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		binding, err := confirmationStore.ReadTargetBinding(ctx, p.ConfirmationID)
		if err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		consumeKey := uuid.NewSHA1(uuid.NameSpaceURL, []byte("extension-consume:"+task.ID+":"+fmt.Sprint(task.Attempt)+":"+fmt.Sprint(task.LeaseEpoch))).String()
		if confirmation.State == coreconfirmation.StateConfirmed {
			_, err = confirmationStore.Consume(ctx, coreconfirmation.ConsumeCommand{
				ConfirmationID: p.ConfirmationID, IdempotencyKey: consumeKey, RequestDigest: coreconfirmation.Digest(digestPG(struct{ Task, Binding any }{task.ID, binding}, "consume")), TaskID: task.ID,
				Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch, ExpectedRevision: confirmation.Revision, ExpectedTaskRevision: int64(task.Revision), Binding: binding, At: time.Now().UTC(),
			})
			if err != nil {
				if errors.Is(err, coreconfirmation.ErrExpired) || errors.Is(err, coreconfirmation.ErrStale) {
					return coreruntime.ManagedOutcome{Err: err, TerminalOwned: true}
				}
				return coreruntime.ManagedOutcome{Err: err}
			}
		} else if confirmation.State != coreconfirmation.StateConsumed {
			return coreruntime.ManagedOutcome{Err: coretask.ErrConflict}
		} else if err = reacquireLifecycleReservation(ctx, s.store, p.ConfirmationID, task); err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		installation, err := s.Get(ctx, p.InstallationID)
		if err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		var version coreextension.VersionRecord
		versionID := installation.ProposedVersionID
		if p.Operation == coretask.ExtensionOperationUninstall {
			versionID = installation.ActiveVersionID
		}
		foundVersion := false
		for _, candidate := range installation.Versions {
			if candidate.VersionID == versionID {
				version = candidate
				foundVersion = true
				break
			}
		}
		var retiringNodeVersions []coreextension.VersionRecord
		if installation.Transport == coreextension.TransportStdioNode && (p.Operation == coretask.ExtensionOperationUpdate || p.Operation == coretask.ExtensionOperationUninstall) {
			retiringNodeVersions = publishedNodeVersionsForRemoval(installation, installation.ProposedVersionID, p.Operation == coretask.ExtensionOperationUninstall)
			for _, retired := range retiringNodeVersions {
				if s.hasPinnedVersion(ctx, installation.ID, retired.VersionID, retired.ArtifactDigest) {
					return completeLifecycleFailure(ctx, s, p, task, coreextension.ErrConflict)
				}
			}
		}
		if promoter != nil {
			var promoteErr error
			if p.Operation == coretask.ExtensionOperationUninstall && installation.Transport == coreextension.TransportStdioNode {
				// Node active references remain available until CompleteLifecycle
				// atomically commits the removed projection and durable cleanup intents.
			} else if p.Operation == coretask.ExtensionOperationUninstall {
				if !foundVersion || len(version.ArtifactDigest) != 64 {
					return completeLifecycleFailure(ctx, s, p, task, coreextension.ErrConflict)
				}
				if s.hasPinnedVersion(ctx, installation.ID, version.VersionID, version.ArtifactDigest) {
					return completeLifecycleFailure(ctx, s, p, task, coreextension.ErrConflict)
				}
				promoteErr = promoter.Remove(ctx, version)
			} else {
				if !foundVersion || len(version.ArtifactDigest) != 64 {
					return completeLifecycleFailure(ctx, s, p, task, coreextension.ErrConflict)
				}
				promoteErr = promoter.Promote(ctx, version)
			}
			if promoteErr != nil {
				if errors.Is(promoteErr, coreextension.ErrInvalid) || errors.Is(promoteErr, coreextension.ErrConflict) {
					return completeLifecycleFailure(ctx, s, p, task, promoteErr)
				}
				return coreruntime.ManagedOutcome{Err: errors.Join(promoteErr, context.Canceled)}
			}
			if version.NodeArtifact == nil && len(version.ArtifactDigest) == 64 && version.ArtifactPath != "" {
				cleaner := CoreExtensionArtifactCleaner{Store: s.store}
				if err := cleaner.Enqueue(ctx, version, installation.ID, "promotion_success"); err != nil {
					return coreruntime.ManagedOutcome{Err: errors.Join(err, context.Canceled)}
				}
			}
		}
		outcome := digestPG(struct{ Task, Operation string }{task.ID, string(p.Operation)}, "lifecycle-outcome")
		_, err = s.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: p.InstallationID, Operation: string(p.Operation), ConfirmationID: p.ConfirmationID, TaskID: task.ID, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch, AcquiredTaskRevision: int64(task.Revision), TerminalAttempt: task.Attempt, TerminalLeaseEpoch: task.LeaseEpoch, TerminalTaskRevision: int64(task.Revision) + 1, ExpectedRevision: int64(p.ExpectedRevision), OutcomeDigest: outcome, Success: true})
		if err != nil {
			if promoter != nil && p.Operation != coretask.ExtensionOperationUninstall && (errors.Is(err, coreextension.ErrInstallationLimit) || errors.Is(err, coreextension.ErrNodeStorageQuota)) {
				if installation.Transport != coreextension.TransportStdioNode {
					if removeErr := promoter.Remove(ctx, version); removeErr != nil {
						return coreruntime.ManagedOutcome{Err: errors.Join(err, removeErr, context.Canceled)}
					}
					return completeLifecycleFailure(ctx, s, p, task, err)
				}
				failure := completePromotedLifecycleFailure(ctx, s, p, task, err)
				if failure.TerminalOwned && installation.Transport == coreextension.TransportStdioNode {
					cleaner := CoreExtensionArtifactCleaner{Store: s.store, lifecyclePromoter: promoter}
					// The failure terminal transition and exact cleanup authority are
					// already durable. Cleanup failure remains restart-retryable and
					// must not rewrite the terminal task.
					_, _ = cleaner.SweepNode(ctx, 128)
				}
				return failure
			}
			return coreruntime.ManagedOutcome{Err: errors.Join(err, context.Canceled)}
		}
		if promoter != nil && installation.Transport == coreextension.TransportStdioNode {
			cleaner := CoreExtensionArtifactCleaner{Store: s.store, lifecyclePromoter: promoter}
			// Completion is already durable. A cleanup error remains pending for
			// the background cleaner and must not rewrite the terminal task.
			_, _ = cleaner.SweepNode(ctx, 128)
		}
		return coreruntime.ManagedOutcome{Result: coretask.Result{Summary: "extension lifecycle completed"}, TerminalOwned: true}
	}
}

func completeLifecycleFailure(ctx context.Context, s *CoreExtensionStore, p *coretask.ExtensionTaskPayload, task coretask.Task, cause error) coreruntime.ManagedOutcome {
	return completeLifecycleFailureWithPromotion(ctx, s, p, task, cause, false)
}

func completePromotedLifecycleFailure(ctx context.Context, s *CoreExtensionStore, p *coretask.ExtensionTaskPayload, task coretask.Task, cause error) coreruntime.ManagedOutcome {
	return completeLifecycleFailureWithPromotion(ctx, s, p, task, cause, true)
}

func completeLifecycleFailureWithPromotion(ctx context.Context, s *CoreExtensionStore, p *coretask.ExtensionTaskPayload, task coretask.Task, cause error, artifactPromoted bool) coreruntime.ManagedOutcome {
	outcome := digestPG(struct{ Task, Operation string }{task.ID, string(p.Operation)}, "lifecycle-failed")
	failureCode, failureSummary := coreextension.LifecycleFailureDetails(cause)
	_, err := s.completeLifecycle(ctx, coreextension.Completion{InstallationID: p.InstallationID, Operation: string(p.Operation), ConfirmationID: p.ConfirmationID, TaskID: task.ID, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch, AcquiredTaskRevision: int64(task.Revision), TerminalAttempt: task.Attempt, TerminalLeaseEpoch: task.LeaseEpoch, TerminalTaskRevision: int64(task.Revision) + 1, ExpectedRevision: int64(p.ExpectedRevision), OutcomeDigest: outcome, Success: false, FailureCode: failureCode, FailureSummary: failureSummary}, artifactPromoted)
	if err != nil {
		return coreruntime.ManagedOutcome{Err: errors.Join(cause, err, context.Canceled)}
	}
	return coreruntime.ManagedOutcome{Err: cause, TerminalOwned: true}
}

func publishedNodeVersionsForRemoval(installation coreextension.Installation, proposedVersionID string, uninstall bool) []coreextension.VersionRecord {
	var ordinary []coreextension.VersionRecord
	var active *coreextension.VersionRecord
	for index := range installation.Versions {
		version := installation.Versions[index]
		if version.NodeArtifact == nil || version.PublishedAt.IsZero() || !uninstall && version.VersionID == proposedVersionID {
			continue
		}
		if version.VersionID == installation.ActiveVersionID {
			copy := version
			active = &copy
		} else {
			ordinary = append(ordinary, version)
		}
	}
	if active != nil {
		ordinary = append(ordinary, *active)
	}
	return ordinary
}

// reacquireLifecycleReservation repairs the lease-bound reservation after a
// worker reclaim. The confirmation remains consumed; only the current fenced
// task attempt/epoch may own the active reservation.
func reacquireLifecycleReservation(ctx context.Context, store *Store, confirmationID string, task coretask.Task) error {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var state string
	var released bool
	if err = tx.QueryRow(ctx, `SELECT state,consumed_released FROM core_confirmations WHERE confirmation_id=$1 FOR UPDATE`, confirmationID).Scan(&state, &released); err != nil {
		return coreconfirmation.ErrNotFound
	}
	if state != string(coreconfirmation.StateConsumed) || released {
		return coretask.ErrConflict
	}
	var taskStatus, holder string
	var attempt, epoch, revision int64
	var expires time.Time
	if err = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,revision,lease_holder,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, task.ID).Scan(&taskStatus, &attempt, &epoch, &revision, &holder, &expires); err != nil {
		return coretask.ErrNotFound
	}
	if taskStatus != string(coretask.StatusRunning) || uint32(attempt) != task.Attempt || uint64(epoch) != task.LeaseEpoch || uint64(revision) != task.Revision || holder == "" || !expires.After(time.Now().UTC()) || task.Lease == nil || holder != task.Lease.Holder {
		return coretask.ErrLeaseConflict
	}
	var taskID string
	var active bool
	var priorAttempt int
	var priorEpoch, priorRevision int64
	if err = tx.QueryRow(ctx, `SELECT task_id::text,acquired_attempt,acquired_lease_epoch,task_revision,active FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, confirmationID).Scan(&taskID, &priorAttempt, &priorEpoch, &priorRevision, &active); err != nil {
		return coretask.ErrConflict
	}
	if taskID != task.ID {
		return coretask.ErrConflict
	}
	if priorEpoch > int64(task.LeaseEpoch) || (priorEpoch == int64(task.LeaseEpoch) && priorAttempt > int(task.Attempt)) || (priorEpoch == int64(task.LeaseEpoch) && priorAttempt == int(task.Attempt) && priorRevision > int64(task.Revision)) {
		return coretask.ErrLeaseConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET acquired_attempt=$2,acquired_lease_epoch=$3,task_revision=$4,active=true WHERE confirmation_id=$1`, confirmationID, task.Attempt, task.LeaseEpoch, task.Revision); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

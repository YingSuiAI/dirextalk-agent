package postgres

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/jackc/pgx/v5"
)

// cloudWorkerOutputHistoryEligibility is one static, fail-closed contract used
// both before claiming a batch and after all dependent authority rows have
// been locked. Keep aliases e/c and cutoff parameter $1 stable at both sites.
const cloudWorkerOutputHistoryEligibility = `e.state IN ('succeeded','failed','canceled','rejected','expired')
		  AND e.needs_reconcile=false
		  AND c.delivery_state='delivered' AND c.delivered_at <= $1
		  AND EXISTS (
			SELECT 1 FROM core_cloud_worker_output_journals j
			WHERE j.execution_id=e.execution_id
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM core_cloud_worker_output_journals j
			WHERE j.execution_id=e.execution_id
			  AND (j.state <> 'verified_clean' OR j.verified_clean_at IS NULL OR j.verified_clean_at > $1)
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM core_cloud_worker_output_versions v
			WHERE v.execution_id=e.execution_id AND NOT (
				(v.state='verified_deleted' AND v.verified_deleted_at IS NOT NULL AND v.verified_deleted_at <= $1)
				OR
				(v.state='retained' AND EXISTS (
					SELECT 1 FROM core_cloud_worker_artifacts a
					WHERE a.execution_id=e.execution_id
					  AND a.s3_bucket=v.bucket AND a.s3_key=v.object_key AND a.s3_version_id=v.version_id
					  AND a.retention_state='verified_deleted'
					  AND a.retention_verified_deleted_at IS NOT NULL
					  AND a.retention_verified_deleted_at <= $1
				))
			)
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM core_cloud_worker_artifacts a
			WHERE a.execution_id=e.execution_id
			  AND (a.retention_state <> 'verified_deleted'
			       OR a.retention_verified_deleted_at IS NULL
			       OR a.retention_verified_deleted_at > $1)
		  )
		  AND EXISTS (
			SELECT 1 FROM core_cloud_worker_aws_ledger l
			WHERE l.execution_id=e.execution_id
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM core_cloud_worker_aws_ledger l
			WHERE l.execution_id=e.execution_id AND l.state <> 'verified_destroyed'
		  )
		  AND EXISTS (
			SELECT 1 FROM core_cloud_worker_input_staging i
			WHERE i.execution_id=e.execution_id
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM core_cloud_worker_input_staging i
			WHERE i.execution_id=e.execution_id AND i.state <> 'verified_destroyed'
		  )
		  AND EXISTS (
			SELECT 1 FROM core_cloud_worker_resources r
			WHERE r.execution_id=e.execution_id
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM core_cloud_worker_resources r
			WHERE r.execution_id=e.execution_id AND r.state <> 'verified_destroyed'
		  )`

const claimCloudWorkerOutputHistorySQL = `SELECT e.execution_id::text
		FROM core_cloud_worker_executions e
		JOIN core_cloud_worker_completion_outbox c ON c.execution_id=e.execution_id
		WHERE ` + cloudWorkerOutputHistoryEligibility + `
		ORDER BY c.delivered_at,e.execution_id
		FOR UPDATE OF e SKIP LOCKED LIMIT $2`

const revalidateCloudWorkerOutputHistorySQL = `SELECT e.execution_id::text
		FROM core_cloud_worker_executions e
		JOIN core_cloud_worker_completion_outbox c ON c.execution_id=e.execution_id
		WHERE e.execution_id=ANY($2::uuid[])
		  AND ` + cloudWorkerOutputHistoryEligibility + `
		ORDER BY e.execution_id`

// PruneOutputHistory removes only database audit rows after every independent
// consumer and cleanup authority has crossed the requested watermark. It does
// not delete execution, completion-outbox, or artifact authority records.
func (s *CloudWorkerStore) PruneOutputHistory(ctx context.Context, request cloudworker.OutputHistoryPruneRequest) (cloudworker.OutputHistoryPruneReport, error) {
	if s == nil || s.store == nil || ctx == nil || request.Validate() != nil {
		return cloudworker.OutputHistoryPruneReport{}, cloudworker.ErrInvalid
	}
	// READ COMMITTED is paired with execution/dependency row locks and a final
	// eligibility revalidation. SERIALIZABLE turns ordinary SKIP LOCKED peers
	// into predicate serialization failures instead of disjoint batch owners.
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudworker.OutputHistoryPruneReport{}, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, claimCloudWorkerOutputHistorySQL, request.Before, request.Limit)
	if err != nil {
		return cloudworker.OutputHistoryPruneReport{}, err
	}
	var executionIDs []string
	for rows.Next() {
		var executionID string
		if err = rows.Scan(&executionID); err != nil {
			rows.Close()
			return cloudworker.OutputHistoryPruneReport{}, err
		}
		executionIDs = append(executionIDs, executionID)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return cloudworker.OutputHistoryPruneReport{}, err
	}
	rows.Close()
	if err = lockCloudWorkerOutputHistoryDependencies(ctx, tx, executionIDs); err != nil {
		return cloudworker.OutputHistoryPruneReport{}, err
	}
	executionIDs, err = revalidateCloudWorkerOutputHistoryCandidates(ctx, tx, executionIDs, request.Before)
	if err != nil {
		return cloudworker.OutputHistoryPruneReport{}, err
	}

	report := cloudworker.OutputHistoryPruneReport{Executions: len(executionIDs)}
	for _, executionID := range executionIDs {
		versionTag, deleteErr := tx.Exec(ctx, `DELETE FROM core_cloud_worker_output_versions WHERE execution_id=$1`, executionID)
		if deleteErr != nil {
			return cloudworker.OutputHistoryPruneReport{}, deleteErr
		}
		journalTag, deleteErr := tx.Exec(ctx, `DELETE FROM core_cloud_worker_output_journals WHERE execution_id=$1`, executionID)
		if deleteErr != nil {
			return cloudworker.OutputHistoryPruneReport{}, deleteErr
		}
		report.Versions += int(versionTag.RowsAffected())
		report.Journals += int(journalTag.RowsAffected())
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.OutputHistoryPruneReport{}, err
	}
	return report, nil
}

// The initial candidate query locks the terminal execution with SKIP LOCKED.
// These dependent row locks then close the gap between eligibility readback
// and deletion. A concurrent stale writer may finish first, but the mandatory
// revalidation below will observe its state and retain all history.
func lockCloudWorkerOutputHistoryDependencies(ctx context.Context, tx pgx.Tx, executionIDs []string) error {
	if len(executionIDs) == 0 {
		return nil
	}
	queries := []string{
		`SELECT event_id::text FROM core_cloud_worker_completion_outbox WHERE execution_id=ANY($1::uuid[]) ORDER BY execution_id,event_id FOR UPDATE`,
		`SELECT identity_key FROM core_cloud_worker_output_journals WHERE execution_id=ANY($1::uuid[]) ORDER BY execution_id,identity_key FOR UPDATE`,
		`SELECT identity_key FROM core_cloud_worker_output_versions WHERE execution_id=ANY($1::uuid[]) ORDER BY execution_id,identity_key FOR UPDATE`,
		`SELECT artifact_id::text FROM core_cloud_worker_artifacts WHERE execution_id=ANY($1::uuid[]) ORDER BY execution_id,artifact_id FOR UPDATE`,
		`SELECT identity_key FROM core_cloud_worker_aws_ledger WHERE execution_id=ANY($1::uuid[]) ORDER BY execution_id,identity_key FOR UPDATE`,
		`SELECT identity_key FROM core_cloud_worker_input_staging WHERE execution_id=ANY($1::uuid[]) ORDER BY execution_id,identity_key FOR UPDATE`,
		`SELECT resource_id::text FROM core_cloud_worker_resources WHERE execution_id=ANY($1::uuid[]) ORDER BY execution_id,resource_id FOR UPDATE`,
	}
	for _, query := range queries {
		rows, err := tx.Query(ctx, query, executionIDs)
		if err != nil {
			return err
		}
		for rows.Next() {
			var ignored string
			if err = rows.Scan(&ignored); err != nil {
				rows.Close()
				return err
			}
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

func revalidateCloudWorkerOutputHistoryCandidates(ctx context.Context, tx pgx.Tx, executionIDs []string, before time.Time) ([]string, error) {
	if len(executionIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, revalidateCloudWorkerOutputHistorySQL, before, executionIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]string, 0, len(executionIDs))
	for rows.Next() {
		var executionID string
		if err = rows.Scan(&executionID); err != nil {
			return nil, err
		}
		result = append(result, executionID)
	}
	return result, rows.Err()
}

var _ cloudworker.OutputHistoryStore = (*CloudWorkerStore)(nil)

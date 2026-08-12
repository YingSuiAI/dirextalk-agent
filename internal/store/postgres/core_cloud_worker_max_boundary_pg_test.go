package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/jackc/pgx/v5"
)

func seedPGTerminalCloudWorkerExecutions(t *testing.T, base *pgCloudWorkerHarness, count int, deliver bool) []string {
	t.Helper()
	executionIDs := make([]string, 0, count)
	for index := 0; index < count; index++ {
		harness := base
		if index > 0 {
			harness = newSharedPGCloudWorkerHarness(t, base)
		}
		fixture := newPGOutputHistoryFixtureForHarness(t, harness)
		fixture.terminalize(t, deliver)
		executionIDs = append(executionIDs, fixture.plan.ExecutionID)
	}
	return executionIDs
}

func TestCloudWorkerPostgresOutputHistoryMaximumBatchDrainsMultipleBatches(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	bulkCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h.ctx = bulkCtx

	const totalExecutions = 2*128 + 1
	executionIDs := seedPGTerminalCloudWorkerExecutions(t, h, totalExecutions, true)
	before := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	if _, err := h.cloud.PruneOutputHistory(h.ctx, cloudworker.OutputHistoryPruneRequest{Before: before, Limit: 129}); !errors.Is(err, cloudworker.ErrInvalid) {
		t.Fatalf("Limit=129 err=%v, want invalid", err)
	}

	for index, want := range []int{128, 128, 1, 0, 0} {
		report, err := h.cloud.PruneOutputHistory(h.ctx, cloudworker.OutputHistoryPruneRequest{Before: before, Limit: 128})
		if err != nil || report.Executions != want || report.Journals != want || report.Versions != 0 {
			t.Fatalf("batch %d report=%+v err=%v want=%d", index+1, report, err, want)
		}
	}
	var journals, awsRows, inputRows, resourceRows int
	if err := h.store.pool.QueryRow(h.ctx, `SELECT
		(SELECT count(*) FROM core_cloud_worker_output_journals WHERE execution_id=ANY($1::uuid[])),
		(SELECT count(*) FROM core_cloud_worker_aws_ledger WHERE execution_id=ANY($1::uuid[])),
		(SELECT count(*) FROM core_cloud_worker_input_staging WHERE execution_id=ANY($1::uuid[])),
		(SELECT count(*) FROM core_cloud_worker_resources WHERE execution_id=ANY($1::uuid[]))`, executionIDs).Scan(
		&journals, &awsRows, &inputRows, &resourceRows); err != nil {
		t.Fatal(err)
	}
	if journals != 0 || awsRows != totalExecutions || inputRows != totalExecutions || resourceRows != totalExecutions {
		t.Fatalf("post-drain journals/aws/input/resources=%d/%d/%d/%d", journals, awsRows, inputRows, resourceRows)
	}
}

func TestCloudWorkerPostgresAuthorityEventsMaximumPagePreservesContinuityAndTruncation(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)

	newest := uint64(cloudworker.MaxRetainedRunEvents + 201)
	if _, err := h.store.pool.Exec(h.ctx, `INSERT INTO core_cloud_worker_events(
		execution_id,sequence,event_id,owner_id,kind,state,revision,payload_digest,payload_json,created_at)
		SELECT $1::uuid,sequence,('00000000-0000-4000-8000-' || lpad(sequence::text,12,'0'))::uuid,
			$2::text,'maximum_page_fixture','waiting_user',1,repeat('a',64),
			jsonb_build_object('owner_id',$2::text,'account_generation',$3::bigint,'run_id',$1::uuid::text,
				'execution_id',$1::uuid::text,'sequence',sequence,
				'event_id',('00000000-0000-4000-8000-' || lpad(sequence::text,12,'0')),
				'type','maximum_page_fixture','status','waiting_user','revision',1,
				'payload_digest',repeat('a',64),'at',$4::timestamptz),$4::timestamptz
		FROM generate_series(2,$5::bigint) AS sequence`, offer.Execution.ExecutionID, h.owner, h.generation, h.now, newest); err != nil {
		t.Fatal(err)
	}
	tx, err := h.store.pool.BeginTx(h.ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(h.ctx)
	if _, err = tx.Exec(h.ctx, `SELECT 1 FROM core_cloud_worker_executions WHERE execution_id=$1 FOR UPDATE`, offer.Execution.ExecutionID); err != nil {
		t.Fatal(err)
	}
	if err = pruneCloudWorkerEventsTx(h.ctx, tx, offer.Execution.ExecutionID, newest); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(h.ctx); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err = h.cloud.EventsForAuthority(h.ctx, h.owner, h.generation, offer.Execution.ExecutionID, 0, 201); !errors.Is(err, cloudworker.ErrInvalid) {
		t.Fatalf("event limit=201 err=%v, want invalid", err)
	}
	watermark := newest - cloudworker.MaxRetainedRunEvents
	first, next, truncated, err := h.cloud.EventsForAuthority(h.ctx, h.owner, h.generation, offer.Execution.ExecutionID, 0, 200)
	if err != nil || !truncated || len(first) != 200 || first[0].Sequence != watermark+1 || first[199].Sequence != watermark+200 || next != watermark+200 {
		t.Fatalf("first maximum page len=%d first/last/next=%d/%d/%d watermark=%d truncated=%v err=%v",
			len(first), firstSequence(first), lastSequence(first), next, watermark, truncated, err)
	}
	second, secondNext, secondTruncated, err := h.cloud.EventsForAuthority(h.ctx, h.owner, h.generation, offer.Execution.ExecutionID, next, 200)
	if err != nil || secondTruncated || len(second) != 200 || second[0].Sequence != next+1 || second[199].Sequence != next+200 || secondNext != next+200 {
		t.Fatalf("second maximum page len=%d first/last/next=%d/%d/%d truncated=%v err=%v",
			len(second), firstSequence(second), lastSequence(second), secondNext, secondTruncated, err)
	}
	for index, event := range append(first, second...) {
		if event.Sequence != watermark+1+uint64(index) {
			t.Fatalf("combined event %d sequence=%d want=%d", index, event.Sequence, watermark+1+uint64(index))
		}
	}
}

func TestCloudWorkerPostgresCompletionOutboxMaximumBatchClaimsWithoutDuplicates(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	bulkCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h.ctx = bulkCtx

	const totalOutboxes = 201
	seedPGTerminalCloudWorkerExecutions(t, h, totalOutboxes, false)
	if _, err := h.cloud.ListPendingCompletionOutbox(h.ctx, 201); !errors.Is(err, cloudworker.ErrInvalid) {
		t.Fatalf("completion limit=201 err=%v, want invalid", err)
	}
	seen := make(map[string]struct{}, totalOutboxes)
	for index, want := range []int{200, 1, 0} {
		items, err := h.cloud.ListPendingCompletionOutbox(h.ctx, 200)
		if err != nil || len(items) != want {
			t.Fatalf("completion batch %d len=%d err=%v want=%d", index+1, len(items), err, want)
		}
		for _, item := range items {
			if _, duplicate := seen[item.EventID]; duplicate {
				t.Fatalf("completion event %s claimed twice", item.EventID)
			}
			seen[item.EventID] = struct{}{}
		}
	}
	if len(seen) != totalOutboxes {
		t.Fatalf("unique completion claims=%d want=%d", len(seen), totalOutboxes)
	}
}

func firstSequence(events []cloudworker.Event) uint64 {
	if len(events) == 0 {
		return 0
	}
	return events[0].Sequence
}

func lastSequence(events []cloudworker.Event) uint64 {
	if len(events) == 0 {
		return 0
	}
	return events[len(events)-1].Sequence
}

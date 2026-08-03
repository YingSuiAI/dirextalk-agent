package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestGitHubSourceSnapshotPostgresIsImmutableAndRestartable(
	t *testing.T,
) {
	pool, store, instanceID := newTeamInputTestStore(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		45*time.Second,
	)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "github-source-integration",
		CredentialID: uuid.NewString(),
	}
	ownerID := "owner-github-source"
	connectionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_connections
		    (connection_id, agent_instance_id, owner_id, account_id, region,
		     control_role_arn, foundation_stack_id, credential_generation,
		     status, revision)
		VALUES ($1,$2,$3,'123456789012','us-east-1',
		        'arn:aws:iam::123456789012:role/test-control',
		        'test-foundation-stack',1,'active',1)`,
		connectionID,
		instanceID,
		ownerID,
	); err != nil {
		t.Fatal(err)
	}
	goal := "Use one immutable GitHub source snapshot."
	createdTask, err := store.Create(
		ctx,
		scope,
		task.CreateCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Goal:           goal,
			Retention:      task.RetentionEphemeralAutoDestroy,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	offer := teamOfferSnapshotFixture(
		t,
		connectionID,
		now.Add(-time.Minute),
	)
	if _, err := store.CreateTeamOfferSnapshot(
		ctx,
		scope,
		postgres.CreateTeamOfferSnapshotCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Snapshot:       offer,
		},
	); err != nil {
		t.Fatal(err)
	}
	plan := teamPlanFixture(
		t,
		offer,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	plan = bindTeamPlanGitHubInput(t, plan, createdTask.TaskID)
	if _, err := store.CreateTeamPlan(
		ctx,
		scope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			TaskID:         createdTask.TaskID,
			Plan:           plan,
		},
	); err != nil {
		t.Fatal(err)
	}
	bindingDigest, err := plan.TaskInput.Digest()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := githubsource.SnapshotV1{
		SchemaVersion:      githubsource.SnapshotSchemaV1,
		InputID:            plan.TaskInput.InputID,
		InputDigest:        plan.TaskInput.InputDigest,
		InputBindingDigest: bindingDigest,
		SourceDigest:       plan.TaskInput.SourceDigest,
		Repository:         plan.TaskInput.Repository,
		WorkspaceDigest:    "sha256:" + strings.Repeat("a", 64),
		SizeBytes:          8192,
		FileCount:          12,
	}
	artifact, err := githubsource.NewArtifactV1(
		snapshot,
		connectionID,
		"dirextalk-artifacts-123456789012-us-east-1",
		"source-version-one",
	)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := githubsource.NewFactV1(snapshot, artifact)
	if err != nil {
		t.Fatal(err)
	}
	key := githubsource.LookupKey{
		InputID:      snapshot.InputID,
		InputDigest:  snapshot.InputDigest,
		ConnectionID: connectionID,
	}
	if stored, found, err := store.FindGitHubSourceSnapshot(
		ctx,
		key,
	); err != nil || found || stored.Fact.SnapshotID != "" {
		t.Fatalf(
			"fresh lookup=%#v found=%v error=%v",
			stored,
			found,
			err,
		)
	}
	first, err := store.PersistGitHubSourceSnapshot(ctx, fact)
	if err != nil ||
		first.Validate() != nil ||
		first.Fact != fact {
		t.Fatalf("persisted snapshot=%#v error=%v", first, err)
	}
	replayed, err := store.PersistGitHubSourceSnapshot(ctx, fact)
	if err != nil || replayed != first {
		t.Fatalf("same-fact replay=%#v error=%v", replayed, err)
	}
	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	readBack, found, err := restarted.FindGitHubSourceSnapshot(
		ctx,
		key,
	)
	if err != nil || !found || readBack != first {
		t.Fatalf(
			"restart lookup=%#v found=%v error=%v",
			readBack,
			found,
			err,
		)
	}
	conflictingArtifact, err := githubsource.NewArtifactV1(
		snapshot,
		connectionID,
		artifact.Bucket,
		"source-version-two",
	)
	if err != nil {
		t.Fatal(err)
	}
	conflictingFact, err := githubsource.NewFactV1(
		snapshot,
		conflictingArtifact,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.PersistGitHubSourceSnapshot(
		ctx,
		conflictingFact,
	); !errors.Is(err, githubsource.ErrIntegrity) {
		t.Fatalf("source version substitution error=%v", err)
	}
	foreign, err := postgres.New(pool, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := foreign.FindGitHubSourceSnapshot(
		ctx,
		key,
	); err != nil || found {
		t.Fatalf("foreign Agent lookup found=%v error=%v", found, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_github_source_snapshots
		SET artifact_version_id='tampered'
		WHERE snapshot_id=$1`,
		fact.SnapshotID,
	); err == nil ||
		!strings.Contains(
			err.Error(),
			"team_github_source_snapshots is immutable",
		) {
		t.Fatalf("immutable source mutation error=%v", err)
	}
	var forbiddenColumnCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema=current_schema()
		  AND table_name='team_github_source_snapshots'
		  AND column_name IN (
		      'installation_token',
		      'private_key',
		      'model_api_key',
		      'credential_payload'
		  )`,
	).Scan(&forbiddenColumnCount); err != nil {
		t.Fatal(err)
	}
	if forbiddenColumnCount != 0 {
		t.Fatalf(
			"source snapshot table contains %d credential columns",
			forbiddenColumnCount,
		)
	}
}

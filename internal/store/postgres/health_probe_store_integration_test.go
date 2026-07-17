package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const healthCapabilityURLCanary = "https://capability-canary.example.com/private-health"

func TestHealthProbePostgresAtomicEvidenceEventsRestartAndRevisionFence(t *testing.T) {
	pool, baseStore, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	taskID, stepID := createWorkerTask(t, baseStore)
	workerStore, err := baseStore.NewWorkerStore(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	workerService, err := worker.NewService(workerStore, bytes.Repeat([]byte{0x72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.NewString()
	prefix := "s3://health-probe-fixture/deployments/" + deploymentID + "/"
	created, enrollment, err := workerService.CreateDeployment(ctx, worker.ControlMutation{
		ClientID: "health-probe-test", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
	}, worker.CreateDeploymentRequest{
		DeploymentID: deploymentID, OwnerID: "owner-health-postgres", TaskID: taskID, StepID: stepID,
		ControlPlaneEndpoint: "grpcs://agent.example.internal:9443", EnrollmentTTL: 10 * time.Minute,
		RecipeBundle:     worker.BundleRef{S3Ref: prefix + "recipe.cbor", SHA256: sha256.Sum256([]byte("health-recipe"))},
		ExecutionBundle:  worker.BundleRef{S3Ref: prefix + "execution.json", SHA256: sha256.Sum256([]byte("health-execution"))},
		ExecutionTimeout: 10 * time.Minute,
		Access: worker.AccessScope{
			ArtifactPrefix: prefix + "artifacts/", CheckpointPrefix: prefix + "checkpoints/",
			EvidencePrefix: prefix + "evidence/", LogPrefix: "cloudwatch://health-probe-fixture/" + deploymentID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment.Destroy()
	seedWorkerIdentityBinding(t, pool, instanceID, created.OwnerID, taskID, deploymentID, "i-0000feed", "123456789019")

	var planHash, recipeDigest string
	if err := pool.QueryRow(ctx, `
		SELECT plan.plan_hash, 'sha256:' || encode(deployment.recipe_bundle_sha256, 'hex')
		FROM worker_deployments deployment
		JOIN cloud_launch_operations launch USING (deployment_id)
		JOIN cloud_plans plan USING (plan_id)
		WHERE deployment.deployment_id=$1`, deploymentID,
	).Scan(&planHash, &recipeDigest); err != nil {
		t.Fatal(err)
	}
	serviceID := uuid.NewString()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `
		INSERT INTO managed_services (service_id,deployment_id,agent_instance_id,owner_id,contract_json,state,revision,created_at,updated_at)
		VALUES ($1,$2,$3,$4,'{}','active',1,$5,$5)`, serviceID, deploymentID, instanceID, created.OwnerID, now); err != nil {
		t.Fatal(err)
	}

	suite := postgresHealthSuite(t, deploymentID, planHash, recipeDigest)
	probeStore, err := baseStore.NewHealthProbeStore()
	if err != nil {
		t.Fatal(err)
	}
	transport := &barrierHealthTransport{release: make(chan struct{}), digest: postgresHealthDigest("response")}
	engine, err := healthprobe.NewEngine(transport)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := resource.NewProbeService(engine, probeStore)
	if err != nil {
		t.Fatal(err)
	}
	configured, err := lifecycle.Configure(ctx, resource.ProbeConfigureRequest{
		OwnerID: created.OwnerID, Suite: suite, Interval: time.Minute,
	})
	if err != nil || configured.Revision != 1 || configured.Status != healthprobe.AggregatePending {
		t.Fatalf("configured=%+v err=%v", configured, err)
	}

	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, runErr := lifecycle.RunStored(ctx, deploymentID)
			results <- runErr
		}()
	}
	transport.waitForFirstCalls(t, 2)
	close(transport.release)
	firstErr, secondErr := <-results, <-results
	if !((firstErr == nil && errors.Is(secondErr, resource.ErrRevisionConflict)) ||
		(secondErr == nil && errors.Is(firstErr, resource.ErrRevisionConflict))) {
		t.Fatalf("concurrent evidence errors=(%v,%v)", firstErr, secondErr)
	}

	var aggregate string
	var healthRevision, evidenceCount, evidenceRevisions int64
	var sources, purposes string
	if err := pool.QueryRow(ctx, `
		SELECT monitor.aggregate_status,monitor.revision,
		       (SELECT count(*) FROM deployment_health_evidence evidence WHERE evidence.deployment_id=monitor.deployment_id),
		       (SELECT count(DISTINCT health_revision) FROM deployment_health_evidence evidence WHERE evidence.deployment_id=monitor.deployment_id),
		       (SELECT string_agg(DISTINCT evidence_source, ',') FROM deployment_health_evidence evidence WHERE evidence.deployment_id=monitor.deployment_id),
		       (SELECT string_agg(purpose, ',' ORDER BY purpose) FROM deployment_health_evidence evidence WHERE evidence.deployment_id=monitor.deployment_id)
		FROM deployment_health_monitors monitor WHERE monitor.deployment_id=$1`, deploymentID,
	).Scan(&aggregate, &healthRevision, &evidenceCount, &evidenceRevisions, &sources, &purposes); err != nil {
		t.Fatal(err)
	}
	if aggregate != "degraded" || healthRevision != 2 || evidenceCount != 2 || evidenceRevisions != 1 ||
		sources != healthprobe.TrustIndependentControlPlane || purposes != "liveness,readiness" {
		t.Fatalf("durable health aggregate=%s revision=%d evidence=%d revisions=%d sources=%s purposes=%s",
			aggregate, healthRevision, evidenceCount, evidenceRevisions, sources, purposes)
	}
	var managedState string
	var managedRevision int64
	if err := pool.QueryRow(ctx, `SELECT state,revision FROM managed_services WHERE service_id=$1`, serviceID).Scan(&managedState, &managedRevision); err != nil {
		t.Fatal(err)
	}
	if managedState != "degraded" || managedRevision != 2 {
		t.Fatalf("managed service state=%s revision=%d", managedState, managedRevision)
	}
	var eventCount, outboxCount, linkedCount int64
	if err := pool.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM task_events WHERE aggregate_id IN ($1,$2)),
		  (SELECT count(*) FROM outbox_events outbox JOIN task_events event ON event.seq=outbox.event_seq WHERE event.aggregate_id IN ($1,$2)),
		  (SELECT count(*) FROM outbox_events outbox JOIN task_events event ON event.seq=outbox.event_seq
		   WHERE event.aggregate_id IN ($1,$2) AND outbox.topic=event.event_type)`, deploymentID, serviceID,
	).Scan(&eventCount, &outboxCount, &linkedCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 3 || outboxCount != eventCount || linkedCount != eventCount {
		t.Fatalf("events=%d outbox=%d linked=%d", eventCount, outboxCount, linkedCount)
	}
	assertHealthEventAndOutboxArePublicOnly(t, ctx, pool, deploymentID)

	restartedBase, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	restartedStore, _ := restartedBase.NewHealthProbeStore()
	reloaded, err := restartedStore.GetProbe(ctx, deploymentID)
	if err != nil || reloaded.Revision != 2 || reloaded.Status != healthprobe.AggregateDegraded || reloaded.Evidence == nil {
		t.Fatalf("restarted monitor=%+v err=%v", reloaded, err)
	}
	if _, err := restartedStore.SaveExternalProbe(ctx, reloaded, healthprobe.ExternalEvidence{}, time.Now().UTC()); !errors.Is(err, healthprobe.ErrInvalidEvidence) {
		t.Fatalf("untrusted Worker evidence error=%v", err)
	}

	entrySuite := postgresPublicEntryHealthSuite(t, deploymentID, planHash, recipeDigest)
	entryConfigured, err := lifecycle.Configure(ctx, resource.ProbeConfigureRequest{
		OwnerID: created.OwnerID, MonitorKind: resource.ProbeMonitorPublicEntry,
		Suite: entrySuite, Interval: time.Minute,
	})
	if err != nil || entryConfigured.MonitorKind != resource.ProbeMonitorPublicEntry || entryConfigured.Revision != 1 {
		t.Fatalf("public-entry monitor=%+v err=%v", entryConfigured, err)
	}
	entryObserved, err := lifecycle.RunStoredMonitor(ctx, deploymentID, resource.ProbeMonitorPublicEntry)
	if err != nil || entryObserved.Revision != 2 || entryObserved.Status != healthprobe.AggregateHealthy || entryObserved.Evidence == nil {
		t.Fatalf("public-entry evidence=%+v err=%v", entryObserved, err)
	}
	serviceAfterEntry, err := restartedStore.GetProbe(ctx, deploymentID)
	if err != nil || !sameProbeRecordForTest(serviceAfterEntry, reloaded) {
		t.Fatalf("service monitor changed after public-entry evidence: before=%+v after=%+v err=%v", reloaded, serviceAfterEntry, err)
	}
	var monitorCount, entryEvidenceCount int64
	if err := pool.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM deployment_health_monitors WHERE deployment_id=$1),
		  (SELECT count(*) FROM deployment_health_evidence WHERE deployment_id=$1 AND monitor_kind='public_entry')`,
		deploymentID,
	).Scan(&monitorCount, &entryEvidenceCount); err != nil {
		t.Fatal(err)
	}
	if monitorCount != 2 || entryEvidenceCount != 1 {
		t.Fatalf("multi-monitor rows=%d public-entry evidence=%d", monitorCount, entryEvidenceCount)
	}
	if err := pool.QueryRow(ctx, `SELECT state,revision FROM managed_services WHERE service_id=$1`, serviceID).Scan(&managedState, &managedRevision); err != nil {
		t.Fatal(err)
	}
	if managedState != "degraded" || managedRevision != 2 {
		t.Fatalf("public-entry monitor changed Managed health: state=%s revision=%d", managedState, managedRevision)
	}
	assertHealthEventAndOutboxArePublicOnly(t, ctx, pool, deploymentID)

	expectedDigest, err := healthprobe.EvidenceDigest(reloaded.Suite, *reloaded.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	health, err := restartedStore.GetDeploymentHealth(ctx, created.OwnerID, deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	assertHealthPublicPayload(t, mustMarshalJSON(t, health))
	if health.Status != cloudstatus.HealthDegraded || health.Revision != 2 || health.ProbeCount != 2 || len(health.ProbeCounts) != 2 ||
		health.ProbeCounts[0] != (cloudstatus.HealthProbeCount{Kind: cloudstatus.HealthProbeLiveness, Count: 1}) ||
		health.ProbeCounts[1] != (cloudstatus.HealthProbeCount{Kind: cloudstatus.HealthProbeReadiness, Count: 1}) ||
		health.EvidenceDigest != expectedDigest || health.EvidenceType != cloudstatus.HealthEvidenceIndependent ||
		!health.ObservedAt.Equal(reloaded.Evidence.ObservedAt) || !health.NextDueAt.Equal(reloaded.NextRunAt) {
		t.Fatalf("sanitized durable health summary=%+v", health)
	}
	unknown, err := restartedStore.GetDeploymentHealth(ctx, created.OwnerID, uuid.NewString())
	if err != nil || unknown.Status != cloudstatus.HealthUnknown || unknown.EvidenceType != cloudstatus.HealthEvidenceNone {
		t.Fatalf("missing health monitor summary=%+v err=%v", unknown, err)
	}
	statusStore, err := postgres.NewCloudStatusStore(restartedBase, restartedStore)
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := statusStore.GetDeployment(ctx, created.OwnerID, deploymentID)
	if err != nil || deployment.Health.EvidenceDigest != expectedDigest || deployment.Health.Revision != 2 {
		t.Fatalf("deployment health projection=%+v err=%v", deployment.Health, err)
	}
	page, err := statusStore.ListDeployments(ctx, cloudstatus.ListQuery{OwnerID: created.OwnerID})
	if err != nil || len(page.Deployments) != 1 || page.Deployments[0].Health.EvidenceDigest != expectedDigest {
		t.Fatalf("deployment health list projection=%+v err=%v", page, err)
	}
	service := rpcapi.NewCloudControlService(nil, instanceID, statusStore)
	getResponse, err := service.GetCloudDeployment(ctx, &agentv1.GetCloudDeploymentRequest{OwnerId: created.OwnerID, DeploymentId: deploymentID})
	if err != nil {
		t.Fatal(err)
	}
	listResponse, err := service.ListCloudDeployments(ctx, &agentv1.ListCloudDeploymentsRequest{OwnerId: created.OwnerID})
	if err != nil || len(listResponse.GetDeployments()) != 1 {
		t.Fatalf("list health deployment response=%+v err=%v", listResponse, err)
	}
	for _, deployment := range []*agentv1.CloudDeployment{getResponse.GetDeployment(), listResponse.GetDeployments()[0]} {
		assertHealthPublicPayload(t, mustMarshalProtoJSON(t, deployment.GetHealth()))
	}
}

func postgresHealthSuite(t *testing.T, deploymentID, planHash, recipeDigest string) healthprobe.SuiteV1 {
	t.Helper()
	bind := func(purpose healthprobe.Purpose, target string) healthprobe.SpecV1 {
		spec, err := healthprobe.Bind(healthprobe.SpecV1{
			SchemaVersion: healthprobe.SchemaV1,
			Binding:       healthprobe.BindingV1{DeploymentID: deploymentID, PlanHash: planHash, RecipeDigest: recipeDigest},
			Purpose:       purpose, Protocol: healthprobe.ProtocolHTTPS, Target: target,
			TimeoutMillis: 500, MaxAttempts: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	return healthprobe.SuiteV1{SchemaVersion: healthprobe.SuiteSchemaV1, Probes: []healthprobe.SpecV1{
		bind(healthprobe.PurposeLiveness, healthCapabilityURLCanary),
		bind(healthprobe.PurposeReadiness, "https://service.example.com/ready"),
	}}
}

func postgresPublicEntryHealthSuite(t *testing.T, deploymentID, planHash, recipeDigest string) healthprobe.SuiteV1 {
	t.Helper()
	spec, err := healthprobe.Bind(healthprobe.SpecV1{
		SchemaVersion: healthprobe.SchemaV1,
		Binding:       healthprobe.BindingV1{DeploymentID: deploymentID, PlanHash: planHash, RecipeDigest: recipeDigest},
		Purpose:       healthprobe.PurposeReadiness,
		Protocol:      healthprobe.ProtocolHTTPS,
		Target:        "https://public-entry.example.com/health/entry",
		TimeoutMillis: 500,
		MaxAttempts:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return healthprobe.SuiteV1{SchemaVersion: healthprobe.SuiteSchemaV1, Probes: []healthprobe.SpecV1{spec}}
}

func sameProbeRecordForTest(left, right resource.ProbeMonitorRecord) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func postgresHealthDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", digest[:])
}

func assertHealthEventAndOutboxArePublicOnly(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deploymentID string) {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT event.summary_json,outbox.payload_json
		FROM task_events event
		JOIN outbox_events outbox ON outbox.event_seq=event.seq
		WHERE event.aggregate_id=$1 AND event.event_type='cloud.deployment.health.changed'
		ORDER BY event.seq`, deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var summary, outbox []byte
		if err := rows.Scan(&summary, &outbox); err != nil {
			t.Fatal(err)
		}
		assertHealthPublicPayload(t, summary)
		assertHealthPublicOutboxPayload(t, outbox)
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("health event/outbox count=%d, want 2", count)
	}
}

func assertHealthPublicOutboxPayload(t *testing.T, payload []byte) {
	t.Helper()
	assertHealthNoCapabilityLeak(t, payload)
	var envelope struct {
		Summary json.RawMessage `json:"summary"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil || len(envelope.Summary) == 0 {
		t.Fatalf("decode health outbox payload: %v (%s)", err, payload)
	}
	assertHealthPublicPayload(t, envelope.Summary)
}

func assertHealthPublicPayload(t *testing.T, payload []byte) {
	t.Helper()
	assertHealthNoCapabilityLeak(t, payload)
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(payload, &summary); err != nil {
		t.Fatalf("decode health public summary: %v (%s)", err, payload)
	}
	want := map[string]struct{}{
		"status": {}, "revision": {}, "observed_at": {}, "next_due_at": {}, "probe_count": {}, "probe_counts": {},
		"external_evidence_digest": {}, "evidence_type": {},
	}
	if len(summary) != len(want) {
		t.Fatalf("health public summary fields=%v, want only %v", summary, want)
	}
	for field := range summary {
		if _, ok := want[field]; !ok {
			t.Fatalf("health public summary exposed field %q: %s", field, payload)
		}
	}
}

func assertHealthNoCapabilityLeak(t *testing.T, payload []byte) {
	t.Helper()
	for _, forbidden := range []string{
		healthCapabilityURLCanary, "capability-canary.example.com", "private-health", "service.example.com/ready",
		"target", "headers", "body", "authorization", "secret_ref", "pairing",
	} {
		if strings.Contains(strings.ToLower(string(payload)), strings.ToLower(forbidden)) {
			t.Fatalf("health public payload exposed %q: %s", forbidden, payload)
		}
	}
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func mustMarshalProtoJSON(t *testing.T, value proto.Message) []byte {
	t.Helper()
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

type barrierHealthTransport struct {
	release chan struct{}
	digest  string
	mu      sync.Mutex
	calls   int
	started chan struct{}
}

func (transport *barrierHealthTransport) Probe(ctx context.Context, request healthprobe.Request) (healthprobe.Observation, error) {
	transport.mu.Lock()
	transport.calls++
	if transport.started != nil && transport.calls >= 2 {
		select {
		case <-transport.started:
		default:
			close(transport.started)
		}
	}
	transport.mu.Unlock()
	select {
	case <-ctx.Done():
		return healthprobe.Observation{}, ctx.Err()
	case <-transport.release:
	}
	status := 200
	if strings.HasSuffix(request.Target, "/ready") {
		status = 503
	}
	return healthprobe.Observation{StatusCode: status, SummaryDigest: transport.digest}, nil
}

func (transport *barrierHealthTransport) waitForFirstCalls(t *testing.T, count int) {
	t.Helper()
	transport.mu.Lock()
	transport.started = make(chan struct{})
	if transport.calls >= count {
		close(transport.started)
	}
	started := transport.started
	transport.mu.Unlock()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent health probes did not start")
	}
}

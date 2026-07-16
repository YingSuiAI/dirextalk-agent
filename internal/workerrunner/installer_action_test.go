package workerrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRunnerBridgesApprovedInstallerCommandToRootClient(t *testing.T) {
	placeholder := validNoopBundle(t, 0)
	runner, config, control, objects := runnerFixture(t, placeholder)
	now := time.Now().UTC().Truncate(time.Millisecond)
	control.claimExpiresAt = now.Add(config.LeaseDuration)
	claimedAssignment := proto.Clone(control.assignment).(*agentv1.WorkerAssignment)
	claimedAssignment.LeaseEpoch = 9
	claimedAssignment.LeaseExpiresAt = timestamppb.New(control.claimExpiresAt)
	delivery, leaseGrant := workerInstallerDelivery(t, claimedAssignment, now)
	control.claimGrants = []*agentv1.WorkerInstallerLeaseGrant{installerGrantProto(t, leaseGrant)}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	control.heartbeatGrants = func(expiresAt time.Time) []*agentv1.WorkerInstallerLeaseGrant {
		grant, issueErr := issuer.IssueLeaseGrant(delivery, "install-service", 9, expiresAt, time.Now().UTC())
		if issueErr != nil {
			return nil
		}
		return []*agentv1.WorkerInstallerLeaseGrant{installerGrantProto(t, grant)}
	}
	command := delivery.SignedPlan.Plan.Commands[0]
	execution, err := json.Marshal(ExecutionBundleV1{
		SchemaVersion: 1,
		RecipeSHA256:  hex.EncodeToString(control.assignment.GetRecipeBundle().GetSha256()),
		Actions: []ActionV1{{
			ID: "install", Kind: installer.ActionExecute, TimeoutSeconds: command.TimeoutSeconds,
			Installer: &InstallerExecuteInputV1{CommandID: command.CommandID, Delivery: delivery},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	executionDigest := sha256.Sum256(execution)
	control.assignment.ExecutionBundle.Sha256 = executionDigest[:]
	objects.mu.Lock()
	objects.objects[control.assignment.ExecutionBundle.S3Ref] = execution
	objects.mu.Unlock()
	client := &recordingInstallerClient{}
	handler, err := NewInstallerExecuteAction(client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runner.Registry, err = NewRegistry(NoopAction{}, handler)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if result.Outcome != agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED || len(result.CompletedActions) != 1 ||
		len(client.commands) != 1 || client.commands[0] != command.CommandID || client.deliveries[0].TrustID != delivery.TrustID {
		t.Fatalf("installer action was not bridged exactly once: result=%#v commands=%#v", result, client.commands)
	}
}

func TestRunnerReadsRenewedInstallerGrantBeforeEveryLongMultiStepAction(t *testing.T) {
	runner, config, control, objects := runnerFixture(t, validNoopBundle(t, 0))
	now := time.Now().UTC().Truncate(time.Millisecond)
	control.claimExpiresAt = now.Add(config.LeaseDuration)
	assignment := proto.Clone(control.assignment).(*agentv1.WorkerAssignment)
	assignment.LeaseEpoch = 9
	assignment.LeaseExpiresAt = timestamppb.New(control.claimExpiresAt)
	binding := installer.BindingV1{
		AgentInstanceID: uuid.NewString(), DeploymentID: assignment.GetDeploymentId(), TaskID: assignment.GetTaskId(),
		PlanHash: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x21}, sha256.Size)), ApprovalID: uuid.NewString(),
		RecipeDigest: "sha256:" + hex.EncodeToString(assignment.GetRecipeBundle().GetSha256()),
	}
	root := installer.PreinstalledArtifactRoot
	artifactDigest := sha256.Sum256([]byte("multi-step installer artifact"))
	commands := []installer.CommandV1{
		{CommandID: "install-base", Argv: []string{root + "/service-installer", "base"}, WorkingDirectory: root, TimeoutSeconds: 2, ArtifactRefs: []string{"service-bundle"}},
		{CommandID: "install-service", Argv: []string{root + "/service-installer", "service"}, WorkingDirectory: root, TimeoutSeconds: 2, ArtifactRefs: []string{"service-bundle"}},
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding,
		Artifacts: []installer.ArtifactV1{{
			Name: "service-bundle", SHA256: "sha256:" + hex.EncodeToString(artifactDigest[:]), SizeBytes: 32, TargetPath: root + "/service-installer",
		}},
		Commands: commands, ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
	}, installer.DaemonConfigV1{SchemaVersion: installer.DaemonConfigSchema, Binding: binding, TargetRoot: root}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		grant, issueErr := issuer.IssueLeaseGrant(delivery, command.CommandID, 9, control.claimExpiresAt, now)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		control.claimGrants = append(control.claimGrants, installerGrantProto(t, grant))
	}
	control.heartbeatGrants = func(expiresAt time.Time) []*agentv1.WorkerInstallerLeaseGrant {
		result := make([]*agentv1.WorkerInstallerLeaseGrant, 0, len(commands))
		for _, command := range commands {
			grant, issueErr := issuer.IssueLeaseGrant(delivery, command.CommandID, 9, expiresAt, time.Now().UTC())
			if issueErr != nil {
				return nil
			}
			result = append(result, installerGrantProto(t, grant))
		}
		return result
	}
	actions := make([]ActionV1, 0, len(commands))
	for index, command := range commands {
		actions = append(actions, ActionV1{
			ID: fmt.Sprintf("install-%d", index+1), Kind: installer.ActionExecute, TimeoutSeconds: command.TimeoutSeconds,
			Installer: &InstallerExecuteInputV1{CommandID: command.CommandID, Delivery: delivery},
		})
	}
	execution, err := json.Marshal(ExecutionBundleV1{
		SchemaVersion: 1, RecipeSHA256: hex.EncodeToString(assignment.GetRecipeBundle().GetSha256()), Actions: actions,
	})
	if err != nil {
		t.Fatal(err)
	}
	executionDigest := sha256.Sum256(execution)
	control.assignment.ExecutionBundle.Sha256 = executionDigest[:]
	objects.mu.Lock()
	objects.objects[control.assignment.ExecutionBundle.S3Ref] = execution
	objects.mu.Unlock()
	client := &recordingInstallerClient{firstDelay: 25 * time.Millisecond}
	handler, err := NewInstallerExecuteAction(client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runner.Registry, err = NewRegistry(NoopAction{}, handler)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if result.Outcome != agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED || len(client.grants) != 2 {
		t.Fatalf("multi-step installer result=%+v grants=%d", result, len(client.grants))
	}
	firstExpiry, _ := time.Parse(time.RFC3339Nano, client.grants[0].Grant.ExpiresAt)
	secondExpiry, _ := time.Parse(time.RFC3339Nano, client.grants[1].Grant.ExpiresAt)
	if client.grants[0].Grant.LeaseEpoch != 9 || client.grants[1].Grant.LeaseEpoch != 9 || !secondExpiry.After(firstExpiry) {
		t.Fatalf("second action did not atomically read a renewed grant: first=%+v second=%+v", client.grants[0].Grant, client.grants[1].Grant)
	}
	control.mu.Lock()
	heartbeats := control.heartbeats
	control.mu.Unlock()
	if heartbeats < 1 {
		t.Fatal("long multi-step execution did not renew its durable lease")
	}
}

func TestExecutionBundleRejectsEmbeddedLeaseGrant(t *testing.T) {
	recipeDigest := sha256.Sum256([]byte("recipe"))
	raw := []byte(`{"schema_version":1,"recipe_sha256":"` + hex.EncodeToString(recipeDigest[:]) + `","actions":[{"id":"install","kind":"installer.execute","timeout_seconds":1,"installer":{"command_id":"install-service","delivery":{},"lease_grant":{}}}]}`)
	if _, err := parseExecutionBundle(raw, recipeDigest[:], time.Minute); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("embedded lease grant error = %v, want invalid bundle", err)
	}
}

func TestInstallerActionRejectsAssignmentAndRuntimeScopeChanges(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	recipeDigest := sha256.Sum256([]byte("recipe"))
	assignment := &agentv1.WorkerAssignment{
		DeploymentId: uuid.NewString(), TaskId: uuid.NewString(), LeaseEpoch: 9,
		LeaseExpiresAt: timestamppb.New(now.Add(time.Minute)),
		RecipeBundle:   &agentv1.WorkerBundleReference{Sha256: recipeDigest[:]},
	}
	delivery, leaseGrant := workerInstallerDelivery(t, assignment, now)
	assignment.InstallerLeaseGrants = []*agentv1.WorkerInstallerLeaseGrant{installerGrantProto(t, leaseGrant)}
	command := delivery.SignedPlan.Plan.Commands[0]
	bundle := ExecutionBundleV1{Actions: []ActionV1{{
		ID: "install", Kind: installer.ActionExecute, TimeoutSeconds: command.TimeoutSeconds,
		Installer: &InstallerExecuteInputV1{CommandID: command.CommandID, Delivery: delivery},
	}}}
	bound, err := bindInstallerAssignment(bundle, assignment, now)
	if err != nil {
		t.Fatalf("valid assignment rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*agentv1.WorkerAssignment)
	}{
		{name: "old lease", mutate: func(value *agentv1.WorkerAssignment) { value.LeaseEpoch++ }},
		{name: "other deployment", mutate: func(value *agentv1.WorkerAssignment) { value.DeploymentId = uuid.NewString() }},
		{name: "other task", mutate: func(value *agentv1.WorkerAssignment) { value.TaskId = uuid.NewString() }},
		{name: "recipe digest", mutate: func(value *agentv1.WorkerAssignment) { value.RecipeBundle.Sha256[0] ^= 0xff }},
		{name: "lease exceeds signed capability", mutate: func(value *agentv1.WorkerAssignment) {
			value.LeaseExpiresAt = timestamppb.New(now.Add(10 * time.Minute))
		}},
		{name: "missing grant", mutate: func(value *agentv1.WorkerAssignment) { value.InstallerLeaseGrants = nil }},
		{name: "extra grant", mutate: func(value *agentv1.WorkerAssignment) {
			value.InstallerLeaseGrants = append(value.InstallerLeaseGrants, proto.Clone(value.InstallerLeaseGrants[0]).(*agentv1.WorkerInstallerLeaseGrant))
		}},
		{name: "tampered grant", mutate: func(value *agentv1.WorkerAssignment) { value.InstallerLeaseGrants[0].Signature[0] ^= 0xff }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := proto.Clone(assignment).(*agentv1.WorkerAssignment)
			test.mutate(changed)
			if _, err := bindInstallerAssignment(bundle, changed, now); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("changed assignment error = %v", err)
			}
		})
	}

	client := &recordingInstallerClient{}
	handler, err := NewInstallerExecuteAction(client, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	changedAction := bound.Actions[0]
	changedAction.TimeoutSeconds++
	if err := handler.Validate(changedAction); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("runtime timeout override error = %v", err)
	}
	changedAction = bound.Actions[0]
	changedAction.Installer = &InstallerExecuteInputV1{CommandID: "not-approved", Delivery: delivery, LeaseGrant: &leaseGrant}
	if err := handler.Validate(changedAction); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("runtime command override error = %v", err)
	}
	if len(client.commands) != 0 {
		t.Fatalf("rejected action reached root client: %#v", client.commands)
	}
}

func TestLeaseStateRejectsStaleGrantRotationAndOldHeartbeatEpoch(t *testing.T) {
	tests := []struct {
		name        string
		oldGrant    bool
		returnEpoch int64
	}{
		{name: "old grant after durable renewal", oldGrant: true, returnEpoch: 9},
		{name: "old lease epoch", returnEpoch: 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, config, control, _ := runnerFixture(t, validNoopBundle(t, 0))
			now := time.Now().UTC().Truncate(time.Millisecond)
			assignment := proto.Clone(control.assignment).(*agentv1.WorkerAssignment)
			assignment.Revision, assignment.LeaseEpoch = 3, 9
			assignment.LeaseExpiresAt = timestamppb.New(now.Add(config.LeaseDuration))
			delivery, initial := workerInstallerDelivery(t, assignment, now)
			initialProto := installerGrantProto(t, initial)
			assignment.InstallerLeaseGrants = []*agentv1.WorkerInstallerLeaseGrant{initialProto}
			issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x73}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer issuer.Close()
			control.revision = assignment.GetRevision()
			control.heartbeatEpoch = test.returnEpoch
			control.heartbeatGrants = func(expiresAt time.Time) []*agentv1.WorkerInstallerLeaseGrant {
				if test.oldGrant {
					return []*agentv1.WorkerInstallerLeaseGrant{proto.Clone(initialProto).(*agentv1.WorkerInstallerLeaseGrant)}
				}
				grant, issueErr := issuer.IssueLeaseGrant(delivery, "install-service", 9, expiresAt, time.Now().UTC())
				if issueErr != nil {
					return nil
				}
				return []*agentv1.WorkerInstallerLeaseGrant{installerGrantProto(t, grant)}
			}
			state := &leaseState{
				control: control, token: []byte("dtxw-session.test"), deploymentID: assignment.GetDeploymentId(), workerID: assignment.GetWorkerId(),
				epoch: 9, revision: assignment.GetRevision(), leaseDuration: config.LeaseDuration, retryDelay: time.Millisecond,
			}
			if err := state.initializeInstallerGrants(assignment); err != nil {
				t.Fatal(err)
			}
			if err := state.heartbeat(context.Background()); err == nil {
				t.Fatal("unsafe heartbeat grant rotation was accepted")
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if state.revision != assignment.GetRevision() || !state.leaseExpiresAt.Equal(assignment.GetLeaseExpiresAt().AsTime()) ||
				state.installerGrants["install-service"].Grant.ExpiresAt != initial.Grant.ExpiresAt {
				t.Fatalf("rejected heartbeat mutated lease state: revision=%d expiry=%s grant=%+v", state.revision, state.leaseExpiresAt, state.installerGrants)
			}
		})
	}
}

func installerGrantProto(t *testing.T, value installer.SignedLeaseGrantV1) *agentv1.WorkerInstallerLeaseGrant {
	t.Helper()
	issuedAt, err := time.Parse(time.RFC3339Nano, value.Grant.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, value.Grant.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	binding := value.Grant.Binding
	return &agentv1.WorkerInstallerLeaseGrant{
		SchemaVersion: value.Grant.SchemaVersion, TrustId: value.Grant.TrustID,
		Binding:    &agentv1.WorkerInstallerBinding{AgentInstanceId: binding.AgentInstanceID, DeploymentId: binding.DeploymentID, TaskId: binding.TaskID, PlanHash: binding.PlanHash, ApprovalId: binding.ApprovalID, RecipeDigest: binding.RecipeDigest},
		PlanDigest: value.Grant.PlanDigest, OperationId: value.Grant.OperationID, CommandId: value.Grant.CommandID,
		LeaseEpoch: value.Grant.LeaseEpoch, IssuedAt: timestamppb.New(issuedAt), ExpiresAt: timestamppb.New(expiresAt),
		SignerKeyId: value.SignerKeyID, Signature: append([]byte(nil), value.Signature...),
	}
}

func workerInstallerDelivery(t *testing.T, assignment *agentv1.WorkerAssignment, now time.Time) (installer.DeliveryV1, installer.SignedLeaseGrantV1) {
	t.Helper()
	binding := installer.BindingV1{
		AgentInstanceID: uuid.NewString(), DeploymentID: assignment.GetDeploymentId(), TaskID: assignment.GetTaskId(),
		PlanHash: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x11}, sha256.Size)), ApprovalID: uuid.NewString(),
		RecipeDigest: "sha256:" + hex.EncodeToString(assignment.GetRecipeBundle().GetSha256()),
	}
	targetRoot := installer.PreinstalledArtifactRoot
	artifactDigest := sha256.Sum256([]byte("digest-locked installer artifact"))
	plan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding,
		Artifacts: []installer.ArtifactV1{{
			Name: "service-bundle", SHA256: "sha256:" + hex.EncodeToString(artifactDigest[:]), SizeBytes: 32,
			TargetPath: targetRoot + "/service-installer",
		}},
		Commands: []installer.CommandV1{{
			CommandID: "install-service", Argv: []string{targetRoot + "/service-installer"},
			WorkingDirectory: targetRoot,
			TimeoutSeconds:   2, ArtifactRefs: []string{"service-bundle"},
		}},
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(plan, installer.DaemonConfigV1{
		SchemaVersion: installer.DaemonConfigSchema, Binding: binding, TargetRoot: targetRoot,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaseGrant, err := issuer.IssueLeaseGrant(delivery, "install-service", assignment.GetLeaseEpoch(), assignment.GetLeaseExpiresAt().AsTime(), now)
	if err != nil {
		t.Fatal(err)
	}
	return delivery, leaseGrant
}

type recordingInstallerClient struct {
	mu         sync.Mutex
	deliveries []installer.DeliveryV1
	commands   []string
	grants     []installer.SignedLeaseGrantV1
	firstDelay time.Duration
}

func (client *recordingInstallerClient) Execute(ctx context.Context, delivery installer.DeliveryV1, grant installer.SignedLeaseGrantV1, commandID string) (installer.ResponseV1, error) {
	client.mu.Lock()
	client.deliveries = append(client.deliveries, delivery)
	client.commands = append(client.commands, commandID)
	client.grants = append(client.grants, cloneInstallerLeaseGrant(grant))
	delay := time.Duration(0)
	if len(client.commands) == 1 {
		delay = client.firstDelay
	}
	client.mu.Unlock()
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return installer.ResponseV1{}, ctx.Err()
		case <-timer.C:
		}
	}
	return installer.ResponseV1{
		SchemaVersion: installer.ResponseSchemaV1, Action: installer.ActionExecute,
		Status: installer.StatusExecuted, CommandID: commandID,
	}, nil
}

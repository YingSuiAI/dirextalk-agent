package workerrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	control.claimExpiresAt = now.Add(time.Minute)
	claimedAssignment := proto.Clone(control.assignment).(*agentv1.WorkerAssignment)
	claimedAssignment.LeaseEpoch = 9
	claimedAssignment.LeaseExpiresAt = timestamppb.New(control.claimExpiresAt)
	delivery, leaseGrant := workerInstallerDelivery(t, claimedAssignment, now)
	command := delivery.SignedPlan.Plan.Commands[0]
	execution, err := json.Marshal(ExecutionBundleV1{
		SchemaVersion: 1,
		RecipeSHA256:  hex.EncodeToString(control.assignment.GetRecipeBundle().GetSha256()),
		Actions: []ActionV1{{
			ID: "install", Kind: installer.ActionExecute, TimeoutSeconds: command.TimeoutSeconds,
			Installer: &InstallerExecuteInputV1{CommandID: command.CommandID, Delivery: delivery, LeaseGrant: leaseGrant},
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

func TestInstallerActionRejectsAssignmentAndRuntimeScopeChanges(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	recipeDigest := sha256.Sum256([]byte("recipe"))
	assignment := &agentv1.WorkerAssignment{
		DeploymentId: uuid.NewString(), TaskId: uuid.NewString(), LeaseEpoch: 9,
		LeaseExpiresAt: timestamppb.New(now.Add(time.Minute)),
		RecipeBundle:   &agentv1.WorkerBundleReference{Sha256: recipeDigest[:]},
	}
	delivery, leaseGrant := workerInstallerDelivery(t, assignment, now)
	command := delivery.SignedPlan.Plan.Commands[0]
	bundle := ExecutionBundleV1{Actions: []ActionV1{{
		ID: "install", Kind: installer.ActionExecute, TimeoutSeconds: command.TimeoutSeconds,
		Installer: &InstallerExecuteInputV1{CommandID: command.CommandID, Delivery: delivery, LeaseGrant: leaseGrant},
	}}}
	if err := validateInstallerAssignment(bundle, assignment, now); err != nil {
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := proto.Clone(assignment).(*agentv1.WorkerAssignment)
			test.mutate(changed)
			if err := validateInstallerAssignment(bundle, changed, now); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("changed assignment error = %v", err)
			}
		})
	}

	client := &recordingInstallerClient{}
	handler, err := NewInstallerExecuteAction(client, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	changedAction := bundle.Actions[0]
	changedAction.TimeoutSeconds++
	if err := handler.Validate(changedAction); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("runtime timeout override error = %v", err)
	}
	changedAction = bundle.Actions[0]
	changedAction.Installer = &InstallerExecuteInputV1{CommandID: "not-approved", Delivery: delivery, LeaseGrant: leaseGrant}
	if err := handler.Validate(changedAction); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("runtime command override error = %v", err)
	}
	if len(client.commands) != 0 {
		t.Fatalf("rejected action reached root client: %#v", client.commands)
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
}

func (client *recordingInstallerClient) Execute(_ context.Context, delivery installer.DeliveryV1, _ installer.SignedLeaseGrantV1, commandID string) (installer.ResponseV1, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.deliveries = append(client.deliveries, delivery)
	client.commands = append(client.commands, commandID)
	return installer.ResponseV1{
		SchemaVersion: installer.ResponseSchemaV1, Action: installer.ActionExecute,
		Status: installer.StatusExecuted, CommandID: commandID,
	}, nil
}

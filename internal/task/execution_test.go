package task

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateCommandValidatesAtomicStepDAG(t *testing.T) {
	t.Parallel()

	rootID, buildID, verifyID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	command := CreateCommand{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        "owner-1",
		Goal:           "build and verify the service",
		Retention:      RetentionEphemeralAutoDestroy,
		Steps: []StepDefinition{
			{StepID: rootID, Name: "research", ExecutorKind: ExecutorControlPlane},
			{StepID: buildID, Name: "build", ExecutorKind: ExecutorCloudWorker, DependsOnStepIDs: []string{rootID}},
			{StepID: verifyID, Name: "verify", ExecutorKind: ExecutorCloudWorker, DependsOnStepIDs: []string{buildID, rootID}},
		},
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid DAG rejected: %v", err)
	}

	tests := []struct {
		name  string
		steps []StepDefinition
	}{
		{
			name: "unknown dependency",
			steps: []StepDefinition{
				{StepID: rootID, Name: "research", ExecutorKind: ExecutorControlPlane, DependsOnStepIDs: []string{uuid.NewString()}},
			},
		},
		{
			name: "self cycle",
			steps: []StepDefinition{
				{StepID: rootID, Name: "research", ExecutorKind: ExecutorControlPlane, DependsOnStepIDs: []string{rootID}},
			},
		},
		{
			name: "indirect cycle",
			steps: []StepDefinition{
				{StepID: rootID, Name: "one", ExecutorKind: ExecutorControlPlane, DependsOnStepIDs: []string{verifyID}},
				{StepID: buildID, Name: "two", ExecutorKind: ExecutorCloudWorker, DependsOnStepIDs: []string{rootID}},
				{StepID: verifyID, Name: "three", ExecutorKind: ExecutorCloudWorker, DependsOnStepIDs: []string{buildID}},
			},
		},
		{
			name: "duplicate step",
			steps: []StepDefinition{
				{StepID: rootID, Name: "one", ExecutorKind: ExecutorControlPlane},
				{StepID: rootID, Name: "two", ExecutorKind: ExecutorCloudWorker},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			invalid := command
			invalid.Steps = test.steps
			if err := invalid.Validate(); !errors.Is(err, ErrInvalidDAG) {
				t.Fatalf("Validate() error = %v, want ErrInvalidDAG", err)
			}
		})
	}
}

func TestCreateDigestBindsDAGButNotDeclarationOrder(t *testing.T) {
	t.Parallel()

	firstID, secondID := uuid.NewString(), uuid.NewString()
	base := CreateCommand{
		OwnerID:   "owner-1",
		Goal:      "compile",
		Retention: RetentionEphemeralAutoDestroy,
		Steps: []StepDefinition{
			{StepID: firstID, Name: "first", ExecutorKind: ExecutorCloudWorker},
			{StepID: secondID, Name: "second", ExecutorKind: ExecutorCloudWorker, DependsOnStepIDs: []string{firstID}},
		},
	}
	reordered := base
	reordered.Steps = []StepDefinition{base.Steps[1], base.Steps[0]}
	if base.Digest() != reordered.Digest() {
		t.Fatal("equivalent DAG declaration order changed digest")
	}
	changed := base
	changed.Steps = append([]StepDefinition(nil), base.Steps...)
	changed.Steps[1].DependsOnStepIDs = nil
	if base.Digest() == changed.Digest() {
		t.Fatal("dependency change did not change digest")
	}
}

func TestMutationScopeRequiresCredentialAndClientIdentity(t *testing.T) {
	t.Parallel()

	valid := MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	for _, invalid := range []MutationScope{
		{CredentialID: valid.CredentialID},
		{ClientID: valid.ClientID},
		{ClientID: valid.ClientID, CredentialID: uuid.Nil.String()},
	} {
		if err := invalid.Validate(); !errors.Is(err, ErrInvalidMutationScope) {
			t.Fatalf("scope %#v error = %v, want ErrInvalidMutationScope", invalid, err)
		}
	}
}

func TestLeaseMutationCommandsBindEpochWorkerAndReferences(t *testing.T) {
	t.Parallel()

	taskID, stepID, workerID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	acquire := AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: taskID, StepID: stepID, WorkerID: workerID,
		ExecutorKind: ExecutorCloudWorker, LeaseDuration: time.Minute,
	}
	if err := acquire.Validate(); err != nil {
		t.Fatalf("valid acquire rejected: %v", err)
	}
	otherStep := acquire
	otherStep.StepID = uuid.NewString()
	if acquire.Digest() == otherStep.Digest() {
		t.Fatal("acquire digest did not bind the exact step")
	}
	renew := RenewStepLeaseCommand{
		IdempotencyKey: uuid.NewString(), TaskID: taskID, StepID: stepID,
		Attempt: 1, LeaseEpoch: 1, WorkerID: workerID, LeaseDuration: time.Minute,
	}
	if err := renew.Validate(); err != nil {
		t.Fatalf("valid renew rejected: %v", err)
	}
	checkpoint := CheckpointStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: taskID, StepID: stepID,
		Attempt: 1, LeaseEpoch: 1, WorkerID: workerID, CheckpointRef: "s3://artifacts/checkpoints/one",
	}
	if err := checkpoint.Validate(); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
	complete := CompleteStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: taskID, StepID: stepID,
		Attempt: 1, LeaseEpoch: 1, WorkerID: workerID, Outcome: OutcomeSucceeded,
		ResultRef: "s3://artifacts/results/one",
	}
	if err := complete.Validate(); err != nil {
		t.Fatalf("valid complete rejected: %v", err)
	}
	withPlan := complete
	withPlan.RelatedPlanID = uuid.NewString()
	if err := withPlan.Validate(); err != nil {
		t.Fatalf("valid complete with related Plan rejected: %v", err)
	}
	if complete.Digest() == withPlan.Digest() {
		t.Fatal("completion digest did not bind related Plan")
	}

	stale := renew
	stale.LeaseEpoch = 0
	if err := stale.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero epoch error = %v, want ErrInvalid", err)
	}
	withSecret := checkpoint
	withSecret.CheckpointRef = "s3://bucket/sk-abcdefghijklmnopqrstuvwxyz012345"
	if err := withSecret.Validate(); !errors.Is(err, ErrRawSecret) {
		t.Fatalf("secret checkpoint error = %v, want ErrRawSecret", err)
	}
	invalidOutcome := complete
	invalidOutcome.Outcome = OutcomeCanceled
	if err := invalidOutcome.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("worker canceled outcome error = %v, want ErrInvalid", err)
	}
	planWithFailedOutcome := withPlan
	planWithFailedOutcome.Outcome = OutcomeFailed
	if err := planWithFailedOutcome.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("related Plan with failed outcome error = %v, want ErrInvalid", err)
	}
}

func TestSuspendStepForSecretsFencesAllRevisionsWithoutSecretIdentity(t *testing.T) {
	t.Parallel()

	command := SuspendStepForSecretsCommand{
		IdempotencyKey: uuid.NewString(), TaskID: uuid.NewString(), StepID: uuid.NewString(),
		Attempt: 1, LeaseEpoch: 3, WorkerID: uuid.NewString(),
		ExpectedTaskRevision: 7, ExpectedStepRevision: 5, ExpectedAttemptRevision: 2,
		AgentInstanceID: uuid.NewString(),
		Requirements:    []SecretWaitRequirement{{Purpose: "model token", RecipeDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid suspend command rejected: %v", err)
	}
	reordered := command
	reordered.Requirements = append([]SecretWaitRequirement(nil), command.Requirements...)
	if command.Digest() != reordered.Digest() {
		t.Fatal("equivalent secret wait requirements changed digest")
	}
	changed := command
	changed.ExpectedAttemptRevision++
	if command.Digest() == changed.Digest() {
		t.Fatal("attempt revision did not bind suspend digest")
	}
	withSecret := command
	withSecret.Requirements = []SecretWaitRequirement{{Purpose: "model token sk-abcdefghijklmnopqrstuvwxyz012345", RecipeDigest: command.Requirements[0].RecipeDigest}}
	if err := withSecret.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("secret-shaped purpose error=%v, want ErrInvalid", err)
	}
	duplicate := command
	duplicate.Requirements = append(duplicate.Requirements, command.Requirements[0])
	if err := duplicate.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate purpose error=%v, want ErrInvalid", err)
	}
}

func TestCancelDigestUsesOnlyRedactedReason(t *testing.T) {
	t.Parallel()

	base := CancelCommand{
		IdempotencyKey: uuid.NewString(), TaskID: uuid.NewString(), ExpectedRevision: 1,
		Reason: "operator requested password=first-secret",
	}
	otherSecret := base
	otherSecret.Reason = "operator requested password=second-secret"
	if base.Digest() != otherSecret.Digest() {
		t.Fatal("cancel digest retained a distinction between redacted secrets")
	}
	if strings.Contains(base.RedactedReason(), "first-secret") || base.RedactedReason() != "operator requested [redacted]" {
		t.Fatalf("redacted reason = %q", base.RedactedReason())
	}
	differentReason := base
	differentReason.Reason = "operator requested maintenance"
	if base.Digest() == differentReason.Digest() {
		t.Fatal("different non-secret cancellation reason did not change digest")
	}
}

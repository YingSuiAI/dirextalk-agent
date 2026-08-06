package production

// Runtime is the Agent-owned execution.v2 provider for the durable Core
// execution records.  It deliberately uses the existing typed Workload
// provider (SSM/ECS/runner) rather than accepting shell text, SDK requests,
// URLs, or credential material from an execution record.  A reconcile call is
// the recovery boundary: provider mutation is attempted only after a typed
// readback proves the desired state is not already present, and every
// provider outcome is reduced to a small status/readback envelope.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
)

var (
	ErrRuntimeInvalid  = errors.New("execution.v2 production: runtime invalid")
	ErrRuntimeNotReady = errors.New("execution.v2 production: runtime not ready")
	ErrRuntimeConflict = errors.New("execution.v2 production: runtime record conflict")
)

type RuntimeConfig struct {
	Store              coreexecutionv2.Store
	Workload           coreworkload.Provider
	Provisioner        ComputeProvisioner
	Inspector          Inspector
	Credentials        CredentialResolver
	CredentialRevision CredentialRevision
	Now                func() time.Time
}

// Runtime is safe to use from concurrent capability calls.  The provider
// itself owns any AWS client pooling; the atomic flag only gates composition
// publication and cannot be changed back to ready after a fatal close.
type Runtime struct {
	store            coreexecutionv2.Store
	workload         coreworkload.Provider
	provisioner      ComputeProvisioner
	inspector        Inspector
	credentials      CredentialResolver
	revisionResolver CredentialRevision
	now              func() time.Time
	ready            atomic.Bool
}

func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	if cfg.Store == nil || cfg.Workload == nil || cfg.Inspector == nil || cfg.Credentials == nil || cfg.CredentialRevision == nil {
		return nil, ErrRuntimeInvalid
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	r := &Runtime{store: cfg.Store, workload: cfg.Workload, provisioner: cfg.Provisioner, inspector: cfg.Inspector, credentials: cfg.Credentials, revisionResolver: cfg.CredentialRevision, now: cfg.Now}
	r.ready.Store(true)
	return r, nil
}

func (r *Runtime) Ready() bool {
	return r != nil && r.ready.Load() && r.store != nil && r.workload != nil && r.inspector != nil && r.credentials != nil && r.revisionResolver != nil
}

// Reconcile executes one owner-scoped run/stage.  It never mutates the run
// record itself; the neutral Service performs the expected-revision CAS after
// validating this redacted result.  That separation makes a crash between
// provider completion and record persistence recoverable: the next call sees
// the provider readback and skips a duplicate mutation.
func (r *Runtime) Reconcile(ctx context.Context, scope coretask.OwnerScope, req coreexecutionv2.ReconcileRequest) (map[string]any, error) {
	if !r.Ready() || scope.Validate() != nil || !coreworkload.ValidUUID(req.RunID) || !coreworkload.ValidUUID(req.StageID) {
		return nil, ErrRuntimeNotReady
	}
	run, err := r.store.Read(ctx, scope, "run", req.RunID, req.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	status := strings.TrimSpace(run.Status)
	if terminalRunStatus(status) {
		return map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": status}, nil
	}
	payloadStatus := stringValue(run.Payload, "status")
	if terminalRunStatus(payloadStatus) {
		return map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": payloadStatus}, nil
	}
	stage, confirmation, bindingErr := r.validateReconcileBinding(ctx, scope, req, run)
	if bindingErr != nil {
		return nil, bindingErr
	}
	planID := stringValue(run.Payload, "plan_id")
	if !coreworkload.ValidUUID(planID) {
		return nil, ErrRuntimeConflict
	}
	planRecord, err := r.store.Read(ctx, scope, "plan", planID, 0)
	if err != nil {
		return nil, err
	}
	targetID := stringValue(planRecord.Payload, "target_id")
	if !coreworkload.ValidUUID(targetID) {
		return nil, ErrRuntimeConflict
	}
	targetRevision := uintValue(planRecord.Payload, "target_revision")
	if targetRevision == 0 {
		targetRevision = 1
	}
	targetRecord, err := r.store.Read(ctx, scope, "target", targetID, targetRevision)
	if err != nil {
		return nil, err
	}
	var provisionEnvelope map[string]any
	plan, err := r.planFromRecords(planRecord, targetRecord, run.Payload["materialized_target"])
	if err != nil {
		// Reserved EC2 targets do not have an SSM target identity until the
		// CloudFormation stack has been created and its instance has joined
		// SSM.  The durable run payload is the recovery fence: once the first
		// provider call has started, subsequent reconciles only read the stack.
		if !isComputeReservation(targetRecord.Payload) {
			return nil, err
		}
		materialized, provisionResult, provisionErr := r.materializeReservation(ctx, scope, req, run, stage, confirmation, targetRecord)
		if provisionErr != nil {
			return provisionResult, nil
		}
		provisionEnvelope = provisionResult
		plan, err = r.planFromRecords(planRecord, targetRecord, materialized)
		if err != nil {
			return nil, err
		}
	}
	kind := coreworkload.OperationApply
	if strings.EqualFold(stringValue(run.Payload, "operation"), "destroy") {
		kind = coreworkload.OperationDestroy
	}
	operation := r.operationFromRun(scope, run, req, plan, kind, targetID)
	finish := func(result map[string]any) map[string]any {
		merged := make(map[string]any, len(provisionEnvelope)+len(result))
		for key, value := range provisionEnvelope {
			merged[key] = value
		}
		for key, value := range result {
			merged[key] = value
		}
		return merged
	}
	if kind == coreworkload.OperationDestroy && isComputeReservation(targetRecord.Payload) {
		return r.reconcileReservationDestroy(ctx, scope, req, run, targetRecord, plan, finish)
	}
	// A successful provider readback is authoritative and avoids replaying a
	// mutation after a crash window or lost response.
	readback, readErr := r.workload.Read(ctx, plan, operation)
	if readErr == nil && desiredReadback(readback, kind) {
		return finish(runtimeResult(req, statusForOperation(kind, readback), readback)), nil
	}
	if readErr != nil {
		// A failed read cannot establish whether a prior mutation committed. Do
		// not dispatch another side effect; expose an explicit uncertain state.
		return finish(map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": "uncertain", "reason": "provider_readback_unavailable"}), nil
	}
	var providerErr error
	if kind == coreworkload.OperationDestroy {
		_, providerErr = r.workload.Destroy(ctx, plan, operation)
	} else {
		_, providerErr = r.workload.Apply(ctx, plan, operation)
	}
	if providerErr != nil {
		// The provider may have accepted a request and lost its response. One
		// typed readback is the only safe recovery; no blind retry is allowed.
		readback, readErr = r.workload.Read(ctx, plan, operation)
		if readErr == nil && desiredReadback(readback, kind) {
			return finish(runtimeResult(req, statusForOperation(kind, readback), readback)), nil
		}
		return finish(map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": "uncertain", "reason": "provider_outcome_uncertain"}), nil
	}
	readback, readErr = r.workload.Read(ctx, plan, operation)
	if readErr != nil || !desiredReadback(readback, kind) {
		return finish(map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": "uncertain", "reason": "provider_readback_mismatch"}), nil
	}
	return finish(runtimeResult(req, statusForOperation(kind, readback), readback)), nil
}

// Invoke implements read-only, schema-pinned workload operations for service
// bindings. Provider mutations must enter through Reconcile, where the exact
// confirmed run and durable stage binding are verified before dispatch. Keeping
// apply/destroy out of this generic invocation surface prevents an allow-list
// configuration mistake from bypassing the confirmation boundary.
func (r *Runtime) Invoke(ctx context.Context, scope coretask.OwnerScope, req coreexecutionv2.InvokeRequest) (map[string]any, error) {
	if !r.Ready() || scope.Validate() != nil || req.BindingID == "" {
		return nil, ErrRuntimeNotReady
	}
	if req.Operation == "target.observe" {
		return r.invokeTargetObserve(ctx, scope, req)
	}
	if req.Operation != "workload.read" {
		return nil, coreexecutionv2.ErrUnsupported
	}
	binding, err := r.store.Read(ctx, scope, "binding", req.BindingID, req.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	targetID := stringValue(req.Input, "target_id")
	if targetID == "" {
		targetID = stringValue(binding.Payload, "target_id")
	}
	planID := stringValue(req.Input, "plan_id")
	if planID == "" {
		planID = stringValue(binding.Payload, "plan_id")
	}
	if !coreworkload.ValidUUID(targetID) || !coreworkload.ValidUUID(planID) {
		return nil, ErrRuntimeConflict
	}
	planRecord, err := r.store.Read(ctx, scope, "plan", planID, 0)
	if err != nil {
		return nil, err
	}
	targetRevision := uintValue(planRecord.Payload, "target_revision")
	if targetRevision == 0 {
		targetRevision = 1
	}
	targetRecord, err := r.store.Read(ctx, scope, "target", targetID, targetRevision)
	if err != nil {
		return nil, err
	}
	plan, err := r.planFromRecords(planRecord, targetRecord)
	if err != nil {
		return nil, err
	}
	operation := r.operationFromBinding(scope, req, plan, false, targetID)
	readback, err := r.workload.Read(ctx, plan, operation)
	if err != nil {
		return map[string]any{"status": "uncertain", "reason": "provider_outcome_uncertain", "target_id": targetID, "plan_id": planID}, nil
	}
	return map[string]any{"status": statusForOperation(operation.Kind, readback), "target_id": targetID, "plan_id": planID, "readback": redactedReadback(readback)}, nil
}

func (r *Runtime) invokeTargetObserve(ctx context.Context, scope coretask.OwnerScope, req coreexecutionv2.InvokeRequest) (map[string]any, error) {
	targetID := stringValue(req.Input, "target_id")
	if targetID == "" {
		binding, err := r.store.Read(ctx, scope, "binding", req.BindingID, req.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		targetID = stringValue(binding.Payload, "target_id")
	}
	if !coreworkload.ValidUUID(targetID) {
		return nil, ErrRuntimeConflict
	}
	targetRevision := uintValue(req.Input, "target_revision")
	if targetRevision == 0 {
		targetRevision = 1
	}
	record, err := r.store.Read(ctx, scope, "target", targetID, targetRevision)
	if err != nil {
		return nil, err
	}
	target, err := targetSettingsFromMap(record.Payload["target_settings"])
	if err != nil {
		return nil, ErrRuntimeConflict
	}
	credentialID := stringValue(record.Payload, "credential_id")
	credentialRevision := uintValue(record.Payload, "credential_revision")
	if credentialID == "" || credentialRevision == 0 {
		return nil, ErrRuntimeConflict
	}
	actualRevision, err := r.credentialRevision(ctx, scope, credentialID)
	if err != nil || actualRevision != credentialRevision {
		return nil, ErrRuntimeConflict
	}
	credential, err := r.credentials.ResolveCredentialScoped(ctx, scope, credentialID)
	if err != nil || credential.ReferenceID != credentialID {
		return nil, ErrRuntimeConflict
	}
	inspection, err := r.inspector.Inspect(ctx, target, credential)
	if err != nil || inspection.State == "" {
		return nil, ErrUnavailable
	}
	return observationMap(targetID, targetRevision, inspection), nil
}

func (r *Runtime) credentialRevision(ctx context.Context, scope coretask.OwnerScope, reference string) (uint64, error) {
	if r == nil || r.revisionResolver == nil {
		return 0, ErrRuntimeNotReady
	}
	return r.revisionResolver(ctx, scope, reference)
}

func (r *Runtime) planFromRecords(planRecord, targetRecord coreexecutionv2.Record, materialized ...any) (coreworkload.Plan, error) {
	rawTarget := targetRecord.Payload["target_settings"]
	if len(materialized) > 0 && materialized[0] != nil {
		rawTarget = materialized[0]
	}
	target, err := targetSettingsFromMap(rawTarget)
	if err != nil {
		return coreworkload.Plan{}, ErrRuntimeConflict
	}
	credentialID := stringValue(targetRecord.Payload, "credential_id")
	credentialRevision := uintValue(targetRecord.Payload, "credential_revision")
	if credentialID == "" || credentialRevision == 0 || !coreworkload.ValidUUID(credentialID) {
		return coreworkload.Plan{}, ErrRuntimeConflict
	}
	commands, ok := stringSliceValue(planRecord.Payload["command_steps"])
	if !ok || len(commands) == 0 {
		// Execution plans are compiled before they reach the provider. Reject a
		// plan that only contains a recipe label instead of an immutable typed
		// command set; never turn caller text into a shell request here.
		return coreworkload.Plan{}, ErrRuntimeConflict
	}
	for _, command := range commands {
		if strings.TrimSpace(command) == "" || len(command) > 4096 || strings.ContainsAny(command, "\r\n\x00") {
			return coreworkload.Plan{}, ErrRuntimeConflict
		}
	}
	if recipeID := stringValue(planRecord.Payload, "recipe_id"); recipeID != "" {
		compiled, compileErr := coreexecutionv2.CompileApprovedPlan(recipeID, stringValue(planRecord.Payload, "intent"), stringValue(planRecord.Payload, "purpose"))
		if compileErr != nil || stringValue(planRecord.Payload, "recipe_digest") != compiled.RecipeDigest || stringValue(planRecord.Payload, "command_steps_digest") != compiled.CommandStepsDigest || len(compiled.Commands) != len(commands) {
			return coreworkload.Plan{}, ErrRuntimeConflict
		}
		for i := range compiled.Commands {
			if commands[i] != compiled.Commands[i] {
				return coreworkload.Plan{}, ErrRuntimeConflict
			}
		}
	}
	digest := strings.TrimSpace(planRecord.Digest)
	if !coreworkload.ValidDigest(digest) {
		return coreworkload.Plan{}, ErrRuntimeConflict
	}
	return coreworkload.Plan{ID: planRecord.ID, Revision: planRecord.Revision, Digest: digest, Summary: stringValue(planRecord.Payload, "intent"), CommandSteps: commands, TargetKind: target.Identity.Kind, Target: target, ExpiresAt: r.now().UTC().Add(time.Hour), SecretGrantRefs: []coreworkload.SecretGrantRef{{ReferenceID: credentialID, Purpose: coreconfirmation.SecretPurposeAWSCredential, BindingDigest: coreconfirmation.Digest(strings.Repeat("a", 64))}}}, nil
}

func isComputeReservation(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	kind, _ := payload["kind"].(string)
	if strings.EqualFold(strings.TrimSpace(kind), "aws_compute_reservation") {
		return true
	}
	_, ok := payload["compute_reservation"]
	return ok
}

// validateReconcileBinding repeats the neutral Service's authorization fence
// at the provider boundary.  Runtime must not create a dispatch intent for a
// caller that presents an unrelated stage or confirmation, even if this
// provider is called directly by a composition test or a future adapter.
func (r *Runtime) validateReconcileBinding(ctx context.Context, scope coretask.OwnerScope, req coreexecutionv2.ReconcileRequest, run coreexecutionv2.Record) (coreexecutionv2.Record, coreexecutionv2.Record, error) {
	if stringValue(run.Payload, "stage_id") != req.StageID || stringValue(run.Payload, "confirmation_id") == "" {
		return coreexecutionv2.Record{}, coreexecutionv2.Record{}, ErrRuntimeConflict
	}
	stage, err := r.store.Read(ctx, scope, "stage", req.StageID, 0)
	if err != nil {
		return coreexecutionv2.Record{}, coreexecutionv2.Record{}, err
	}
	if stage.OwnerID != scope.OwnerID || stage.AccountGeneration != scope.AccountGeneration || stage.ID != req.StageID || stringValue(stage.Payload, "run_id") != req.RunID || stringValue(stage.Payload, "confirmation_id") != stringValue(run.Payload, "confirmation_id") || stringValue(stage.Payload, "plan_id") != stringValue(run.Payload, "plan_id") || stringValue(stage.Payload, "operation") != stringValue(run.Payload, "operation") || stage.Status == "waiting_user" {
		return coreexecutionv2.Record{}, coreexecutionv2.Record{}, ErrRuntimeConflict
	}
	confirmationID := stringValue(run.Payload, "confirmation_id")
	if !coreworkload.ValidUUID(confirmationID) || stringValue(stage.Payload, "confirmation_id") != confirmationID {
		return coreexecutionv2.Record{}, coreexecutionv2.Record{}, ErrRuntimeConflict
	}
	confirmation, err := r.store.Read(ctx, scope, "confirmation", confirmationID, 0)
	if err != nil {
		return coreexecutionv2.Record{}, coreexecutionv2.Record{}, err
	}
	if confirmation.OwnerID != scope.OwnerID || confirmation.AccountGeneration != scope.AccountGeneration || confirmation.ID != confirmationID || confirmation.Status != "confirmed" || stringValue(confirmation.Payload, "state") != "confirmed" || stringValue(confirmation.Payload, "run_id") != req.RunID || stringValue(confirmation.Payload, "stage_id") != req.StageID {
		return coreexecutionv2.Record{}, coreexecutionv2.Record{}, ErrRuntimeConflict
	}
	return stage, confirmation, nil
}

// ensureProvisionIntent writes a durable dispatch fence before the first
// CloudFormation CreateChangeSet call.  The intent's existence means the
// external mutation may have happened even when the process died before a
// response or the neutral run CAS; every retry therefore uses Reconcile.
// Store.Create provides the single-writer race fence for concurrent retries.
func (r *Runtime) ensureProvisionIntent(ctx context.Context, scope coretask.OwnerScope, req coreexecutionv2.ReconcileRequest, run, stage, confirmation, targetRecord coreexecutionv2.Record) (bool, error) {
	intentID := deterministicID(scope, "execution-v2-provision-intent", req.RunID+"\x00"+req.StageID)
	operation := stringValue(run.Payload, "operation")
	planID := stringValue(run.Payload, "plan_id")
	intentPayload := map[string]any{
		"kind":                  "compute_reservation_provision",
		"run_id":                req.RunID,
		"run_revision":          run.Revision,
		"stage_id":              req.StageID,
		"stage_revision":        stage.Revision,
		"confirmation_id":       stringValue(run.Payload, "confirmation_id"),
		"confirmation_revision": confirmation.Revision,
		"plan_id":               planID,
		"plan_revision":         uintValue(run.Payload, "plan_revision"),
		"operation":             operation,
		"target_id":             targetRecord.ID,
		"target_revision":       targetRecord.Revision,
		"request_digest": runtimeDigest(map[string]any{
			"owner_id": scope.OwnerID, "account_generation": scope.AccountGeneration, "run_id": req.RunID, "stage_id": req.StageID, "confirmation_id": stringValue(run.Payload, "confirmation_id"),
			"plan_id": planID, "operation": operation, "target_id": targetRecord.ID, "target_revision": targetRecord.Revision, "target_digest": targetRecord.Digest,
		}),
	}
	existing, err := r.store.Read(ctx, scope, "dispatch_intent", intentID, 0)
	if err == nil {
		if !provisionIntentMatches(existing, scope, intentPayload) {
			return false, ErrRuntimeConflict
		}
		return true, nil
	}
	if !errors.Is(err, coreexecutionv2.ErrNotFound) {
		return false, err
	}
	now := r.now().UTC()
	intent := coreexecutionv2.Record{OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, Kind: "dispatch_intent", ID: intentID, Revision: 1, Status: "dispatching", Digest: runtimeDigest(intentPayload), Payload: intentPayload, CreatedAt: now, UpdatedAt: now}
	if _, err = r.store.Create(ctx, intent); err == nil {
		return false, nil
	} else if !errors.Is(err, coreexecutionv2.ErrConflict) {
		return false, err
	}
	// Another reconciler won the insert race. Re-read and continue through
	// provider Reconcile; never fall back to Create after a conflict.
	existing, err = r.store.Read(ctx, scope, "dispatch_intent", intentID, 0)
	if err != nil {
		return false, err
	}
	if !provisionIntentMatches(existing, scope, intentPayload) {
		return false, ErrRuntimeConflict
	}
	return true, nil
}

func provisionIntentMatches(record coreexecutionv2.Record, scope coretask.OwnerScope, expected map[string]any) bool {
	if record.OwnerID != scope.OwnerID || record.AccountGeneration != scope.AccountGeneration || record.Kind != "dispatch_intent" || record.Status != "dispatching" && record.Status != "accepted" && record.Status != "uncertain" {
		return false
	}
	for _, key := range []string{"kind", "run_id", "stage_id", "confirmation_id", "plan_id", "operation", "target_id", "request_digest"} {
		if stringValue(record.Payload, key) != stringValue(expected, key) {
			return false
		}
	}
	return uintValue(record.Payload, "target_revision") == uintValue(expected, "target_revision") && uintValue(record.Payload, "plan_revision") == uintValue(expected, "plan_revision")
}

// materializeReservation performs the only mutation in the reservation
// workflow.  The first reconcile calls Create exactly once for a fresh run;
// it records provisioning_started even for an uncertain response.  Every
// later call is Reconcile-only, so a lost CloudFormation response cannot turn
// into a second EC2 stack request.
func (r *Runtime) materializeReservation(ctx context.Context, scope coretask.OwnerScope, req coreexecutionv2.ReconcileRequest, run, stage, confirmation coreexecutionv2.Record, targetRecord coreexecutionv2.Record) (coreworkload.TargetSettings, map[string]any, error) {
	envelope := map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "provisioning_started": true}
	if r == nil || r.provisioner == nil || !r.provisioner.Ready() {
		envelope["status"], envelope["reason"] = "uncertain", "provisioner_unavailable"
		return coreworkload.TargetSettings{}, envelope, ErrRuntimeNotReady
	}
	reservation, ok := targetRecord.Payload["compute_reservation"].(map[string]any)
	if !ok {
		// PostgreSQL JSON decoders return map[string]any; typed tests may use a
		// map alias, so marshal/unmarshal once to retain the same contract.
		encoded, marshalErr := json.Marshal(targetRecord.Payload["compute_reservation"])
		if marshalErr == nil {
			_ = json.Unmarshal(encoded, &reservation)
		}
	}
	if reservation == nil {
		envelope["status"], envelope["reason"] = "uncertain", "reservation_missing"
		return coreworkload.TargetSettings{}, envelope, ErrRuntimeConflict
	}
	credentialID := stringValue(targetRecord.Payload, "credential_id")
	credentialRevision := uintValue(targetRecord.Payload, "credential_revision")
	if !coreworkload.ValidUUID(credentialID) || credentialRevision == 0 {
		envelope["status"], envelope["reason"] = "uncertain", "credential_binding_invalid"
		return coreworkload.TargetSettings{}, envelope, ErrRuntimeConflict
	}
	actualRevision, revisionErr := r.credentialRevision(ctx, scope, credentialID)
	if revisionErr != nil || actualRevision != credentialRevision {
		envelope["status"], envelope["reason"] = "uncertain", "credential_revision_conflict"
		return coreworkload.TargetSettings{}, envelope, ErrRuntimeConflict
	}
	credential, credentialErr := r.credentials.ResolveCredentialScoped(ctx, scope, credentialID)
	if credentialErr != nil || credential.ReferenceID != credentialID || credential.AccountID != stringValue(targetRecord.Payload, "account_id") || credential.Region != stringValue(targetRecord.Payload, "region") {
		envelope["status"], envelope["reason"] = "uncertain", "credential_precondition_failed"
		return coreworkload.TargetSettings{}, envelope, ErrRuntimeConflict
	}
	reservationDigest := strings.TrimSpace(targetRecord.Digest)
	if !coreworkload.ValidDigest(reservationDigest) {
		envelope["status"], envelope["reason"] = "uncertain", "reservation_digest_invalid"
		return coreworkload.TargetSettings{}, envelope, ErrRuntimeConflict
	}
	request := ComputeProvisionRequest{
		OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, ReservationTargetID: targetRecord.ID, ReservationDigest: reservationDigest,
		CredentialID: credentialID, CredentialRevision: credentialRevision, AccountID: credential.AccountID, Region: credential.Region,
		InstanceType: stringValue(reservation, "instance_type"), AvailabilityZone: stringValue(reservation, "availability_zone"),
		VolumeGiB: uintValue(reservation, "volume_gib"), AMIParameter: stringValue(reservation, "ami_parameter"),
		PublicIP: boolValueDefault(reservation, "public_ip", true), PublicInbound: boolValueDefault(reservation, "public_inbound", false),
	}
	started, intentErr := r.ensureProvisionIntent(ctx, scope, req, run, stage, confirmation, targetRecord)
	if intentErr != nil {
		envelope["status"], envelope["reason"] = "uncertain", "provision_intent_unavailable"
		return coreworkload.TargetSettings{}, envelope, intentErr
	}
	envelope["provision_intent_id"] = deterministicID(scope, "execution-v2-provision-intent", req.RunID+"\x00"+req.StageID)
	var result ComputeProvisionResult
	var provisionErr error
	if started {
		result, provisionErr = r.provisioner.Reconcile(ctx, request, credential)
	} else {
		result, provisionErr = r.provisioner.Create(ctx, request, credential)
	}
	envelope["provisioning"] = provisionResultMap(result)
	if provisionErr != nil {
		switch {
		case errors.Is(provisionErr, ErrProvisionPending):
			envelope["status"], envelope["reason"] = "running", "provision_pending"
		case errors.Is(provisionErr, ErrProvisionUncertain):
			envelope["status"], envelope["reason"] = "uncertain", "provision_outcome_uncertain"
		default:
			envelope["status"], envelope["reason"] = "uncertain", "provision_failed"
		}
		return coreworkload.TargetSettings{}, envelope, provisionErr
	}
	target := coreworkload.TargetSettings{
		Identity: coreworkload.TargetIdentity{Kind: coreworkload.TargetAWSEC2SSM, AccountID: credential.AccountID, Region: credential.Region, InstanceID: result.InstanceID},
		Region:   credential.Region, AccountID: credential.AccountID, InstanceID: result.InstanceID,
		EC2DocumentVersion: "1", EC2SystemdService: "dirextalk-agent.service",
		RequiredInstanceTags: map[string]string{"dirextalk-managed": "execution-v2"},
	}
	if target.ValidateProviderTarget(coreworkload.TargetAWSEC2SSM) != nil || result.InstanceID == "" {
		envelope["status"], envelope["reason"] = "running", "ssm_registration_pending"
		return coreworkload.TargetSettings{}, envelope, ErrProvisionPending
	}
	inspection, inspectErr := r.inspector.Inspect(ctx, target, credential)
	if inspectErr != nil || inspection.State != "ready" {
		envelope["status"], envelope["reason"] = "running", "ssm_registration_pending"
		return coreworkload.TargetSettings{}, envelope, ErrProvisionPending
	}
	envelope["materialized_target"] = targetSettingsMap(target)
	envelope["status"] = "running"
	return target, envelope, nil
}

func provisionResultMap(result ComputeProvisionResult) map[string]any {
	cleanup := map[string]any{"stack_name": result.StackName, "stack_id": result.StackID, "reservation_target_id": result.ReservationTargetID, "managed_tag": "dirextalk-managed=execution-v2", "stack_prefix": "dirextalk-exec-"}
	return map[string]any{
		"stack_name": result.StackName, "stack_id": result.StackID, "status": result.Status,
		"instance_id": result.InstanceID, "public_ip": result.PublicIP, "availability_zone": result.AvailabilityZone,
		"instance_type": result.InstanceType, "pending_reason": result.PendingReason, "resource_ids": result.ResourceIDs, "cleanup_identifiers": cleanup,
	}
}

func boolValueAny(value any) bool {
	v, _ := value.(bool)
	return v
}

func boolValueDefault(values map[string]any, key string, fallback bool) bool {
	if value, ok := values[key]; ok {
		if v, ok := value.(bool); ok {
			return v
		}
	}
	return fallback
}

func (r *Runtime) reconcileReservationDestroy(ctx context.Context, scope coretask.OwnerScope, req coreexecutionv2.ReconcileRequest, run coreexecutionv2.Record, targetRecord coreexecutionv2.Record, plan coreworkload.Plan, finish func(map[string]any) map[string]any) (map[string]any, error) {
	if r.provisioner == nil || !r.provisioner.Ready() {
		return finish(map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": "uncertain", "reason": "provisioner_unavailable"}), nil
	}
	request, credential, err := r.reservationRequest(ctx, scope, targetRecord)
	if err != nil {
		return finish(map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": "uncertain", "reason": "credential_precondition_failed"}), nil
	}
	started := boolValueAny(run.Payload["provisioning_destroy_started"])
	if !started {
		if err := r.provisioner.Destroy(ctx, request, credential); err != nil {
			return finish(map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": "uncertain", "reason": "provision_destroy_uncertain", "provisioning_destroy_started": true}), nil
		}
		// The DeleteStack response only proves acceptance. Persist the fence and
		// require a later readback before terminalizing the run.
		return finish(map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": "uncertain", "reason": "provision_destroy_reconcile_required", "provisioning_destroy_started": true}), nil
	}
	result, reconcileErr := r.provisioner.ReconcileDestroy(ctx, request, credential)
	if reconcileErr != nil {
		status, reason := "uncertain", "provision_destroy_uncertain"
		if errors.Is(reconcileErr, ErrProvisionPending) {
			status, reason = "running", "provision_destroy_pending"
		}
		return finish(map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": status, "reason": reason, "provisioning_destroy_started": true, "provisioning": provisionResultMap(result)}), nil
	}
	readback := coreworkload.Readback{TargetKind: plan.TargetKind, WorkloadID: targetRecord.ID, State: "destroyed", Identity: plan.Target.Identity, ProviderVersion: "cloudformation-v1", At: r.now().UTC()}
	return finish(runtimeResult(req, "succeeded", readback)), nil
}

func (r *Runtime) reservationRequest(ctx context.Context, scope coretask.OwnerScope, targetRecord coreexecutionv2.Record) (ComputeProvisionRequest, workaws.CredentialHandle, error) {
	reservation, ok := targetRecord.Payload["compute_reservation"].(map[string]any)
	if !ok {
		encoded, marshalErr := json.Marshal(targetRecord.Payload["compute_reservation"])
		if marshalErr != nil || json.Unmarshal(encoded, &reservation) != nil {
			return ComputeProvisionRequest{}, workaws.CredentialHandle{}, ErrRuntimeConflict
		}
	}
	credentialID := stringValue(targetRecord.Payload, "credential_id")
	credentialRevision := uintValue(targetRecord.Payload, "credential_revision")
	if !coreworkload.ValidUUID(credentialID) || credentialRevision == 0 || !coreworkload.ValidDigest(targetRecord.Digest) {
		return ComputeProvisionRequest{}, workaws.CredentialHandle{}, ErrRuntimeConflict
	}
	actualRevision, err := r.credentialRevision(ctx, scope, credentialID)
	if err != nil || actualRevision != credentialRevision {
		return ComputeProvisionRequest{}, workaws.CredentialHandle{}, ErrRuntimeConflict
	}
	credential, err := r.credentials.ResolveCredentialScoped(ctx, scope, credentialID)
	if err != nil || credential.ReferenceID != credentialID || credential.AccountID != stringValue(targetRecord.Payload, "account_id") || credential.Region != stringValue(targetRecord.Payload, "region") {
		return ComputeProvisionRequest{}, workaws.CredentialHandle{}, ErrRuntimeConflict
	}
	request := ComputeProvisionRequest{OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, ReservationTargetID: targetRecord.ID, ReservationDigest: targetRecord.Digest, CredentialID: credentialID, CredentialRevision: credentialRevision, AccountID: credential.AccountID, Region: credential.Region, InstanceType: stringValue(reservation, "instance_type"), AvailabilityZone: stringValue(reservation, "availability_zone"), VolumeGiB: uintValue(reservation, "volume_gib"), AMIParameter: stringValue(reservation, "ami_parameter"), PublicIP: boolValueDefault(reservation, "public_ip", true), PublicInbound: boolValueDefault(reservation, "public_inbound", false)}
	return request, credential, nil
}

func (r *Runtime) operationFromRun(scope coretask.OwnerScope, run coreexecutionv2.Record, req coreexecutionv2.ReconcileRequest, plan coreworkload.Plan, kind coreworkload.OperationKind, targetID string) coreworkload.Operation {
	return coreworkload.Operation{ID: deterministicID(scope, "execution-v2-operation", run.ID+"\x00"+req.StageID), WorkloadID: targetID, PlanID: plan.ID, Kind: kind, PlanRevision: plan.Revision, PlanDigest: plan.Digest, TargetKind: plan.TargetKind, TaskID: deterministicID(scope, "execution-v2-task", run.ID+"\x00"+req.StageID), ConfirmationID: stringValue(run.Payload, "confirmation_id"), Status: coreworkload.OperationRunning, Revision: 1, CreatedAt: r.now().UTC(), UpdatedAt: r.now().UTC()}
}

func (r *Runtime) operationFromBinding(scope coretask.OwnerScope, req coreexecutionv2.InvokeRequest, plan coreworkload.Plan, destroy bool, targetID string) coreworkload.Operation {
	kind := coreworkload.OperationApply
	if destroy {
		kind = coreworkload.OperationDestroy
	}
	now := r.now().UTC()
	return coreworkload.Operation{ID: deterministicID(scope, "execution-v2-binding-operation", req.BindingID+"\x00"+req.IdempotencyKey), WorkloadID: targetID, PlanID: plan.ID, Kind: kind, PlanRevision: plan.Revision, PlanDigest: plan.Digest, TargetKind: plan.TargetKind, TaskID: deterministicID(scope, "execution-v2-binding-task", req.BindingID+"\x00"+req.IdempotencyKey), ConfirmationID: deterministicID(scope, "execution-v2-binding-confirmation", req.BindingID), Status: coreworkload.OperationRunning, Revision: 1, CreatedAt: now, UpdatedAt: now}
}

func runtimeResult(req coreexecutionv2.ReconcileRequest, status string, readback coreworkload.Readback) map[string]any {
	return map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": status, "target_id": readback.Identity.InstanceID, "observation": redactedReadback(readback)}
}

func statusForOperation(kind coreworkload.OperationKind, readback coreworkload.Readback) string {
	if desiredReadback(readback, kind) {
		return "succeeded"
	}
	return "uncertain"
}

func desiredReadback(readback coreworkload.Readback, kind coreworkload.OperationKind) bool {
	if readback.WorkloadID == "" {
		return false
	}
	if kind == coreworkload.OperationDestroy {
		return readback.State == "destroyed"
	}
	return readback.State == "ready"
}

func redactedReadback(readback coreworkload.Readback) map[string]any {
	return map[string]any{"target_kind": string(readback.TargetKind), "workload_id": readback.WorkloadID, "state": readback.State, "identity": map[string]any{"kind": string(readback.Identity.Kind), "region": readback.Identity.Region, "account_id": readback.Identity.AccountID, "instance_id": readback.Identity.InstanceID, "cluster": readback.Identity.Cluster, "service": readback.Identity.Service}, "provider_version": readback.ProviderVersion, "observed_at": readback.At.UTC().Format(time.RFC3339Nano)}
}

func terminalRunStatus(value string) bool {
	switch value {
	case "succeeded", "failed", "canceled", "rejected", "expired":
		return true
	default:
		return false
	}
}

func stringSliceValue(raw any) ([]string, bool) {
	switch values := raw.(type) {
	case []string:
		return append([]string(nil), values...), true
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		return nil, false
	}
}

func runtimeDigest(value any) string {
	bytes, _ := json.Marshal(value)
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

var _ RunReconciler = (*Runtime)(nil)
var _ BindingInvoker = (*Runtime)(nil)

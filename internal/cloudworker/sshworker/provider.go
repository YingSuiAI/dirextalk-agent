package sshworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Provider struct {
	aws             AWS
	keys            KeyMaterial
	ssh             SSHExecutor
	store           Store
	target          ConnectionTargetResolver
	status          StatusSource
	now             func() time.Time
	pool            *Pool
	authorizeCreate CreateAuthorizer
	active          map[string]struct{}
}

// Pool serializes owner-wide Worker admission across credential revisions.
// SSH execution itself never holds this lock.
type Pool struct{ mu sync.Mutex }
type CreateAuthorizer func(context.Context, CredentialIdentity) error

func NewPool() *Pool { return &Pool{} }

func New(awsClient AWS, keys KeyMaterial, ssh SSHExecutor, store Store, status ...StatusSource) (*Provider, error) {
	return NewWithPool(awsClient, keys, ssh, store, NewPool(), func(context.Context, CredentialIdentity) error { return nil }, status...)
}

func NewWithPool(awsClient AWS, keys KeyMaterial, ssh SSHExecutor, store Store, pool *Pool, authorizeCreate CreateAuthorizer, status ...StatusSource) (*Provider, error) {
	if awsClient == nil || keys == nil || ssh == nil || store == nil || pool == nil || authorizeCreate == nil {
		return nil, ErrInvalid
	}
	var source StatusSource
	if len(status) > 0 {
		source = status[0]
	}
	return &Provider{aws: awsClient, keys: keys, ssh: ssh, store: store, target: PublicIPTarget{}, status: source, now: time.Now,
		pool: pool, authorizeCreate: authorizeCreate, active: make(map[string]struct{})}, nil
}

func (provider *Provider) Discover(ctx context.Context, credential CredentialIdentity) (Discovery, error) {
	if provider == nil || ctx == nil || credential.validate() != nil {
		return Discovery{}, ErrInvalid
	}
	discovery, err := provider.aws.Discover(ctx, credential)
	if err != nil || discovery.validate() != nil {
		return Discovery{}, errors.Join(ErrInvalid, err)
	}
	return discovery, nil
}

// ResolveIdleWorker performs the same instance read-back used by lease,
// without reserving or mutating either AWS or the local pool.
func (provider *Provider) ResolveIdleWorker(ctx context.Context, authority OwnerAuthority, credential CredentialIdentity, minVCPU, minMemoryGiB uint32, minVolumeGiB int32) (WorkerRecord, bool, error) {
	if provider == nil || ctx == nil || authority.validate() != nil || credential.validate() != nil || minVCPU == 0 || minMemoryGiB == 0 || minVolumeGiB < 8 {
		return WorkerRecord{}, false, ErrInvalid
	}
	workers, err := provider.store.ListWorkers(ctx)
	if err != nil {
		return WorkerRecord{}, false, err
	}
	for _, worker := range workers {
		if worker.authority() != authority || !sameLogicalCredential(worker.Credential, credential) || worker.Phase != WorkerIdle || worker.VCPU < minVCPU || worker.MemoryGiB < minMemoryGiB || worker.VolumeGiB < minVolumeGiB {
			continue
		}
		observed, found, observeErr := provider.aws.ObserveInstance(ctx, credential, worker.Instance.ID, resourceTags(worker.WorkerID, authority, worker.Credential, worker.CreationProof))
		if observeErr != nil {
			return WorkerRecord{}, false, observeErr
		}
		if found && observed.State == "running" && observed.PublicIP != "" {
			worker.Instance = observed
			return worker, true, nil
		}
	}
	return WorkerRecord{}, false, nil
}

// Execute leases an idle persistent Worker or creates one after confirmation.
// Task completion returns it to idle; it never destroys cloud resources.
func (provider *Provider) Execute(ctx context.Context, request ExecuteRequest) (ExecutionResult, error) {
	if provider == nil || ctx == nil || request.validate() != nil {
		return ExecutionResult{}, ErrInvalid
	}
	if request.ReportProgress != nil {
		if err := request.ReportProgress(ctx, "provisioning_worker", "Selecting or provisioning Worker"); err != nil {
			return ExecutionResult{}, err
		}
	}
	worker, execution, completed, resume, err := provider.lease(ctx, request)
	if err != nil {
		return ExecutionResult{}, err
	}
	if completed {
		return execution.Result, nil
	}
	if request.ReportProgress != nil {
		if err := request.ReportProgress(ctx, "connecting_worker", "Connecting to Worker"); err != nil {
			return ExecutionResult{}, errors.Join(err, provider.failExecution(ctx, &execution, &worker))
		}
	}

	privateKey, _, err := provider.keys.Ensure(ctx, worker.WorkerID)
	if err != nil {
		return ExecutionResult{}, errors.Join(err, provider.failExecution(ctx, &execution, &worker))
	}
	target, err := provider.target.Resolve(worker.Instance)
	if err != nil {
		return ExecutionResult{}, errors.Join(err, provider.failExecution(ctx, &execution, &worker))
	}
	result, runErr := provider.ssh.Execute(ctx, SSHRequest{ExecutionID: request.ExecutionID, Host: target, User: worker.SSHUser,
		PrivateKeyPath: privateKey, WorkerScript: request.WorkerScript, WorkerScriptSHA256: request.WorkerScriptSHA256,
		Runtime: request.Runtime, WorkspacePath: request.WorkspacePath, MaxWorkspaceBytes: request.MaxWorkspaceBytes, MaxResultBytes: request.MaxResultBytes, Sink: request.Sink,
		ResolveGuidance: request.ResolveGuidance, ReportProgress: request.ReportProgress,
		RecordCompletion: func(recordCtx context.Context) error {
			return provider.recordRemoteCompletion(recordCtx, &execution)
		}, Resume: resume, CollectOnly: execution.RemoteCompleted})
	if runErr != nil {
		deterministicCollectionFailure := errors.Is(runErr, ErrResultTooLarge) || errors.Is(runErr, ErrInvalid)
		if !deterministicCollectionFailure && (errors.Is(runErr, ErrAmbiguous) || errors.Is(runErr, errRetryableResultCollection)) {
			provider.pool.mu.Lock()
			delete(provider.active, execution.ExecutionID)
			provider.pool.mu.Unlock()
			return ExecutionResult{}, runErr
		}
		return ExecutionResult{}, errors.Join(runErr, provider.failExecution(ctx, &execution, &worker))
	}
	result.WorkerID = worker.WorkerID
	if request.Finalize != nil {
		if err := request.Finalize(ctx, worker.WorkerID, &result); err != nil {
			return result, errors.Join(err, provider.failExecution(ctx, &execution, &worker))
		}
	}
	completionPersisted, err := provider.completeExecution(ctx, &execution, &worker, result)
	if err != nil && !completionPersisted {
		return result, err
	}
	if err != nil {
		provider.pool.mu.Lock()
		_ = provider.reconcileTerminalWorkerReleaseLocked(ctx, execution, TaskCompleted)
		provider.pool.mu.Unlock()
	}
	return result, nil
}

// lease serializes only the pool decision and durable lease. SSH tasks run
// without holding poolMu, so separate Workers can execute concurrently.
func (provider *Provider) lease(ctx context.Context, request ExecuteRequest) (WorkerRecord, ExecutionRecord, bool, bool, error) {
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	execution, exists, err := provider.store.LoadExecution(ctx, request.ExecutionID)
	if err != nil {
		return WorkerRecord{}, ExecutionRecord{}, false, false, err
	}
	if exists && (execution.authority() != request.Authority || !sameLogicalCredential(execution.Credential, request.Credential)) {
		return WorkerRecord{}, ExecutionRecord{}, false, false, ErrIdentity
	}
	if exists && execution.Phase == TaskCompleted {
		_ = provider.reconcileTerminalWorkerReleaseLocked(ctx, execution, TaskCompleted)
		return WorkerRecord{}, execution, true, false, nil
	}
	if exists && execution.Phase == TaskFailed {
		reconcileErr := provider.reconcileTerminalWorkerReleaseLocked(ctx, execution, TaskFailed)
		return WorkerRecord{}, execution, false, false, errors.Join(ErrExecutionFailed, reconcileErr)
	}
	if _, running := provider.active[request.ExecutionID]; running {
		return WorkerRecord{}, ExecutionRecord{}, false, false, ErrBusy
	}
	resume := exists && execution.Phase == TaskRunning && execution.WorkerID != ""
	worker, err := provider.acquire(ctx, request, execution)
	if err != nil {
		return WorkerRecord{}, ExecutionRecord{}, false, false, err
	}
	if !resume {
		execution = ExecutionRecord{ExecutionID: request.ExecutionID, WorkerID: worker.WorkerID, OwnerID: request.Authority.OwnerID,
			AccountGeneration: request.Authority.AccountGeneration, Credential: request.Credential, Phase: TaskRunning}
		if err := provider.saveExecution(ctx, &execution); err != nil {
			_ = provider.releaseLocked(ctx, &worker, request.ExecutionID)
			return WorkerRecord{}, ExecutionRecord{}, false, false, err
		}
	}
	provider.active[request.ExecutionID] = struct{}{}
	return worker, execution, false, resume, nil
}

func (provider *Provider) acquire(ctx context.Context, request ExecuteRequest, prior ExecutionRecord) (WorkerRecord, error) {
	workers, err := provider.store.ListWorkers(ctx)
	if err != nil {
		return WorkerRecord{}, err
	}
	if prior.WorkerID != "" {
		for _, worker := range workers {
			if worker.authority() == request.Authority && sameLogicalCredential(worker.Credential, request.Credential) && worker.WorkerID == prior.WorkerID && worker.Phase == WorkerBusy && worker.CurrentExecutionID == request.ExecutionID && (!request.ReuseOnly || request.ReuseWorkerID == worker.WorkerID) {
				return worker, nil
			}
		}
		return WorkerRecord{}, ErrBusy
	}
	if request.ReuseOnly {
		for _, worker := range workers {
			if worker.WorkerID != request.ReuseWorkerID {
				continue
			}
			if worker.authority() != request.Authority || !sameLogicalCredential(worker.Credential, request.Credential) {
				return WorkerRecord{}, ErrIdentity
			}
			if worker.Phase != WorkerIdle || worker.VCPU < request.VCPU || worker.MemoryGiB < request.MemoryGiB || worker.VolumeGiB < request.VolumeGiB {
				return WorkerRecord{}, ErrBusy
			}
			observed, found, observeErr := provider.aws.ObserveInstance(ctx, request.Credential, worker.Instance.ID, resourceTags(worker.WorkerID, request.Authority, worker.Credential, worker.CreationProof))
			if observeErr != nil {
				return WorkerRecord{}, observeErr
			}
			if !found || observed.State != "running" || observed.PublicIP == "" {
				return WorkerRecord{}, ErrBusy
			}
			worker.Instance = observed
			worker.Phase = WorkerBusy
			worker.CurrentExecutionID = request.ExecutionID
			if err := provider.saveWorker(ctx, &worker); err != nil {
				return WorkerRecord{}, err
			}
			return worker, nil
		}
		return WorkerRecord{}, ErrBusy
	}
	for _, worker := range workers {
		if worker.WorkerID == request.ExecutionID && worker.authority() == request.Authority && worker.Credential == request.Credential && worker.Phase == WorkerProvisioning {
			if err := provider.authorizeCreate(ctx, request.Credential); err != nil {
				return WorkerRecord{}, errors.Join(err, provider.reconcileProvisioning(ctx, &worker))
			}
			return provider.create(ctx, request)
		}
	}
	for _, worker := range workers {
		if worker.WorkerID == request.ExecutionID {
			return WorkerRecord{}, ErrIdentity
		}
	}
	if err := provider.checkCreateCapacity(ctx, request.Authority, request.Credential, workers); err != nil {
		return WorkerRecord{}, err
	}
	if err := request.Confirmation.validate(); err != nil {
		return WorkerRecord{}, err
	}
	if err := provider.authorizeCreate(ctx, request.Credential); err != nil {
		return WorkerRecord{}, err
	}
	return provider.create(ctx, request)
}

func (provider *Provider) create(ctx context.Context, request ExecuteRequest) (WorkerRecord, error) {
	workerID := request.ExecutionID
	tags := resourceTags(workerID, request.Authority, request.Credential, request.Confirmation.Proof)
	keyName, groupName, clientToken := resourceNames(workerID)
	worker, exists, err := provider.store.LoadWorker(ctx, workerID)
	if err != nil {
		return WorkerRecord{}, err
	}
	if !exists {
		worker = WorkerRecord{WorkerID: workerID, OwnerID: request.Authority.OwnerID, AccountGeneration: request.Authority.AccountGeneration,
			Credential: request.Credential, CreationProof: request.Confirmation.Proof,
			Phase: WorkerProvisioning, SSHUser: request.Discovery.SSHUser, InstanceType: request.InstanceType, VCPU: request.VCPU, MemoryGiB: request.MemoryGiB, VolumeGiB: request.VolumeGiB, CreatedAt: provider.now().UTC()}
		worker.UpdatedAt = provider.now().UTC()
		if err := provider.store.SaveWorkerIntent(ctx, worker, func(ctx context.Context) error {
			return provider.authorizeCreate(ctx, request.Credential)
		}); err != nil {
			return WorkerRecord{}, err
		}
	}
	if worker.authority() != request.Authority || worker.Credential != request.Credential || worker.CreationProof != request.Confirmation.Proof {
		return WorkerRecord{}, ErrIdentity
	}
	privatePath, publicKey, err := provider.keys.Ensure(ctx, workerID)
	if err != nil || privatePath == "" || len(publicKey) == 0 {
		return WorkerRecord{}, errors.Join(ErrInvalid, err)
	}
	key, found, err := provider.aws.FindKeyPair(ctx, request.Credential, keyName, tags)
	if err != nil {
		return WorkerRecord{}, err
	}
	if !found {
		if err := provider.authorizeCreate(ctx, request.Credential); err != nil {
			return WorkerRecord{}, errors.Join(err, provider.reconcileProvisioning(ctx, &worker))
		}
		key, err = provider.aws.ImportKeyPair(ctx, request.Credential, request.Confirmation, keyName, publicKey, tags)
		if err != nil {
			key, found, _ = provider.aws.FindKeyPair(ctx, request.Credential, keyName, tags)
			if !found {
				return WorkerRecord{}, errors.Join(ErrAmbiguous, err)
			}
		}
	}
	worker.KeyPair = key
	if err := provider.saveWorker(ctx, &worker); err != nil {
		return WorkerRecord{}, err
	}
	group, found, err := provider.aws.FindSecurityGroup(ctx, request.Credential, groupName, tags)
	if err != nil {
		return WorkerRecord{}, err
	}
	if !found {
		if err := provider.authorizeCreate(ctx, request.Credential); err != nil {
			return WorkerRecord{}, errors.Join(err, provider.reconcileProvisioning(ctx, &worker))
		}
		group, err = provider.aws.CreateSecurityGroup(ctx, request.Credential, request.Confirmation, groupName, request.Discovery.VPCID, tags)
		if err != nil {
			group, found, _ = provider.aws.FindSecurityGroup(ctx, request.Credential, groupName, tags)
			if !found {
				return WorkerRecord{}, errors.Join(ErrAmbiguous, err)
			}
		}
	}
	worker.SecurityGroup = group
	if err := provider.saveWorker(ctx, &worker); err != nil {
		return WorkerRecord{}, err
	}
	if err := provider.authorizeCreate(ctx, request.Credential); err != nil {
		return WorkerRecord{}, errors.Join(err, provider.reconcileProvisioning(ctx, &worker))
	}
	if err := provider.aws.AuthorizeSSH(ctx, request.Credential, request.Confirmation, group, request.Discovery.PublicEgressCIDR); err != nil {
		return WorkerRecord{}, err
	}
	instance, found, err := provider.aws.FindInstance(ctx, request.Credential, clientToken, tags)
	if err != nil {
		return WorkerRecord{}, err
	}
	if !found {
		if err := provider.authorizeCreate(ctx, request.Credential); err != nil {
			return WorkerRecord{}, errors.Join(err, provider.reconcileProvisioning(ctx, &worker))
		}
		instance, err = provider.aws.RunInstance(ctx, request.Credential, request.Confirmation, LaunchRequest{WorkerID: workerID, ClientToken: clientToken,
			Discovery: request.Discovery, InstanceType: request.InstanceType, VolumeGiB: request.VolumeGiB, KeyName: key.Name, SecurityGroupID: group.ID, Tags: tags})
		if err != nil {
			instance, found, _ = provider.aws.FindInstance(ctx, request.Credential, clientToken, tags)
			if !found {
				return WorkerRecord{}, errors.Join(ErrAmbiguous, err)
			}
		}
	}
	worker.Instance = instance
	if err := provider.saveWorker(ctx, &worker); err != nil {
		return WorkerRecord{}, err
	}
	if err := provider.waitRunning(ctx, &worker); err != nil {
		return WorkerRecord{}, err
	}
	worker.Phase, worker.CurrentExecutionID = WorkerBusy, request.ExecutionID
	if err := provider.saveWorker(ctx, &worker); err != nil {
		return WorkerRecord{}, err
	}
	return worker, nil
}

// reconcileProvisioning records only resources that already exist under the
// stale intent's exact tags. It never creates or resumes execution.
func (provider *Provider) reconcileProvisioning(ctx context.Context, worker *WorkerRecord) error {
	keyName, groupName, clientToken := resourceNames(worker.WorkerID)
	tags := resourceTags(worker.WorkerID, worker.authority(), worker.Credential, worker.CreationProof)
	var result error
	if worker.KeyPair.ID == "" {
		key, found, err := provider.aws.FindKeyPair(ctx, worker.Credential, keyName, tags)
		result = errors.Join(result, err)
		if err == nil && found {
			worker.KeyPair = key
			result = errors.Join(result, provider.saveWorker(ctx, worker))
		}
	}
	if worker.SecurityGroup.ID == "" {
		group, found, err := provider.aws.FindSecurityGroup(ctx, worker.Credential, groupName, tags)
		result = errors.Join(result, err)
		if err == nil && found {
			worker.SecurityGroup = group
			result = errors.Join(result, provider.saveWorker(ctx, worker))
		}
	}
	if worker.Instance.ID == "" {
		instance, found, err := provider.aws.FindInstance(ctx, worker.Credential, clientToken, tags)
		result = errors.Join(result, err)
		if err == nil && found {
			worker.Instance = instance
			result = errors.Join(result, provider.saveWorker(ctx, worker))
		}
	}
	return result
}

func (provider *Provider) waitRunning(ctx context.Context, worker *WorkerRecord) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		instance, found, err := provider.aws.ObserveInstance(ctx, worker.Credential, worker.Instance.ID, resourceTags(worker.WorkerID, worker.authority(), worker.Credential, worker.CreationProof))
		if err != nil {
			return err
		}
		if !found || instance.State == "terminated" || instance.State == "shutting-down" {
			return fmt.Errorf("worker ended before SSH: %w", ErrAmbiguous)
		}
		if instance.State == "running" && strings.TrimSpace(instance.PublicIP) != "" {
			worker.Instance = instance
			return provider.saveWorker(ctx, worker)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (provider *Provider) releaseLocked(ctx context.Context, worker *WorkerRecord, executionID string) error {
	if executionID != "" && worker.CurrentExecutionID != executionID {
		return ErrIdentity
	}
	worker.Phase, worker.CurrentExecutionID = WorkerIdle, ""
	return provider.saveWorker(ctx, worker)
}

func (provider *Provider) failExecution(ctx context.Context, execution *ExecutionRecord, worker *WorkerRecord) error {
	cleanupCtx := ctx
	cancel := func() {}
	if ctx.Err() != nil {
		cleanupCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	}
	defer cancel()
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	delete(provider.active, execution.ExecutionID)
	execution.Phase = TaskFailed
	return errors.Join(provider.saveExecution(cleanupCtx, execution), provider.releaseLocked(cleanupCtx, worker, execution.ExecutionID))
}

func (provider *Provider) completeExecution(ctx context.Context, execution *ExecutionRecord, worker *WorkerRecord, result ExecutionResult) (bool, error) {
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	delete(provider.active, execution.ExecutionID)
	execution.Result, execution.Phase = result, TaskCompleted
	if err := provider.saveExecution(ctx, execution); err != nil {
		return false, errors.Join(ErrAmbiguous, err)
	}
	// Once the remote result is durable, releasing the retained Worker is
	// bookkeeping. A transient release failure must not reclassify completed
	// remote work as a failed workload.
	return true, provider.releaseLocked(ctx, worker, execution.ExecutionID)
}

func (provider *Provider) recordRemoteCompletion(ctx context.Context, execution *ExecutionRecord) error {
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	if execution.RemoteCompleted {
		return nil
	}
	if execution.Phase != TaskRunning {
		return ErrIdentity
	}
	execution.RemoteCompleted = true
	if err := provider.saveExecution(ctx, execution); err != nil {
		execution.RemoteCompleted = false
		return err
	}
	return nil
}

func (provider *Provider) reconcileTerminalWorkerReleaseLocked(ctx context.Context, execution ExecutionRecord, phase TaskPhase) error {
	if phase != TaskCompleted && phase != TaskFailed || execution.Phase != phase || execution.WorkerID == "" {
		return ErrInvalid
	}
	worker, found, err := provider.store.LoadWorker(ctx, execution.WorkerID)
	if err != nil {
		return err
	}
	if !found {
		return ErrIdentity
	}
	if worker.authority() != execution.authority() || !sameLogicalCredential(worker.Credential, execution.Credential) {
		return ErrIdentity
	}
	if worker.Phase == WorkerIdle && worker.CurrentExecutionID == "" {
		return nil
	}
	if worker.Phase != WorkerBusy || worker.CurrentExecutionID != execution.ExecutionID {
		return ErrIdentity
	}
	next := worker
	return provider.releaseLocked(ctx, &next, execution.ExecutionID)
}

// CheckCreateCapacity reports whether one more retained Worker may be created
// after idle reuse has already failed. It includes live owner-tagged instances
// that are not present in the local Worker store.
func (provider *Provider) CheckCreateCapacity(ctx context.Context, authority OwnerAuthority, credential CredentialIdentity) error {
	if provider == nil || ctx == nil || authority.validate() != nil || credential.validate() != nil {
		return ErrInvalid
	}
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	workers, err := provider.store.ListWorkers(ctx)
	if err != nil {
		return err
	}
	return provider.checkCreateCapacity(ctx, authority, credential, workers)
}

func (provider *Provider) checkCreateCapacity(ctx context.Context, authority OwnerAuthority, credential CredentialIdentity, workers []WorkerRecord) error {
	active := 0
	tracked := make(map[string]struct{})
	for _, worker := range workers {
		if worker.authority() != authority || worker.Phase == WorkerDestroyed || (worker.Phase == WorkerDestroying && worker.ResourcesDestroyed) {
			continue
		}
		active++
		if worker.Credential.AccountID == credential.AccountID && worker.Credential.Region == credential.Region && worker.Instance.ID != "" {
			tracked[worker.Instance.ID] = struct{}{}
		}
	}
	live, err := provider.aws.ListInstances(ctx, credential, poolTags(authority))
	if err != nil {
		return err
	}
	for _, instance := range live {
		if _, ok := tracked[instance.ID]; !ok {
			active++
		}
	}
	if active >= MaxWorkers {
		return ErrCapacity
	}
	return nil
}

func (provider *Provider) DestroyWorker(ctx context.Context, request DestroyRequest) error {
	if err := provider.DestroyWorkerResources(ctx, request); err != nil {
		return err
	}
	return provider.FinalizeWorkerDestroy(ctx, request)
}

func (provider *Provider) DestroyWorkerResources(ctx context.Context, request DestroyRequest) error {
	if provider == nil || ctx == nil || request.Authorization.validate() != nil || request.Identity.authority().validate() != nil || request.Identity.Credential.validate() != nil || !validID(request.Identity.WorkerID) {
		if request.Authorization.validate() != nil {
			return ErrNotAuthorized
		}
		return ErrInvalid
	}
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	worker, found, err := provider.store.LoadWorker(ctx, request.Identity.WorkerID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if worker.authority() != request.Identity.authority() || worker.Credential != request.Identity.Credential || worker.Instance.ID != request.Identity.InstanceID || worker.KeyPair.ID != request.Identity.KeyPairID ||
		worker.SecurityGroup.ID != request.Identity.SecurityGroupID {
		return ErrIdentity
	}
	if worker.Phase == WorkerBusy {
		if _, running := provider.active[worker.CurrentExecutionID]; running {
			return ErrBusy
		}
	}
	if worker.Phase == WorkerDestroyed {
		return nil
	}
	if worker.Phase == WorkerDestroying && worker.ResourcesDestroyed {
		return nil
	}
	worker.Phase = WorkerDestroying
	if err := provider.saveWorker(ctx, &worker); err != nil {
		return err
	}
	tags := resourceTags(worker.WorkerID, worker.authority(), worker.Credential, worker.CreationProof)
	if err := provider.destroy(ctx, request.Authorization, tags, &worker); err != nil {
		return err
	}
	worker.ResourcesDestroyed = true
	return provider.saveWorker(ctx, &worker)
}

func (provider *Provider) FinalizeWorkerDestroy(ctx context.Context, request DestroyRequest) error {
	if provider == nil || ctx == nil || request.Authorization.validate() != nil || request.Identity.authority().validate() != nil || request.Identity.Credential.validate() != nil || !validID(request.Identity.WorkerID) {
		if request.Authorization.validate() != nil {
			return ErrNotAuthorized
		}
		return ErrInvalid
	}
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	worker, found, err := provider.store.LoadWorker(ctx, request.Identity.WorkerID)
	if err != nil || !found {
		return err
	}
	if worker.authority() != request.Identity.authority() || worker.Credential != request.Identity.Credential || worker.Instance.ID != request.Identity.InstanceID || worker.KeyPair.ID != request.Identity.KeyPairID ||
		worker.SecurityGroup.ID != request.Identity.SecurityGroupID {
		return ErrIdentity
	}
	if worker.Phase == WorkerDestroyed {
		return nil
	}
	if worker.Phase != WorkerDestroying {
		return ErrBusy
	}
	if !worker.ResourcesDestroyed {
		return ErrBusy
	}
	if err := provider.keys.Delete(ctx, worker.WorkerID); err != nil {
		return err
	}
	worker.Phase = WorkerDestroyed
	return provider.saveWorker(ctx, &worker)
}

func (provider *Provider) destroy(ctx context.Context, authorization DestroyAuthorization, tags ResourceTags, worker *WorkerRecord) error {
	if worker.Instance.ID != "" {
		instance, found, err := provider.aws.ObserveInstance(ctx, worker.Credential, worker.Instance.ID, tags)
		if err != nil {
			return err
		}
		if found && instance.State != "terminated" {
			if err := provider.aws.TerminateInstance(ctx, worker.Credential, authorization, instance, tags); err != nil {
				instance, found, _ = provider.aws.ObserveInstance(ctx, worker.Credential, worker.Instance.ID, tags)
				if found && instance.State != "shutting-down" && instance.State != "terminated" {
					return errors.Join(ErrAmbiguous, err)
				}
			}
		}
		if err := provider.waitTerminated(ctx, worker, tags); err != nil {
			return err
		}
	}
	if worker.SecurityGroup.ID != "" && worker.SecurityGroup.Name != "" {
		if err := provider.aws.DeleteSecurityGroup(ctx, worker.Credential, authorization, worker.SecurityGroup, tags); err != nil {
			_, found, _ := provider.aws.FindSecurityGroup(ctx, worker.Credential, worker.SecurityGroup.Name, tags)
			if found {
				return errors.Join(ErrAmbiguous, err)
			}
		}
	}
	if worker.KeyPair.ID != "" && worker.KeyPair.Name != "" {
		if err := provider.aws.DeleteKeyPair(ctx, worker.Credential, authorization, worker.KeyPair, tags); err != nil {
			_, found, _ := provider.aws.FindKeyPair(ctx, worker.Credential, worker.KeyPair.Name, tags)
			if found {
				return errors.Join(ErrAmbiguous, err)
			}
		}
	}
	return nil
}

func (provider *Provider) waitTerminated(ctx context.Context, worker *WorkerRecord, tags ResourceTags) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		instance, found, err := provider.aws.ObserveInstance(ctx, worker.Credential, worker.Instance.ID, tags)
		if err != nil {
			return err
		}
		if !found || instance.State == "terminated" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (provider *Provider) ListWorkers(ctx context.Context, authority OwnerAuthority, credential CredentialIdentity) ([]WorkerStatus, error) {
	if provider == nil || authority.validate() != nil || credential.validate() != nil {
		return nil, ErrInvalid
	}
	workers, err := provider.store.ListWorkers(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]WorkerStatus, 0, len(workers))
	for _, worker := range workers {
		if worker.authority() != authority || worker.Credential != credential || worker.Phase == WorkerDestroyed {
			continue
		}
		status := WorkerStatus{Identity: workerIdentity(worker), InstanceType: worker.InstanceType, VCPU: worker.VCPU,
			MemoryGiB: worker.MemoryGiB, VolumeGiB: worker.VolumeGiB, Availability: WorkerAvailable, EC2State: "unknown", WorkerPhase: worker.Phase,
			CurrentExecutionID: worker.CurrentExecutionID, ObservedAt: provider.now().UTC()}
		instance, found := Instance{}, false
		if worker.Instance.ID != "" {
			var observeErr error
			instance, found, observeErr = provider.aws.ObserveInstance(ctx, credential, worker.Instance.ID, resourceTags(worker.WorkerID, authority, worker.Credential, worker.CreationProof))
			if observeErr != nil {
				status.Availability, status.Error = WorkerUnavailable, "AWS instance status is unavailable"
			}
		}
		if worker.Instance.ID != "" && status.Availability == WorkerAvailable && !found {
			status.Availability, status.Error = WorkerUnavailable, "AWS instance was not found"
		}
		if status.Availability == WorkerAvailable && found {
			status.EC2State, status.PublicIP = instance.State, instance.PublicIP
			if worker.Instance != instance {
				worker.Instance = instance
				if err := provider.saveWorker(ctx, &worker); err != nil {
					status.Availability, status.Error = WorkerUnavailable, "Worker state could not be persisted"
				}
			}
		}
		if worker.CurrentExecutionID != "" {
			if execution, ok, _ := provider.store.LoadExecution(ctx, worker.CurrentExecutionID); ok && execution.WorkerID == worker.WorkerID &&
				execution.authority() == authority && sameLogicalCredential(execution.Credential, credential) {
				status.TaskPhase = execution.Phase
			}
		}
		if provider.status != nil && status.Availability == WorkerAvailable {
			status.Runner, _ = provider.status.Observe(ctx, worker)
			status.Quote, _ = provider.status.HourlyQuote(ctx, worker)
		}
		result = append(result, status)
	}
	return result, nil
}

func (provider *Provider) WorkerIdentity(ctx context.Context, authority OwnerAuthority, credential CredentialIdentity, workerID string) (WorkerIdentity, error) {
	if provider == nil || authority.validate() != nil || credential.validate() != nil || !validID(workerID) {
		return WorkerIdentity{}, ErrInvalid
	}
	worker, found, err := provider.store.LoadWorker(ctx, workerID)
	if err != nil {
		return WorkerIdentity{}, err
	}
	if !found || worker.authority() != authority || !sameLogicalCredential(worker.Credential, credential) || worker.Phase == WorkerDestroyed {
		return WorkerIdentity{}, ErrIdentity
	}
	return workerIdentity(worker), nil
}

func (provider *Provider) ObserveService(ctx context.Context, identity WorkerIdentity, taskID string) (ServiceRuntimeStatus, error) {
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	worker, found, err := provider.store.LoadWorker(ctx, identity.WorkerID)
	if err != nil {
		return ServiceRuntimeStatus{}, err
	}
	if !found || workerIdentity(worker) != identity || worker.Phase == WorkerDestroyed {
		return ServiceRuntimeStatus{}, ErrIdentity
	}
	source, ok := provider.status.(interface {
		ObserveService(context.Context, WorkerRecord, string) (ServiceRuntimeStatus, error)
	})
	if !ok {
		return ServiceRuntimeStatus{}, ErrInvalid
	}
	return source.ObserveService(ctx, worker, taskID)
}

func (provider *Provider) SetPublicPort(ctx context.Context, identity WorkerIdentity, port uint16, enabled bool) error {
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	worker, found, err := provider.store.LoadWorker(ctx, identity.WorkerID)
	if err != nil {
		return err
	}
	if !found || workerIdentity(worker) != identity || worker.Phase == WorkerDestroyed {
		return ErrIdentity
	}
	manager, ok := provider.aws.(interface {
		SetPublicPort(context.Context, CredentialIdentity, SecurityGroup, ResourceTags, uint16, bool) error
	})
	if !ok {
		return ErrInvalid
	}
	return manager.SetPublicPort(ctx, identity.Credential, worker.SecurityGroup,
		resourceTags(worker.WorkerID, worker.authority(), worker.Credential, worker.CreationProof), port, enabled)
}

func (provider *Provider) ObserveWorker(ctx context.Context, identity WorkerIdentity) (WorkerStatus, error) {
	statuses, err := provider.ListWorkers(ctx, identity.authority(), identity.Credential)
	if err != nil {
		return WorkerStatus{}, err
	}
	for _, status := range statuses {
		if status.Identity == identity {
			return status, nil
		}
	}
	return WorkerStatus{}, ErrIdentity
}

func workerIdentity(worker WorkerRecord) WorkerIdentity {
	return WorkerIdentity{WorkerID: worker.WorkerID, InstanceID: worker.Instance.ID,
		KeyPairID: worker.KeyPair.ID, SecurityGroupID: worker.SecurityGroup.ID, OwnerID: worker.OwnerID,
		AccountGeneration: worker.AccountGeneration, Credential: worker.Credential}
}
func (provider *Provider) saveWorker(ctx context.Context, worker *WorkerRecord) error {
	worker.UpdatedAt = provider.now().UTC()
	return provider.store.SaveWorker(ctx, *worker)
}
func (provider *Provider) saveExecution(ctx context.Context, execution *ExecutionRecord) error {
	execution.UpdatedAt = provider.now().UTC()
	return provider.store.SaveExecution(ctx, *execution)
}

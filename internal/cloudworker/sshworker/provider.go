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
}

// Pool serializes owner-wide Worker admission across credential revisions.
// SSH execution itself never holds this lock.
type Pool struct {
	mu         sync.Mutex
	runsMu     sync.Mutex
	runs       map[string]*activeExecution
	destroying map[string]int
}

type activeExecution struct {
	workerID   string
	authority  OwnerAuthority
	credential CredentialIdentity
	cancel     context.CancelCauseFunc
	done       chan struct{}
}
type CreateAuthorizer func(context.Context, CredentialIdentity) error

func NewPool() *Pool {
	return &Pool{runs: make(map[string]*activeExecution), destroying: make(map[string]int)}
}

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
		pool: pool, authorizeCreate: authorizeCreate}, nil
}

// Register before acquiring the pool lock: provisioning holds that lock across
// AWS calls, but an authorized destroy must still be able to cancel its wait.
func (provider *Provider) registerExecution(ctx context.Context, request ExecuteRequest) (context.Context, func(), error) {
	provider.pool.runsMu.Lock()
	defer provider.pool.runsMu.Unlock()
	workerID := request.ExecutionID
	if request.ReuseOnly {
		workerID = request.ReuseWorkerID
	}
	if provider.pool.destroying[workerID] > 0 {
		return nil, nil, ErrExecutionFailed
	}
	if _, found := provider.pool.runs[request.ExecutionID]; found {
		return nil, nil, ErrBusy
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	run := &activeExecution{workerID: workerID, authority: request.Authority, credential: request.Credential, cancel: cancel, done: make(chan struct{})}
	provider.pool.runs[request.ExecutionID] = run
	return runCtx, func() {
		cancel(nil)
		provider.pool.runsMu.Lock()
		defer provider.pool.runsMu.Unlock()
		if provider.pool.runs[request.ExecutionID] == run {
			delete(provider.pool.runs, request.ExecutionID)
		}
		close(run.done)
	}, nil
}

func (provider *Provider) discover(ctx context.Context, credential CredentialIdentity, instanceType, acceleratorType string) (Discovery, error) {
	if provider == nil || ctx == nil || credential.validate() != nil {
		return Discovery{}, ErrInvalid
	}
	discovery, err := provider.aws.Discover(ctx, credential, instanceType, acceleratorType)
	if err != nil {
		return Discovery{}, err
	}
	if discovery.validate() != nil {
		return Discovery{}, ErrInvalid
	}
	return discovery, nil
}

// ResolveIdleWorker performs the same instance read-back used by lease,
// without reserving or mutating either AWS or the local pool.
func (provider *Provider) ResolveIdleWorker(ctx context.Context, authority OwnerAuthority, credential CredentialIdentity, minVCPU, minMemoryGiB uint32, minVolumeGiB int32, acceleratorType string) (WorkerRecord, bool, error) {
	if provider == nil || ctx == nil || authority.validate() != nil || credential.validate() != nil || minVCPU == 0 || minMemoryGiB == 0 || minVolumeGiB < 8 || !validAcceleratorRequirement(acceleratorType) {
		return WorkerRecord{}, false, ErrInvalid
	}
	workers, err := provider.store.ListWorkers(ctx)
	if err != nil {
		return WorkerRecord{}, false, err
	}
	for _, worker := range workers {
		if worker.authority() != authority || !sameLogicalCredential(worker.Credential, credential) || worker.Phase != WorkerIdle || worker.VCPU < minVCPU || worker.MemoryGiB < minMemoryGiB || worker.VolumeGiB < minVolumeGiB ||
			!workerAcceleratorSatisfies(acceleratorType, worker.AcceleratorType) || !worker.hasVerifiedImageContract() {
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
	ctx, unregister, err := provider.registerExecution(ctx, request)
	if err != nil {
		return ExecutionResult{}, err
	}
	defer unregister()
	if request.ReportProgress != nil {
		if err := request.ReportProgress(ctx, "provisioning_worker", "Selecting or provisioning Worker"); err != nil {
			return ExecutionResult{}, err
		}
	}
	worker, execution, completed, resume, err := provider.lease(ctx, request)
	if err != nil {
		if errors.Is(context.Cause(ctx), ErrExecutionFailed) {
			return ExecutionResult{}, errors.Join(context.Canceled, ErrExecutionFailed)
		}
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
		if ctx.Err() != nil {
			return ExecutionResult{}, errors.Join(ctx.Err(), provider.failExecution(ctx, &execution, &worker))
		}
		deterministicCollectionFailure := errors.Is(runErr, ErrResultTooLarge) || errors.Is(runErr, ErrInvalid)
		if !deterministicCollectionFailure && (errors.Is(runErr, ErrAmbiguous) || errors.Is(runErr, errRetryableResultCollection)) {
			return ExecutionResult{}, runErr
		}
		return ExecutionResult{}, errors.Join(runErr, provider.failExecution(ctx, &execution, &worker))
	}
	result.WorkerID = worker.WorkerID
	if ctx.Err() != nil {
		return ExecutionResult{}, errors.Join(ctx.Err(), provider.failExecution(ctx, &execution, &worker))
	}
	if request.Finalize != nil {
		if err := request.Finalize(ctx, worker.WorkerID, &result); err != nil {
			if errors.Is(context.Cause(ctx), ErrExecutionFailed) {
				err = errors.Join(context.Canceled, ErrExecutionFailed)
			}
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
	if err := ctx.Err(); err != nil {
		return WorkerRecord{}, ExecutionRecord{}, false, false, err
	}
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
			if worker.Phase != WorkerIdle || worker.VCPU < request.VCPU || worker.MemoryGiB < request.MemoryGiB || worker.VolumeGiB < request.VolumeGiB || !worker.hasVerifiedImageContract() {
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
			request, err = provider.discoverForCreate(ctx, request)
			if err != nil {
				return WorkerRecord{}, err
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
	request, err = provider.discoverForCreate(ctx, request)
	if err != nil {
		return WorkerRecord{}, err
	}
	return provider.create(ctx, request)
}

func (provider *Provider) discoverForCreate(ctx context.Context, request ExecuteRequest) (ExecuteRequest, error) {
	if request.Discovery != (Discovery{}) {
		if request.Discovery.validate() != nil {
			return ExecuteRequest{}, ErrInvalid
		}
		return request, nil
	}
	discovery, err := provider.discover(ctx, request.Credential, request.InstanceType, request.AcceleratorType)
	if err != nil {
		return ExecuteRequest{}, err
	}
	request.Discovery = discovery
	return request, nil
}

func (provider *Provider) create(ctx context.Context, request ExecuteRequest) (WorkerRecord, error) {
	if request.Discovery.validate() != nil {
		return WorkerRecord{}, ErrInvalid
	}
	if request.Discovery.RootVolumeGiB > request.VolumeGiB {
		return WorkerRecord{}, fmt.Errorf("confirmed %d GiB root volume is smaller than AMI snapshot minimum %d GiB; request a fresh quote: %w", request.VolumeGiB, request.Discovery.RootVolumeGiB, ErrProviderRejected)
	}
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
			DisplayName: strings.TrimSpace(request.ServerName),
			Phase:       WorkerProvisioning, SSHUser: request.Discovery.SSHUser, InstanceType: request.InstanceType, AcceleratorType: request.AcceleratorType,
			VCPU: request.VCPU, MemoryGiB: request.MemoryGiB, VolumeGiB: request.VolumeGiB,
			ImageID: request.Discovery.ImageID, ImageFlavor: request.Discovery.ImageFlavor, ImageVersion: request.Discovery.ImageVersion,
			ImageOwnerID: request.Discovery.ImageOwnerID, ImagePiVersion: request.Discovery.ImagePiVersion,
			CreatedAt: provider.now().UTC()}
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
	worker.ImageID, worker.ImageFlavor, worker.ImageVersion = request.Discovery.ImageID, request.Discovery.ImageFlavor, request.Discovery.ImageVersion
	worker.ImageOwnerID, worker.ImagePiVersion = request.Discovery.ImageOwnerID, request.Discovery.ImagePiVersion
	if err := provider.saveWorker(ctx, &worker); err != nil {
		return WorkerRecord{}, err
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
			Discovery: request.Discovery, InstanceType: request.InstanceType, VCPU: request.VCPU, VolumeGiB: request.VolumeGiB, KeyName: key.Name, SecurityGroupID: group.ID, Tags: tags})
		if err != nil {
			instance, found, _ = provider.aws.FindInstance(ctx, request.Credential, clientToken, tags)
			if !found {
				var quotaFailure *QuotaError
				if errors.As(err, &quotaFailure) {
					requested, requestErr := provider.aws.RequestInstanceQuotaIncrease(ctx, request.Credential, QuotaIncreaseRequest{
						InstanceType: request.InstanceType, VCPU: request.VCPU, Confirmation: request.Confirmation,
					})
					if requested != nil {
						quotaFailure = requested
					}
					worker.Phase = WorkerFailed
					worker.FailureCode = quotaFailure.FailureCode()
					worker.FailureSummary = quotaFailure.UserSummary()
					return WorkerRecord{}, errors.Join(ErrProviderRejected, quotaFailure, requestErr, provider.saveWorkerAfterExternalFailure(ctx, &worker))
				}
				if errors.Is(err, ErrProviderRejected) {
					return WorkerRecord{}, err
				}
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
	current, found, err := provider.store.LoadWorker(ctx, worker.WorkerID)
	if err != nil {
		return err
	}
	if !found || workerIdentity(current) != workerIdentity(*worker) {
		return ErrIdentity
	}
	if current.Phase == WorkerDestroying || current.Phase == WorkerDestroyed {
		return nil
	}
	*worker = current
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
	execution.Phase = TaskFailed
	return errors.Join(provider.saveExecution(cleanupCtx, execution), provider.releaseLocked(cleanupCtx, worker, execution.ExecutionID))
}

func (provider *Provider) completeExecution(ctx context.Context, execution *ExecutionRecord, worker *WorkerRecord, result ExecutionResult) (bool, error) {
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	if err := provider.executionStillOwned(ctx, execution); err != nil {
		return false, err
	}
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
	if err := provider.executionStillOwned(ctx, execution); err != nil {
		return err
	}
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

func (provider *Provider) executionStillOwned(ctx context.Context, execution *ExecutionRecord) error {
	worker, found, err := provider.store.LoadWorker(ctx, execution.WorkerID)
	if err != nil {
		return err
	}
	if !found || worker.authority() != execution.authority() || !sameLogicalCredential(worker.Credential, execution.Credential) {
		return ErrIdentity
	}
	if worker.Phase == WorkerDestroying || worker.Phase == WorkerDestroyed {
		return ErrExecutionFailed
	}
	if worker.CurrentExecutionID != execution.ExecutionID {
		return ErrIdentity
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
	if worker.Phase == WorkerDestroying || worker.Phase == WorkerDestroyed || worker.Phase == WorkerIdle && worker.CurrentExecutionID == "" {
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
		if worker.authority() != authority || worker.Phase == WorkerDestroyed || worker.Phase == WorkerFailed || (worker.Phase == WorkerDestroying && worker.ResourcesDestroyed) {
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
	worker, found, err := provider.store.LoadWorker(ctx, request.Identity.WorkerID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if !matchesDestroyIdentity(worker, request.Identity) ||
		(worker.Phase != WorkerDestroying && worker.Phase != WorkerDestroyed && workerIdentity(worker) != request.Identity) {
		return ErrIdentity
	}
	// Fence new starts and cancel current provisioning/SSH before waiting for
	// the pool lock. Only the already-validated owner/resource can be canceled.
	provider.pool.runsMu.Lock()
	provider.pool.destroying[worker.WorkerID]++
	var stopped []<-chan struct{}
	for _, run := range provider.pool.runs {
		if run.workerID == worker.WorkerID && run.authority == worker.authority() && sameLogicalCredential(run.credential, worker.Credential) {
			run.cancel(ErrExecutionFailed)
			stopped = append(stopped, run.done)
		}
	}
	provider.pool.runsMu.Unlock()
	initial := worker
	defer func() {
		provider.pool.runsMu.Lock()
		defer provider.pool.runsMu.Unlock()
		provider.pool.destroying[initial.WorkerID]--
		if provider.pool.destroying[initial.WorkerID] == 0 {
			delete(provider.pool.destroying, initial.WorkerID)
		}
	}()
	provider.pool.mu.Lock()
	locked := true
	defer func() {
		if locked {
			provider.pool.mu.Unlock()
		}
	}()
	worker, found, err = provider.store.LoadWorker(ctx, request.Identity.WorkerID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if worker.CreationProof != initial.CreationProof || !matchesDestroyIdentity(worker, request.Identity) {
		return ErrIdentity
	}
	request.Identity = workerIdentity(worker)
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
	if worker.Instance.ID == "" || worker.KeyPair.ID == "" || worker.SecurityGroup.ID == "" {
		// A canceled AWS request may have succeeded before its identity was
		// saved. Discover only this intent's exact tags; never create on cleanup.
		if err := provider.reconcileProvisioning(ctx, &worker); err != nil {
			return err
		}
		request.Identity = workerIdentity(worker)
	}
	if worker.CurrentExecutionID != "" {
		execution, exists, err := provider.store.LoadExecution(ctx, worker.CurrentExecutionID)
		if err != nil {
			return err
		}
		if exists {
			if execution.WorkerID != worker.WorkerID || execution.authority() != worker.authority() || !sameLogicalCredential(execution.Credential, worker.Credential) {
				return ErrIdentity
			}
			if execution.Phase == TaskRunning {
				execution.Phase = TaskFailed
				if err := provider.saveExecution(ctx, &execution); err != nil {
					return err
				}
			}
		}
	}
	// Release the pool lock so canceled execution cleanup can finish. Keeping
	// the durable destroy intent prevents late completion/release resurrecting
	// the Worker; waiting also drains result/service publication before cleanup.
	provider.pool.mu.Unlock()
	locked = false
	for _, done := range stopped {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	provider.pool.mu.Lock()
	locked = true
	worker, found, err = provider.store.LoadWorker(ctx, request.Identity.WorkerID)
	if err != nil {
		return err
	}
	if !found || workerIdentity(worker) != request.Identity {
		return ErrIdentity
	}
	if worker.Phase == WorkerDestroyed || worker.ResourcesDestroyed {
		return nil
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
	if !matchesDestroyIdentity(worker, request.Identity) {
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
	worker.Phase, worker.CurrentExecutionID = WorkerDestroyed, ""
	return provider.saveWorker(ctx, &worker)
}

// A provisioning request may initially have only some resource IDs. Those
// already supplied must still match; cleanup may have discovered the others
// under the same durable Worker intent after canceling an in-flight AWS call.
func matchesDestroyIdentity(worker WorkerRecord, identity WorkerIdentity) bool {
	return worker.WorkerID == identity.WorkerID && worker.authority() == identity.authority() && worker.Credential == identity.Credential &&
		(identity.InstanceID == "" || worker.Instance.ID == identity.InstanceID) &&
		(identity.KeyPairID == "" || worker.KeyPair.ID == identity.KeyPairID) &&
		(identity.SecurityGroupID == "" || worker.SecurityGroup.ID == identity.SecurityGroupID)
}

func (provider *Provider) destroy(ctx context.Context, authorization DestroyAuthorization, tags ResourceTags, worker *WorkerRecord) error {
	if worker.Instance.ID != "" {
		instance, found, err := provider.aws.ObserveInstance(ctx, worker.Credential, worker.Instance.ID, tags)
		if err != nil {
			return err
		}
		if found && instance.State != "terminated" && instance.State != "shutting-down" {
			if err := provider.aws.TerminateInstance(ctx, worker.Credential, authorization, instance, tags); err != nil {
				return err
			}
		}
		if err := provider.waitTerminated(ctx, worker, tags); err != nil {
			return err
		}
	}
	if worker.SecurityGroup.ID != "" && worker.SecurityGroup.Name != "" {
		if err := provider.aws.DeleteSecurityGroup(ctx, worker.Credential, authorization, worker.SecurityGroup, tags); err != nil {
			return err
		}
	}
	if worker.KeyPair.ID != "" && worker.KeyPair.Name != "" {
		if err := provider.aws.DeleteKeyPair(ctx, worker.Credential, authorization, worker.KeyPair, tags); err != nil {
			return err
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
		status := WorkerStatus{Identity: workerIdentity(worker), DisplayName: worker.DisplayName, CreatedAt: worker.CreatedAt, InstanceType: worker.InstanceType, AcceleratorType: worker.AcceleratorType, VCPU: worker.VCPU,
			MemoryGiB: worker.MemoryGiB, VolumeGiB: worker.VolumeGiB, Availability: WorkerAvailable, EC2State: "unknown", WorkerPhase: worker.Phase,
			CurrentExecutionID: worker.CurrentExecutionID, ObservedAt: provider.now().UTC()}
		if worker.Phase == WorkerFailed {
			status.Availability, status.Error = WorkerUnavailable, worker.FailureSummary
		}
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
			current, refreshErr := provider.refreshObservedInstance(ctx, worker, instance)
			if refreshErr != nil {
				status.Availability, status.Error = WorkerUnavailable, "Worker state could not be persisted"
			} else {
				worker = current
				if worker.Phase == WorkerDestroyed {
					continue
				}
				status.WorkerPhase, status.CurrentExecutionID = worker.Phase, worker.CurrentExecutionID
			}
			if instance.State == "terminated" || instance.State == "shutting-down" {
				status.Availability, status.Error = WorkerUnavailable, "AWS instance has been terminated"
			}
		}
		if worker.CurrentExecutionID != "" {
			if execution, ok, _ := provider.store.LoadExecution(ctx, worker.CurrentExecutionID); ok && execution.WorkerID == worker.WorkerID &&
				execution.authority() == authority && sameLogicalCredential(execution.Credential, credential) {
				status.TaskPhase = execution.Phase
			}
		}
		if provider.status != nil && status.Availability == WorkerAvailable && worker.Phase != WorkerDestroying && instance.State == "running" && instance.PublicIP != "" {
			status.Runner, _ = provider.status.Observe(ctx, worker)
			status.Quote, _ = provider.status.HourlyQuote(ctx, worker)
		}
		result = append(result, status)
	}
	return result, nil
}

// Later SSH mutations resolve their target from retained state. Keep the
// observed address current, but merge it into a freshly locked record so an
// observation cannot overwrite a newer lease or destroy intent.
func (provider *Provider) refreshObservedInstance(ctx context.Context, snapshot WorkerRecord, instance Instance) (WorkerRecord, error) {
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	current, found, err := provider.store.LoadWorker(ctx, snapshot.WorkerID)
	if err != nil {
		return WorkerRecord{}, err
	}
	if !found || workerIdentity(current) != workerIdentity(snapshot) || current.CreationProof != snapshot.CreationProof {
		return WorkerRecord{}, ErrIdentity
	}
	if current.Phase == WorkerDestroying || current.Phase == WorkerDestroyed || current.Instance == instance {
		return current, nil
	}
	current.Instance = instance
	return current, provider.saveWorker(ctx, &current)
}

func (provider *Provider) WorkerIdentity(ctx context.Context, authority OwnerAuthority, credential CredentialIdentity, workerID string) (WorkerIdentity, error) {
	if provider == nil || authority.validate() != nil || credential.validate() != nil || !validID(workerID) {
		return WorkerIdentity{}, ErrInvalid
	}
	worker, found, err := provider.store.LoadWorker(ctx, workerID)
	if err != nil {
		return WorkerIdentity{}, err
	}
	if !found || worker.authority() != authority || !sameLogicalCredential(worker.Credential, credential) || worker.Phase == WorkerDestroyed || worker.Phase == WorkerDestroying {
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
	if !found || workerIdentity(worker) != identity || worker.Phase == WorkerDestroyed || worker.Phase == WorkerDestroying {
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
	if !found || workerIdentity(worker) != identity || worker.Phase == WorkerDestroyed || worker.Phase == WorkerDestroying {
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

// ReconcileServiceExposure installs the exact managed Caddy route
// on a retained Worker after re-reading its complete persisted identity. The
// pool fence prevents destroy from crossing this SSH mutation.
func (provider *Provider) ReconcileServiceExposure(ctx context.Context, identity WorkerIdentity, exposure ServiceExposure) error {
	provider.pool.mu.Lock()
	defer provider.pool.mu.Unlock()
	worker, found, err := provider.store.LoadWorker(ctx, identity.WorkerID)
	if err != nil {
		return err
	}
	if !found || workerIdentity(worker) != identity || worker.Phase == WorkerDestroyed || worker.Phase == WorkerDestroying {
		return ErrIdentity
	}
	manager, ok := provider.status.(interface {
		ReconcileServiceExposure(context.Context, WorkerRecord, ServiceExposure) error
	})
	if !ok {
		return ErrInvalid
	}
	return manager.ReconcileServiceExposure(ctx, worker, exposure)
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
func (provider *Provider) saveWorkerAfterExternalFailure(ctx context.Context, worker *WorkerRecord) error {
	saveCtx := ctx
	cancel := func() {}
	if ctx.Err() != nil {
		saveCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	}
	defer cancel()
	return provider.saveWorker(saveCtx, worker)
}
func (provider *Provider) saveExecution(ctx context.Context, execution *ExecutionRecord) error {
	execution.UpdatedAt = provider.now().UTC()
	return provider.store.SaveExecution(ctx, *execution)
}

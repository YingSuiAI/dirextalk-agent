package sshworker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Provider struct {
	aws    AWS
	keys   KeyMaterial
	ssh    SSHExecutor
	store  Store
	target ConnectionTargetResolver
	status StatusSource
	now    func() time.Time
	poolMu sync.Mutex
	active map[string]struct{}
}

func New(awsClient AWS, keys KeyMaterial, ssh SSHExecutor, store Store, status ...StatusSource) (*Provider, error) {
	if awsClient == nil || keys == nil || ssh == nil || store == nil {
		return nil, ErrInvalid
	}
	var source StatusSource
	if len(status) > 0 {
		source = status[0]
	}
	return &Provider{aws: awsClient, keys: keys, ssh: ssh, store: store, target: PublicIPTarget{}, status: source, now: time.Now, active: make(map[string]struct{})}, nil
}

func (provider *Provider) Discover(ctx context.Context, credential CredentialIdentity) (Discovery, error) {
	if provider == nil || ctx == nil || credential.validate() != nil {
		return Discovery{}, ErrInvalid
	}
	if err := provider.aws.VerifyIdentity(ctx, credential); err != nil {
		return Discovery{}, err
	}
	discovery, err := provider.aws.Discover(ctx, credential)
	if err != nil || discovery.validate() != nil {
		return Discovery{}, errors.Join(ErrInvalid, err)
	}
	return discovery, nil
}

// Execute leases an idle persistent Worker or creates one after confirmation.
// Task completion returns it to idle; it never destroys cloud resources.
func (provider *Provider) Execute(ctx context.Context, request ExecuteRequest) (ExecutionResult, error) {
	if provider == nil || ctx == nil || request.validate() != nil {
		return ExecutionResult{}, ErrInvalid
	}
	if err := provider.aws.VerifyIdentity(ctx, request.Credential); err != nil {
		return ExecutionResult{}, err
	}
	worker, execution, completed, err := provider.lease(ctx, request)
	if err != nil {
		return ExecutionResult{}, err
	}
	if completed {
		return execution.Result, nil
	}

	privateKey, _, err := provider.keys.Ensure(ctx, worker.WorkerID)
	if err != nil {
		provider.failExecution(ctx, &execution, &worker)
		return ExecutionResult{}, err
	}
	target, err := provider.target.Resolve(worker.Instance)
	if err != nil {
		provider.failExecution(ctx, &execution, &worker)
		return ExecutionResult{}, err
	}
	result, runErr := provider.ssh.Execute(ctx, SSHRequest{ExecutionID: request.ExecutionID, Host: target, User: worker.SSHUser,
		PrivateKeyPath: privateKey, WorkerScript: request.WorkerScript, WorkerScriptSHA256: request.WorkerScriptSHA256,
		Runtime: request.Runtime, WorkspacePath: request.WorkspacePath, MaxWorkspaceBytes: request.MaxWorkspaceBytes, MaxResultBytes: request.MaxResultBytes, Sink: request.Sink})
	if runErr != nil {
		provider.failExecution(ctx, &execution, &worker)
		return ExecutionResult{}, runErr
	}
	result.WorkerID = worker.WorkerID
	if err := provider.completeExecution(ctx, &execution, &worker, result); err != nil {
		return result, err
	}
	return result, nil
}

// lease serializes only the pool decision and durable lease. SSH tasks run
// without holding poolMu, so separate Workers can execute concurrently.
func (provider *Provider) lease(ctx context.Context, request ExecuteRequest) (WorkerRecord, ExecutionRecord, bool, error) {
	provider.poolMu.Lock()
	defer provider.poolMu.Unlock()
	execution, exists, err := provider.store.LoadExecution(ctx, request.ExecutionID)
	if err != nil {
		return WorkerRecord{}, ExecutionRecord{}, false, err
	}
	if exists && execution.Credential != request.Credential {
		return WorkerRecord{}, ExecutionRecord{}, false, ErrIdentity
	}
	if exists && execution.Phase == TaskCompleted {
		return WorkerRecord{}, execution, true, nil
	}
	if _, running := provider.active[request.ExecutionID]; running {
		return WorkerRecord{}, ExecutionRecord{}, false, ErrBusy
	}
	worker, err := provider.acquire(ctx, request, execution)
	if err != nil {
		return WorkerRecord{}, ExecutionRecord{}, false, err
	}
	execution = ExecutionRecord{ExecutionID: request.ExecutionID, WorkerID: worker.WorkerID, Credential: request.Credential, Phase: TaskRunning}
	if err := provider.saveExecution(ctx, &execution); err != nil {
		_ = provider.releaseLocked(ctx, &worker, request.ExecutionID)
		return WorkerRecord{}, ExecutionRecord{}, false, err
	}
	provider.active[request.ExecutionID] = struct{}{}
	return worker, execution, false, nil
}

func (provider *Provider) acquire(ctx context.Context, request ExecuteRequest, prior ExecutionRecord) (WorkerRecord, error) {
	workers, err := provider.store.ListWorkers(ctx, request.Credential)
	if err != nil {
		return WorkerRecord{}, err
	}
	if prior.WorkerID != "" {
		for _, worker := range workers {
			if worker.WorkerID == prior.WorkerID && worker.Phase == WorkerBusy && worker.CurrentExecutionID == request.ExecutionID {
				return worker, nil
			}
		}
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].UpdatedAt.Before(workers[j].UpdatedAt) })
	for _, worker := range workers {
		if worker.Phase != WorkerIdle || worker.InstanceType != request.InstanceType {
			continue
		}
		observed, found, err := provider.aws.ObserveInstance(ctx, request.Credential, worker.Instance.ID, resourceTags(worker.WorkerID, worker.Credential, worker.CreationProof))
		if err != nil {
			return WorkerRecord{}, err
		}
		if !found || observed.State != "running" || observed.PublicIP == "" {
			continue
		}
		worker.Instance = observed
		worker.Phase = WorkerBusy
		worker.CurrentExecutionID = request.ExecutionID
		if err := provider.saveWorker(ctx, &worker); err != nil {
			return WorkerRecord{}, err
		}
		return worker, nil
	}
	active := 0
	for _, worker := range workers {
		if worker.Phase != WorkerDestroyed {
			active++
		}
	}
	live, err := provider.aws.ListInstances(ctx, request.Credential, poolTags(request.Credential))
	if err != nil {
		return WorkerRecord{}, err
	}
	if len(live) > active {
		active = len(live)
	}
	if active >= MaxWorkersPerCredential {
		return WorkerRecord{}, ErrCapacity
	}
	if err := request.Confirmation.validate(); err != nil {
		return WorkerRecord{}, err
	}
	return provider.create(ctx, request)
}

func (provider *Provider) create(ctx context.Context, request ExecuteRequest) (WorkerRecord, error) {
	workerID := request.ExecutionID
	tags := resourceTags(workerID, request.Credential, request.Confirmation.Proof)
	keyName, groupName, clientToken := resourceNames(workerID)
	worker, exists, err := provider.store.LoadWorker(ctx, workerID)
	if err != nil {
		return WorkerRecord{}, err
	}
	if !exists {
		worker = WorkerRecord{WorkerID: workerID, Credential: request.Credential, CreationProof: request.Confirmation.Proof,
			Phase: WorkerProvisioning, SSHUser: request.Discovery.SSHUser, InstanceType: request.InstanceType, VolumeGiB: request.VolumeGiB, CreatedAt: provider.now().UTC()}
	}
	if worker.Credential != request.Credential || worker.CreationProof != request.Confirmation.Proof {
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
	if err := provider.aws.AuthorizeSSH(ctx, request.Credential, request.Confirmation, group, request.Discovery.PublicEgressCIDR); err != nil {
		return WorkerRecord{}, err
	}
	instance, found, err := provider.aws.FindInstance(ctx, request.Credential, clientToken, tags)
	if err != nil {
		return WorkerRecord{}, err
	}
	if !found {
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

func (provider *Provider) waitRunning(ctx context.Context, worker *WorkerRecord) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		instance, found, err := provider.aws.ObserveInstance(ctx, worker.Credential, worker.Instance.ID, resourceTags(worker.WorkerID, worker.Credential, worker.CreationProof))
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

func (provider *Provider) failExecution(ctx context.Context, execution *ExecutionRecord, worker *WorkerRecord) {
	provider.poolMu.Lock()
	defer provider.poolMu.Unlock()
	delete(provider.active, execution.ExecutionID)
	execution.Phase = TaskFailed
	_ = provider.saveExecution(ctx, execution)
	_ = provider.releaseLocked(ctx, worker, execution.ExecutionID)
}

func (provider *Provider) completeExecution(ctx context.Context, execution *ExecutionRecord, worker *WorkerRecord, result ExecutionResult) error {
	provider.poolMu.Lock()
	defer provider.poolMu.Unlock()
	delete(provider.active, execution.ExecutionID)
	execution.Result, execution.Phase = result, TaskCompleted
	if err := provider.saveExecution(ctx, execution); err != nil {
		return err
	}
	return provider.releaseLocked(ctx, worker, execution.ExecutionID)
}

func (provider *Provider) DestroyWorker(ctx context.Context, request DestroyRequest) error {
	if provider == nil || ctx == nil || request.Authorization.validate() != nil || request.Identity.Credential.validate() != nil || !validID(request.Identity.WorkerID) {
		if request.Authorization.validate() != nil {
			return ErrNotAuthorized
		}
		return ErrInvalid
	}
	if err := provider.aws.VerifyIdentity(ctx, request.Identity.Credential); err != nil {
		return err
	}
	provider.poolMu.Lock()
	defer provider.poolMu.Unlock()
	worker, found, err := provider.store.LoadWorker(ctx, request.Identity.WorkerID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if worker.Credential != request.Identity.Credential || worker.Instance.ID != request.Identity.InstanceID || worker.KeyPair.ID != request.Identity.KeyPairID ||
		worker.SecurityGroup.ID != request.Identity.SecurityGroupID {
		return ErrIdentity
	}
	if worker.Phase == WorkerBusy {
		return ErrBusy
	}
	if worker.Phase == WorkerDestroyed {
		return nil
	}
	worker.Phase = WorkerDestroying
	if err := provider.saveWorker(ctx, &worker); err != nil {
		return err
	}
	tags := resourceTags(worker.WorkerID, worker.Credential, worker.CreationProof)
	if err := provider.destroy(ctx, request.Authorization, tags, &worker); err != nil {
		return err
	}
	worker.Phase = WorkerDestroyed
	if err := provider.saveWorker(ctx, &worker); err != nil {
		return err
	}
	return provider.keys.Delete(ctx, worker.WorkerID)
}

func (provider *Provider) destroy(ctx context.Context, authorization DestroyAuthorization, tags ResourceTags, worker *WorkerRecord) error {
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
	if err := provider.aws.DeleteSecurityGroup(ctx, worker.Credential, authorization, worker.SecurityGroup, tags); err != nil {
		_, found, _ := provider.aws.FindSecurityGroup(ctx, worker.Credential, worker.SecurityGroup.Name, tags)
		if found {
			return errors.Join(ErrAmbiguous, err)
		}
	}
	if err := provider.aws.DeleteKeyPair(ctx, worker.Credential, authorization, worker.KeyPair, tags); err != nil {
		_, found, _ := provider.aws.FindKeyPair(ctx, worker.Credential, worker.KeyPair.Name, tags)
		if found {
			return errors.Join(ErrAmbiguous, err)
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

func (provider *Provider) ListWorkers(ctx context.Context, credential CredentialIdentity) ([]WorkerStatus, error) {
	if provider == nil || credential.validate() != nil {
		return nil, ErrInvalid
	}
	if err := provider.aws.VerifyIdentity(ctx, credential); err != nil {
		return nil, err
	}
	workers, err := provider.store.ListWorkers(ctx, credential)
	if err != nil {
		return nil, err
	}
	result := make([]WorkerStatus, 0, len(workers))
	for _, worker := range workers {
		if worker.Phase == WorkerDestroyed {
			continue
		}
		instance, found, err := provider.aws.ObserveInstance(ctx, credential, worker.Instance.ID, resourceTags(worker.WorkerID, worker.Credential, worker.CreationProof))
		if err != nil {
			return nil, err
		}
		status := WorkerStatus{Identity: workerIdentity(worker), WorkerPhase: worker.Phase, CurrentExecutionID: worker.CurrentExecutionID, ObservedAt: provider.now().UTC()}
		if found {
			status.EC2State, status.PublicIP = instance.State, instance.PublicIP
		}
		if worker.CurrentExecutionID != "" {
			if execution, ok, _ := provider.store.LoadExecution(ctx, worker.CurrentExecutionID); ok {
				status.TaskPhase = execution.Phase
			}
		}
		if provider.status != nil {
			status.Runner, _ = provider.status.Observe(ctx, worker)
			status.Quote, _ = provider.status.HourlyQuote(ctx, credential, worker.InstanceType, worker.VolumeGiB)
		}
		result = append(result, status)
	}
	return result, nil
}

func (provider *Provider) ObserveWorker(ctx context.Context, identity WorkerIdentity) (WorkerStatus, error) {
	statuses, err := provider.ListWorkers(ctx, identity.Credential)
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
		KeyPairID: worker.KeyPair.ID, SecurityGroupID: worker.SecurityGroup.ID, Credential: worker.Credential}
}
func (provider *Provider) saveWorker(ctx context.Context, worker *WorkerRecord) error {
	worker.UpdatedAt = provider.now().UTC()
	return provider.store.SaveWorker(ctx, *worker)
}
func (provider *Provider) saveExecution(ctx context.Context, execution *ExecutionRecord) error {
	execution.UpdatedAt = provider.now().UTC()
	return provider.store.SaveExecution(ctx, *execution)
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	workercap "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/worker"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/workspacearchive"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

type sshWorkerExecutor struct {
	authority *cloudWorkerCredentialAuthority
	exact     workaws.ExactCredentialResolver
	providers map[sshworker.CredentialIdentity]*sshworker.Provider
	artifacts *localartifact.Repository
	pricing   cloudworker.PricingCatalog
	sources   cloudworker.SourceReader
	state     *sshworker.FileStore
	pool      *sshworker.Pool
	workloads *sshworkload.Repository
	route53   map[sshworker.CredentialIdentity]remoteservice.Route53
	root      string
	mu        sync.Mutex
}

func newSSHWorkerExecutor(authority *cloudWorkerCredentialAuthority, exact workaws.ExactCredentialResolver, artifacts *localartifact.Repository, pricing cloudworker.PricingCatalog, sources cloudworker.SourceReader, state *sshworker.FileStore, root string) (*sshWorkerExecutor, error) {
	if authority == nil || exact == nil || artifacts == nil || pricing == nil || sources == nil || state == nil || !filepath.IsAbs(root) {
		return nil, sshworker.ErrInvalid
	}
	workloads, err := sshworkload.NewRepository(filepath.Join(root, "workloads"))
	if err != nil {
		return nil, err
	}
	return &sshWorkerExecutor{authority: authority, exact: exact, providers: make(map[sshworker.CredentialIdentity]*sshworker.Provider), artifacts: artifacts,
		pricing: pricing, sources: sources, state: state, pool: sshworker.NewPool(), workloads: workloads,
		route53: make(map[sshworker.CredentialIdentity]remoteservice.Route53), root: root}, nil
}

func (executor *sshWorkerExecutor) provider(ctx context.Context, binding cloudworker.AWSBinding) (*sshworker.Provider, sshworker.CredentialIdentity, error) {
	handle, err := executor.exact.ResolveCredentialRevision(ctx, binding.CredentialID, binding.CredentialRevision)
	identity := sshworker.CredentialIdentity{CredentialID: binding.CredentialID, CredentialRevision: binding.CredentialRevision, AccountID: binding.AccountID, Region: binding.Region}
	if err != nil || handle.ReferenceID != identity.CredentialID || handle.AccountID != identity.AccountID || handle.Region != identity.Region {
		return nil, identity, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if provider := executor.providers[identity]; provider != nil {
		return provider, identity, nil
	}
	credentialProvider, err := newCloudWorkerAWSCredentialsProvider(executor.authority, binding)
	if err != nil {
		return nil, identity, err
	}
	config := awssdk.Config{Region: handle.Region, Credentials: credentialProvider}
	handle.AccessKeyID, handle.SecretAccessKey, handle.SessionToken = "", "", ""
	client, err := sshworker.NewSDK(config, sshworker.HTTPPublicIPReader{})
	if err != nil {
		return nil, identity, err
	}
	keys, err := sshworker.NewLocalKeyMaterial(filepath.Join(executor.root, "keys"))
	if err != nil {
		return nil, identity, err
	}
	status := sshworker.CommandStatusSource{Keys: keys, Quote: executor.hourlyQuote}
	provider, err := sshworker.NewWithPool(client, keys, sshworker.CommandSSHExecutor{}, executor.state, executor.pool, executor.authorizeWorkerCreate, status)
	if err == nil {
		executor.providers[identity] = provider
		if dns, dnsErr := remoteservice.NewRoute53SDK(config); dnsErr == nil {
			executor.route53[identity] = dns
		}
	}
	return provider, identity, err
}

func (executor *sshWorkerExecutor) authorizeWorkerCreate(ctx context.Context, credential sshworker.CredentialIdentity) error {
	if executor == nil || executor.authority == nil || ctx == nil {
		return cloudworker.ErrStaleAuthorization
	}
	current, err := executor.authority.ResolveCurrentAWSBinding(ctx)
	expected := cloudworker.AWSBinding{AccountID: credential.AccountID, Region: credential.Region,
		CredentialID: credential.CredentialID, CredentialRevision: credential.CredentialRevision}
	if err != nil || current != expected {
		return errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	return nil
}

func (executor *sshWorkerExecutor) hourlyQuote(ctx context.Context, worker sshworker.WorkerRecord) (sshworker.HourlyQuote, error) {
	if executor == nil || executor.pricing == nil || worker.AccountGeneration == 0 || worker.VolumeGiB <= 0 {
		return sshworker.HourlyQuote{}, sshworker.ErrInvalid
	}
	identity := worker.Credential
	snapshot, err := executor.pricing.Snapshot(ctx, cloudworker.PricingCatalogRequest{AccountID: identity.AccountID, AccountGeneration: worker.AccountGeneration,
		Region: identity.Region, CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision,
		InstanceType: worker.InstanceType, Architecture: "x86_64", VolumeGiB: uint64(worker.VolumeGiB), VolumeType: "gp3", VolumeIOPS: 3000,
		VolumeThroughput: 125, MaxRuntimeSeconds: 3600, MaxTokens: 1, BasisDigest: strings.Repeat("0", 64), WorkspaceMode: cloudworker.WorkspaceNone})
	if err != nil {
		return sshworker.HourlyQuote{}, err
	}
	storagePerHour := (snapshot.Rates.EBSStorageMicrosPerGiBMonth*uint64(worker.VolumeGiB) + 729) / 730
	return sshworker.HourlyQuote{Currency: snapshot.Currency,
		MicrosPerHour: snapshot.Rates.ComputeMicrosPerHour + snapshot.Rates.PublicIPv4MicrosPerHour + storagePerHour,
		ObservedAt:    snapshot.SourceTime, ExpiresAt: snapshot.ExpiresAt}, nil
}

func (executor *sshWorkerExecutor) Execute(ctx context.Context, request sshflow.Request) (sshflow.Result, error) {
	current, err := executor.authority.ResolveCurrentAWSBinding(ctx)
	if err != nil || current != request.AWS {
		return sshflow.Result{}, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	workspacePath, cleanupWorkspace, err := executor.materializeWorkspace(ctx, request)
	if err != nil {
		return sshflow.Result{}, err
	}
	defer cleanupWorkspace()
	provider, identity, err := executor.provider(ctx, request.AWS)
	if err != nil {
		return sshflow.Result{}, err
	}
	discovery, err := provider.Discover(ctx, identity)
	if err != nil {
		return sshflow.Result{}, err
	}
	workload := sshworker.WorkloadJob
	var service *sshworker.RuntimeServiceSpec
	if request.WorkloadKind == cloudworker.WorkloadService && request.Service != nil {
		workload = sshworker.WorkloadService
		service = &sshworker.RuntimeServiceSpec{WorkloadID: request.Service.WorkloadID, Port: request.Service.Port, HealthPath: request.Service.HealthPath}
	}
	material, err := sshworker.CompileRuntime(sshworker.RuntimeRequest{TaskID: request.ExecutionID, Objective: request.Objective,
		Architecture: request.Compute.Architecture, Workload: workload, MaxRuntimeSeconds: request.Limits.MaxRuntimeSeconds, Service: service,
		Model: workerRuntimeModel(request.ModelSnapshot)})
	if err != nil {
		return sshflow.Result{}, err
	}
	sink, err := executor.artifacts.Bind(localartifact.Authority{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration}, request.ExecutionID)
	if err != nil {
		return sshflow.Result{}, err
	}
	confirmation := sshworker.Confirmation{Confirmed: true, Proof: request.ConfirmationProof}
	if request.ReuseOnly {
		confirmation = sshworker.Confirmation{}
	}
	result, err := provider.Execute(ctx, sshworker.ExecuteRequest{ExecutionID: request.ExecutionID,
		Authority: sshworker.OwnerAuthority{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration}, Credential: identity,
		Confirmation: confirmation, Discovery: discovery, ReuseOnly: request.ReuseOnly,
		InstanceType: request.Compute.InstanceType, VCPU: request.Compute.VCPU, MemoryGiB: request.Compute.MemoryGiB,
		VolumeGiB: int32(request.Compute.VolumeGiB), WorkerScript: material.WorkerScript,
		WorkerScriptSHA256: material.WorkerScriptSHA256, Runtime: material.Protocol,
		WorkspacePath: workspacePath, MaxWorkspaceBytes: 512 << 20, MaxResultBytes: int64(request.Limits.MaxOutputBytes), Sink: sink})
	workerResult := sshflow.Result{ExitCode: result.ExitCode, WorkerID: result.WorkerID}
	artifacts, artifactErr := executor.executionArtifacts(ctx, localartifact.Authority{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration}, request.ExecutionID)
	workerResult.Artifacts = artifacts
	if artifactErr != nil {
		err = errors.Join(err, artifactErr)
	}
	workerResult.Summary = boundedWorkerSummary(result.Summary)
	if workerResult.Summary == "" {
		workerResult.Summary = fmt.Sprintf("Cloud Worker %s completed with exit code %d and %d artifacts", workerResult.WorkerID, result.ExitCode, result.ArtifactCount)
	}
	if errors.Is(err, sshworker.ErrAmbiguous) {
		err = errors.Join(sshflow.ErrExecutionUncertain, err)
	}
	if err != nil {
		return workerResult, err
	}
	if result.ExitCode != 0 {
		return workerResult, fmt.Errorf("remote Worker exited with code %d", result.ExitCode)
	}
	if service != nil {
		if err = executor.publishService(ctx, provider, sshworker.OwnerAuthority{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration}, identity, result.WorkerID, request.ExecutionID, *service); err != nil {
			return workerResult, err
		}
	}
	return workerResult, nil
}

func workerRuntimeModel(snapshot coremodel.ExecutionSnapshot) sshworker.RuntimeModel {
	return sshworker.RuntimeModel{Provider: string(snapshot.Provider), BaseURL: snapshot.BaseURL,
		Name: snapshot.Model, APIKey: snapshot.APIKey, MaxOutputTokens: snapshot.MaxOutputTokens}
}

var errSSHWorkerArtifactLimit = fmt.Errorf("SSH Worker artifact count exceeds %d", coretask.MaxFileCount)

func (executor *sshWorkerExecutor) executionArtifacts(ctx context.Context, authority localartifact.Authority, executionID string) ([]sshflow.Artifact, error) {
	list, next, err := executor.artifacts.List(ctx, authority, executionID, "", coretask.MaxFileCount)
	if err != nil {
		return nil, err
	}
	if next != "" {
		return nil, errSSHWorkerArtifactLimit
	}
	result := make([]sshflow.Artifact, 0, len(list))
	for _, artifact := range list {
		result = append(result, sshflow.Artifact{ArtifactID: artifact.ArtifactID, ExecutionID: artifact.ExecutionID,
			Kind: artifact.Kind, Name: artifact.Name, MediaType: artifact.MediaType,
			RelativePath: filepath.ToSlash(filepath.Join("cloud-worker/artifacts", executionID, artifact.Name)), SizeBytes: artifact.SizeBytes, SHA256: artifact.SHA256})
	}
	return result, nil
}

func (executor *sshWorkerExecutor) materializeWorkspace(ctx context.Context, request sshflow.Request) (string, func(), error) {
	manifest := request.InputManifest
	manifest.Items = append([]cloudworker.InputManifestItem(nil), request.InputManifest.Items...)
	if _, err := manifest.Seal(); err != nil || !reflect.DeepEqual(manifest, request.InputManifest) {
		return "", func() {}, errors.Join(sshworker.ErrInvalid, err)
	}
	switch request.WorkspaceMode {
	case cloudworker.WorkspaceNone:
		if len(manifest.Items) != 0 {
			return "", func() {}, sshworker.ErrInvalid
		}
		return "", func() {}, nil
	case cloudworker.WorkspaceReadOnly:
		if len(manifest.Items) == 0 {
			return "", func() {}, sshworker.ErrInvalid
		}
	case cloudworker.WorkspaceWrite:
	default:
		return "", func() {}, sshworker.ErrInvalid
	}
	inputRoot := filepath.Join(executor.root, "workspace-inputs")
	if err := os.MkdirAll(inputRoot, 0o700); err != nil {
		return "", func() {}, err
	}
	info, err := os.Lstat(inputRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", func() {}, errors.Join(sshworker.ErrInvalid, err)
	}
	stagingRoot, err := os.MkdirTemp(inputRoot, request.ExecutionID+"-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { cleanupWorkspaceInputs(stagingRoot) }
	workspacePath := filepath.Join(stagingRoot, "workspace")
	if err = os.Mkdir(workspacePath, 0o700); err != nil {
		cleanup()
		return "", func() {}, err
	}
	// Archives describe the workspace root and must be extracted while it is
	// empty. Ordinary sealed inputs are then mounted below their exact paths.
	for _, kind := range []string{"archive", "file"} {
		for _, item := range manifest.Items {
			if item.Kind != kind {
				continue
			}
			if err = executor.materializeWorkspaceItem(ctx, request, workspacePath, item); err != nil {
				cleanup()
				return "", func() {}, err
			}
		}
	}
	return workspacePath, cleanup, nil
}

func (executor *sshWorkerExecutor) materializeWorkspaceItem(ctx context.Context, request sshflow.Request, workspacePath string, item cloudworker.InputManifestItem) error {
	read, err := executor.sources.OpenSource(ctx, cloudworker.SourceRequest{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration, Input: item})
	if err != nil || read.Body == nil {
		return errors.Join(sshworker.ErrInvalid, err)
	}
	defer read.Body.Close()
	if read.SourceRef != item.SourceRef || read.SourceRevision != item.SourceRevision || read.SizeBytes != item.SizeBytes || read.MediaType != item.MediaType {
		return sshworker.ErrInvalid
	}
	if item.Kind == "archive" {
		body, readErr := io.ReadAll(io.LimitReader(read.Body, int64(item.SizeBytes)+1))
		defer clear(body)
		if readErr != nil || uint64(len(body)) != item.SizeBytes || !matchesSHA256(body, item.SHA256) || workspacearchive.Extract(bytes.NewReader(body), workspacePath) != nil {
			return errors.Join(sshworker.ErrInvalid, readErr)
		}
		return nil
	}
	target := filepath.Join(workspacePath, filepath.FromSlash(item.MountPath))
	if !strings.HasPrefix(target, workspacePath+string(os.PathSeparator)) || filepath.Clean(target) != target || os.MkdirAll(filepath.Dir(target), 0o700) != nil {
		return sshworker.ErrInvalid
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(read.Body, int64(item.SizeBytes)+1))
	syncErr, closeErr := file.Sync(), file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != int64(item.SizeBytes) || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), item.SHA256) {
		return errors.Join(sshworker.ErrInvalid, copyErr, syncErr, closeErr)
	}
	return nil
}

func cleanupWorkspaceInputs(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(root)
}

func matchesSHA256(body []byte, expected string) bool {
	digest := sha256.Sum256(body)
	return strings.EqualFold(hex.EncodeToString(digest[:]), expected)
}

type serviceWorker interface {
	WorkerIdentity(context.Context, sshworker.OwnerAuthority, sshworker.CredentialIdentity, string) (sshworker.WorkerIdentity, error)
	SetPublicPort(context.Context, sshworker.WorkerIdentity, uint16, bool) error
}

func (executor *sshWorkerExecutor) publishService(ctx context.Context, provider serviceWorker, authority sshworker.OwnerAuthority, credential sshworker.CredentialIdentity, workerID, taskID string, service sshworker.RuntimeServiceSpec) error {
	worker, err := provider.WorkerIdentity(ctx, authority, credential, workerID)
	if err != nil {
		return err
	}
	if err = executor.workloads.PutService(ctx, sshworkload.Service{Worker: worker, TaskID: taskID,
		WorkloadID: service.WorkloadID, Port: service.Port, HealthPath: service.HealthPath}); err != nil {
		return err
	}
	return provider.SetPublicPort(ctx, worker, service.Port, true)
}

func (executor *sshWorkerExecutor) ResolveIdleWorker(ctx context.Context, ownerID string, accountGeneration uint64, binding cloudworker.AWSBinding, compute cloudworker.ComputeSpec) (cloudworker.ComputeSpec, bool, error) {
	provider, identity, err := executor.provider(ctx, binding)
	if err != nil {
		return cloudworker.ComputeSpec{}, false, err
	}
	worker, found, err := provider.ResolveIdleWorker(ctx, sshworker.OwnerAuthority{OwnerID: ownerID, AccountGeneration: accountGeneration}, identity,
		compute.InstanceType, compute.VCPU, compute.MemoryGiB, int32(compute.VolumeGiB))
	if err != nil || !found {
		return cloudworker.ComputeSpec{}, false, err
	}
	return cloudworker.ComputeSpec{InstanceType: worker.InstanceType, Architecture: "x86_64", VCPU: worker.VCPU, MemoryGiB: worker.MemoryGiB,
		RootDeviceName: "/dev/xvda", VolumeGiB: uint64(worker.VolumeGiB), VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125}, true, nil
}

func (executor *sshWorkerExecutor) CheckCreateWorkerCapacity(ctx context.Context, ownerID string, accountGeneration uint64, binding cloudworker.AWSBinding, _ cloudworker.ComputeSpec) error {
	provider, identity, err := executor.provider(ctx, binding)
	if err != nil {
		return err
	}
	return provider.CheckCreateCapacity(ctx, sshworker.OwnerAuthority{OwnerID: ownerID, AccountGeneration: accountGeneration}, identity)
}

func boundedWorkerSummary(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 3000 {
		return value
	}
	runes := []rune(value)
	for len(string(runes)) > 3000 {
		runes = runes[1:]
	}
	return strings.TrimSpace(string(runes))
}

type sshWorkerCredentials struct{ executor *sshWorkerExecutor }

func (source sshWorkerCredentials) HasCurrentVerifiedCredential(ctx context.Context) bool {
	if source.executor == nil || source.executor.authority == nil {
		return false
	}
	return source.executor.authority.HasCurrentVerifiedAWSBinding(ctx)
}

func (executor *sshWorkerExecutor) providerForIdentity(ctx context.Context, identity sshworker.CredentialIdentity) (*sshworker.Provider, error) {
	provider, actual, err := executor.provider(ctx, cloudworker.AWSBinding{AccountID: identity.AccountID, Region: identity.Region,
		CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision})
	if err != nil || actual != identity {
		return nil, errors.Join(sshworker.ErrIdentity, err)
	}
	return provider, nil
}

func (executor *sshWorkerExecutor) HasManagedWorkers(ctx context.Context) bool {
	if executor == nil || executor.state == nil || ctx == nil {
		return false
	}
	identities, err := executor.state.ListCredentialIdentities(ctx)
	return err == nil && len(identities) > 0
}

func (executor *sshWorkerExecutor) ListWorkers(ctx context.Context, authority sshworker.OwnerAuthority) ([]sshworker.WorkerStatus, error) {
	if executor == nil || executor.state == nil || ctx == nil || authority.OwnerID == "" || authority.AccountGeneration == 0 {
		return nil, sshworker.ErrInvalid
	}
	records, err := executor.state.ListWorkers(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]sshworker.WorkerStatus, 0)
	byCredential := make(map[sshworker.CredentialIdentity][]sshworker.WorkerRecord)
	for _, worker := range records {
		if worker.OwnerID == authority.OwnerID && worker.AccountGeneration == authority.AccountGeneration && worker.Phase != sshworker.WorkerDestroyed {
			byCredential[worker.Credential] = append(byCredential[worker.Credential], worker)
		}
	}
	for identity, retained := range byCredential {
		provider, providerErr := executor.providerForIdentity(ctx, identity)
		if providerErr != nil {
			for _, worker := range retained {
				result = append(result, sshworker.UnavailableStatus(worker, time.Now(), "AWS credential revision is unavailable"))
			}
			continue
		}
		workers, listErr := provider.ListWorkers(ctx, authority, identity)
		if listErr != nil {
			for _, worker := range retained {
				result = append(result, sshworker.UnavailableStatus(worker, time.Now(), "Worker provider is unavailable"))
			}
			continue
		}
		result = append(result, workers...)
	}
	return result, nil
}

func (executor *sshWorkerExecutor) ResolveRetainedWorkerInventory(ctx context.Context, ownerID string, accountGeneration uint64) (cloudworker.RetainedWorkerInventory, error) {
	statuses, err := executor.ListWorkers(ctx, sshworker.OwnerAuthority{OwnerID: ownerID, AccountGeneration: accountGeneration})
	if err != nil {
		return cloudworker.RetainedWorkerInventory{}, err
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Identity.WorkerID < statuses[j].Identity.WorkerID })
	inventory := cloudworker.RetainedWorkerInventory{ObservedAt: time.Now().UTC(), AtCapacity: len(statuses) >= sshworker.MaxWorkers,
		Workers: make([]cloudworker.RetainedWorkerSnapshot, 0, len(statuses))}
	for _, status := range statuses {
		worker := cloudworker.RetainedWorkerSnapshot{WorkerID: status.Identity.WorkerID, Availability: string(status.Availability),
			EC2State: status.EC2State, WorkerPhase: string(status.WorkerPhase), PublicIPv4: status.PublicIP, Error: status.Error}
		if status.CurrentExecutionID != "" {
			worker.CurrentTask = &cloudworker.RetainedWorkerTask{ExecutionID: status.CurrentExecutionID, Phase: string(status.TaskPhase)}
		}
		if !status.Runner.LastSeen.IsZero() {
			worker.Server = &cloudworker.RetainedWorkerServer{LastSeen: status.Runner.LastSeen.UTC(), Load1: status.Runner.Load1,
				Load5: status.Runner.Load5, Load15: status.Runner.Load15}
		}
		if status.Quote.Currency != "" && !status.Quote.ExpiresAt.IsZero() {
			worker.HourlyQuote = &cloudworker.RetainedWorkerQuote{Currency: status.Quote.Currency, MicrosPerHour: status.Quote.MicrosPerHour,
				ObservedAt: status.Quote.ObservedAt.UTC(), ExpiresAt: status.Quote.ExpiresAt.UTC()}
		}
		if status.Availability == sshworker.WorkerAvailable {
			workloads, workloadErr := executor.ListWorkerWorkloads(ctx, status)
			if workloadErr != nil {
				return cloudworker.RetainedWorkerInventory{}, workloadErr
			}
			sort.Slice(workloads, func(i, j int) bool { return workloads[i].WorkloadID < workloads[j].WorkloadID })
			worker.Workloads = make([]cloudworker.RetainedWorkerWorkload, 0, len(workloads))
			for _, workload := range workloads {
				item := cloudworker.RetainedWorkerWorkload{WorkloadID: workload.WorkloadID, Kind: workload.Kind, Phase: workload.Phase,
					ActiveState: workload.ActiveState, Health: workload.Health, Port: workload.Port}
				if workload.Domain != nil {
					item.Hostname = workload.Domain.Hostname
				}
				worker.Workloads = append(worker.Workloads, item)
			}
		}
		inventory.Workers = append(inventory.Workers, worker)
	}
	return inventory, nil
}

func (executor *sshWorkerExecutor) ObserveWorker(ctx context.Context, authority sshworker.OwnerAuthority, identity sshworker.WorkerIdentity) (sshworker.WorkerStatus, error) {
	identity.OwnerID, identity.AccountGeneration = authority.OwnerID, authority.AccountGeneration
	worker, found, loadErr := executor.state.LoadWorker(ctx, identity.WorkerID)
	if loadErr != nil || !found || worker.OwnerID != authority.OwnerID || worker.AccountGeneration != authority.AccountGeneration || worker.Credential != identity.Credential || worker.Instance.ID != identity.InstanceID || worker.KeyPair.ID != identity.KeyPairID || worker.SecurityGroup.ID != identity.SecurityGroupID || worker.Phase == sshworker.WorkerDestroyed {
		return sshworker.WorkerStatus{}, errors.Join(sshworker.ErrIdentity, loadErr)
	}
	provider, err := executor.providerForIdentity(ctx, identity.Credential)
	if err != nil {
		return sshworker.UnavailableStatus(worker, time.Now(), "AWS credential revision is unavailable"), nil
	}
	return provider.ObserveWorker(ctx, identity)
}

func (executor *sshWorkerExecutor) DestroyWorker(ctx context.Context, authority sshworker.OwnerAuthority, request sshworker.DestroyRequest) error {
	request.Identity.OwnerID, request.Identity.AccountGeneration = authority.OwnerID, authority.AccountGeneration
	worker, found, err := executor.state.LoadWorker(ctx, request.Identity.WorkerID)
	if err != nil || !found || worker.OwnerID != authority.OwnerID || worker.AccountGeneration != authority.AccountGeneration ||
		worker.Credential != request.Identity.Credential || worker.Instance.ID != request.Identity.InstanceID || worker.KeyPair.ID != request.Identity.KeyPairID || worker.SecurityGroup.ID != request.Identity.SecurityGroupID {
		return errors.Join(sshworker.ErrIdentity, err)
	}
	provider, err := executor.providerForIdentity(ctx, request.Identity.Credential)
	if err != nil {
		return err
	}
	return executor.destroyWorkerResources(ctx, provider, request)
}

type workerDestroyer interface {
	DestroyWorkerResources(context.Context, sshworker.DestroyRequest) error
	FinalizeWorkerDestroy(context.Context, sshworker.DestroyRequest) error
}

func (executor *sshWorkerExecutor) destroyWorkerResources(ctx context.Context, provider workerDestroyer, request sshworker.DestroyRequest) error {
	if !completeWorkerResourceIdentity(request.Identity) {
		if err := provider.DestroyWorkerResources(ctx, request); err != nil {
			return err
		}
		return provider.FinalizeWorkerDestroy(ctx, request)
	}
	services, err := executor.workloads.List(ctx, request.Identity)
	if err != nil {
		return err
	}
	var dnsErr error
	for _, service := range services {
		if service.Domain == nil {
			continue
		}
		dnsErr = errors.Join(dnsErr, executor.deleteDomain(ctx, service, "destroy_worker"))
	}
	if err = provider.DestroyWorkerResources(ctx, request); err != nil {
		return err
	}
	if dnsErr != nil {
		// The exact compute is gone, but retain the exact DNS/workload identity
		// so a later owner-authorized cleanup can retry the unresolved record.
		return dnsErr
	}
	if err = executor.workloads.RemoveWorker(ctx, request.Identity); err != nil {
		return err
	}
	return provider.FinalizeWorkerDestroy(ctx, request)
}

func completeWorkerResourceIdentity(identity sshworker.WorkerIdentity) bool {
	return strings.TrimSpace(identity.InstanceID) != "" && strings.TrimSpace(identity.KeyPairID) != "" && strings.TrimSpace(identity.SecurityGroupID) != ""
}

type sshWorkerDomains struct{ executor *sshWorkerExecutor }

func (domains sshWorkerDomains) BindDomain(ctx context.Context, command workercap.DomainCommand) (workercap.DomainStatus, error) {
	provider, err := domains.executor.providerForIdentity(ctx, command.Worker.Credential)
	if err != nil {
		return workercap.DomainStatus{}, err
	}
	status, err := provider.ObserveWorker(ctx, command.Worker)
	if err != nil || status.PublicIP == "" {
		return workercap.DomainStatus{}, errors.Join(sshworker.ErrIdentity, err)
	}
	service, err := domains.executor.workloads.Get(ctx, command.Worker, command.WorkloadID)
	if err != nil {
		return workercap.DomainStatus{}, err
	}
	if runtime, observeErr := provider.ObserveService(ctx, command.Worker, service.TaskID); observeErr != nil || runtime.Health != "healthy" {
		return workercap.DomainStatus{}, errors.Join(sshworker.ErrInvalid, observeErr)
	}
	dns := domains.executor.route53For(command.Worker.Credential)
	if dns == nil {
		return workercap.DomainStatus{}, remoteservice.ErrInvalid
	}
	domain := &sshworkload.Domain{ZoneID: command.ZoneID, Hostname: command.Hostname, TTL: command.TTL, BoundIPv4: status.PublicIP, PublicPort: service.Port}
	mutation := remoteservice.DNSMutation{Action: remoteservice.DNSUpsertA, AccountID: command.Worker.Credential.AccountID, WorkerID: command.Worker.WorkerID,
		WorkloadID: command.WorkloadID, Record: remoteservice.ARecord{ZoneID: domain.ZoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}}
	if err = remoteservice.ReconcileLiteral(ctx, dns, mutation, command.Confirmation); err != nil {
		return workercap.DomainStatus{}, err
	}
	if err = domains.executor.workloads.SetDomain(ctx, command.Worker, command.WorkloadID, domain); err != nil {
		return workercap.DomainStatus{}, err
	}
	return projectDomain(domain, "current"), nil
}

func (domains sshWorkerDomains) UnbindDomain(ctx context.Context, command workercap.DomainCommand) (workercap.DomainStatus, error) {
	service, err := domains.executor.workloads.Get(ctx, command.Worker, command.WorkloadID)
	if err != nil {
		return workercap.DomainStatus{}, err
	}
	if service.Domain == nil || service.Domain.ZoneID != command.ZoneID || service.Domain.Hostname != command.Hostname || service.Domain.TTL != command.TTL {
		return workercap.DomainStatus{}, sshworkload.ErrIdentity
	}
	domain := *service.Domain
	if err = domains.executor.deleteDomain(ctx, service, command.Confirmation); err != nil {
		return workercap.DomainStatus{}, err
	}
	return projectDomain(&domain, "current"), nil
}

func (executor *sshWorkerExecutor) deleteDomain(ctx context.Context, service sshworkload.Service, confirmation string) error {
	domain := service.Domain
	if domain == nil {
		return nil
	}
	dns := executor.route53For(service.Worker.Credential)
	if dns == nil {
		return remoteservice.ErrInvalid
	}
	mutation := remoteservice.DNSMutation{Action: remoteservice.DNSDeleteA, AccountID: service.Worker.Credential.AccountID, WorkerID: service.Worker.WorkerID,
		WorkloadID: service.WorkloadID, Record: remoteservice.ARecord{ZoneID: domain.ZoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}}
	if err := remoteservice.ReconcileLiteral(ctx, dns, mutation, confirmation); err != nil {
		return err
	}
	if confirmation == "destroy_worker" {
		return nil
	}
	return executor.workloads.SetDomain(ctx, service.Worker, service.WorkloadID, nil)
}

func projectDomain(domain *sshworkload.Domain, state string) workercap.DomainStatus {
	if domain == nil {
		return workercap.DomainStatus{}
	}
	return workercap.DomainStatus{Mode: "route53_same_account", ZoneID: domain.ZoneID, Hostname: domain.Hostname,
		TargetIPv4: domain.BoundIPv4, TTL: domain.TTL, RecordStatus: state}
}

func (executor *sshWorkerExecutor) ListWorkerWorkloads(ctx context.Context, worker sshworker.WorkerStatus) ([]workercap.WorkloadStatus, error) {
	if !completeWorkerResourceIdentity(worker.Identity) {
		return nil, nil
	}
	services, err := executor.workloads.List(ctx, worker.Identity)
	if err != nil {
		return nil, err
	}
	provider, err := executor.providerForIdentity(ctx, worker.Identity.Credential)
	if err != nil {
		return nil, err
	}
	result := make([]workercap.WorkloadStatus, 0, len(services))
	for _, service := range services {
		runtime, observeErr := provider.ObserveService(ctx, worker.Identity, service.TaskID)
		status := workercap.WorkloadStatus{WorkloadID: service.WorkloadID, Kind: "service", Phase: "unavailable", ActiveState: "unknown", Health: "unknown", Port: service.Port}
		if observeErr == nil {
			status.Phase, status.ActiveState, status.Health = runtime.Phase, runtime.ActiveState, runtime.Health
		}
		if service.Domain != nil {
			status.Domain = ptrDomain(projectDomainForWorker(service.Domain, worker.PublicIP))
		}
		result = append(result, status)
	}
	return result, nil
}

func projectDomainForWorker(domain *sshworkload.Domain, currentPublicIP string) workercap.DomainStatus {
	state := "current"
	if domain != nil && currentPublicIP != "" && domain.BoundIPv4 != currentPublicIP {
		state = "drifted"
	}
	return projectDomain(domain, state)
}

func ptrDomain(value workercap.DomainStatus) *workercap.DomainStatus { return &value }

func (executor *sshWorkerExecutor) route53For(identity sshworker.CredentialIdentity) remoteservice.Route53 {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.route53[identity]
}

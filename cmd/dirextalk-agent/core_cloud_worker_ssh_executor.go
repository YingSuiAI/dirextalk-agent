package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	workercap "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type sshWorkerExecutor struct {
	authority *cloudWorkerCredentialAuthority
	exact     workaws.ExactCredentialResolver
	providers map[sshworker.CredentialIdentity]*sshworker.Provider
	artifacts *localartifact.Repository
	workloads *sshworkload.Repository
	route53   map[sshworker.CredentialIdentity]remoteservice.Route53
	root      string
	mu        sync.Mutex
}

func newSSHWorkerExecutor(authority *cloudWorkerCredentialAuthority, exact workaws.ExactCredentialResolver, artifacts *localartifact.Repository, root string) (*sshWorkerExecutor, error) {
	if authority == nil || exact == nil || artifacts == nil || !filepath.IsAbs(root) {
		return nil, sshworker.ErrInvalid
	}
	workloads, err := sshworkload.NewRepository(filepath.Join(root, "workloads"))
	if err != nil {
		return nil, err
	}
	return &sshWorkerExecutor{authority: authority, exact: exact, providers: make(map[sshworker.CredentialIdentity]*sshworker.Provider), artifacts: artifacts,
		workloads: workloads, route53: make(map[sshworker.CredentialIdentity]remoteservice.Route53), root: root}, nil
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
	config := awssdk.Config{Region: handle.Region, Credentials: credentials.NewStaticCredentialsProvider(handle.AccessKeyID, handle.SecretAccessKey, handle.SessionToken)}
	client, err := sshworker.NewSDK(config, sshworker.HTTPPublicIPReader{})
	if err != nil {
		return nil, identity, err
	}
	store, err := sshworker.NewFileStore(filepath.Join(executor.root, "state"))
	if err != nil {
		return nil, identity, err
	}
	keys, err := sshworker.NewLocalKeyMaterial(filepath.Join(executor.root, "keys"))
	if err != nil {
		return nil, identity, err
	}
	status := sshworker.CommandStatusSource{Keys: keys}
	provider, err := sshworker.New(client, keys, sshworker.CommandSSHExecutor{}, store, status)
	if err == nil {
		executor.providers[identity] = provider
		if dns, dnsErr := remoteservice.NewRoute53SDK(config); dnsErr == nil {
			executor.route53[identity] = dns
		}
	}
	return provider, identity, err
}

func (executor *sshWorkerExecutor) Execute(ctx context.Context, request sshflow.Request) (sshflow.Result, error) {
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
		Architecture: request.Compute.Architecture, Workload: workload, Service: service,
		Model: sshworker.RuntimeModel{Provider: string(request.ModelSnapshot.Provider), BaseURL: request.ModelSnapshot.BaseURL,
			Name: request.ModelSnapshot.Model, APIKey: request.ModelSnapshot.APIKey, MaxOutputTokens: request.ModelSnapshot.MaxOutputTokens}})
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
	result, err := provider.Execute(ctx, sshworker.ExecuteRequest{ExecutionID: request.ExecutionID, Credential: identity,
		Confirmation: confirmation, Discovery: discovery,
		InstanceType: request.Compute.InstanceType, VolumeGiB: int32(request.Compute.VolumeGiB), WorkerScript: material.WorkerScript,
		WorkerScriptSHA256: material.WorkerScriptSHA256, Runtime: material.Protocol,
		MaxWorkspaceBytes: 512 << 20, MaxResultBytes: int64(request.Limits.MaxOutputBytes), Sink: sink})
	workerResult := sshflow.Result{ExitCode: result.ExitCode, WorkerID: result.WorkerID}
	if list, _, listErr := executor.artifacts.List(ctx, localartifact.Authority{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration}, request.ExecutionID, "", 200); listErr == nil {
		for _, artifact := range list {
			workerResult.Artifacts = append(workerResult.Artifacts, sshflow.Artifact{ArtifactID: artifact.ArtifactID, ExecutionID: artifact.ExecutionID,
				Kind: artifact.Kind, Name: artifact.Name, MediaType: artifact.MediaType,
				RelativePath: filepath.ToSlash(filepath.Join("cloud-worker/artifacts", request.ExecutionID, artifact.Name)), SizeBytes: artifact.SizeBytes, SHA256: artifact.SHA256})
		}
	}
	workerResult.Summary = boundedWorkerSummary(result.Summary)
	if workerResult.Summary == "" {
		workerResult.Summary = fmt.Sprintf("Cloud Worker %s completed with exit code %d and %d artifacts", workerResult.WorkerID, result.ExitCode, result.ArtifactCount)
	}
	if err != nil {
		return workerResult, err
	}
	if result.ExitCode != 0 {
		return workerResult, fmt.Errorf("remote Worker exited with code %d", result.ExitCode)
	}
	if service != nil {
		workerIdentity, identityErr := provider.WorkerIdentity(ctx, identity, result.WorkerID)
		if identityErr != nil {
			return workerResult, identityErr
		}
		if err = executor.workloads.PutService(ctx, sshworkload.Service{Worker: workerIdentity, TaskID: request.ExecutionID,
			WorkloadID: service.WorkloadID, Port: service.Port, HealthPath: service.HealthPath}); err != nil {
			return workerResult, err
		}
	}
	return workerResult, nil
}

func (executor *sshWorkerExecutor) HasIdleWorker(ctx context.Context, binding cloudworker.AWSBinding, compute cloudworker.ComputeSpec) (bool, error) {
	provider, identity, err := executor.provider(ctx, binding)
	if err != nil {
		return false, err
	}
	return provider.HasIdleWorker(ctx, identity, compute.InstanceType)
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

func (source sshWorkerCredentials) CurrentVerifiedCredential(ctx context.Context) (sshworker.CredentialIdentity, error) {
	binding, err := source.executor.authority.ResolveCurrentAWSBinding(ctx)
	if err != nil {
		return sshworker.CredentialIdentity{}, err
	}
	_, identity, err := source.executor.provider(ctx, binding)
	return identity, err
}

func (executor *sshWorkerExecutor) providerForIdentity(ctx context.Context, identity sshworker.CredentialIdentity) (*sshworker.Provider, error) {
	provider, actual, err := executor.provider(ctx, cloudworker.AWSBinding{AccountID: identity.AccountID, Region: identity.Region,
		CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision})
	if err != nil || actual != identity {
		return nil, errors.Join(sshworker.ErrIdentity, err)
	}
	return provider, nil
}

func (executor *sshWorkerExecutor) ListWorkers(ctx context.Context, identity sshworker.CredentialIdentity) ([]sshworker.WorkerStatus, error) {
	provider, err := executor.providerForIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}
	return provider.ListWorkers(ctx, identity)
}

func (executor *sshWorkerExecutor) ObserveWorker(ctx context.Context, identity sshworker.WorkerIdentity) (sshworker.WorkerStatus, error) {
	provider, err := executor.providerForIdentity(ctx, identity.Credential)
	if err != nil {
		return sshworker.WorkerStatus{}, err
	}
	return provider.ObserveWorker(ctx, identity)
}

func (executor *sshWorkerExecutor) DestroyWorker(ctx context.Context, request sshworker.DestroyRequest) error {
	provider, err := executor.providerForIdentity(ctx, request.Identity.Credential)
	if err != nil {
		return err
	}
	services, err := executor.workloads.List(ctx, request.Identity)
	if err != nil {
		return err
	}
	for _, service := range services {
		if service.Domain == nil {
			continue
		}
		if err = executor.deleteDomain(ctx, provider, service, "destroy_worker"); err != nil {
			return err
		}
	}
	if err = provider.DestroyWorker(ctx, request); err != nil {
		return err
	}
	return executor.workloads.RemoveWorker(ctx, request.Identity)
}

type sshWorkerDomains struct{ executor *sshWorkerExecutor }

func (domains sshWorkerDomains) BindDomain(ctx context.Context, command workercap.DomainCommand) (workercap.DomainStatus, error) {
	return domains.change(ctx, command, remoteservice.DNSUpsertA)
}

func (domains sshWorkerDomains) UnbindDomain(ctx context.Context, command workercap.DomainCommand) (workercap.DomainStatus, error) {
	return domains.change(ctx, command, remoteservice.DNSDeleteA)
}

func (domains sshWorkerDomains) change(ctx context.Context, command workercap.DomainCommand, action remoteservice.DNSAction) (workercap.DomainStatus, error) {
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
	if action == remoteservice.DNSDeleteA {
		if service.Domain == nil || service.Domain.ZoneID != command.ZoneID || service.Domain.Hostname != command.Hostname || service.Domain.TTL != command.TTL {
			return workercap.DomainStatus{}, sshworkload.ErrIdentity
		}
		domain := *service.Domain
		if err = domains.executor.deleteDomain(ctx, provider, service, command.Confirmation); err != nil {
			return workercap.DomainStatus{}, err
		}
		return projectDomain(&domain, "current"), nil
	}
	if runtime, observeErr := provider.ObserveService(ctx, command.Worker, service.TaskID); observeErr != nil || runtime.Health != "healthy" {
		return workercap.DomainStatus{}, errors.Join(sshworker.ErrInvalid, observeErr)
	}
	dns := domains.executor.route53For(command.Worker.Credential)
	if dns == nil {
		return workercap.DomainStatus{}, remoteservice.ErrInvalid
	}
	domain := &sshworkload.Domain{ZoneID: command.ZoneID, Hostname: command.Hostname, TTL: command.TTL, BoundIPv4: status.PublicIP, PublicPort: service.Port}
	if err = provider.SetPublicPort(ctx, command.Worker, service.Port, true); err != nil {
		return workercap.DomainStatus{}, err
	}
	mutation := remoteservice.DNSMutation{Action: action, AccountID: command.Worker.Credential.AccountID, WorkerID: command.Worker.WorkerID,
		WorkloadID: command.WorkloadID, Record: remoteservice.ARecord{ZoneID: domain.ZoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}}
	if err = remoteservice.ReconcileLiteral(ctx, dns, mutation, command.Confirmation); err != nil {
		_ = provider.SetPublicPort(ctx, command.Worker, service.Port, false)
		return workercap.DomainStatus{}, err
	}
	if err = domains.executor.workloads.SetDomain(ctx, command.Worker, command.WorkloadID, domain); err != nil {
		return workercap.DomainStatus{}, err
	}
	return projectDomain(domain, "current"), nil
}

func (executor *sshWorkerExecutor) deleteDomain(ctx context.Context, provider *sshworker.Provider, service sshworkload.Service, confirmation string) error {
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
	if err := provider.SetPublicPort(ctx, service.Worker, service.Port, false); err != nil {
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
			if worker.PublicIP != "" && service.Domain.BoundIPv4 != worker.PublicIP {
				dns := executor.route53For(worker.Identity.Credential)
				mutation := remoteservice.DNSMutation{Action: remoteservice.DNSUpsertA, AccountID: worker.Identity.Credential.AccountID, WorkerID: worker.Identity.WorkerID,
					WorkloadID: service.WorkloadID, Record: remoteservice.ARecord{ZoneID: service.Domain.ZoneID, Hostname: service.Domain.Hostname, IPv4: worker.PublicIP, TTL: service.Domain.TTL}}
				if dns == nil || remoteservice.ReconcileLiteral(ctx, dns, mutation, "bind_domain") != nil {
					status.Domain = ptrDomain(projectDomain(service.Domain, "error"))
					result = append(result, status)
					continue
				}
				service.Domain.BoundIPv4 = worker.PublicIP
				if err = executor.workloads.SetDomain(ctx, worker.Identity, service.WorkloadID, service.Domain); err != nil {
					return nil, err
				}
			}
			status.Domain = ptrDomain(projectDomain(service.Domain, "current"))
		}
		result = append(result, status)
	}
	return result, nil
}

func ptrDomain(value workercap.DomainStatus) *workercap.DomainStatus { return &value }

func (executor *sshWorkerExecutor) route53For(identity sshworker.CredentialIdentity) remoteservice.Route53 {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.route53[identity]
}

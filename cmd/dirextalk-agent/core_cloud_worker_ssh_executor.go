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
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type sshWorkerExecutor struct {
	authority *cloudWorkerCredentialAuthority
	exact     workaws.ExactCredentialResolver
	providers map[sshworker.CredentialIdentity]*sshworker.Provider
	artifacts *localartifact.Repository
	pricing   cloudworker.PricingCatalog
	root      string
	mu        sync.Mutex
}

func newSSHWorkerExecutor(authority *cloudWorkerCredentialAuthority, exact workaws.ExactCredentialResolver, artifacts *localartifact.Repository, pricing cloudworker.PricingCatalog, root string) (*sshWorkerExecutor, error) {
	if authority == nil || exact == nil || artifacts == nil || pricing == nil || !filepath.IsAbs(root) {
		return nil, sshworker.ErrInvalid
	}
	return &sshWorkerExecutor{authority: authority, exact: exact, providers: make(map[sshworker.CredentialIdentity]*sshworker.Provider), artifacts: artifacts, pricing: pricing, root: root}, nil
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
	status := sshworker.CommandStatusSource{Keys: keys, Quote: executor.hourlyQuote}
	provider, err := sshworker.New(client, keys, sshworker.CommandSSHExecutor{}, store, status)
	if err == nil {
		executor.providers[identity] = provider
	}
	return provider, identity, err
}

func (executor *sshWorkerExecutor) hourlyQuote(ctx context.Context, identity sshworker.CredentialIdentity, instanceType string, volumeGiB int32) (sshworker.HourlyQuote, error) {
	if volumeGiB <= 0 {
		return sshworker.HourlyQuote{}, sshworker.ErrInvalid
	}
	snapshot, err := executor.pricing.Snapshot(ctx, cloudworker.PricingCatalogRequest{AccountID: identity.AccountID, AccountGeneration: 1,
		Region: identity.Region, CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision,
		InstanceType: instanceType, Architecture: "x86_64", VolumeGiB: uint64(volumeGiB), VolumeType: "gp3", VolumeIOPS: 3000,
		VolumeThroughput: 125, MaxRuntimeSeconds: 3600, MaxTokens: 1, BasisDigest: strings.Repeat("0", 64), WorkspaceMode: cloudworker.WorkspaceNone})
	if err != nil {
		return sshworker.HourlyQuote{}, err
	}
	storagePerHour := (snapshot.Rates.EBSStorageMicrosPerGiBMonth * uint64(volumeGiB)) / 730
	return sshworker.HourlyQuote{Currency: snapshot.Currency, MicrosPerHour: snapshot.Rates.ComputeMicrosPerHour + snapshot.Rates.PublicIPv4MicrosPerHour + storagePerHour,
		ObservedAt: snapshot.SourceTime, ExpiresAt: snapshot.ExpiresAt}, nil
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
	material, err := sshworker.CompileRuntime(sshworker.RuntimeRequest{TaskID: request.ExecutionID, Objective: request.Objective,
		Architecture: request.Compute.Architecture, Workload: sshworker.WorkloadJob,
		Model: sshworker.RuntimeModel{Provider: string(request.ModelSnapshot.Provider), BaseURL: request.ModelSnapshot.BaseURL,
			Name: request.ModelSnapshot.Model, APIKey: request.ModelSnapshot.APIKey, MaxOutputTokens: request.ModelSnapshot.MaxOutputTokens}})
	if err != nil {
		return sshflow.Result{}, err
	}
	sink, err := executor.artifacts.Bind(localartifact.Authority{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration}, request.ExecutionID)
	if err != nil {
		return sshflow.Result{}, err
	}
	result, err := provider.Execute(ctx, sshworker.ExecuteRequest{ExecutionID: request.ExecutionID, Credential: identity,
		Confirmation: sshworker.Confirmation{Confirmed: true, Proof: request.ConfirmationProof}, Discovery: discovery,
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
	return workerResult, nil
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
	return provider.DestroyWorker(ctx, request)
}

type sshWorkerDomains struct{ executor *sshWorkerExecutor }

func (domains sshWorkerDomains) BindDomain(ctx context.Context, command workercap.DomainCommand) (workercap.DomainStatus, error) {
	return domains.change(ctx, command, remoteservice.DNSUpsertA)
}

func (domains sshWorkerDomains) UnbindDomain(ctx context.Context, command workercap.DomainCommand) (workercap.DomainStatus, error) {
	return domains.change(ctx, command, remoteservice.DNSDeleteA)
}

func (domains sshWorkerDomains) change(ctx context.Context, command workercap.DomainCommand, action remoteservice.DNSAction) (workercap.DomainStatus, error) {
	// Domain binding belongs to a persisted service workload. The current job
	// contract does not create one, so no Route53 mutation is authorized yet.
	return workercap.DomainStatus{}, remoteservice.ErrInvalid
}

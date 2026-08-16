package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/workspacearchive"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

type sshWorkerExecutor struct {
	authority   *cloudWorkerCredentialAuthority
	exact       workaws.ExactCredentialResolver
	providers   map[sshworker.CredentialIdentity]*sshworker.Provider
	artifacts   *localartifact.Repository
	pricing     cloudworker.PricingCatalog
	sources     cloudworker.SourceReader
	steers      coreconversation.TurnSteerStore
	state       *sshworker.FileStore
	pool        *sshworker.Pool
	workloads   *sshworkload.Repository
	route53     map[sshworker.CredentialIdentity]remoteservice.HostedZoneRoute53
	root        string
	verifyHTTPS func(context.Context, string, string, string, func(context.Context, string, string) error) error
	mu          sync.Mutex
}

func newSSHWorkerExecutor(authority *cloudWorkerCredentialAuthority, exact workaws.ExactCredentialResolver, artifacts *localartifact.Repository, pricing cloudworker.PricingCatalog, sources cloudworker.SourceReader, steers coreconversation.TurnSteerStore, state *sshworker.FileStore, root string) (*sshWorkerExecutor, error) {
	if authority == nil || exact == nil || artifacts == nil || pricing == nil || sources == nil || steers == nil || state == nil || !filepath.IsAbs(root) {
		return nil, sshworker.ErrInvalid
	}
	workloads, err := sshworkload.NewRepository(filepath.Join(root, "workloads"))
	if err != nil {
		return nil, err
	}
	return &sshWorkerExecutor{authority: authority, exact: exact, providers: make(map[sshworker.CredentialIdentity]*sshworker.Provider), artifacts: artifacts,
		pricing: pricing, sources: sources, steers: steers, state: state, pool: sshworker.NewPool(), workloads: workloads,
		route53: make(map[sshworker.CredentialIdentity]remoteservice.HostedZoneRoute53), root: root}, nil
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
	binding, err := executor.currentBindingForCredential(ctx, worker.Credential)
	if err != nil {
		return sshworker.HourlyQuote{}, err
	}
	identity := sshworker.CredentialIdentity{CredentialID: binding.CredentialID, CredentialRevision: binding.CredentialRevision, AccountID: binding.AccountID, Region: binding.Region}
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
	if request.ReuseOnly {
		worker, found, loadErr := executor.state.LoadWorker(ctx, request.ReuseWorkerID)
		compatible, compatibleErr := executor.workerSupportsService(ctx, worker, request.Service)
		if loadErr != nil || !found || compatibleErr != nil || !compatible {
			return sshflow.Result{}, errors.Join(sshworker.ErrBusy, loadErr, compatibleErr)
		}
	}
	discovery, err := provider.Discover(ctx, identity)
	if err != nil {
		return sshflow.Result{}, err
	}
	workload := sshworker.WorkloadJob
	var service *sshworker.RuntimeServiceSpec
	if request.WorkloadKind == cloudworker.WorkloadService && request.Service != nil {
		workload = sshworker.WorkloadService
		service = &sshworker.RuntimeServiceSpec{WorkloadID: request.Service.WorkloadID, Port: request.Service.Port, HealthPath: request.Service.HealthPath, Hostname: request.Service.Hostname}
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
	var finalize func(context.Context, string, *sshworker.ExecutionResult) error
	if service != nil {
		finalize = func(finalizeCtx context.Context, workerID string, result *sshworker.ExecutionResult) error {
			if request.ReportProgress != nil {
				if progressErr := request.ReportProgress(finalizeCtx, "verifying_service", "Verifying deployed service"); progressErr != nil {
					return progressErr
				}
			}
			publication, publishErr := executor.publishService(finalizeCtx, provider, sshworker.OwnerAuthority{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration}, identity, workerID, request.ExecutionID, *request.Service, request.ReportProgress)
			if detail := publication.summary(); publishErr == nil && detail != "" {
				if strings.TrimSpace(result.Summary) == "" {
					result.Summary = detail
				} else {
					result.Summary = boundedWorkerSummary(result.Summary + "\n\n" + detail)
				}
			}
			return publishErr
		}
	}
	result, err := provider.Execute(ctx, sshworker.ExecuteRequest{ExecutionID: request.ExecutionID,
		Authority: sshworker.OwnerAuthority{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration}, Credential: identity,
		Confirmation: confirmation, Discovery: discovery, ReuseOnly: request.ReuseOnly, ReuseWorkerID: request.ReuseWorkerID,
		InstanceType: request.Compute.InstanceType, VCPU: request.Compute.VCPU, MemoryGiB: request.Compute.MemoryGiB,
		VolumeGiB: int32(request.Compute.VolumeGiB), WorkerScript: material.WorkerScript,
		WorkerScriptSHA256: material.WorkerScriptSHA256, Runtime: material.Protocol,
		WorkspacePath: workspacePath, MaxWorkspaceBytes: 512 << 20, MaxResultBytes: int64(request.Limits.MaxOutputBytes), Sink: sink,
		ResolveGuidance: func(guidanceCtx context.Context) (sshworker.RuntimeGuidance, error) {
			return executor.resolveDeferredWorkerGuidance(guidanceCtx, request)
		}, ReportProgress: request.ReportProgress, Finalize: finalize})
	workerResult := sshflow.Result{ExitCode: result.ExitCode, WorkerID: result.WorkerID}
	workerResult.AppliedSteerIDs = append([]string(nil), result.AppliedSteerIDs...)
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
	return workerResult, nil
}

func (executor *sshWorkerExecutor) resolveDeferredWorkerGuidance(ctx context.Context, request sshflow.Request) (sshworker.RuntimeGuidance, error) {
	if executor == nil || executor.sources == nil || executor.steers == nil {
		return sshworker.RuntimeGuidance{}, sshworker.ErrInvalid
	}
	steers, err := executor.steers.ListTurnSteers(ctx, request.TurnID)
	if err != nil {
		return sshworker.RuntimeGuidance{}, err
	}
	var guidance strings.Builder
	ids := make([]string, 0, len(steers))
	for _, steer := range steers {
		if !steer.Deferred {
			continue
		}
		ids = append(ids, steer.RequestID)
		guidance.WriteString(strings.TrimSpace(steer.Instruction))
		guidance.WriteByte('\n')
		for _, attachment := range steer.AttachmentSources {
			if attachment.Kind != coreconversation.TurnAttachmentKindFile ||
				(attachment.MediaType != "text/plain" && attachment.MediaType != "text/markdown") {
				continue
			}
			input := cloudworker.InputManifestItem{InputID: attachment.SourceID, Kind: "file", Name: attachment.Name,
				MountPath: "inputs/" + attachment.SourceID + "/" + attachment.Name, MediaType: attachment.MediaType,
				SizeBytes: attachment.SizeBytes, SHA256: attachment.SHA256, SourceRef: attachment.SourceID, SourceRevision: attachment.Revision}
			read, readErr := executor.sources.OpenSource(ctx, cloudworker.SourceRequest{OwnerID: request.OwnerID, AccountGeneration: request.AccountGeneration, Input: input})
			if readErr != nil {
				return sshworker.RuntimeGuidance{}, readErr
			}
			body, readErr := io.ReadAll(read.Body)
			closeErr := read.Body.Close()
			if readErr != nil || closeErr != nil || coreconversation.ValidateTurnModelAttachmentContent(attachment, body) != nil {
				clear(body)
				return sshworker.RuntimeGuidance{}, errors.Join(sshworker.ErrInvalid, readErr, closeErr)
			}
			guidance.WriteString("[ATTACHMENT: " + attachment.Name + "]\n")
			guidance.Write(body)
			guidance.WriteString("\n[END ATTACHMENT]\n")
			clear(body)
		}
	}
	return sshworker.RuntimeGuidance{SteerIDs: ids, Text: strings.TrimSpace(guidance.String())}, nil
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
	ObserveWorker(context.Context, sshworker.WorkerIdentity) (sshworker.WorkerStatus, error)
	SetPublicPort(context.Context, sshworker.WorkerIdentity, uint16, bool) error
}

type servicePublication struct {
	Hostname, PublicIPv4, ZoneID, ManualDNS, HealthPath string
	DNSLookupFailed                                     bool
	TLSReady                                            bool
	Port                                                uint16
}

func (publication servicePublication) summary() string {
	if publication.Hostname == "" || publication.PublicIPv4 == "" {
		return ""
	}
	if publication.ZoneID != "" {
		if publication.TLSReady {
			return fmt.Sprintf("Service HTTPS ready: https://%s%s (A -> %s, Route53 hosted zone %s).", publication.Hostname, publication.HealthPath, publication.PublicIPv4, publication.ZoneID)
		}
		return fmt.Sprintf("Service DNS is configured but HTTPS is not ready: %s A -> %s (Route53 hosted zone %s).", publication.Hostname, publication.PublicIPv4, publication.ZoneID)
	}
	reason := "No matching Route53 hosted zone was available."
	if publication.DNSLookupFailed {
		reason = "Automatic Route53 lookup failed."
	}
	return fmt.Sprintf("Service is running on public IPv4 %s (port %d). %s %s", publication.PublicIPv4, publication.Port, reason, publication.ManualDNS)
}

func (executor *sshWorkerExecutor) publishService(ctx context.Context, provider serviceWorker, authority sshworker.OwnerAuthority, credential sshworker.CredentialIdentity, workerID, taskID string, service cloudworker.ServiceSpec, report func(context.Context, string, string) error) (servicePublication, error) {
	worker, err := provider.WorkerIdentity(ctx, authority, credential, workerID)
	if err != nil {
		return servicePublication{}, err
	}
	if err = executor.workloads.PutService(ctx, sshworkload.Service{Worker: worker, TaskID: taskID,
		WorkloadID: service.WorkloadID, Port: service.Port, HealthPath: service.HealthPath,
		Hostname: remoteservice.CanonicalHostname(service.Hostname)}); err != nil {
		return servicePublication{}, err
	}
	publicPorts := []uint16{service.Port}
	if service.Hostname != "" {
		publicPorts = []uint16{80, 443}
	}
	for _, port := range publicPorts {
		if _, err = executor.currentBindingForCredential(ctx, credential); err != nil {
			return servicePublication{}, err
		}
		if err = provider.SetPublicPort(ctx, worker, port, true); err != nil {
			return servicePublication{}, err
		}
	}
	if service.Hostname != "" {
		if _, err = executor.currentBindingForCredential(ctx, credential); err != nil {
			return servicePublication{}, err
		}
		if err = provider.SetPublicPort(ctx, worker, service.Port, false); err != nil {
			return servicePublication{}, err
		}
	}
	if service.Hostname == "" {
		return servicePublication{}, nil
	}
	if _, err = executor.currentBindingForCredential(ctx, credential); err != nil {
		return servicePublication{}, err
	}
	status, err := provider.ObserveWorker(ctx, worker)
	if err != nil || status.PublicIP == "" {
		return servicePublication{}, errors.Join(sshworker.ErrIdentity, err)
	}
	publication := servicePublication{Hostname: remoteservice.CanonicalHostname(service.Hostname), PublicIPv4: status.PublicIP, Port: service.Port, HealthPath: service.HealthPath}
	instructions, err := remoteservice.CompileExternalDNS(remoteservice.DomainBinding{Mode: remoteservice.DomainExternal,
		Hostname: publication.Hostname, TTL: 300}, publication.PublicIPv4)
	if err != nil {
		return servicePublication{}, err
	}
	publication.ManualDNS = instructions.Summary
	dns := executor.route53For(ctx, credential)
	if dns == nil {
		publication.DNSLookupFailed = true
		return publication, nil
	}
	if err = dns.VerifyAccount(ctx, credential.AccountID); err != nil {
		publication.DNSLookupFailed = true
		slog.Warn("[cloud-worker.route53] account_verification_failed", "error", err, "hostname", publication.Hostname)
		return publication, nil
	}
	zoneID, found, resolveErr := dns.ResolveHostedZone(ctx, publication.Hostname)
	if resolveErr != nil {
		publication.DNSLookupFailed = true
		slog.Warn("[cloud-worker.route53] hosted_zone_lookup_failed", "error", resolveErr, "hostname", publication.Hostname)
		return publication, nil
	}
	if !found {
		return publication, nil
	}
	domain := &sshworkload.Domain{ZoneID: zoneID, Hostname: publication.Hostname, TTL: 300, BoundIPv4: publication.PublicIPv4}
	mutation := remoteservice.DNSMutation{Action: remoteservice.DNSUpsertA, AccountID: credential.AccountID, WorkerID: worker.WorkerID,
		WorkloadID: service.WorkloadID, Record: remoteservice.ARecord{ZoneID: zoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}}
	stored, err := executor.workloads.Get(ctx, worker, service.WorkloadID)
	if err != nil {
		return servicePublication{}, err
	}
	if err = executor.workloads.StageDomain(ctx, worker, service.WorkloadID, domain); err != nil {
		return servicePublication{}, err
	}
	if err = remoteservice.ReconcilePlannedUpsert(ctx, dns, mutation); err != nil {
		return servicePublication{}, err
	}
	if stored.Domain != nil && !sameDomainRecordKey(stored.Domain, domain) {
		if err = remoteservice.ReconcilePlannedDelete(ctx, dns, domainMutation(credential.AccountID, worker.WorkerID, service.WorkloadID, remoteservice.DNSDeleteA, stored.Domain)); err != nil {
			return servicePublication{}, err
		}
	}
	if err = executor.workloads.CommitDomain(ctx, worker, service.WorkloadID); err != nil {
		return servicePublication{}, err
	}
	publication.ZoneID = zoneID
	verify := executor.verifyHTTPS
	if verify == nil {
		verify = verifyPublicServiceHTTPS
	}
	if err = verify(ctx, publication.Hostname, publication.PublicIPv4, publication.HealthPath, report); err != nil {
		return publication, err
	}
	publication.TLSReady = true
	return publication, nil
}

func verifyPublicServiceHTTPS(ctx context.Context, hostname, publicIPv4, healthPath string, report func(context.Context, string, string) error) error {
	if net.ParseIP(publicIPv4).To4() == nil {
		return fmt.Errorf("public HTTPS health verification has invalid IPv4 %q", publicIPv4)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(publicIPv4, port))
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	var lastErr error
	for attempt := 0; attempt < 24; attempt++ {
		if report != nil {
			if err := report(ctx, "verifying_service", "Verifying public HTTPS service"); err != nil {
				return err
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+healthPath, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 400 {
				return nil
			}
			err = fmt.Errorf("HTTPS health returned %d", response.StatusCode)
		}
		lastErr = err
		if attempt == 23 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("public HTTPS health verification failed for %s: %w", hostname, lastErr)
}

func (executor *sshWorkerExecutor) ResolveIdleWorker(ctx context.Context, ownerID string, accountGeneration uint64, binding cloudworker.AWSBinding, requirements cloudworker.ComputeRequirements, service *cloudworker.ServiceSpec) (cloudworker.WorkerReuseSelection, bool, error) {
	provider, identity, err := executor.provider(ctx, binding)
	if err != nil {
		return cloudworker.WorkerReuseSelection{}, false, err
	}
	worker, found, err := provider.ResolveIdleWorker(ctx, sshworker.OwnerAuthority{OwnerID: ownerID, AccountGeneration: accountGeneration}, identity,
		requirements.MinVCPU, requirements.MinMemoryGiB, int32(requirements.DiskGiB))
	if err != nil || !found {
		return cloudworker.WorkerReuseSelection{}, false, err
	}
	compatible, err := executor.workerSupportsService(ctx, worker, service)
	if err != nil || !compatible {
		return cloudworker.WorkerReuseSelection{}, false, err
	}
	return cloudworker.WorkerReuseSelection{WorkerID: worker.WorkerID, Compute: cloudworker.ComputeSpec{InstanceType: worker.InstanceType, Architecture: "x86_64", VCPU: worker.VCPU, MemoryGiB: worker.MemoryGiB,
		RootDeviceName: "/dev/xvda", VolumeGiB: uint64(worker.VolumeGiB), VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125}}, true, nil
}

func (executor *sshWorkerExecutor) workerSupportsService(ctx context.Context, worker sshworker.WorkerRecord, requested *cloudworker.ServiceSpec) (bool, error) {
	if requested == nil {
		return true, nil
	}
	identity := sshworker.WorkerIdentity{WorkerID: worker.WorkerID, OwnerID: worker.OwnerID, AccountGeneration: worker.AccountGeneration,
		Credential: worker.Credential, InstanceID: worker.Instance.ID, KeyPairID: worker.KeyPair.ID, SecurityGroupID: worker.SecurityGroup.ID}
	services, err := executor.workloads.List(ctx, identity)
	if err != nil {
		return false, err
	}
	reserved := map[uint16]struct{}{requested.Port: {}}
	if requested.Hostname != "" {
		reserved[80], reserved[443] = struct{}{}, struct{}{}
	}
	for _, service := range services {
		existingHostname := remoteservice.CanonicalHostname(service.Hostname)
		if existingHostname == "" && service.Domain != nil {
			existingHostname = remoteservice.CanonicalHostname(service.Domain.Hostname)
		}
		if service.WorkloadID == requested.WorkloadID {
			if service.Port != requested.Port || service.HealthPath != requested.HealthPath ||
				(existingHostname != "" && existingHostname != remoteservice.CanonicalHostname(requested.Hostname)) {
				return false, nil
			}
		}
		if requested.Hostname != "" && service.WorkloadID != requested.WorkloadID &&
			existingHostname == remoteservice.CanonicalHostname(requested.Hostname) {
			return false, nil
		}
		if _, conflict := reserved[service.Port]; conflict {
			if service.WorkloadID == requested.WorkloadID && service.Port == requested.Port {
				continue
			}
			return false, nil
		}
	}
	return true, nil
}

func (executor *sshWorkerExecutor) CheckCreateWorkerCapacity(ctx context.Context, ownerID string, accountGeneration uint64, binding cloudworker.AWSBinding) error {
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
	binding, err := executor.currentBindingForCredential(ctx, identity)
	if err != nil {
		return nil, err
	}
	provider, actual, err := executor.provider(ctx, binding)
	if err != nil || actual.CredentialID != identity.CredentialID || actual.AccountID != identity.AccountID || actual.Region != identity.Region {
		return nil, errors.Join(sshworker.ErrIdentity, err)
	}
	return provider, nil
}

func (executor *sshWorkerExecutor) currentBindingForCredential(ctx context.Context, identity sshworker.CredentialIdentity) (cloudworker.AWSBinding, error) {
	if executor == nil || executor.authority == nil || ctx == nil {
		return cloudworker.AWSBinding{}, sshworker.ErrIdentity
	}
	binding, err := executor.authority.ResolveCurrentAWSBinding(ctx)
	if err != nil || binding.CredentialID != identity.CredentialID || binding.AccountID != identity.AccountID || binding.Region != identity.Region {
		return cloudworker.AWSBinding{}, errors.Join(sshworker.ErrIdentity, err)
	}
	return binding, nil
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
		worker := cloudworker.RetainedWorkerSnapshot{WorkerID: status.Identity.WorkerID, InstanceType: status.InstanceType,
			VCPU: status.VCPU, MemoryGiB: status.MemoryGiB, VolumeGiB: status.VolumeGiB, Availability: string(status.Availability),
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
					ActiveState: workload.ActiveState, Health: workload.Health, Port: workload.Port, Hostname: workload.Hostname}
				if item.Hostname == "" && workload.Domain != nil {
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

func (executor *sshWorkerExecutor) DestroyRetainedWorker(ctx context.Context, ownerID string, accountGeneration uint64, workerID, proof string) error {
	if executor == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || accountGeneration == 0 || strings.TrimSpace(workerID) == "" || strings.TrimSpace(proof) == "" {
		return sshworker.ErrInvalid
	}
	worker, found, err := executor.state.LoadWorker(ctx, workerID)
	if err != nil || !found || worker.OwnerID != ownerID || worker.AccountGeneration != accountGeneration {
		return errors.Join(sshworker.ErrIdentity, err)
	}
	identity := sshworker.WorkerIdentity{
		WorkerID: worker.WorkerID, OwnerID: worker.OwnerID, AccountGeneration: worker.AccountGeneration,
		Credential: worker.Credential, InstanceID: worker.Instance.ID,
		KeyPairID: worker.KeyPair.ID, SecurityGroupID: worker.SecurityGroup.ID,
	}
	return executor.DestroyWorker(ctx, sshworker.OwnerAuthority{OwnerID: ownerID, AccountGeneration: accountGeneration}, sshworker.DestroyRequest{
		Identity: identity, Authorization: sshworker.DestroyAuthorization{Authorized: true, Proof: proof},
	})
}

type workerDestroyer interface {
	DestroyWorkerResources(context.Context, sshworker.DestroyRequest) error
	FinalizeWorkerDestroy(context.Context, sshworker.DestroyRequest) error
}

const retainedWorkerDestroyCompletionTimeout = 10 * time.Minute

func (executor *sshWorkerExecutor) destroyWorkerResources(ctx context.Context, provider workerDestroyer, request sshworker.DestroyRequest) error {
	completionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), retainedWorkerDestroyCompletionTimeout)
	defer cancel()
	if !completeWorkerResourceIdentity(request.Identity) {
		if err := provider.DestroyWorkerResources(completionCtx, request); err != nil {
			return err
		}
		return provider.FinalizeWorkerDestroy(completionCtx, request)
	}
	services, err := executor.workloads.List(completionCtx, request.Identity)
	if err != nil {
		return err
	}
	var dnsErr error
	for _, service := range services {
		if service.Domain == nil && service.PendingDomain == nil {
			continue
		}
		dnsErr = errors.Join(dnsErr, executor.deleteDomain(completionCtx, service, "destroy_worker"))
	}
	if err = provider.DestroyWorkerResources(completionCtx, request); err != nil {
		return err
	}
	if dnsErr != nil {
		// The exact compute is gone, but retain the exact DNS/workload identity
		// so a later owner-authorized cleanup can retry the unresolved record.
		return dnsErr
	}
	if err = executor.workloads.RemoveWorker(completionCtx, request.Identity); err != nil {
		return err
	}
	return provider.FinalizeWorkerDestroy(completionCtx, request)
}

func completeWorkerResourceIdentity(identity sshworker.WorkerIdentity) bool {
	return strings.TrimSpace(identity.InstanceID) != "" && strings.TrimSpace(identity.KeyPairID) != "" && strings.TrimSpace(identity.SecurityGroupID) != ""
}

func (executor *sshWorkerExecutor) deleteDomain(ctx context.Context, service sshworkload.Service, confirmation string) error {
	if service.Domain == nil && service.PendingDomain == nil {
		return nil
	}
	dns := executor.route53For(ctx, service.Worker.Credential)
	if dns == nil {
		return remoteservice.ErrInvalid
	}
	var result error
	pendingDeleted := false
	if service.PendingDomain != nil {
		err := remoteservice.ReconcileLiteral(ctx, dns, domainMutation(service.Worker.Credential.AccountID, service.Worker.WorkerID, service.WorkloadID, remoteservice.DNSDeleteA, service.PendingDomain), confirmation)
		pendingDeleted = err == nil
		if err != nil && !(errors.Is(err, remoteservice.ErrReadback) && sameDomainRecordKey(service.PendingDomain, service.Domain)) {
			result = errors.Join(result, err)
		}
	}
	if service.Domain != nil && !(pendingDeleted && sameDomainRecordKey(service.PendingDomain, service.Domain)) {
		result = errors.Join(result, remoteservice.ReconcileLiteral(ctx, dns, domainMutation(service.Worker.Credential.AccountID, service.Worker.WorkerID, service.WorkloadID, remoteservice.DNSDeleteA, service.Domain), confirmation))
	}
	if result != nil {
		return result
	}
	if confirmation == "destroy_worker" {
		return nil
	}
	return executor.workloads.SetDomain(ctx, service.Worker, service.WorkloadID, nil)
}

func domainMutation(accountID, workerID, workloadID string, action remoteservice.DNSAction, domain *sshworkload.Domain) remoteservice.DNSMutation {
	return remoteservice.DNSMutation{Action: action, AccountID: accountID, WorkerID: workerID, WorkloadID: workloadID,
		Record: remoteservice.ARecord{ZoneID: domain.ZoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}}
}

func sameDomainRecordKey(left, right *sshworkload.Domain) bool {
	return left != nil && right != nil && left.ZoneID == right.ZoneID &&
		remoteservice.CanonicalHostname(left.Hostname) == remoteservice.CanonicalHostname(right.Hostname)
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
		status := workercap.WorkloadStatus{WorkloadID: service.WorkloadID, Kind: "service", Phase: "unavailable", ActiveState: "unknown", Health: "unknown", Port: service.Port, Hostname: service.Hostname}
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

func (executor *sshWorkerExecutor) route53For(ctx context.Context, identity sshworker.CredentialIdentity) remoteservice.HostedZoneRoute53 {
	binding, err := executor.currentBindingForCredential(ctx, identity)
	if err != nil {
		return nil
	}
	_, current, err := executor.provider(ctx, binding)
	if err != nil {
		return nil
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.route53[current]
}

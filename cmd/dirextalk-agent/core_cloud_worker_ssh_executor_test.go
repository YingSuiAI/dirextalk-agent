package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	workercap "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

type serviceWorkerStub struct {
	identity sshworker.WorkerIdentity
	port     uint16
	open     bool
	err      error
}

func (worker *serviceWorkerStub) WorkerIdentity(context.Context, sshworker.OwnerAuthority, sshworker.CredentialIdentity, string) (sshworker.WorkerIdentity, error) {
	return worker.identity, nil
}

func (worker *serviceWorkerStub) SetPublicPort(_ context.Context, _ sshworker.WorkerIdentity, port uint16, open bool) error {
	worker.port, worker.open = port, open
	return worker.err
}

type route53Stub struct {
	record    remoteservice.ARecord
	exists    bool
	deletes   int
	deleteErr error
}

func (*route53Stub) VerifyAccount(context.Context, string) error { return nil }
func (*route53Stub) UpsertA(context.Context, remoteservice.DNSMutation) error {
	return errors.New("unexpected upsert")
}
func (route53 *route53Stub) DeleteA(context.Context, remoteservice.DNSMutation) error {
	route53.deletes++
	if route53.deleteErr != nil {
		return route53.deleteErr
	}
	route53.exists = false
	return nil
}

type workspaceSourceStub struct {
	reads map[string]cloudworker.SourceRead
	calls int
}

func (source *workspaceSourceStub) OpenSource(_ context.Context, request cloudworker.SourceRequest) (cloudworker.SourceRead, error) {
	source.calls++
	read, ok := source.reads[request.Input.SourceRef]
	if !ok {
		return cloudworker.SourceRead{}, cloudworker.ErrNotFound
	}
	body, err := io.ReadAll(read.Body)
	if err != nil {
		return cloudworker.SourceRead{}, err
	}
	_ = read.Body.Close()
	read.Body = &workspaceReadSeekCloser{Reader: bytes.NewReader(body)}
	return read, nil
}

type workspaceReadSeekCloser struct{ *bytes.Reader }

func (*workspaceReadSeekCloser) Close() error { return nil }

type workerDestroyerStub struct {
	resourceCalls int
	finalizeCalls int
	request       sshworker.DestroyRequest
	finalized     sshworker.WorkerIdentity
}

func (destroyer *workerDestroyerStub) DestroyWorkerResources(_ context.Context, request sshworker.DestroyRequest) error {
	destroyer.resourceCalls++
	destroyer.request = request
	return nil
}

func (destroyer *workerDestroyerStub) FinalizeWorkerDestroy(_ context.Context, request sshworker.DestroyRequest) error {
	destroyer.finalizeCalls++
	destroyer.finalized = request.Identity
	return nil
}
func (route53 *route53Stub) ReadA(context.Context, string, string) (remoteservice.ARecord, bool, error) {
	return route53.record, route53.exists, nil
}

type workerStatusPricingCatalog struct {
	snapshot cloudworker.PricingCatalogSnapshot
	request  cloudworker.PricingCatalogRequest
}

func (catalog *workerStatusPricingCatalog) Snapshot(_ context.Context, request cloudworker.PricingCatalogRequest) (cloudworker.PricingCatalogSnapshot, error) {
	catalog.request = request
	return catalog.snapshot, nil
}

func TestSSHWorkerHourlyQuoteUsesLiveInfrastructureRates(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	catalog := &workerStatusPricingCatalog{snapshot: cloudworker.PricingCatalogSnapshot{
		Currency: "USD", SourceTime: now, ExpiresAt: now.Add(5 * time.Minute),
		Rates: cloudworker.PricingCatalogRates{
			ComputeMicrosPerHour: 20_800, EBSStorageMicrosPerGiBMonth: 80_000, PublicIPv4MicrosPerHour: 5_000,
		},
	}}
	executor := &sshWorkerExecutor{pricing: catalog}
	identity := sshworker.CredentialIdentity{CredentialID: "credential-1", CredentialRevision: 7, AccountID: "123456789012", Region: "ap-east-1"}
	worker := sshworker.WorkerRecord{OwnerID: "owner", AccountGeneration: 9, Credential: identity, InstanceType: "t3.small", VolumeGiB: 20}
	quote, err := executor.hourlyQuote(context.Background(), worker)
	if err != nil {
		t.Fatal(err)
	}
	if quote.Currency != "USD" || quote.MicrosPerHour != 27_992 || quote.ObservedAt != now || quote.ExpiresAt != now.Add(5*time.Minute) {
		t.Fatalf("quote=%+v", quote)
	}
	if catalog.request.AccountGeneration != worker.AccountGeneration || catalog.request.AccountID != identity.AccountID || catalog.request.Region != identity.Region || catalog.request.CredentialID != identity.CredentialID ||
		catalog.request.CredentialRevision != identity.CredentialRevision || catalog.request.InstanceType != "t3.small" || catalog.request.VolumeGiB != 20 || catalog.request.VolumeType != "gp3" {
		t.Fatalf("pricing request=%+v", catalog.request)
	}
}

func TestSSHWorkerListAndGetProjectUnavailableHistoricalCredential(t *testing.T) {
	state, err := sshworker.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := workerIdentityFixture()
	worker := sshworker.WorkerRecord{WorkerID: identity.WorkerID, OwnerID: identity.OwnerID, AccountGeneration: identity.AccountGeneration,
		Credential: identity.Credential, Phase: sshworker.WorkerIdle, Instance: sshworker.Instance{ID: identity.InstanceID},
		KeyPair: sshworker.KeyPair{ID: identity.KeyPairID}, SecurityGroup: sshworker.SecurityGroup{ID: identity.SecurityGroupID}}
	if err = state.SaveWorker(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	resolver := &cloudWorkerCredentialResolverFake{exactRevision: identity.Credential.CredentialRevision, exactErr: errors.New("historical secret unavailable")}
	executor := &sshWorkerExecutor{exact: resolver, state: state}
	authority := workerAuthorityFixture()
	statuses, err := executor.ListWorkers(context.Background(), authority)
	if err != nil || len(statuses) != 1 || statuses[0].Availability != sshworker.WorkerUnavailable || statuses[0].Error == "" {
		t.Fatalf("list statuses=%+v err=%v", statuses, err)
	}
	status, err := executor.ObserveWorker(context.Background(), authority, identity)
	if err != nil || status.Availability != sshworker.WorkerUnavailable || status.Identity != identity {
		t.Fatalf("get status=%+v err=%v", status, err)
	}
}

func TestSSHWorkerDestroyResolvesCredentialBeforeBusyState(t *testing.T) {
	state, err := sshworker.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := workerIdentityFixture()
	worker := sshworker.WorkerRecord{WorkerID: identity.WorkerID, OwnerID: identity.OwnerID, AccountGeneration: identity.AccountGeneration,
		Credential: identity.Credential, Phase: sshworker.WorkerBusy, CurrentExecutionID: "execution-live",
		Instance: sshworker.Instance{ID: identity.InstanceID}, KeyPair: sshworker.KeyPair{ID: identity.KeyPairID}, SecurityGroup: sshworker.SecurityGroup{ID: identity.SecurityGroupID}}
	if err = state.SaveWorker(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	credentialErr := errors.New("historical secret unavailable")
	resolver := &cloudWorkerCredentialResolverFake{exactRevision: identity.Credential.CredentialRevision, exactErr: credentialErr}
	executor := &sshWorkerExecutor{exact: resolver, state: state}
	err = executor.DestroyWorker(context.Background(), workerAuthorityFixture(), sshworker.DestroyRequest{Identity: identity,
		Authorization: sshworker.DestroyAuthorization{Authorized: true, Proof: "destroy"}})
	if !errors.Is(err, credentialErr) || errors.Is(err, sshworker.ErrBusy) {
		t.Fatalf("destroy error=%v", err)
	}
}

func TestSSHWorkerExecuteRejectsRotatedCurrentCredentialBeforeWorkspaceRead(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	requestBinding, err := authority.ResolveCurrentAWSBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resolver.revisions = []uint64{4, 4}
	resolver.views[0].Revision, resolver.views[0].VerifiedRevision = 4, 4
	sources := &workspaceSourceStub{reads: make(map[string]cloudworker.SourceRead)}
	executor := &sshWorkerExecutor{authority: authority, sources: sources, root: t.TempDir()}
	_, err = executor.Execute(context.Background(), sshflow.Request{AWS: requestBinding})
	if !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("rotated credential returned %v", err)
	}
	if sources.calls != 0 {
		t.Fatal("workspace source was read before current credential revalidation")
	}
}

func TestSSHWorkerRuntimePreservesUnsetProfileOutputLimit(t *testing.T) {
	snapshot := coremodel.ExecutionSnapshot{Provider: coremodel.ProviderOpenAICompatible,
		BaseURL: "https://openrouter.example.test/v1", Model: "deepseek/test", APIKey: "secret"}
	model := workerRuntimeModel(snapshot)
	if model.MaxOutputTokens != 0 {
		t.Fatalf("max output tokens = %d", model.MaxOutputTokens)
	}
	if _, err := sshworker.CompileRuntime(sshworker.RuntimeRequest{TaskID: "33333333-3333-4333-8333-333333333333", MaxRuntimeSeconds: 3600,
		Objective: "deploy the service", Architecture: "x86_64", Workload: sshworker.WorkloadJob, Model: model}); err != nil {
		t.Fatalf("compile profile using Pi default output limit: %v", err)
	}
}

func TestSSHWorkerCreateAuthorizationRechecksCurrentCredentialAtAdmission(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	binding, err := authority.ResolveCurrentAWSBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	executor := &sshWorkerExecutor{authority: authority}
	identity := sshworker.CredentialIdentity{AccountID: binding.AccountID, Region: binding.Region,
		CredentialID: binding.CredentialID, CredentialRevision: binding.CredentialRevision}
	if err = executor.authorizeWorkerCreate(context.Background(), identity); err != nil {
		t.Fatalf("current exact binding was rejected: %v", err)
	}
	resolver.revisions = []uint64{4, 4}
	resolver.views[0].Revision, resolver.views[0].VerifiedRevision = 4, 4
	if err = executor.authorizeWorkerCreate(context.Background(), identity); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("rotated binding was admitted for paid create: %v", err)
	}
}

func TestProjectDomainForWorkerReportsDriftWithoutChangingPersistedTarget(t *testing.T) {
	domain := &sshworkload.Domain{ZoneID: "Z123", Hostname: "app.example.test", BoundIPv4: "203.0.113.10", TTL: 300, PublicPort: 8080}
	status := projectDomainForWorker(domain, "203.0.113.20")
	if status.RecordStatus != "drifted" || status.TargetIPv4 != "203.0.113.10" || domain.BoundIPv4 != "203.0.113.10" {
		t.Fatalf("status=%+v domain=%+v", status, domain)
	}
}

func TestPublishServicePersistsBeforeOpeningPort(t *testing.T) {
	repository, err := sshworkload.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := workerIdentityFixture()
	executor := &sshWorkerExecutor{workloads: repository}
	worker := &serviceWorkerStub{identity: identity}
	service := sshworker.RuntimeServiceSpec{WorkloadID: "web", Port: 8080, HealthPath: "/health"}
	if err = executor.publishService(context.Background(), worker, workerAuthorityFixture(), identity.Credential, identity.WorkerID, "task-a", service); err != nil {
		t.Fatal(err)
	}
	if !worker.open || worker.port != service.Port {
		t.Fatalf("service port open=%t port=%d", worker.open, worker.port)
	}
	if _, err = repository.Get(context.Background(), identity, service.WorkloadID); err != nil {
		t.Fatal(err)
	}

	failedRepository, _ := sshworkload.NewRepository(t.TempDir())
	failedExecutor := &sshWorkerExecutor{workloads: failedRepository}
	worker.err = errors.New("open port failed")
	if err = failedExecutor.publishService(context.Background(), worker, workerAuthorityFixture(), identity.Credential, identity.WorkerID, "task-b", service); err == nil {
		t.Fatal("port failure was accepted")
	}
	if _, err = failedRepository.Get(context.Background(), identity, service.WorkloadID); err != nil {
		t.Fatalf("port failure left service untracked: %v", err)
	}
}

func TestUnbindDomainUsesPersistedAddressWithoutObservingWorker(t *testing.T) {
	identity := workerIdentityFixture()
	repository, err := sshworkload.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := sshworkload.Service{Worker: identity, TaskID: "task-a", WorkloadID: "web", Port: 8080, HealthPath: "/health"}
	domain := &sshworkload.Domain{ZoneID: "Z123", Hostname: "app.example.test", BoundIPv4: "203.0.113.10", TTL: 300, PublicPort: service.Port}
	if err = repository.PutService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	if err = repository.SetDomain(context.Background(), identity, service.WorkloadID, domain); err != nil {
		t.Fatal(err)
	}
	service.Domain = domain
	dns := &route53Stub{record: remoteservice.ARecord{ZoneID: domain.ZoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}, exists: true}
	executor := &sshWorkerExecutor{workloads: repository, route53: map[sshworker.CredentialIdentity]remoteservice.Route53{identity.Credential: dns}}
	_, err = (sshWorkerDomains{executor: executor}).UnbindDomain(context.Background(), workercap.DomainCommand{Worker: identity,
		WorkloadID: service.WorkloadID, ZoneID: domain.ZoneID, Hostname: domain.Hostname, TTL: domain.TTL, Confirmation: "unbind_domain"})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(context.Background(), identity, service.WorkloadID)
	if err != nil || stored.Domain != nil || dns.deletes != 1 {
		t.Fatalf("stored=%+v deletes=%d err=%v", stored, dns.deletes, err)
	}
}

func TestMaterializeWorkspaceUsesExactSealedSourcesAndCleansUp(t *testing.T) {
	content := []byte("authorized input\n")
	item := workspaceManifestItem("44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555", "inputs/input.txt", "file", "text/plain", content)
	manifest := sealedWorkspaceManifest(t, item)
	sources := &workspaceSourceStub{reads: map[string]cloudworker.SourceRead{item.SourceRef: sourceRead(item, content)}}
	executor := &sshWorkerExecutor{root: t.TempDir(), sources: sources}
	path, cleanup, err := executor.materializeWorkspace(context.Background(), sshflowRequest(manifest, cloudworker.WorkspaceReadOnly))
	if err != nil {
		t.Fatal(err)
	}
	stagingRoot := filepath.Dir(path)
	actual, err := os.ReadFile(filepath.Join(path, "inputs", "input.txt"))
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatalf("materialized=%q err=%v", actual, err)
	}
	cleanup()
	if _, err = os.Stat(stagingRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("execution staging directory remains: %v", err)
	}
}

func TestMaterializeWorkspaceRejectsArchiveFileCollisionAndSourceMismatch(t *testing.T) {
	archive := workspaceArchiveFixture(t, "inputs/input.txt", []byte("archive"))
	archiveItem := workspaceManifestItem("44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555", "workspace", "archive", "application/vnd.dirextalk.workspace+tar+gzip", archive)
	fileContent := []byte("ordinary")
	fileItem := workspaceManifestItem("66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777", "inputs/input.txt", "file", "text/plain", fileContent)
	manifest := sealedWorkspaceManifest(t, archiveItem, fileItem)
	sources := &workspaceSourceStub{reads: map[string]cloudworker.SourceRead{
		archiveItem.SourceRef: sourceRead(archiveItem, archive), fileItem.SourceRef: sourceRead(fileItem, fileContent),
	}}
	executor := &sshWorkerExecutor{root: t.TempDir(), sources: sources}
	if _, _, err := executor.materializeWorkspace(context.Background(), sshflowRequest(manifest, cloudworker.WorkspaceWrite)); err == nil {
		t.Fatal("archive/file path collision was accepted")
	}

	mismatch := sealedWorkspaceManifest(t, fileItem)
	badRead := sourceRead(fileItem, fileContent)
	badRead.SourceRevision++
	executor.sources = &workspaceSourceStub{reads: map[string]cloudworker.SourceRead{fileItem.SourceRef: badRead}}
	if _, _, err := executor.materializeWorkspace(context.Background(), sshflowRequest(mismatch, cloudworker.WorkspaceWrite)); !errors.Is(err, sshworker.ErrInvalid) {
		t.Fatalf("source identity mismatch returned %v", err)
	}
}

func TestExecutionArtifactsRejectsMoreThanTerminalFileLimit(t *testing.T) {
	repository, err := localartifact.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := localartifact.Authority{OwnerID: "owner", AccountGeneration: 1}
	executionID := "33333333-3333-4333-8333-333333333333"
	sink, err := repository.Bind(authority, executionID)
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.StoreText(context.Background(), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 127; index++ {
		name := fmt.Sprintf("artifact-%03d.txt", index)
		if err = sink.StoreArtifact(context.Background(), name, bytes.NewReader([]byte{byte(index)}), 1); err != nil {
			t.Fatal(err)
		}
	}
	executor := &sshWorkerExecutor{artifacts: repository}
	if artifacts, err := executor.executionArtifacts(context.Background(), authority, executionID); !errors.Is(err, errSSHWorkerArtifactLimit) || artifacts != nil {
		t.Fatalf("artifacts=%d err=%v", len(artifacts), err)
	}
}

func TestDestroyWorkerReportsDNSFailureAfterComputeDestruction(t *testing.T) {
	identity := workerIdentityFixture()
	repository, err := sshworkload.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := sshworkload.Service{Worker: identity, TaskID: "task-a", WorkloadID: "web", Port: 8080, HealthPath: "/health"}
	domain := &sshworkload.Domain{ZoneID: "Z123", Hostname: "app.example.test", BoundIPv4: "203.0.113.10", TTL: 300, PublicPort: service.Port}
	if err = repository.PutService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	if err = repository.SetDomain(context.Background(), identity, service.WorkloadID, domain); err != nil {
		t.Fatal(err)
	}
	dnsFailure := errors.New("Route53 delete failed")
	dns := &route53Stub{record: remoteservice.ARecord{ZoneID: domain.ZoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}, exists: true, deleteErr: dnsFailure}
	destroyer := &workerDestroyerStub{}
	executor := &sshWorkerExecutor{workloads: repository, route53: map[sshworker.CredentialIdentity]remoteservice.Route53{identity.Credential: dns}}
	request := sshworker.DestroyRequest{Identity: identity, Authorization: sshworker.DestroyAuthorization{Authorized: true, Proof: "destroy"}}
	if err = executor.destroyWorkerResources(context.Background(), destroyer, request); !errors.Is(err, dnsFailure) {
		t.Fatalf("destroy returned %v", err)
	}
	if destroyer.resourceCalls != 1 || destroyer.finalizeCalls != 0 || destroyer.request.Identity != identity {
		t.Fatalf("exact compute destroy was not invoked: %+v", destroyer)
	}
	if services, listErr := repository.List(context.Background(), identity); listErr != nil || len(services) != 1 || services[0].Domain == nil {
		t.Fatalf("unresolved DNS identity was not retained: %+v err=%v", services, listErr)
	}
	dns.deleteErr = nil
	if err = executor.destroyWorkerResources(context.Background(), destroyer, request); err != nil {
		t.Fatalf("exact DNS cleanup retry failed: %v", err)
	}
	if destroyer.resourceCalls != 2 || destroyer.finalizeCalls != 1 || destroyer.finalized != identity || dns.deletes != 2 {
		t.Fatalf("cleanup retry did not finalize exactly once: destroyer=%+v dns=%+v", destroyer, dns)
	}
	if services, listErr := repository.List(context.Background(), identity); listErr != nil || len(services) != 0 {
		t.Fatalf("resolved workload state remains: %+v err=%v", services, listErr)
	}
}

func TestDestroyPartialWorkerSkipsWorkloadStoreAndUsesExactProviderIdentity(t *testing.T) {
	destroyer := &workerDestroyerStub{}
	executor := &sshWorkerExecutor{}
	identity := workerIdentityFixture()
	identity.InstanceID, identity.KeyPairID, identity.SecurityGroupID = "", "", ""
	request := sshworker.DestroyRequest{Identity: identity, Authorization: sshworker.DestroyAuthorization{Authorized: true, Proof: "destroy"}}
	if err := executor.destroyWorkerResources(context.Background(), destroyer, request); err != nil {
		t.Fatal(err)
	}
	if destroyer.resourceCalls != 1 || destroyer.finalizeCalls != 1 || destroyer.request.Identity != identity || destroyer.finalized != identity {
		t.Fatalf("partial exact identity was not passed through: %+v", destroyer)
	}
}

func TestListWorkerWorkloadsReturnsEmptyForPartialWorkerIdentity(t *testing.T) {
	executor := &sshWorkerExecutor{}
	status := sshworker.WorkerStatus{Identity: workerIdentityFixture()}
	status.Identity.SecurityGroupID = ""
	workloads, err := executor.ListWorkerWorkloads(context.Background(), status)
	if err != nil || len(workloads) != 0 {
		t.Fatalf("workloads=%+v err=%v", workloads, err)
	}
}

func workspaceManifestItem(inputID, sourceRef, mountPath, kind, mediaType string, body []byte) cloudworker.InputManifestItem {
	digest := sha256.Sum256(body)
	return cloudworker.InputManifestItem{InputID: inputID, Kind: kind, Name: filepath.Base(mountPath), MountPath: mountPath,
		MediaType: mediaType, SizeBytes: uint64(len(body)), SHA256: hex.EncodeToString(digest[:]), SourceRef: sourceRef, SourceRevision: 1}
}

func sealedWorkspaceManifest(t *testing.T, items ...cloudworker.InputManifestItem) cloudworker.InputManifest {
	t.Helper()
	manifest := cloudworker.InputManifest{Schema: cloudworker.InputManifestSchema, Items: items}
	if _, err := manifest.Seal(); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func sourceRead(item cloudworker.InputManifestItem, body []byte) cloudworker.SourceRead {
	return cloudworker.SourceRead{SourceRef: item.SourceRef, SourceRevision: item.SourceRevision, SizeBytes: item.SizeBytes,
		MediaType: item.MediaType, Body: &workspaceReadSeekCloser{Reader: bytes.NewReader(body)}}
}

func sshflowRequest(manifest cloudworker.InputManifest, mode cloudworker.WorkspaceMode) sshflow.Request {
	return sshflow.Request{OwnerID: "owner", AccountGeneration: 1, ExecutionID: "33333333-3333-4333-8333-333333333333", InputManifest: manifest, WorkspaceMode: mode}
}

func workspaceArchiveFixture(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	writer := tar.NewWriter(gz)
	if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func workerIdentityFixture() sshworker.WorkerIdentity {
	return sshworker.WorkerIdentity{WorkerID: "worker-a", InstanceID: "i-1", KeyPairID: "key-1", SecurityGroupID: "sg-1",
		OwnerID: "owner", AccountGeneration: 1,
		Credential: sshworker.CredentialIdentity{CredentialID: "credential-1", CredentialRevision: 1, AccountID: "123456789012", Region: "ap-east-1"}}
}

func workerAuthorityFixture() sshworker.OwnerAuthority {
	return sshworker.OwnerAuthority{OwnerID: "owner", AccountGeneration: 1}
}

package postgres

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	coreexecution "github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/source"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const nodeProductAcceptancePackage = "dirextalk-node-product-fixture"
const nodeProductAcceptanceVersion = "1.0.0"
const nodeProductAcceptanceTool = "offline_echo"
const nodeProductAcceptanceToolSchemaDigest = "84dd2557aeddb7f13dd570feb30ab5b4a5fbc875b9eb2cb4d9fcd4f44d7bf425"
const publicNodeResolverPackage = "@mantine/mcp-server"
const publicNodeResolverVersion = "9.5.1"

// TestManagedNodeProductFreshStateAcceptance is an opt-in release gate. It is
// intentionally excluded from ordinary unit runs because it requires a fresh
// PostgreSQL 18 database, the production image's pinned node/npm runtime, an
// authenticated real extension-runner socket, and npm registry access.
func TestManagedNodeProductFreshStateAcceptance(t *testing.T) {
	if os.Getenv("AGENT_TEST_NODE_PRODUCT_ACCEPTANCE") != "1" {
		t.Skip("AGENT_TEST_NODE_PRODUCT_ACCEPTANCE=1 not set")
	}
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	socket := strings.TrimSpace(os.Getenv("AGENT_TEST_NODE_RUNNER_SOCKET"))
	if dsn == "" || socket == "" {
		t.Fatal("AGENT_TEST_POSTGRES_DSN and AGENT_TEST_NODE_RUNNER_SOCKET are required")
	}
	uid := uint64(65531)
	if raw := strings.TrimSpace(os.Getenv("AGENT_TEST_NODE_RUNNER_UID")); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		uid = parsed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	pool, store := freshNodeProductStore(t, ctx, dsn)
	runner, err := extensionrunner.NewClient(socket, uint32(uid))
	if err != nil {
		t.Fatal(err)
	}
	if err = runner.Probe(ctx); err != nil {
		t.Fatal(err)
	}

	verifyProductionNodeResolverOnline(t, ctx)
	registryServer, fixtureResolver := newNodeProductRegistry(t)
	registry := coreextension.NewRegistry()
	npm, err := source.NewNPMForTest(source.HTTPConfig{BaseURL: registryServer.URL, Client: registryServer.Client()}, fixtureResolver)
	if err != nil {
		t.Fatal(err)
	}
	if err = registry.Register(coreextension.SourceNPM, npm); err != nil {
		t.Fatal(err)
	}
	extensions := NewCoreExtensionStore(store)
	secrets := NewCoreExtensionSecretStore(store)
	coordinator, err := NewValidatedPostgresExtensionExecutionCoordinator(store, "/opaque/runner-owned", secrets)
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := coreexecution.NewMaterializer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifacts := coreexecution.ArtifactStoreAdapter{Materializer: materializer, NodeBuilder: runner}
	local := &coreexecution.LocalExecutor{Runner: runner, Secrets: secrets}
	runtime := NewPostgresExtensionRunnerToolRuntime(store, coordinator, local, &coreexecution.RemoteExecutor{Secrets: secrets})
	service, err := coreextension.NewProductionService(extensions, registry, coordinator, artifacts, secrets, runtime)
	if err != nil {
		t.Fatal(err)
	}
	rpc := rpcapi.NewMCPService(service)
	promoter := coreexecution.StagedLifecyclePromoter{NodeBuilder: runner}
	lifecycle := NewCoreExtensionLifecycleHandlerWithPromoter(extensions, promoter)
	tasks := NewCoreTaskStore(store)
	confirmations, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal(err)
	}

	candidate, inspection := discoverAndInspectNodeProduct(t, ctx, rpc)
	install, err := rpc.RequestInstall(ctx, &agentv1.MCPServiceRequestInstallRequest{IdempotencyKey: uuid.NewString(), Candidate: candidate, Inspection: inspection})
	if err != nil {
		t.Fatal(err)
	}
	if install.Installation == nil || install.Installation.State != agentv1.CoreExtensionState_CORE_EXTENSION_STATE_INSTALLING || install.Installation.Versions[0].NodeArtifact != nil {
		t.Fatalf("pre-confirmation installation=%+v", install.Installation)
	}
	runConfirmedTask(t, ctx, confirmations, tasks, install.ConfirmationId, install.TaskId, lifecycle)

	installedResponse, err := rpc.Get(ctx, &agentv1.MCPServiceGetRequest{InstallationId: install.Installation.InstallationId})
	if err != nil {
		t.Fatal(err)
	}
	installed := installedResponse.Installation
	if installed.State != agentv1.CoreExtensionState_CORE_EXTENSION_STATE_INSTALLED || installed.ActiveVersionId == "" || len(installed.Versions) != 1 || installed.Versions[0].NodeArtifact == nil {
		t.Fatalf("installed projection=%+v", installed)
	}
	receipt := installed.Versions[0].NodeArtifact
	if receipt.ProtoReflect().Descriptor().Fields().Len() != 8 || receipt.PackageName != nodeProductAcceptancePackage || receipt.PackageVersion != nodeProductAcceptanceVersion || receipt.NodeVersion != extensionrunner.ManagedNodeVersionV1 || receipt.NpmVersion != extensionrunner.ManagedNPMVersionV1 || receipt.ArtifactBytes == 0 || receipt.FileCount == 0 || !receipt.LifecycleScriptsDisabled || !receipt.NativeAddonsAbsent {
		t.Fatalf("public eight-field Node receipt=%+v fields=%d", receipt, receipt.ProtoReflect().Descriptor().Fields().Len())
	}

	toolPage, err := rpc.ListTools(ctx, &agentv1.MCPServiceListToolsRequest{InstallationId: installed.InstallationId, ExpectedRevision: installed.Revision})
	if err != nil || len(toolPage.Tools) == 0 {
		t.Fatalf("list_tools=%+v err=%v", toolPage, err)
	}
	var acceptanceTool *agentv1.CoreTool
	for _, tool := range toolPage.Tools {
		if tool.Name == nodeProductAcceptanceTool {
			acceptanceTool = tool
			break
		}
	}
	if acceptanceTool == nil || acceptanceTool.InputSchemaDigest != nodeProductAcceptanceToolSchemaDigest {
		t.Fatalf("known acceptance tool missing or schema changed: %+v", toolPage.Tools)
	}
	executionResult, err := service.Execute(ctx, coreextension.ExecuteRequest{OwnerID: "@owner:product-acceptance.test", AccountGeneration: 1, InstallationID: installed.InstallationId, ExpectedRevision: installed.Revision, ToolName: acceptanceTool.Name, Input: json.RawMessage(`{"message":"product acceptance"}`), IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	confirmedExecution, err := confirmations.ConfirmAuthorized(ctx, coreconfirmation.Authority{OwnerID: "@owner:product-acceptance.test", AccountGeneration: 1}, coreconfirmation.ConfirmCommand{ConfirmationID: executionResult.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, At: time.Now().UTC()})
	if err != nil || confirmedExecution.State != coreconfirmation.StateConfirmed {
		t.Fatalf("execute confirmation=%+v err=%v", confirmedExecution, err)
	}
	claimedExecution := claimExactTask(t, ctx, tasks, executionResult.TaskID, "node-product-execute")
	executionOutcome := (&coreexecution.Handler{Coordinator: coordinator, Local: local}).Handle(ctx, claimedExecution)
	if executionOutcome.Err != nil || !executionOutcome.TerminalOwned {
		t.Fatalf("execute outcome=%+v", executionOutcome)
	}
	completedExecution, err := tasks.GetTask(ctx, executionResult.TaskID)
	if err != nil || completedExecution.Status != coretask.StatusSucceeded || completedExecution.Result == nil {
		t.Fatalf("execute task=%+v err=%v", completedExecution, err)
	}
	var callResult struct {
		Content []json.RawMessage `json:"content"`
		IsError bool              `json:"isError"`
	}
	if completedExecution.Result.Summary != "local MCP tool result" || json.Unmarshal(completedExecution.Result.JSON, &callResult) != nil || callResult.IsError || len(callResult.Content) == 0 {
		t.Fatalf("execute returned provider error or empty content: %+v", completedExecution.Result)
	}
	var textContent struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(callResult.Content[0], &textContent) != nil || textContent.Type != "text" || textContent.Text != "product acceptance" {
		t.Fatalf("execute content mismatch: %s", callResult.Content[0])
	}
	latestResponse, err := rpc.Get(ctx, &agentv1.MCPServiceGetRequest{InstallationId: installed.InstallationId})
	if err != nil {
		t.Fatal(err)
	}
	installed = latestResponse.Installation

	uninstall, err := rpc.RequestUninstall(ctx, &agentv1.MCPServiceRequestUninstallRequest{IdempotencyKey: uuid.NewString(), InstallationId: installed.InstallationId, ExpectedRevision: installed.Revision})
	if err != nil {
		t.Fatal(err)
	}
	runConfirmedTask(t, ctx, confirmations, tasks, uninstall.ConfirmationId, uninstall.TaskId, lifecycle)
	removed, err := rpc.Get(ctx, &agentv1.MCPServiceGetRequest{InstallationId: installed.InstallationId})
	if err != nil || removed.Installation.State != agentv1.CoreExtensionState_CORE_EXTENSION_STATE_REMOVED || removed.Installation.ActiveVersionId != "" {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}

	failedInstall, err := rpc.RequestInstall(ctx, &agentv1.MCPServiceRequestInstallRequest{IdempotencyKey: uuid.NewString(), Candidate: candidate, Inspection: inspection})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmations.Reject(ctx, coreconfirmation.RejectCommand{ConfirmationID: failedInstall.ConfirmationId, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Reason: "acceptance_failure_injection", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := rpc.Get(ctx, &agentv1.MCPServiceGetRequest{InstallationId: failedInstall.Installation.InstallationId})
	if err != nil || rolledBack.Installation.State != agentv1.CoreExtensionState_CORE_EXTENSION_STATE_FAILED || rolledBack.Installation.ProposedVersionId != "" {
		t.Fatalf("rolled back=%+v err=%v", rolledBack, err)
	}

	// First cleaner process loses its runner dependency. The durable row must
	// remain failed. A fresh cleaner instance then retries the exact generation.
	firstCleaner, err := NewCoreExtensionArtifactCleaner(store, materializer.Root, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	firstCleaner.SetArtifactStore(failingNodeArtifactStore{})
	if completed, sweepErr := firstCleaner.Sweep(ctx, 128); sweepErr != nil || completed != 0 {
		t.Fatalf("first cleanup completed=%d err=%v", completed, sweepErr)
	}
	if _, err = pool.Exec(ctx, `UPDATE core_extension_artifact_cleanup SET next_attempt_at=clock_timestamp() WHERE installation_id=$1 AND state='failed'`, failedInstall.Installation.InstallationId); err != nil {
		t.Fatal(err)
	}
	restartedCleaner, err := NewCoreExtensionArtifactCleaner(store, materializer.Root, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	restartedCleaner.SetArtifactStore(artifacts)
	restartedCleaner.SetLifecyclePromoter(promoter)
	if completed, sweepErr := restartedCleaner.Sweep(ctx, 128); sweepErr != nil || completed != 1 {
		t.Fatalf("restart cleanup completed=%d err=%v", completed, sweepErr)
	}
	var failedCleanupRows int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM core_extension_artifact_cleanup WHERE installation_id=$1 AND node_artifact=true AND state='succeeded'`, failedInstall.Installation.InstallationId).Scan(&failedCleanupRows); err != nil || failedCleanupRows != 1 {
		t.Fatalf("durable failed cleanup rows=%d err=%v", failedCleanupRows, err)
	}

	var pendingCleanup int
	if err = pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM core_extension_artifact_cleanup WHERE state<>'succeeded')+
		(SELECT count(*) FROM core_extension_node_artifact_cleanup WHERE state<>'succeeded')`).Scan(&pendingCleanup); err != nil || pendingCleanup != 0 {
		t.Fatalf("pending cleanup=%d err=%v", pendingCleanup, err)
	}
	fmt.Printf("managed_node_product_acceptance_ok package=%s version=%s receipt_fields=8 tools=%d execute=succeeded uninstall=removed rollback=failed restart_cleanup=succeeded\n", nodeProductAcceptancePackage, nodeProductAcceptanceVersion, len(toolPage.Tools))
}

func verifyProductionNodeResolverOnline(t *testing.T, ctx context.Context) {
	t.Helper()
	resolver, err := source.NewProductionNodeDependencyResolver(source.NodeDependencyResolverConfig{})
	if err != nil {
		t.Fatal(err)
	}
	npm, err := source.NewNPM(source.HTTPConfig{BaseURL: source.NPMRegistryAuthority}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	page, err := npm.Search(ctx, coreextension.SearchQuery{Kind: coreextension.KindMCP, Source: coreextension.SourceNPM, Text: publicNodeResolverPackage, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	var candidate coreextension.Candidate
	for _, current := range page.Candidates {
		if current.ID == publicNodeResolverPackage && current.Pin.RegistryVersion == publicNodeResolverVersion {
			candidate = current
			break
		}
	}
	if candidate.ID == "" {
		t.Fatalf("public resolver candidate missing: %+v", page.Candidates)
	}
	artifact, err := npm.Fetch(ctx, candidate)
	if err != nil || artifact.Validate() != nil || artifact.Inspection.Execution.Stdio == nil || artifact.Inspection.Execution.Stdio.Runtime != "node" {
		t.Fatalf("public production resolver artifact=%+v err=%v", artifact.Inspection, err)
	}
}

type nodeProductFixtureResolver struct {
	packageName, packageVersion string
	tarball                     []byte
	tarballURL, integrity       string
}

func (r nodeProductFixtureResolver) Resolve(_ context.Context, request source.NodeDependencyRequest) (source.NodeDependencyResolution, error) {
	if request.Source != coreextension.SourceNPM || request.PackageName != r.packageName || request.PackageVersion != r.packageVersion || len(request.RootPackageJSON) == 0 || !bytes.Equal(request.DirectTarball, r.tarball) {
		return source.NodeDependencyResolution{}, coreextension.ErrInvalid
	}
	lock, err := json.Marshal(map[string]any{
		"name": "dirextalk-managed-mcp", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{"name": "dirextalk-managed-mcp", "version": "0.0.0"},
			"node_modules/" + r.packageName: map[string]any{
				"name": r.packageName, "version": r.packageVersion, "resolved": r.tarballURL, "integrity": r.integrity,
			},
		},
	})
	if err != nil {
		return source.NodeDependencyResolution{}, err
	}
	return source.NodeDependencyResolution{PackageLock: lock, Tarballs: []source.NodeResolvedTarball{{LockPath: "node_modules/" + r.packageName, Content: append([]byte(nil), r.tarball...)}}}, nil
}

func newNodeProductRegistry(t *testing.T) (*httptest.Server, source.NodeDependencyResolver) {
	t.Helper()
	serverJS := []byte(`const send = value => process.stdout.write(JSON.stringify(value) + "\n");
try { const result = await fetch("https://registry.npmjs.org/", {signal: AbortSignal.timeout(1000)}); if (result) process.exit(73); } catch {}
let pending = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => { pending += chunk; for (;;) { const index = pending.indexOf("\n"); if (index < 0) break; const line = pending.slice(0, index); pending = pending.slice(index + 1); if (!line) continue; const message = JSON.parse(line); if (message.method === "initialize") send({jsonrpc:"2.0",id:message.id,result:{protocolVersion:"2024-11-05",capabilities:{tools:{}},serverInfo:{name:"dirextalk-offline-fixture",version:"1.0.0"}}}); if (message.method === "tools/list") send({jsonrpc:"2.0",id:message.id,result:{tools:[{name:"offline_echo",description:"Echo a message without network access",inputSchema:{type:"object",properties:{message:{type:"string"}},required:["message"],additionalProperties:false}}]}}); if (message.method === "tools/call") { const args = message.params?.arguments; const valid = message.params?.name === "offline_echo" && args && typeof args.message === "string" && Object.keys(args).length === 1; send({jsonrpc:"2.0",id:message.id,result:{content:[{type:"text",text:valid ? args.message : "invalid input"}],isError:!valid}}); } }});
`)
	packageJSON := []byte(`{"name":"` + nodeProductAcceptancePackage + `","version":"` + nodeProductAcceptanceVersion + `","type":"module","bin":{"` + nodeProductAcceptancePackage + `":"server.js"}}`)
	tarball := nodeProductTarball(t, map[string][]byte{"package.json": packageJSON, "server.js": serverJS})
	sha1sum := sha1.Sum(tarball)
	sha512sum := sha512.Sum512(tarball)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sha512sum[:])
	var registry *httptest.Server
	registry = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/v1/search":
			_ = json.NewEncoder(w).Encode(map[string]any{"objects": []any{map[string]any{"package": map[string]any{"name": nodeProductAcceptancePackage, "version": nodeProductAcceptanceVersion, "description": "offline product acceptance MCP"}}}, "total": 1})
		case "/" + nodeProductAcceptancePackage:
			version := map[string]any{"name": nodeProductAcceptancePackage, "version": nodeProductAcceptanceVersion, "description": "offline product acceptance MCP", "dist": map[string]any{"tarball": registry.URL + "/" + nodeProductAcceptancePackage + "/-/" + nodeProductAcceptancePackage + "-" + nodeProductAcceptanceVersion + ".tgz", "integrity": integrity, "shasum": hex.EncodeToString(sha1sum[:])}}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": nodeProductAcceptancePackage, "description": "offline product acceptance MCP", "versions": map[string]any{nodeProductAcceptanceVersion: version}})
		case "/" + nodeProductAcceptancePackage + "/-/" + nodeProductAcceptancePackage + "-" + nodeProductAcceptanceVersion + ".tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(tarball)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(registry.Close)
	return registry, nodeProductFixtureResolver{packageName: nodeProductAcceptancePackage, packageVersion: nodeProductAcceptanceVersion, tarball: tarball, tarballURL: registry.URL + "/" + nodeProductAcceptancePackage + "/-/" + nodeProductAcceptancePackage + "-" + nodeProductAcceptanceVersion + ".tgz", integrity: integrity}
}

func nodeProductTarball(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Header.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	for _, name := range []string{"package.json", "server.js"} {
		content := files[name]
		header := &tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(content)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

type failingNodeArtifactStore struct{}

func (failingNodeArtifactStore) Materialize(context.Context, coreextension.FetchArtifact) (coreextension.ArtifactReceipt, error) {
	return coreextension.ArtifactReceipt{}, errors.New("acceptance injected unavailable artifact store")
}

func (failingNodeArtifactStore) Remove(context.Context, coreextension.ArtifactReceipt) error {
	return errors.New("acceptance injected unavailable artifact store")
}

func freshNodeProductStore(t *testing.T, ctx context.Context, dsn string) (*pgxpool.Pool, *Store) {
	t.Helper()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "dtx_node_product_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	instanceID := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	return pool, store
}

func discoverAndInspectNodeProduct(t *testing.T, ctx context.Context, rpc *rpcapi.MCPService) (*agentv1.CoreExtensionCandidate, *agentv1.CoreExtensionInspection) {
	t.Helper()
	page, err := rpc.Search(ctx, &agentv1.MCPServiceSearchRequest{Kind: agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_MCP, Source: agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_NPM, Text: nodeProductAcceptancePackage, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	var candidate *agentv1.CoreExtensionCandidate
	for _, current := range page.Candidates {
		if current.Id == nodeProductAcceptancePackage && current.Pin != nil && current.Pin.RegistryVersion == nodeProductAcceptanceVersion {
			candidate = current
			break
		}
	}
	if candidate == nil {
		t.Fatalf("exact npm candidate not found: %+v", page.Candidates)
	}
	inspection, err := rpc.Inspect(ctx, &agentv1.MCPServiceInspectRequest{Kind: agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_MCP, Source: agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_NPM, Id: candidate.Id, Pin: candidate.Pin})
	if err != nil || inspection.Inspection == nil || inspection.Inspection.Execution.GetStdio().Runtime != "node" {
		t.Fatalf("inspection=%+v err=%v", inspection, err)
	}
	return candidate, inspection.Inspection
}

func runConfirmedTask(t *testing.T, ctx context.Context, confirmations *coreconfirmation.Service, tasks *CoreTaskStore, confirmationID, taskID string, handler func(context.Context, coretask.Task) coreruntime.ManagedOutcome) {
	t.Helper()
	confirmed, err := confirmations.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: confirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, At: time.Now().UTC()})
	if err != nil || confirmed.State != coreconfirmation.StateConfirmed {
		t.Fatalf("confirmation=%+v err=%v", confirmed, err)
	}
	claimed := claimExactTask(t, ctx, tasks, taskID, "node-product-lifecycle")
	outcome := handler(ctx, claimed)
	if outcome.Err != nil || !outcome.TerminalOwned {
		t.Fatalf("lifecycle outcome=%+v", outcome)
	}
}

func claimExactTask(t *testing.T, ctx context.Context, tasks *CoreTaskStore, taskID, holder string) coretask.Task {
	t.Helper()
	claimed, _, err := tasks.ClaimNextDue(ctx, holder, time.Now().UTC(), 2*time.Minute, 32)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != taskID {
		t.Fatalf("claimed task=%s want=%s", claimed.ID, taskID)
	}
	return claimed
}

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/source"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/google/uuid"
)

func main() {
	if len(os.Args) != 5 {
		panic("usage: nodeacceptance SOCKET RUNNER_UID PACKAGE VERSION")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if os.Args[3] == "fixture" {
		runFixture(ctx, os.Args[1], os.Args[2])
		return
	}
	resolver, err := source.NewProductionNodeDependencyResolver(source.NodeDependencyResolverConfig{})
	must(err)
	npm, err := source.NewNPM(source.HTTPConfig{BaseURL: source.NPMRegistryAuthority}, resolver)
	must(err)
	page, err := npm.Search(ctx, core.SearchQuery{Kind: core.KindMCP, Source: core.SourceNPM, Text: os.Args[3], PageSize: 10})
	must(err)
	var candidate core.Candidate
	for _, value := range page.Candidates {
		if value.ID == os.Args[3] && (os.Args[4] == "*" || value.Pin.RegistryVersion == os.Args[4]) {
			candidate = value
		}
	}
	if candidate.ID == "" {
		panic("exact npm candidate not found")
	}
	artifact, err := npm.Fetch(ctx, candidate)
	must(err)
	if os.Args[1] == "resolve-only" {
		fmt.Printf("node_resolver_container_ok package_version=%s source_bytes=%d entry=%s\n", candidate.Pin.RegistryVersion, len(artifact.Content), artifact.Inspection.Execution.Stdio.RelativePath)
		return
	}
	uid := uint32(0)
	for _, char := range os.Args[2] {
		if char < '0' || char > '9' {
			panic("invalid runner uid")
		}
		uid = uid*10 + uint32(char-'0')
	}
	client, err := extensionrunner.NewClient(os.Args[1], uid)
	must(err)
	materializer, err := execution.NewMaterializer("/tmp/node-acceptance-staging")
	must(err)
	store := execution.ArtifactStoreAdapter{Materializer: materializer, NodeBuilder: client}
	receipt, err := store.Materialize(ctx, artifact)
	must(err)
	version := core.VersionRecord{VersionID: uuid.NewString(), ContentDigest: artifact.ContentDigest, ArtifactDigest: receipt.ArtifactDigest, ArtifactCleanupToken: receipt.CleanupToken, Execution: artifact.Inspection.Execution, NodeArtifact: receipt.NodeArtifact}
	promoter := execution.StagedLifecyclePromoter{NodeBuilder: client}
	must(promoter.Promote(ctx, version))
	defer func() { must(promoter.Remove(context.Background(), version)) }()
	entry := artifact.Inspection.Execution.Stdio
	if entry == nil || entry.Runtime != "node" {
		panic("managed Node execution missing")
	}
	local := &execution.LocalExecutor{Runner: observingRunner{client}}
	tools, err := local.ListTools(ctx, execution.LocalInvocation{
		TaskID: uuid.NewString(), TaskFence: uuid.NewString(), InstallationID: uuid.NewString(), VersionID: version.VersionID,
		InstallDigest: receipt.ArtifactDigest, ContentDigest: artifact.ContentDigest, ArtifactDigest: receipt.ArtifactDigest,
		EntryPath: entry.RelativePath, EntrySHA256: entry.Digest, Runtime: entry.Runtime, Argv: append([]string(nil), entry.Argv...),
		Workspace: "/opaque/runner-owned", Timeout: 30 * time.Second, Limits: execution.LocalSandboxLimitsV2(),
	})
	must(err)
	if len(tools) == 0 {
		panic("managed Node MCP returned no tools")
	}
	callText := "not_requested"
	if candidate.ID == "mcp-mx-calculator" && candidate.Pin.RegistryVersion == "1.0.1" {
		found := false
		for _, tool := range tools {
			if tool.Name == "add" {
				found = true
				break
			}
		}
		if !found {
			panic("calculator add tool missing")
		}
		call := invocationForCall(receipt, artifact)
		result, err := local.CallTool(ctx, call, "add", json.RawMessage(`{"a":2,"b":3}`))
		must(err)
		var payload struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		}
		if json.Unmarshal(result.JSON, &payload) != nil || payload.IsError || len(payload.Content) == 0 || payload.Content[0].Type != "text" || payload.Content[0].Text != "5" {
			panic("calculator add result was not exact text 5")
		}
		callText = payload.Content[0].Text
	}
	fmt.Printf("node_mcp_container_ok package=%s package_version=%s node=%s npm=%s tools=%d call=%s artifact_bytes=%d files=%d\n", candidate.ID, candidate.Pin.RegistryVersion, receipt.NodeArtifact.NodeVersion, receipt.NodeArtifact.NPMVersion, len(tools), callText, receipt.NodeArtifact.ArtifactBytes, receipt.NodeArtifact.FileCount)
}

func invocationForCall(receipt core.ArtifactReceipt, artifact core.FetchArtifact) execution.LocalInvocation {
	entry := artifact.Inspection.Execution.Stdio
	return execution.LocalInvocation{
		TaskID: uuid.NewString(), TaskFence: uuid.NewString(), InstallationID: uuid.NewString(), VersionID: uuid.NewString(),
		InstallDigest: receipt.ArtifactDigest, ContentDigest: artifact.ContentDigest, ArtifactDigest: receipt.ArtifactDigest,
		EntryPath: entry.RelativePath, EntrySHA256: entry.Digest, Runtime: entry.Runtime, Argv: append([]string(nil), entry.Argv...),
		Workspace: "/opaque/runner-owned", Timeout: 30 * time.Second, Limits: execution.LocalSandboxLimitsV2(),
	}
}

type observingRunner struct{ client *extensionrunner.Client }

func (r observingRunner) RunV2(ctx context.Context, request extensionrunner.RequestV2, files []*os.File) (extensionrunner.StatusV1, error) {
	validation := extensionrunner.ValidateRequestV2(request)
	fds := make([]int, len(files))
	for index, file := range files {
		fds[index] = int(file.Fd())
	}
	fdValidation := extensionrunner.ValidateRequestFDs(request, fds)
	status, err := r.client.RunV2(ctx, request, files)
	exit := -999
	if status.ExitCode != nil {
		exit = *status.ExitCode
	}
	fmt.Fprintf(os.Stderr, "node_acceptance_run phase=%s error=%s exit=%d stdin_size=%d fd_count=%d validation_error=%t fd_validation_error=%t stdout_bytes=%d stderr_bytes=%d transport_error=%t\n", status.Phase, status.Error, exit, func() int64 {
		if request.Stdin == nil {
			return 0
		}
		return request.Stdin.Size
	}(), len(files), validation != nil, fdValidation != nil, len(status.Stdout), len(status.Stderr), err != nil)
	return status, err
}

type canonicalFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type sourceManifest struct {
	SchemaVersion  string                 `json:"schema_version"`
	PackageName    string                 `json:"package_name"`
	PackageVersion string                 `json:"package_version"`
	EntryPath      string                 `json:"entry_path"`
	EntrySHA256    string                 `json:"entry_sha256"`
	LockSHA256     string                 `json:"lock_sha256"`
	Tarballs       []sourceTarballBinding `json:"tarballs"`
}

type sourceTarballBinding struct {
	LockPath  string `json:"lock_path"`
	Path      string `json:"path"`
	Integrity string `json:"integrity"`
}

func runFixture(ctx context.Context, socket, uidText string) {
	uid := parseUID(uidText)
	client, err := extensionrunner.NewClient(socket, uid)
	must(err)
	content, request := fixtureSource("")
	receipt, err := client.BuildNode(ctx, request, content)
	must(err)
	cleanupScope := "prepared"
	defer func() {
		must(client.RemoveNode(context.Background(), cleanupScope, receipt.ArtifactDigest, request.CleanupToken))
	}()
	if receipt.FileCount > 8 || receipt.ArtifactBytes > 64<<10 {
		panic("installer cache leaked into published artifact")
	}
	must(client.PromoteNode(ctx, request.CleanupToken, receipt))
	cleanupScope = "active"
	local := &execution.LocalExecutor{Runner: observingRunner{client}}
	invocation := execution.LocalInvocation{
		TaskID: uuid.NewString(), TaskFence: uuid.NewString(), InstallationID: uuid.NewString(), VersionID: uuid.NewString(),
		InstallDigest: receipt.ArtifactDigest, ContentDigest: request.InputDigest, ArtifactDigest: receipt.ArtifactDigest,
		EntryPath: request.EntryPath, EntrySHA256: request.EntrySHA256, Runtime: "node",
		Workspace: "/opaque/runner-owned", Timeout: 30 * time.Second, Limits: execution.LocalSandboxLimitsV2(),
	}
	tools, err := local.ListTools(ctx, invocation)
	if err != nil {
		invocation.TaskID, invocation.TaskFence = uuid.NewString(), uuid.NewString()
		invocation.Stdin = []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n")
		status, executeErr := local.Execute(ctx, invocation)
		exit := -999
		if status.ExitCode != nil {
			exit = *status.ExitCode
		}
		panic(fmt.Sprintf("list tools failed: %v; direct status phase=%s error=%s exit=%d stdout=%q stderr=%q execute=%v", err, status.Phase, status.Error, exit, status.Stdout, status.Stderr, executeErr))
	}
	if len(tools) != 1 || tools[0].Name != "offline_echo" {
		panic("unexpected fixture tool list")
	}
	malicious, maliciousRequest := fixtureSource("lifecycle")
	maliciousReceipt, err := client.BuildNode(ctx, maliciousRequest, malicious)
	must(err)
	maliciousCleanupScope := "prepared"
	defer func() {
		must(client.RemoveNode(context.Background(), maliciousCleanupScope, maliciousReceipt.ArtifactDigest, maliciousRequest.CleanupToken))
	}()
	if maliciousReceipt.InputDigest != maliciousRequest.InputDigest || maliciousReceipt.FileCount < 6 || !maliciousReceipt.LifecycleScriptsDisabled {
		panic("scripts-disabled receipt lost source binding or published a lifecycle marker")
	}
	must(client.PromoteNode(ctx, maliciousRequest.CleanupToken, maliciousReceipt))
	maliciousCleanupScope = "active"
	maliciousInvocation := invocation
	maliciousInvocation.TaskID, maliciousInvocation.TaskFence, maliciousInvocation.VersionID = uuid.NewString(), uuid.NewString(), uuid.NewString()
	maliciousInvocation.InstallDigest = maliciousReceipt.ArtifactDigest
	maliciousInvocation.ContentDigest = maliciousRequest.InputDigest
	maliciousInvocation.ArtifactDigest = maliciousReceipt.ArtifactDigest
	maliciousInvocation.EntrySHA256 = maliciousRequest.EntrySHA256
	maliciousTools, err := local.ListTools(ctx, maliciousInvocation)
	must(err)
	if len(maliciousTools) != 1 || maliciousTools[0].Name != "offline_echo" {
		panic("root or transitive lifecycle declaration was lost, or a lifecycle marker was written")
	}
	native, nativeRequest := fixtureSource("native")
	if _, err := client.BuildNode(ctx, nativeRequest, native); err == nil {
		panic("native addon package accepted")
	}
	fmt.Printf("node_mcp_container_ok node=%s npm=%s tools=%d artifact_bytes=%d files=%d runtime_network=blocked lifecycle_scripts=disabled native_addon=rejected cleanup=scheduled\n", receipt.NodeVersion, receipt.NPMVersion, len(tools), receipt.ArtifactBytes, receipt.FileCount)
}

func fixtureSource(negative string) ([]byte, extensionrunner.NodeBuildRequestV1) {
	const name = "dirextalk-node-fixture"
	const version = "1.0.0"
	const dependencyName = "dirextalk-lifecycle-dependency"
	const dependencyVersion = "1.0.0"
	var scripts map[string]string
	if negative == "lifecycle" {
		scripts = lifecycleScripts("root")
	}
	rootPackage := map[string]any{"name": name, "version": version, "private": true, "type": "module", "bin": map[string]string{"dirextalk-node-fixture": "server.js"}}
	rootLockPackage := map[string]any{"name": name, "version": version, "bin": map[string]string{"dirextalk-node-fixture": "server.js"}}
	lockPackages := map[string]any{"": rootLockPackage}
	bindings := []sourceTarballBinding{}
	files := []canonicalFile{}
	if negative == "lifecycle" {
		rootPackage["scripts"] = scripts
		rootPackage["dependencies"] = map[string]string{dependencyName: dependencyVersion}
		rootLockPackage["scripts"] = scripts
		rootLockPackage["dependencies"] = map[string]string{dependencyName: dependencyVersion}
		rootLockPackage["hasInstallScript"] = true
		dependencyPackage, _ := json.Marshal(map[string]any{"name": dependencyName, "version": dependencyVersion, "scripts": lifecycleScripts("transitive"), "main": "index.js"})
		dependencyTarball := npmTarball(map[string][]byte{"package.json": dependencyPackage, "index.js": []byte("export default true;\n")})
		dependencySum := sha512.Sum512(dependencyTarball)
		integrity := "sha512-" + base64.StdEncoding.EncodeToString(dependencySum[:])
		cachePath := ".dirextalk-npm-tarballs/" + hex.EncodeToString(dependencySum[:]) + ".tgz"
		lockPackages["node_modules/"+dependencyName] = map[string]any{"name": dependencyName, "version": dependencyVersion, "resolved": "https://registry.example.invalid/" + dependencyName + "-" + dependencyVersion + ".tgz", "integrity": integrity, "hasInstallScript": true}
		bindings = append(bindings, sourceTarballBinding{LockPath: "node_modules/" + dependencyName, Path: cachePath, Integrity: integrity})
		files = append(files, canonicalFile{Path: cachePath, Content: base64.RawStdEncoding.EncodeToString(dependencyTarball)})
	}
	packageJSON, _ := json.Marshal(rootPackage)
	packageLock, _ := json.Marshal(map[string]any{"name": name, "version": version, "lockfileVersion": 3, "requires": true, "packages": lockPackages})
	server := []byte(`const response = (value) => process.stdout.write(JSON.stringify(value) + "\n");
import {existsSync, readFileSync} from "node:fs";
const lifecycle = ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"];
if (` + fmt.Sprintf("%t", negative == "lifecycle") + `) {
  const root = JSON.parse(readFileSync("/app/package.json", "utf8"));
  const dependency = JSON.parse(readFileSync("/app/node_modules/dirextalk-lifecycle-dependency/package.json", "utf8"));
  if (!lifecycle.every(name => typeof root.scripts?.[name] === "string" && typeof dependency.scripts?.[name] === "string")) process.exit(91);
  if (lifecycle.some(name => existsSync("/app/root-" + name + ".marker") || existsSync("/app/node_modules/dirextalk-lifecycle-dependency/transitive-" + name + ".marker"))) process.exit(92);
}
try { const result = await fetch("https://registry.npmjs.org/", {signal: AbortSignal.timeout(2000)}); if (result) process.exit(73); } catch {}
let pending = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => { pending += chunk; for (;;) { const index = pending.indexOf("\n"); if (index < 0) break; const line = pending.slice(0, index); pending = pending.slice(index + 1); if (!line) continue; const message = JSON.parse(line); if (message.method === "initialize") response({jsonrpc:"2.0",id:message.id,result:{protocolVersion:"2024-11-05",capabilities:{tools:{}},serverInfo:{name:"fixture",version:"1.0.0"}}}); if (message.method === "tools/list") response({jsonrpc:"2.0",id:message.id,result:{tools:[{name:"offline_echo",description:"offline fixture",inputSchema:{type:"object",properties:{},additionalProperties:false}}]}}); }});
`)
	entryDigest := digest(server)
	lockDigest := digest(packageLock)
	manifestBytes, _ := json.Marshal(sourceManifest{SchemaVersion: "dirextalk.node-source/v1", PackageName: name, PackageVersion: version, EntryPath: "server.js", EntrySHA256: entryDigest, LockSHA256: lockDigest, Tarballs: bindings})
	files = append(files,
		canonicalFile{Path: ".dirextalk-node-source-v1.json", Content: base64.RawStdEncoding.EncodeToString(manifestBytes)},
		canonicalFile{Path: "package-lock.json", Content: base64.RawStdEncoding.EncodeToString(packageLock)},
		canonicalFile{Path: "package.json", Content: base64.RawStdEncoding.EncodeToString(packageJSON)},
		canonicalFile{Path: "server.js", Content: base64.RawStdEncoding.EncodeToString(server)},
	)
	if negative == "native" {
		files = append(files, canonicalFile{Path: "addon.node", Content: base64.RawStdEncoding.EncodeToString([]byte("native addon fixture"))})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	content, _ := json.Marshal(files)
	inputDigest := digest(content)
	return content, extensionrunner.NodeBuildRequestV1{Op: "build_node_v1", InputDigest: inputDigest, CleanupToken: uuid.NewString(), ContentSize: int64(len(content)), ContentSHA256: inputDigest, EntryPath: "server.js", EntrySHA256: entryDigest, PackageName: name, PackageVersion: version, LockSHA256: lockDigest}
}

func lifecycleScripts(prefix string) map[string]string {
	scripts := make(map[string]string, 7)
	for _, lifecycle := range []string{"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"} {
		scripts[lifecycle] = "touch " + prefix + "-" + lifecycle + ".marker; wget https://example.invalid; exit 99"
	}
	return scripts
}

func npmTarball(files map[string][]byte) []byte {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		content := files[path]
		must(tw.WriteHeader(&tar.Header{Name: "package/" + path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(content)
		must(err)
	}
	must(tw.Close())
	must(gz.Close())
	return compressed.Bytes()
}

func parseUID(value string) uint32 {
	var uid uint32
	for _, char := range value {
		if char < '0' || char > '9' {
			panic("invalid runner uid")
		}
		uid = uid*10 + uint32(char-'0')
	}
	return uid
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func must(err error) {
	if err != nil {
		panic(strings.ReplaceAll(err.Error(), os.Args[3], "<package>"))
	}
}

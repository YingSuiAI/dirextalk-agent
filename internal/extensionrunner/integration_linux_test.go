//go:build linux

package extensionrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This lane requires a cgroup-v2 subtree delegated to the test UID. Unlike the
// unit tests, it launches the real re-exec child and therefore proves that the
// complete kernel boundary is usable rather than silently skipping a weaker
// implementation.
func TestLinuxIsolationIntegrationOptIn(t *testing.T) {
	if os.Getenv("DIREXTALK_EXTENSION_RUNNER_INTEGRATION") != "1" {
		t.Skip("set DIREXTALK_EXTENSION_RUNNER_INTEGRATION=1 and DIREXTALK_EXTENSION_RUNNER_CGROUP_ROOT to a delegated cgroup-v2 subtree")
	}
	cgroupRoot := os.Getenv("DIREXTALK_EXTENSION_RUNNER_CGROUP_ROOT")
	if !filepath.IsAbs(cgroupRoot) {
		t.Fatal("DIREXTALK_EXTENSION_RUNNER_CGROUP_ROOT must be absolute")
	}
	runnerBinary := buildRunnerBinary(t)
	backend := LinuxBackend{CgroupRoot: cgroupRoot, ProbeRoot: t.TempDir(), ReexecPath: runnerBinary}
	if err := backend.Probe(context.Background()); err != nil {
		t.Fatalf("real isolation kernel unavailable: %v", err)
	}

	probe := buildIsolationProbe(t)
	installRoot, digest := materializeIntegrationInstall(t, probe)
	workspaceRoot := t.TempDir()
	runner := Runner{
		InstallResolver:   DiskInstallResolver{Root: installRoot},
		WorkspaceResolver: DiskWorkspaceResolver{Root: workspaceRoot},
		V2Backend:         backend,
	}

	hostSentinel := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(hostSentinel, []byte("must-not-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := []byte("approved-value")
	secretFD, err := sealedMemfd("approved", secret)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(secretFD)
	request := integrationRequest(digest)
	request.Argv = []string{"/app/entry", hostSentinel}
	request.Secrets = []SecretFD{{Name: "allowed", Index: 0, Size: int64(len(secret)), SHA256: DigestBytes(secret)}}
	request.ResultFiles = []string{"result.json"}
	status, err := runner.RunV2(context.Background(), request, []int{secretFD}, NewRunRegistry())
	if err != nil || status.Error != ErrorNone || status.Status != "succeeded" || len(status.ResultFiles) != 1 {
		t.Fatalf("status=%+v err=%v stderr=%s", status, err, status.Stderr)
	}
	resultPath := filepath.Join(workspaceRoot, request.TaskID, request.TaskFence, "result.json")
	body, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence struct {
		EmptyEnvironment bool `json:"empty_environment"`
		HostHidden       bool `json:"host_hidden"`
		ConfigHidden     bool `json:"config_hidden"`
		ProcHidden       bool `json:"proc_hidden"`
		UnapprovedHidden bool `json:"unapproved_hidden"`
		ApprovedReadable bool `json:"approved_readable"`
		InstallReadable  bool `json:"install_readable"`
		NetworkDenied    bool `json:"network_denied"`
	}
	if json.Unmarshal(body, &evidence) != nil ||
		!evidence.EmptyEnvironment ||
		!evidence.HostHidden ||
		!evidence.ConfigHidden ||
		!evidence.ProcHidden ||
		!evidence.UnapprovedHidden ||
		!evidence.ApprovedReadable ||
		!evidence.InstallReadable ||
		!evidence.NetworkDenied {
		t.Fatalf("isolation evidence=%+v", evidence)
	}
	if _, err := os.Lstat(filepath.Join(workspaceRoot, request.TaskID, request.TaskFence, "unregistered.tmp")); !os.IsNotExist(err) {
		t.Fatalf("unregistered output remained: %v", err)
	}

	cancelRequest := integrationRequest(digest)
	cancelRequest.RunID = "44444444-4444-4444-8444-444444444444"
	cancelRequest.TaskID = "55555555-5555-4555-8555-555555555555"
	cancelRequest.TaskFence = "66666666-6666-4666-8666-666666666666"
	cancelRequest.Argv = []string{"/app/entry", "loop"}
	cancelCtx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan StatusV1, 1)
	errCh := make(chan error, 1)
	go func() {
		value, runErr := runner.RunV2(cancelCtx, cancelRequest, nil, NewRunRegistry())
		resultCh <- value
		errCh <- runErr
	}()
	cancelWorkspace := filepath.Join(workspaceRoot, cancelRequest.TaskID, cancelRequest.TaskFence)
	started := filepath.Join(cancelWorkspace, "started")
	childStarted := filepath.Join(cancelWorkspace, "child-started")
	unregistered := filepath.Join(cancelWorkspace, "unregistered.tmp")
	deadline := time.Now().Add(10 * time.Second)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		startedOK := fileExists(started)
		childOK := fileExists(childStarted)
		if startedOK && childOK {
			break
		}
		select {
		case status := <-resultCh:
			runErr := <-errCh
			t.Fatalf("sandbox exited before loop markers: status=%+v err=%v stdout=%q stderr=%q", status, runErr, status.Stdout, status.Stderr)
		case <-ticker.C:
			if time.Now().After(deadline) {
				cancel()
				status := <-resultCh
				runErr := <-errCh
				t.Fatalf("sandbox did not create loop markers: started=%t child_started=%t status=%+v err=%v stdout=%q stderr=%q", startedOK, childOK, status, runErr, status.Stdout, status.Stderr)
			}
		}
	}
	cancel()
	cancelStatus := <-resultCh
	if runErr := <-errCh; runErr != nil || cancelStatus.Error != ErrorCancelled {
		t.Fatalf("cancel status=%+v err=%v", cancelStatus, runErr)
	}
	if _, err := os.Lstat(started); !os.IsNotExist(err) {
		t.Fatalf("cancel output remained: %v", err)
	}
	if _, err := os.Lstat(childStarted); !os.IsNotExist(err) {
		t.Fatalf("cancel descendant marker remained: %v", err)
	}
	if _, err := os.Lstat(unregistered); !os.IsNotExist(err) {
		t.Fatalf("cancel unregistered output remained: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, cancelRequest.RunID)); !os.IsNotExist(err) {
		t.Fatalf("cgroup or child process remained: %v", err)
	}
}

func TestLinuxIsolationServerClientHTMLResultOptIn(t *testing.T) {
	if os.Getenv("DIREXTALK_EXTENSION_RUNNER_INTEGRATION") != "1" {
		t.Skip("set DIREXTALK_EXTENSION_RUNNER_INTEGRATION=1 and DIREXTALK_EXTENSION_RUNNER_CGROUP_ROOT to a delegated cgroup-v2 subtree")
	}
	cgroupRoot := os.Getenv("DIREXTALK_EXTENSION_RUNNER_CGROUP_ROOT")
	if !filepath.IsAbs(cgroupRoot) {
		t.Fatal("DIREXTALK_EXTENSION_RUNNER_CGROUP_ROOT must be absolute")
	}
	runnerBinary := buildRunnerBinary(t)
	backend := LinuxBackend{CgroupRoot: cgroupRoot, ProbeRoot: t.TempDir(), ReexecPath: runnerBinary}
	if err := backend.Probe(context.Background()); err != nil {
		t.Fatalf("real isolation kernel unavailable: %v", err)
	}

	probe := buildIsolationProbe(t)
	installRoot, digest := materializeIntegrationInstall(t, probe)
	workspaceRoot, sharedWorkspaceGID := productionSharedWorkspaceRoot(t)
	socketPath := filepath.Join(t.TempDir(), "runner.sock")
	listener, err := Listen(socketPath, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, cancelServer := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	registry := NewRunRegistry()
	server := Server{
		Listener:           listener,
		Authorizer:         UIDAllowlist{uint32(os.Geteuid()): {}},
		RunnerUID:          uint32(os.Geteuid()),
		SharedWorkspaceGID: sharedWorkspaceGID,
		Runner: Runner{
			InstallResolver:   DiskInstallResolver{Root: installRoot},
			WorkspaceResolver: DiskWorkspaceResolver{Root: workspaceRoot, SharedGID: sharedWorkspaceGID},
			V2Backend:         backend,
		},
		Registry:        registry,
		PublicationRoot: installRoot,
	}
	go func() { serveDone <- server.ServeV2(serverCtx) }()
	t.Cleanup(func() {
		cancelServer()
		select {
		case serveErr := <-serveDone:
			if serveErr != nil {
				t.Errorf("serve: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})

	client, err := NewClient(socketPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	request := integrationRequest(digest)
	request.RunID = "77777777-7777-4777-8777-777777777777"
	request.TaskID = "88888888-8888-4888-8888-888888888888"
	request.TaskFence = "99999999-9999-4999-8999-999999999999"
	request.Argv = []string{"/app/entry", "html"}
	request.ResultFiles = []string{"index.html"}
	request.Limits = LimitsV2{CPUSeconds: 30, MemoryBytes: 256 << 20, Processes: 32, FileBytes: 16 << 20, OpenFiles: 64}
	status, resultFiles, err := client.RunV2WithResultFiles(context.Background(), request, nil)
	if err != nil || status.Error != ErrorNone || status.Status != "succeeded" || len(status.ResultFiles) != 1 {
		t.Fatalf("status=%+v err=%v stderr=%s", status, err, status.Stderr)
	}
	defer func() {
		for _, file := range resultFiles {
			_ = file.Close()
		}
	}()
	const wantHTML = "<h1>Hello from Dirextalk</h1>"
	const wantSHA256 = "b0012fd52e5edc0ce0ac66a4e4020d45a6a5226229276c961744d0d826776b84"
	result := status.ResultFiles[0]
	if len(wantHTML) != 29 || result.Path != "index.html" || result.Size != int64(len(wantHTML)) || result.SHA256 != wantSHA256 {
		t.Fatalf("result=%+v", result)
	}
	if len(resultFiles) != 1 {
		t.Fatalf("result descriptors=%d", len(resultFiles))
	}
	handedOff, err := io.ReadAll(resultFiles[0])
	if err != nil || string(handedOff) != wantHTML {
		t.Fatalf("handed-off index.html=%q err=%v", handedOff, err)
	}
	resultPath := filepath.Join(workspaceRoot, request.TaskID, request.TaskFence, "index.html")
	body, err := os.ReadFile(resultPath)
	if err != nil || string(body) != wantHTML {
		t.Fatalf("index.html=%q err=%v", body, err)
	}
	if request.Limits != (LimitsV2{CPUSeconds: 30, MemoryBytes: 256 << 20, Processes: 32, FileBytes: 16 << 20, OpenFiles: 64}) {
		t.Fatalf("request limits drifted: %+v", request.Limits)
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, request.RunID)); !os.IsNotExist(err) {
		t.Fatalf("cgroup or child process remained: %v", err)
	}

	outputRequest := integrationRequest(digest)
	outputRequest.RunID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	outputRequest.TaskID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	outputRequest.TaskFence = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	outputRequest.Argv = []string{"/app/entry", "output-over"}
	outputRequest.Limits = localIntegrationLimitsV2()
	outputStatus, err := client.RunV2(context.Background(), outputRequest, nil)
	if err != nil || outputStatus.Phase != PhaseFailed || outputStatus.Error != ErrorExecution || outputStatus.Status != "output_limit" || len(outputStatus.Stdout) != MaxOutputBytes {
		t.Fatalf("output threshold+1 status=%+v err=%v", outputStatus, err)
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, outputRequest.RunID)); !os.IsNotExist(err) {
		t.Fatalf("output-limit cgroup remained: %v", err)
	}

	filesRequest := integrationRequest(digest)
	filesRequest.RunID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	filesRequest.TaskID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	filesRequest.TaskFence = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	filesRequest.Argv = []string{"/app/entry", "files-over"}
	filesRequest.TimeoutMS = 30_000
	filesRequest.Limits = localIntegrationLimitsV2()
	filesStatus, err := client.RunV2(context.Background(), filesRequest, nil)
	if err != nil || filesStatus.Phase != PhaseFailed || filesStatus.Error != ErrorCleanup {
		t.Fatalf("workspace threshold+1 status=%+v err=%v", filesStatus, err)
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, filesRequest.RunID)); !os.IsNotExist(err) {
		t.Fatalf("file-limit cgroup remained: %v", err)
	}

	slowRequest := integrationRequest(digest)
	slowRequest.RunID = "12345678-1234-4234-8234-123456789abc"
	slowRequest.TaskID = "23456789-2345-4345-8345-23456789abcd"
	slowRequest.TaskFence = "3456789a-3456-4456-8456-3456789abcde"
	slowRequest.Argv = []string{"/app/entry", "output-over"}
	slowRequest.Limits = localIntegrationLimitsV2()
	slowPacket, err := EncodeRequestV2(slowRequest)
	if err != nil {
		t.Fatal(err)
	}
	slowFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(slowFD)
	if err := unix.Connect(slowFD, &unix.SockaddrUnix{Name: socketPath}); err != nil && err != unix.EINPROGRESS {
		t.Fatal(err)
	}
	if err := waitFD(context.Background(), slowFD, unix.POLLOUT, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := unix.SendmsgN(slowFD, slowPacket, nil, nil, 0); err != nil || n != len(slowPacket) {
		t.Fatalf("slow send n=%d err=%v", n, err)
	}
	poll := []unix.PollFd{{Fd: int32(slowFD), Events: unix.POLLHUP}}
	if n, err := unix.Poll(poll, int((serverSocketWriteTimeout + 3*time.Second).Milliseconds())); err != nil || n == 0 || poll[0].Revents&unix.POLLHUP == 0 {
		t.Fatalf("slow consumer connection not bounded: n=%d revents=%#x err=%v", n, poll[0].Revents, err)
	}
	if tombstone, ok := registry.TombstoneOf(slowRequest.RunID); !ok || tombstone.Status.Phase != PhaseFailed || tombstone.Status.Error != ErrorExecution {
		t.Fatalf("slow consumer tombstone=%+v ok=%v", tombstone, ok)
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, slowRequest.RunID)); !os.IsNotExist(err) {
		t.Fatalf("slow-consumer cgroup remained: %v", err)
	}
}

func TestBuiltinLocalSandboxShellOptIn(t *testing.T) {
	if os.Getenv("DIREXTALK_BUILTIN_LOCAL_SANDBOX_INTEGRATION") != "1" {
		t.Skip("set DIREXTALK_BUILTIN_LOCAL_SANDBOX_INTEGRATION=1 with the production runner paths")
	}
	cgroupRoot := os.Getenv("DIREXTALK_EXTENSION_RUNNER_CGROUP_ROOT")
	entryPath := os.Getenv("DIREXTALK_BUILTIN_LOCAL_SANDBOX_ENTRY")
	runnerSource := os.Getenv("DIREXTALK_EXTENSION_RUNNER_BINARY")
	if !filepath.IsAbs(cgroupRoot) || !filepath.IsAbs(entryPath) || !filepath.IsAbs(runnerSource) {
		t.Fatal("production runner paths must be absolute")
	}
	entry, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	shell, err := os.ReadFile("/usr/local/libexec/dirextalk-core-shell")
	if err != nil {
		t.Fatal(err)
	}
	runnerBytes, err := os.ReadFile(runnerSource)
	if err != nil {
		t.Fatal(err)
	}
	runnerPath := filepath.Join(t.TempDir(), "dirextalk-extension-runner")
	if err = os.WriteFile(runnerPath, runnerBytes, 0o500); err != nil {
		t.Fatal(err)
	}
	entries := []ManifestEntry{
		{Path: "entry", SHA256: DigestBytes(entry), Size: int64(len(entry))},
		{Path: "shell", SHA256: DigestBytes(shell), Size: int64(len(shell))},
	}
	digest := ManifestDigest(entries)
	installRoot := t.TempDir()
	install := filepath.Join(installRoot, digest)
	if err = os.Mkdir(install, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(install, 0o700) })
	if err = os.WriteFile(filepath.Join(install, "entry"), entry, 0o500); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(install, "shell"), shell, 0o500); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(DiskInstallManifestV1{SchemaVersion: installManifestSchemaV1, Entries: entries})
	if err = os.WriteFile(filepath.Join(install, installManifestName), append(manifest, '\n'), 0o400); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(install, 0o500); err != nil {
		t.Fatal(err)
	}
	backend := LinuxBackend{CgroupRoot: cgroupRoot, ProbeRoot: t.TempDir(), ReexecPath: runnerPath}
	if err = backend.Probe(context.Background()); err != nil {
		t.Fatalf("production isolation unavailable: %v", err)
	}
	workspaceRoot := t.TempDir()
	request := integrationRequest(digest)
	request.RunID = "12345678-aaaa-4aaa-8aaa-123456789abc"
	request.TaskID = "23456789-bbbb-4bbb-8bbb-23456789abcd"
	request.TaskFence = "3456789a-cccc-4ccc-8ccc-3456789abcde"
	request.Argv = []string{"entry", "local_sandbox"}
	request.ResultFiles = []string{"acceptance.html"}
	request.TimeoutMS = 30_000
	request.Limits = LimitsV2{CPUSeconds: 30, MemoryBytes: 256 << 20, Processes: 32, FileBytes: 16 << 20, OpenFiles: 64}
	stdin := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"local_sandbox_run\",\"arguments\":{\"script\":\"printf LOCAL_SANDBOX_ACCEPTANCE > acceptance.html; cat acceptance.html\",\"result_paths\":[\"acceptance.html\"]}}}\n")
	stdinFD, err := sealedMemfd("stdin", stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stdinFD)
	request.Stdin = &FDRef{Index: 0, Size: int64(len(stdin)), SHA256: DigestBytes(stdin)}
	runner := Runner{InstallResolver: DiskInstallResolver{Root: installRoot}, WorkspaceResolver: DiskWorkspaceResolver{Root: workspaceRoot}, V2Backend: backend}
	status, err := runner.RunV2(context.Background(), request, []int{stdinFD}, NewRunRegistry())
	if err != nil || status.Phase != PhaseTombstone || status.Error != ErrorNone || !bytes.Contains(status.Stdout, []byte(`"isError":false`)) {
		t.Fatalf("status=%+v err=%v stdout=%s stderr=%s", status, err, status.Stdout, status.Stderr)
	}
	body, err := os.ReadFile(filepath.Join(workspaceRoot, request.TaskID, request.TaskFence, "acceptance.html"))
	if err != nil || string(body) != "LOCAL_SANDBOX_ACCEPTANCE" {
		t.Fatalf("artifact=%q err=%v", body, err)
	}
}

func localIntegrationLimitsV2() LimitsV2 {
	return LimitsV2{CPUSeconds: 30, MemoryBytes: 256 << 20, Processes: 32, FileBytes: 16 << 20, OpenFiles: 64}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func buildIsolationProbe(t *testing.T) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "entry")
	command := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", output, "./testdata/isolationprobe")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build isolation probe: %v: %s", err, body)
	}
	return output
}

func buildRunnerBinary(t *testing.T) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "dirextalk-extension-runner")
	command := exec.Command("go", "build", "-trimpath", "-o", output, "../../cmd/dirextalk-extension-runner")
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build extension runner: %v: %s", err, body)
	}
	return output
}

func materializeIntegrationInstall(t *testing.T, probe string) (string, string) {
	t.Helper()
	entry, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	resource := []byte("installed-resource")
	entries := []ManifestEntry{
		{Path: "entry", SHA256: DigestBytes(entry), Size: int64(len(entry))},
		{Path: "resource.txt", SHA256: DigestBytes(resource), Size: int64(len(resource))},
	}
	digest := ManifestDigest(entries)
	root := t.TempDir()
	install := filepath.Join(root, digest)
	if err := os.Mkdir(install, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(install, 0o700) })
	if err := os.WriteFile(filepath.Join(install, "entry"), entry, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "resource.txt"), resource, 0o400); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(DiskInstallManifestV1{SchemaVersion: installManifestSchemaV1, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, installManifestName), append(manifest, '\n'), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(install, 0o500); err != nil {
		t.Fatal(err)
	}
	return root, digest
}

func integrationRequest(digest string) RequestV2 {
	return RequestV2{
		RunID:         "11111111-1111-4111-8111-111111111111",
		TaskID:        "22222222-2222-4222-8222-222222222222",
		TaskFence:     "33333333-3333-4333-8333-333333333333",
		InstallDigest: digest,
		Entry:         "entry",
		TimeoutMS:     15_000,
		Limits: LimitsV2{
			CPUSeconds:  5,
			MemoryBytes: 128 << 20,
			Processes:   32,
			FileBytes:   16 << 20,
			OpenFiles:   128,
		},
	}
}

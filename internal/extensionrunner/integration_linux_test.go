//go:build linux

package extensionrunner

import (
	"context"
	"encoding/json"
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

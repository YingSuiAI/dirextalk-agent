package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSafeWorkerErrorProjectsOnlyClosedRuntimeFailure(t *testing.T) {
	t.Parallel()

	secret := "sk-abcdefghijklmnopqrstuvwxyz"
	closed := coreteamruntime.ClosedFailure{
		Stage: coreteamruntime.FailurePi,
		Code:  coreteamruntime.FailureProviderAuthentication,
	}
	for name, test := range map[string]struct {
		err     error
		failure coreteamruntime.ClosedFailure
		want    string
	}{
		"closed":   {errors.New("provider said " + secret), closed, "pi/provider_authentication"},
		"internal": {errors.New("bootstrap failed " + secret), coreteamruntime.ClosedFailure{}, "worker_internal"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := safeWorkerError(test.err, test.failure)
			if got != test.want || strings.Contains(got, secret) || strings.Contains(got, "provider said") {
				t.Fatalf("safe error = %q", got)
			}
		})
	}
}

func TestLoadConfigRejectsSecretValuesAndUnpinnedRelease(t *testing.T) {
	t.Parallel()

	environment := map[string]string{
		"DIREXTALK_PI_EXECUTABLE":             "/opt/dirextalk-worker/runtimes/pi/bin/pi",
		"DIREXTALK_PI_EXECUTABLE_SHA256":      coreteamruntime.OfficialPiExecutableSHA256,
		"DIREXTALK_PI_EXTENSION":              "/opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts",
		"DIREXTALK_PI_EXTENSION_SHA256":       coreteamruntime.OfficialPiResultExtensionSHA256,
		"DIREXTALK_PI_SANDBOX":                "/usr/local/bin/dirextalk-pi-sandbox",
		"DIREXTALK_PI_SANDBOX_SHA256_FILE":    "/usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256",
		"DIREXTALK_PI_STATE_ROOT":             "/var/lib/dirextalk-worker",
		"DIREXTALK_PI_SEARCH_PATH":            "/usr/bin:/bin",
		"DIREXTALK_WORKER_BINARY_SHA256_FILE": "/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256",
	}
	getenv := func(name string) string { return environment[name] }
	if _, err := loadConfig(getenv); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	environment["DIREXTALK_PI_EXECUTABLE_SHA256"] = strings.Repeat("0", 64)
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("different executable digest was accepted")
	}
	environment["DIREXTALK_PI_EXECUTABLE_SHA256"] = coreteamruntime.OfficialPiExecutableSHA256
	environment["DIREXTALK_PI_EXTENSION_SHA256"] = strings.Repeat("0", 64)
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("different result extension digest was accepted")
	}
	environment["DIREXTALK_PI_EXTENSION_SHA256"] = coreteamruntime.OfficialPiResultExtensionSHA256
	delete(environment, "DIREXTALK_PI_SANDBOX")
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("missing fail-closed sandbox launcher was accepted")
	}
	environment["DIREXTALK_PI_SANDBOX"] = "/usr/local/bin/dirextalk-pi-sandbox"
	environment["DIREXTALK_PI_SEARCH_PATH"] = "/usr/local/bin:/usr/bin:/bin"
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("search path exposing the Worker binary was accepted")
	}
	environment["DIREXTALK_PI_SEARCH_PATH"] = "/usr/bin:/bin"
	for variable, unsafePath := range map[string]string{
		"DIREXTALK_PI_STATE_ROOT":             "/var/lib/dirextalk-worker/workspaces/runtime-state",
		"DIREXTALK_PI_SANDBOX_SHA256_FILE":    "/var/lib/dirextalk-worker/workspaces/sandbox.sha256",
		"DIREXTALK_WORKER_BINARY_SHA256_FILE": "/var/lib/dirextalk-worker/workspaces/worker.sha256",
	} {
		original := environment[variable]
		environment[variable] = unsafePath
		if _, err := loadConfig(getenv); err == nil {
			t.Fatalf("workspace-overlapping %s=%q was accepted", variable, unsafePath)
		}
		environment[variable] = original
	}
	environment["DIREXTALK_PI_STATE_ROOT"] = "/tmp/sk-abcdefghijklmnopqrstuvwxyz"
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("secret-bearing configuration was accepted")
	}
}

func TestWorkerContainerRequiresExplicitLinuxAMD64AndDurableRoots(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/container/pi-worker/worker.Containerfile")
	if err != nil {
		t.Fatal(err)
	}
	containerfile := string(raw)
	for _, forbidden := range []string{"ARG TARGETOS=", "ARG TARGETARCH="} {
		if strings.Contains(containerfile, forbidden) {
			t.Fatalf("Containerfile contains unsafe platform default %q", forbidden)
		}
	}
	for _, required := range []string{
		"ARG TARGETOS\n", "ARG TARGETARCH\n", `test "$TARGETOS" = linux`, `test "$TARGETARCH" = amd64`,
		"/var/lib/dirextalk-worker/receipts", "/run/dirextalk-worker/secrets",
		"DIREXTALK_WORKER_RECEIPT_ROOT=/var/lib/dirextalk-worker/receipts",
		"DIREXTALK_WORKER_SECRET_ROOT=/run/dirextalk-worker/secrets",
		"go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' -o /out/usr/local/bin/dirextalk-pi-sandbox ./cmd/dirextalk-pi-sandbox",
		"DIREXTALK_PI_SANDBOX=/usr/local/bin/dirextalk-pi-sandbox",
		"DIREXTALK_PI_SANDBOX_SHA256_FILE=/usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256",
		"git=1:2.39.5-0+deb12u3",
		"ca-certificates=20230311+deb12u1",
		"libcap2-bin=1:2.66-4+deb12u3+b1",
		"setcap cap_kill,cap_setgid,cap_setuid=ep /usr/local/bin/dirextalk-cloud-worker",
	} {
		if !strings.Contains(containerfile, required) {
			t.Fatalf("Containerfile missing %q", required)
		}
	}
	service, err := os.ReadFile("../../deploy/container/pi-worker/dirextalk-cloud-worker.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(service), "ProtectProc=ptraceable") || strings.Contains(string(service), "ProtectProc=invisible") {
		t.Fatal("systemd unit does not hide the non-dumpable control process from Pi")
	}
	for _, required := range []string{
		"User=65532",
		"Group=65532",
		"CapabilityBoundingSet=CAP_KILL CAP_SETGID CAP_SETUID",
		"AmbientCapabilities=CAP_KILL CAP_SETGID CAP_SETUID",
	} {
		if !strings.Contains(string(service), required) {
			t.Fatalf("systemd unit missing separate Pi identity control %q", required)
		}
	}
}

func TestWorkerReleaseDocumentsClosedLaunchFields(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/container/pi-worker/README.md")
	if err != nil {
		t.Fatal(err)
	}
	documentation := string(raw)
	for _, required := range []string{
		"DIREXTALK_WORKER_MODEL_REVISION",
		"DIREXTALK_WORKER_CREDENTIAL_REVISION",
		"DIREXTALK_WORKER_INPUT_MANIFEST_FILE",
		"DIREXTALK_WORKER_INPUT_MANIFEST_SHA256",
		"DIREXTALK_WORKER_SECRET_ROOT",
		"DIREXTALK_WORKER_WORKSPACE_SHA256",
		"DIREXTALK_WORKER_RECEIPT_ROOT",
	} {
		if !strings.Contains(documentation, "`"+required+"`") {
			t.Fatalf("README missing %q", required)
		}
	}
	if strings.Contains(documentation, "DIREXTALK_WORKER_MODEL_CREDENTIAL_FILE") {
		t.Fatal("README still documents the obsolete reusable credential-file path")
	}
}

func TestLoadLaunchRequiresCompleteBoundInputAndRejectsSecretShapedModel(t *testing.T) {
	t.Parallel()
	environment := map[string]string{
		"DIREXTALK_WORKER_ATTEMPT":               "1",
		"DIREXTALK_WORKER_MODEL_REVISION":        "7",
		"DIREXTALK_WORKER_CREDENTIAL_REVISION":   "11",
		"DIREXTALK_WORKER_CONTROL_ENDPOINT":      "central.example.test:443",
		"DIREXTALK_WORKER_TLS_SERVER_NAME":       "central.example.test",
		"DIREXTALK_WORKER_TLS_CA_FILE":           "/run/dirextalk-worker/tls/ca.pem",
		"DIREXTALK_WORKER_TLS_CERT_FILE":         "/run/dirextalk-worker/tls/cert.pem",
		"DIREXTALK_WORKER_TLS_KEY_FILE":          "/run/dirextalk-worker/tls/key.pem",
		"DIREXTALK_WORKER_EXECUTION_ID":          "22222222-2222-4222-8222-222222222222",
		"DIREXTALK_WORKER_ROLE_ID":               "implementer",
		"DIREXTALK_WORKER_IDEMPOTENCY_KEY":       "55555555-5555-4555-8555-555555555555",
		"DIREXTALK_WORKER_MODEL_PROVIDER":        "deepseek",
		"DIREXTALK_WORKER_MODEL":                 "deepseek-v4-pro",
		"DIREXTALK_WORKER_CONTEXT_FILE":          "/var/lib/dirextalk-worker/input/context.json",
		"DIREXTALK_WORKER_CONTEXT_SHA256":        strings.Repeat("a", 64),
		"DIREXTALK_WORKER_INPUT_MANIFEST_FILE":   "/var/lib/dirextalk-worker/input/manifest.json",
		"DIREXTALK_WORKER_INPUT_MANIFEST_SHA256": strings.Repeat("b", 64),
		"DIREXTALK_WORKER_SECRET_ROOT":           "/run/dirextalk-worker/secrets",
		"DIREXTALK_WORKER_WORKSPACE_SHA256":      strings.Repeat("c", 64),
		"DIREXTALK_WORKER_RECEIPT_ROOT":          "/var/lib/dirextalk-worker/receipts",
		"DIREXTALK_WORKER_WORKSPACE":             "/var/lib/dirextalk-worker/workspaces/role",
		"DIREXTALK_WORKER_RPC_TIMEOUT":           "20s",
	}
	getenv := func(name string) string { return environment[name] }
	launch, err := loadLaunch(getenv)
	if err != nil || launch.modelRevision != 7 || launch.credentialRevision != 11 || launch.manifestDigest != strings.Repeat("b", 64) {
		t.Fatalf("launch=%+v err=%v", launch, err)
	}
	for _, unsafeWorkspace := range []string{
		"/var/lib/dirextalk-worker", "/var/lib/dirextalk-worker/workspaces", "/etc", "/run",
	} {
		environment["DIREXTALK_WORKER_WORKSPACE"] = unsafeWorkspace
		if _, err := loadLaunch(getenv); err == nil {
			t.Fatalf("unsafe workspace %q was accepted", unsafeWorkspace)
		}
	}
	environment["DIREXTALK_WORKER_WORKSPACE"] = "/var/lib/dirextalk-worker/workspaces/role"
	for variable, unsafePath := range map[string]string{
		"DIREXTALK_WORKER_TLS_CA_FILE":         "/var/lib/dirextalk-worker/workspaces/role/ca.pem",
		"DIREXTALK_WORKER_TLS_CERT_FILE":       "/var/lib/dirextalk-worker/workspaces/role/cert.pem",
		"DIREXTALK_WORKER_TLS_KEY_FILE":        "/var/lib/dirextalk-worker/workspaces/role/key.pem",
		"DIREXTALK_WORKER_CONTEXT_FILE":        "/var/lib/dirextalk-worker/workspaces/role/context.json",
		"DIREXTALK_WORKER_INPUT_MANIFEST_FILE": "/var/lib/dirextalk-worker/workspaces/role/manifest.json",
		"DIREXTALK_WORKER_SECRET_ROOT":         "/var/lib/dirextalk-worker/workspaces/role/secrets",
		"DIREXTALK_WORKER_RECEIPT_ROOT":        "/var/lib/dirextalk-worker/workspaces",
	} {
		original := environment[variable]
		environment[variable] = unsafePath
		if _, err := loadLaunch(getenv); err == nil {
			t.Fatalf("workspace-overlapping %s=%q was accepted", variable, unsafePath)
		}
		environment[variable] = original
	}
	delete(environment, "DIREXTALK_WORKER_MODEL_REVISION")
	if _, err := loadLaunch(getenv); err == nil {
		t.Fatal("missing model revision was accepted")
	}
	environment["DIREXTALK_WORKER_MODEL_REVISION"] = "7"
	environment["DIREXTALK_WORKER_MODEL"] = "sk-abcdefghijklmnopqrstuvwxyz"
	if _, err := loadLaunch(getenv); err == nil {
		t.Fatal("secret-shaped model identifier was accepted")
	}
}

func TestVerifyExecutableRequiresMatchingImmutableSidecar(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(t.TempDir(), "worker.sha256")
	if err := os.WriteFile(sidecar, []byte(coreDigest(content)+"  "+executable+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutable(executable, sidecar); err != nil {
		t.Fatalf("valid executable rejected: %v", err)
	}
	tamperedSidecar := filepath.Join(t.TempDir(), "tampered-worker.sha256")
	if err := os.WriteFile(tamperedSidecar, []byte(strings.Repeat("0", 64)+"  "+executable+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutable(executable, tamperedSidecar); err == nil {
		t.Fatal("tampered digest sidecar was accepted")
	}
}

func TestExecuteRoleSubmitsOnlyDigestBoundStructuredResult(t *testing.T) {
	t.Parallel()
	launch, runtimeContextDigest := testLaunch(t)
	control := newFakeControl(runtimeContextDigest)
	receipt := &fakeReceipt{}
	runtime := &fakeRuntime{result: coreteamworker.ResultPayloadV1{
		SchemaVersion: coreteamworker.ResultSchemaVersion,
		Status:        "completed", Summary: "Finished the role.",
		Deliverables: []string{"artifact"}, Tests: []string{"qualified"}, Risks: []string{},
		Usage: coreteamworker.ResultUsageV1{InputTokens: 12, OutputTokens: 8},
	}}

	failure, err := executeRole(t.Context(), control, runtime, launch, strings.Repeat("d", 64), receipt)
	if err != nil || failure.Valid() {
		t.Fatalf("execute error=%v failure=%+v", err, failure)
	}
	if runtime.calls != 1 || control.complete == nil ||
		control.complete.GetOutcome() != agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_SUCCEEDED ||
		control.complete.GetFailureCode() != agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_UNSPECIFIED ||
		len(control.complete.GetResultJson()) == 0 || control.complete.GetResultDigest() == "" {
		t.Fatalf("runtime calls=%d complete=%+v", runtime.calls, control.complete)
	}
	metadata := coreteamworker.ResultMetadata{
		SchemaVersion: control.complete.GetResultSchemaVersion(), Digest: control.complete.GetResultDigest(),
		SizeBytes: control.complete.GetResultSizeBytes(), PayloadJSON: control.complete.GetResultJson(),
	}
	if metadata.Validate() != nil {
		t.Fatalf("invalid result metadata: %+v", metadata)
	}
	if string(runtime.workspace.Credential) == "" || strings.Contains(string(control.complete.GetResultJson()), "credential") {
		t.Fatal("credential handling or result projection is invalid")
	}
	wantCalls := []string{"challenge", "enroll", "assignment", "claim", "complete"}
	if strings.Join(control.calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("control calls = %v", control.calls)
	}
	if receipt.state != receiptCompletionAcknowledged || receipt.pending == nil {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestExecuteRoleReportsClosedFailureOnceThenExitsCleanly(t *testing.T) {
	t.Parallel()
	launch, runtimeContextDigest := testLaunch(t)
	control := newFakeControl(runtimeContextDigest)
	receipt := &fakeReceipt{}
	runtime := &fakeRuntime{failure: coreteamruntime.ClosedFailure{
		Stage: coreteamruntime.FailurePi,
		Code:  coreteamruntime.FailureProviderAuthentication,
	}}

	failure, err := executeRole(t.Context(), control, runtime, launch, strings.Repeat("d", 64), receipt)
	if err != nil || failure.Valid() {
		t.Fatalf("reported failure must exit cleanly: error=%v failure=%+v", err, failure)
	}
	if control.complete == nil ||
		control.complete.GetOutcome() != agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_FAILED ||
		control.complete.GetFailureCode() != agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_PI ||
		len(control.complete.GetResultJson()) != 0 {
		t.Fatalf("complete = %+v", control.complete)
	}
}

func TestLaunchCommittedRestartNeverRunsPiAgain(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	control := newFakeControl(runtimeContextDigest)
	request := testCompleteRequest()
	raw, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	receipt := &fakeReceipt{state: receiptLaunchCommitted, raw: raw}

	failure, err := executeRole(t.Context(), control, nil, launch, strings.Repeat("d", 64), receipt)
	if err != nil || failure.Valid() {
		t.Fatalf("recovery error=%v failure=%+v", err, failure)
	}
	if control.complete == nil ||
		control.complete.GetFailureCode() != agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_EXECUTION_UNCERTAIN ||
		receipt.state != receiptCompletionAcknowledged || !slices.Equal(control.calls, []string{"complete"}) {
		t.Fatalf("complete=%+v receipt=%+v calls=%v", control.complete, receipt, control.calls)
	}
}

func TestRecoveringReceiptSkipsPiRuntimeInitialization(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	request := testCompleteRequest()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{receiptLaunchCommitted, receiptCompletionPending} {
		t.Run(state, func(t *testing.T) {
			control := newFakeControl(runtimeContextDigest)
			receipt := &fakeReceipt{state: state, raw: append([]byte(nil), raw...)}
			initialized := 0
			failure, err := executeLockedRole(
				t.Context(), control, launch, strings.Repeat("d", 64), receipt,
				func() (coreteamruntime.Runner, error) {
					initialized++
					return nil, errors.New("Pi runtime unavailable")
				},
			)
			if err != nil || failure.Valid() || initialized != 0 || receipt.state != receiptCompletionAcknowledged ||
				!slices.Equal(control.calls, []string{"complete"}) {
				t.Fatalf("error=%v failure=%+v initialized=%d receipt=%+v calls=%v", err, failure, initialized, receipt, control.calls)
			}
		})
	}
}

func TestCompletionPendingReplaysExactRequestAfterResponseLoss(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	control := newFakeControl(runtimeContextDigest)
	runtime := &fakeRuntime{}
	request := testCompleteRequest()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &fakeReceipt{state: receiptCompletionPending, pending: proto.Clone(request).(*agentv1.CoreTeamWorkerServiceCompleteRequest), raw: raw}

	failure, err := executeRole(t.Context(), control, runtime, launch, strings.Repeat("d", 64), receipt)
	if err != nil || failure.Valid() {
		t.Fatalf("pending recovery error=%v failure=%+v", err, failure)
	}
	got, err := proto.MarshalOptions{Deterministic: true}.Marshal(control.complete)
	if err != nil || !bytes.Equal(got, raw) || runtime.calls != 0 || receipt.state != receiptCompletionAcknowledged {
		t.Fatalf("replayed=%x want=%x runtime calls=%d receipt=%+v err=%v", got, raw, runtime.calls, receipt, err)
	}
	if !slices.Equal(control.calls, []string{"complete"}) {
		t.Fatalf("pending replay called unrelated Worker RPCs: %v", control.calls)
	}
}

func TestCompletionPendingKeepsStaleFenceDurableWhenCentralRejects(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	control := newFakeControl(runtimeContextDigest)
	control.completeErr = errors.New("stale fence")
	runtime := &fakeRuntime{}
	request := testCompleteRequest()
	request.Fence.LeaseEpoch++
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &fakeReceipt{state: receiptCompletionPending, pending: proto.Clone(request).(*agentv1.CoreTeamWorkerServiceCompleteRequest), raw: raw}

	_, err = executeRole(t.Context(), control, runtime, launch, strings.Repeat("d", 64), receipt)
	if err == nil || runtime.calls != 0 || control.complete == nil || receipt.state != receiptCompletionPending ||
		!slices.Equal(control.calls, []string{"complete"}) {
		t.Fatalf("error=%v runtime calls=%d complete=%+v receipt=%+v", err, runtime.calls, control.complete, receipt)
	}
}

func TestResponseLossRestartReplaysDurableCompletionWithoutPi(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	journal, err := newReceiptJournal(launch.receiptRoot, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	key := receiptKey{ExecutionID: launch.executionID, RoleID: launch.roleID, Attempt: launch.attempt}
	firstReceipt, err := journal.lock(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	firstControl := newFakeControl(runtimeContextDigest)
	firstControl.completeErr = errors.New("response lost after request delivery")
	firstRuntime := &fakeRuntime{result: validTestResult()}
	_, err = executeRole(t.Context(), firstControl, firstRuntime, launch, strings.Repeat("d", 64), firstReceipt)
	if err == nil || firstRuntime.calls != 1 || firstControl.complete == nil {
		t.Fatalf("first error=%v runtime calls=%d complete=%+v", err, firstRuntime.calls, firstControl.complete)
	}
	want, err := proto.MarshalOptions{Deterministic: true}.Marshal(firstControl.complete)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstReceipt.close(); err != nil {
		t.Fatal(err)
	}

	restartedReceipt, err := journal.lock(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedReceipt.close()
	restartedControl := newFakeControl(runtimeContextDigest)
	restartedRuntime := &fakeRuntime{}
	_, err = executeRole(t.Context(), restartedControl, restartedRuntime, launch, strings.Repeat("d", 64), restartedReceipt)
	got, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(restartedControl.complete)
	if err != nil || marshalErr != nil || !bytes.Equal(got, want) || restartedRuntime.calls != 0 {
		t.Fatalf("restart error=%v marshal=%v replayed=%x want=%x runtime calls=%d", err, marshalErr, got, want, restartedRuntime.calls)
	}
	receipt, found, err := restartedReceipt.load()
	if err != nil || !found || receipt.State != receiptCompletionAcknowledged {
		t.Fatalf("receipt=%+v found=%v err=%v", receipt, found, err)
	}
	if !slices.Equal(restartedControl.calls, []string{"complete"}) {
		t.Fatalf("restart replay called unrelated Worker RPCs: %v", restartedControl.calls)
	}
}

func TestConcurrentWorkerProcessesExecuteAtMostOnce(t *testing.T) {
	if os.Getenv("DIREXTALK_TEST_CONCURRENT_WORKER_HELPER") == "1" {
		runConcurrentWorkerHelper(t)
		return
	}
	launch, runtimeContextDigest := testLaunch(t)
	root := filepath.Dir(launch.contextFile)
	type process struct {
		command *exec.Cmd
		output  bytes.Buffer
	}
	processes := make([]process, 2)
	for index := range processes {
		processes[index].command = exec.Command(os.Args[0], "-test.run=^TestConcurrentWorkerProcessesExecuteAtMostOnce$", "-test.count=1")
		processes[index].command.Env = append(os.Environ(),
			"DIREXTALK_TEST_CONCURRENT_WORKER_HELPER=1",
			"DIREXTALK_TEST_CONCURRENT_WORKER_ROOT="+root,
			"DIREXTALK_TEST_CONCURRENT_WORKER_DIGEST="+runtimeContextDigest,
		)
		processes[index].command.Stdout = &processes[index].output
		processes[index].command.Stderr = &processes[index].output
		if err := processes[index].command.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for index := range processes {
		if err := processes[index].command.Wait(); err != nil {
			t.Fatalf("Worker process %d failed: %v output=%q", index+1, err, processes[index].output.String())
		}
	}
	if marker, err := os.ReadFile(filepath.Join(root, "pi-executed")); err != nil || string(marker) != "once" {
		t.Fatalf("Pi execution marker=%q err=%v", marker, err)
	}
	journal, err := newReceiptJournal(launch.receiptRoot, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	locked, err := journal.lock(t.Context(), receiptKey{ExecutionID: launch.executionID, RoleID: launch.roleID, Attempt: launch.attempt})
	if err != nil {
		t.Fatal(err)
	}
	defer locked.close()
	receipt, found, err := locked.load()
	if err != nil || !found || receipt.State != receiptCompletionAcknowledged {
		t.Fatalf("receipt=%+v found=%v err=%v", receipt, found, err)
	}
}

func runConcurrentWorkerHelper(t *testing.T) {
	root := os.Getenv("DIREXTALK_TEST_CONCURRENT_WORKER_ROOT")
	runtimeContextDigest := os.Getenv("DIREXTALK_TEST_CONCURRENT_WORKER_DIGEST")
	if root == "" || runtimeContextDigest == "" {
		t.Fatal("missing concurrent Worker helper configuration")
	}
	launch, err := concurrentWorkerLaunch(root)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := newReceiptJournal(launch.receiptRoot, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	locked, err := journal.lock(t.Context(), receiptKey{ExecutionID: launch.executionID, RoleID: launch.roleID, Attempt: launch.attempt})
	if err != nil {
		t.Fatal(err)
	}
	defer locked.close()
	runtime := &fakeRuntime{result: validTestResult(), beforeRun: func() error {
		marker, openErr := os.OpenFile(filepath.Join(root, "pi-executed"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			return openErr
		}
		if _, writeErr := marker.WriteString("once"); writeErr != nil {
			_ = marker.Close()
			return writeErr
		}
		if closeErr := marker.Close(); closeErr != nil {
			return closeErr
		}
		time.Sleep(100 * time.Millisecond)
		return nil
	}}
	if _, err = executeRole(t.Context(), newFakeControl(runtimeContextDigest), runtime, launch, strings.Repeat("d", 64), locked); err != nil {
		receipt, found, loadErr := locked.load()
		_, credentialErr := os.Lstat(filepath.Join(launch.credentialRoot, modelCredentialFileName))
		t.Fatalf("execute: %v receipt=%+v found=%v load=%v credential=%v runtime_calls=%d", err, receipt, found, loadErr, credentialErr, runtime.calls)
	}
}

func concurrentWorkerLaunch(root string) (launchConfig, error) {
	contextFile := filepath.Join(root, "context.json")
	manifestFile := filepath.Join(root, "manifest.json")
	contextJSON, err := os.ReadFile(contextFile)
	if err != nil {
		return launchConfig{}, err
	}
	manifestJSON, err := os.ReadFile(manifestFile)
	if err != nil {
		return launchConfig{}, err
	}
	return launchConfig{
		executionID: "22222222-2222-4222-8222-222222222222", roleID: "implementer", attempt: 1,
		idempotencyKey: "55555555-5555-4555-8555-555555555555",
		model:          coreteamruntime.ModelBinding{Provider: "deepseek", Name: "deepseek-v4-pro", Interface: "openai_compatible"},
		modelRevision:  7, credentialRevision: 11,
		contextFile: contextFile, contextDigest: coreDigest(contextJSON),
		manifestFile: manifestFile, manifestDigest: coreDigest(manifestJSON),
		credentialRoot: filepath.Join(root, "secrets"), workspaceDigest: coreteamruntime.EmptyWorkspaceDigest,
		receiptRoot: filepath.Join(root, "receipts"), rpcTimeout: time.Second,
	}, nil
}

func TestReceiptWriteFailurePreventsPiLaunch(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	control := newFakeControl(runtimeContextDigest)
	runtime := &fakeRuntime{}
	receipt := &fakeReceipt{commitLaunchErr: errors.New("directory sync failed")}

	_, err := executeRole(t.Context(), control, runtime, launch, strings.Repeat("d", 64), receipt)
	if err == nil || runtime.calls != 0 || control.complete != nil {
		t.Fatalf("error=%v runtime calls=%d complete=%+v", err, runtime.calls, control.complete)
	}
}

func TestCompletionResponseMismatchIsNotAcknowledged(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	control := newFakeControl(runtimeContextDigest)
	control.completeResponse = func(request *agentv1.CoreTeamWorkerServiceCompleteRequest) *agentv1.CoreTeamWorkerServiceCompleteResponse {
		return &agentv1.CoreTeamWorkerServiceCompleteResponse{
			CompletionId: "99999999-9999-4999-8999-999999999999", Outcome: request.GetOutcome(), AcceptedAt: timestamppb.Now(),
		}
	}
	receipt := &fakeReceipt{}
	runtime := &fakeRuntime{result: coreteamworker.ResultPayloadV1{
		SchemaVersion: 1, Status: "completed", Summary: "Finished.", Deliverables: []string{}, Tests: []string{}, Risks: []string{},
		Usage: coreteamworker.ResultUsageV1{InputTokens: 1, OutputTokens: 1},
	}}

	_, err := executeRole(t.Context(), control, runtime, launch, strings.Repeat("d", 64), receipt)
	if err == nil || receipt.state != receiptCompletionPending || receipt.ackCalls != 0 {
		t.Fatalf("error=%v receipt=%+v", err, receipt)
	}
}

func TestAcknowledgedReceiptDoesNotRequireControlCredential(t *testing.T) {
	required, err := receiptRequiresControl(&fakeReceipt{state: receiptCompletionAcknowledged})
	if err != nil || required {
		t.Fatalf("required=%v err=%v", required, err)
	}
	for _, state := range []string{"", receiptLaunchCommitted, receiptCompletionPending} {
		required, err := receiptRequiresControl(&fakeReceipt{state: state})
		if err != nil || !required {
			t.Fatalf("state=%q required=%v err=%v", state, required, err)
		}
	}
}

func TestConsumeCredentialUnlinksBeforePiStarts(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	control := newFakeControl(runtimeContextDigest)
	receipt := &fakeReceipt{}
	runtime := &fakeRuntime{
		result: coreteamworker.ResultPayloadV1{
			SchemaVersion: 1, Status: "completed", Summary: "Finished.", Deliverables: []string{}, Tests: []string{}, Risks: []string{},
			Usage: coreteamworker.ResultUsageV1{InputTokens: 1, OutputTokens: 1},
		},
		beforeRun: func() error {
			if _, err := os.Lstat(filepath.Join(launch.credentialRoot, modelCredentialFileName)); !errors.Is(err, os.ErrNotExist) {
				return errors.New("credential path still exists")
			}
			return nil
		},
	}

	_, err := executeRole(t.Context(), control, runtime, launch, strings.Repeat("d", 64), receipt)
	if err != nil || runtime.calls != 1 {
		t.Fatalf("error=%v runtime calls=%d", err, runtime.calls)
	}
}

func TestExecuteRoleRejectsWorkspaceContentOutsideBoundDigest(t *testing.T) {
	launch, runtimeContextDigest := testLaunch(t)
	launch.workspace = filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(launch.workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(launch.workspace, "source.txt"), []byte("not-bound"), 0o600); err != nil {
		t.Fatal(err)
	}
	control := newFakeControl(runtimeContextDigest)
	runtime := &fakeRuntime{result: validTestResult()}
	receipt := &fakeReceipt{}

	_, err := executeRole(t.Context(), control, runtime, launch, strings.Repeat("d", 64), receipt)
	if err != nil || runtime.calls != 0 || control.complete.GetFailureCode() != agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_INTERNAL {
		t.Fatalf("error=%v runtime_calls=%d completion=%+v", err, runtime.calls, control.complete)
	}
	if _, err := os.Lstat(filepath.Join(launch.credentialRoot, modelCredentialFileName)); err != nil {
		t.Fatalf("workspace rejection consumed model credential: %v", err)
	}
}

type fakeRuntime struct {
	result    coreteamruntime.Result
	failure   coreteamruntime.ClosedFailure
	err       error
	calls     int
	workspace coreteamruntime.Workspace
	beforeRun func() error
}

func validTestResult() coreteamruntime.Result {
	return coreteamworker.ResultPayloadV1{
		SchemaVersion: coreteamworker.ResultSchemaVersion,
		Status:        "completed", Summary: "Finished.", Deliverables: []string{}, Tests: []string{}, Risks: []string{},
		Usage: coreteamworker.ResultUsageV1{InputTokens: 1, OutputTokens: 1},
	}
}

func (runtime *fakeRuntime) Run(_ context.Context, _ coreteamruntime.Assignment, workspace coreteamruntime.Workspace) (coreteamruntime.Result, coreteamruntime.ClosedFailure, error) {
	runtime.calls++
	if runtime.beforeRun != nil {
		if err := runtime.beforeRun(); err != nil {
			return coreteamruntime.Result{}, coreteamruntime.ClosedFailure{}, err
		}
	}
	runtime.workspace = coreteamruntime.Workspace{
		Directory:   workspace.Directory,
		ContextJSON: append([]byte(nil), workspace.ContextJSON...),
		Credential:  append([]byte(nil), workspace.Credential...),
	}
	return runtime.result, runtime.failure, runtime.err
}

type fakeControl struct {
	calls            []string
	complete         *agentv1.CoreTeamWorkerServiceCompleteRequest
	runtimeDigest    string
	completeResponse func(*agentv1.CoreTeamWorkerServiceCompleteRequest) *agentv1.CoreTeamWorkerServiceCompleteResponse
	completeErr      error
}

func newFakeControl(runtimeDigest string) *fakeControl {
	return &fakeControl{runtimeDigest: runtimeDigest}
}

func (control *fakeControl) CreateIdentityChallenge(_ context.Context, _ *agentv1.CoreTeamWorkerServiceCreateIdentityChallengeRequest, _ ...grpc.CallOption) (*agentv1.CoreTeamWorkerServiceCreateIdentityChallengeResponse, error) {
	control.calls = append(control.calls, "challenge")
	return &agentv1.CoreTeamWorkerServiceCreateIdentityChallengeResponse{
		ChallengeId: "44444444-4444-4444-8444-444444444444",
		WorkerId:    "11111111-1111-4111-8111-111111111111",
		ExecutionId: "22222222-2222-4222-8222-222222222222",
		RoleId:      "implementer", Attempt: 1,
	}, nil
}

func (control *fakeControl) Enroll(_ context.Context, _ *agentv1.CoreTeamWorkerServiceEnrollRequest, _ ...grpc.CallOption) (*agentv1.CoreTeamWorkerServiceEnrollResponse, error) {
	control.calls = append(control.calls, "enroll")
	return &agentv1.CoreTeamWorkerServiceEnrollResponse{
		WorkerId:    "11111111-1111-4111-8111-111111111111",
		ExecutionId: "22222222-2222-4222-8222-222222222222",
		RoleId:      "implementer", Attempt: 1,
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

func (control *fakeControl) GetAssignment(_ context.Context, _ *agentv1.CoreTeamWorkerServiceGetAssignmentRequest, _ ...grpc.CallOption) (*agentv1.CoreTeamWorkerServiceGetAssignmentResponse, error) {
	control.calls = append(control.calls, "assignment")
	return &agentv1.CoreTeamWorkerServiceGetAssignmentResponse{
		WorkerId:    "11111111-1111-4111-8111-111111111111",
		ExecutionId: "22222222-2222-4222-8222-222222222222",
		PlanId:      "33333333-3333-4333-8333-333333333333",
		RoleId:      "implementer", Attempt: 1, PlanDigest: strings.Repeat("a", 64),
		Goal:         "Implement the approved change.",
		Capabilities: []string{string(coreteam.CapabilityRepositoryWrite), string(coreteam.CapabilityStructuredResult)},
		RuntimeId:    coreteam.OfficialRuntimeID, OutputTokens: 4096,
		ResultSchemaVersion:  coreteamworker.ResultSchemaVersion,
		RuntimeContextDigest: control.runtimeDigest,
	}, nil
}

func (control *fakeControl) Claim(_ context.Context, _ *agentv1.CoreTeamWorkerServiceClaimRequest, _ ...grpc.CallOption) (*agentv1.CoreTeamWorkerServiceClaimResponse, error) {
	control.calls = append(control.calls, "claim")
	return &agentv1.CoreTeamWorkerServiceClaimResponse{
		Fence: &agentv1.CoreTeamWorkerLeaseFence{
			ExecutionId: "22222222-2222-4222-8222-222222222222", RoleId: "implementer",
			WorkerId: "11111111-1111-4111-8111-111111111111", Attempt: 1, LeaseEpoch: 1,
		},
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

func (control *fakeControl) Heartbeat(_ context.Context, _ *agentv1.CoreTeamWorkerServiceHeartbeatRequest, _ ...grpc.CallOption) (*agentv1.CoreTeamWorkerServiceHeartbeatResponse, error) {
	control.calls = append(control.calls, "heartbeat")
	return nil, errors.New("unexpected heartbeat")
}

func (control *fakeControl) EmitMilestone(_ context.Context, _ *agentv1.CoreTeamWorkerServiceEmitMilestoneRequest, _ ...grpc.CallOption) (*agentv1.CoreTeamWorkerServiceEmitMilestoneResponse, error) {
	return nil, errors.New("unexpected milestone")
}

func (control *fakeControl) Complete(_ context.Context, request *agentv1.CoreTeamWorkerServiceCompleteRequest, _ ...grpc.CallOption) (*agentv1.CoreTeamWorkerServiceCompleteResponse, error) {
	control.calls = append(control.calls, "complete")
	control.complete = proto.Clone(request).(*agentv1.CoreTeamWorkerServiceCompleteRequest)
	if control.completeErr != nil {
		return nil, control.completeErr
	}
	if control.completeResponse != nil {
		return control.completeResponse(request), nil
	}
	return &agentv1.CoreTeamWorkerServiceCompleteResponse{
		CompletionId: request.GetCompletionId(), Outcome: request.GetOutcome(), AcceptedAt: timestamppb.Now(),
	}, nil
}

func testLaunch(t *testing.T) (launchConfig, string) {
	t.Helper()
	root := t.TempDir()
	credential := []byte("scoped-test-credential-1234567890")
	model := coreteaminput.ModelBindingV1{Provider: "deepseek", Name: "deepseek-v4-pro", Interface: "openai_compatible", Revision: 7}
	compiled, err := coreteaminput.Compile(coreteaminput.CompileRequest{
		Assignment: coreteamworker.Assignment{
			WorkerID: "11111111-1111-4111-8111-111111111111", ExecutionID: "22222222-2222-4222-8222-222222222222",
			PlanID: "33333333-3333-4333-8333-333333333333", RoleID: "implementer", Attempt: 1,
			PlanDigest: strings.Repeat("a", 64), Goal: "Implement the approved change.",
			Capabilities: []coreteam.Capability{coreteam.CapabilityRepositoryWrite, coreteam.CapabilityStructuredResult},
			RuntimeID:    coreteam.OfficialRuntimeID, OutputTokens: 4096, ResultSchemaVersion: coreteamworker.ResultSchemaVersion,
		},
		Model: model, CredentialRevision: 11,
		Context: coreteaminput.ContextInput{
			GoalSummary: "Implement the approved change.", Constraints: []string{},
			Dependencies: []coreteaminput.DependencyResultV1{}, Artifacts: []coreteaminput.ArtifactRefV1{},
		},
		DependencyRoles: []string{}, WorkspaceDigest: coreteamruntime.EmptyWorkspaceDigest, Credential: credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Destroy()
	contextFile := filepath.Join(root, "context.json")
	manifestFile := filepath.Join(root, "manifest.json")
	credentialRoot := filepath.Join(root, "secrets")
	receiptRoot := filepath.Join(root, "receipts")
	for _, directory := range []string{credentialRoot, receiptRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(contextFile, compiled.ContextJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestFile, compiled.ManifestJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credentialRoot, modelCredentialFileName), credential, 0o600); err != nil {
		t.Fatal(err)
	}
	return launchConfig{
		executionID: "22222222-2222-4222-8222-222222222222", roleID: "implementer", attempt: 1,
		idempotencyKey: "55555555-5555-4555-8555-555555555555",
		model:          coreteamruntime.ModelBinding{Provider: "deepseek", Name: "deepseek-v4-pro", Interface: "openai_compatible"},
		modelRevision:  model.Revision, credentialRevision: 11,
		contextFile: contextFile, contextDigest: coreDigest(compiled.ContextJSON),
		manifestFile: manifestFile, manifestDigest: coreDigest(compiled.ManifestJSON),
		credentialRoot: credentialRoot, workspaceDigest: coreteamruntime.EmptyWorkspaceDigest, receiptRoot: receiptRoot,
		rpcTimeout: time.Second,
	}, compiled.RuntimeContextDigest
}

type fakeReceipt struct {
	state           string
	pending         *agentv1.CoreTeamWorkerServiceCompleteRequest
	raw             []byte
	commitLaunchErr error
	ackCalls        int
}

func (receipt *fakeReceipt) load() (executionReceipt, bool, error) {
	if receipt.state == "" {
		return executionReceipt{}, false, nil
	}
	return executionReceipt{State: receipt.state, CompletionRequest: append([]byte(nil), receipt.raw...)}, true, nil
}

func (receipt *fakeReceipt) commitLaunch(request *agentv1.CoreTeamWorkerServiceCompleteRequest) error {
	if receipt.commitLaunchErr != nil {
		return receipt.commitLaunchErr
	}
	if receipt.state != "" {
		return errInput
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return err
	}
	receipt.raw = raw
	receipt.state = receiptLaunchCommitted
	return nil
}

func (receipt *fakeReceipt) commitPending(request *agentv1.CoreTeamWorkerServiceCompleteRequest) error {
	if receipt.state != receiptLaunchCommitted {
		return errInput
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return err
	}
	receipt.pending = proto.Clone(request).(*agentv1.CoreTeamWorkerServiceCompleteRequest)
	receipt.raw = raw
	receipt.state = receiptCompletionPending
	return nil
}

func (receipt *fakeReceipt) commitAcknowledged() error {
	if receipt.state != receiptCompletionPending {
		return errInput
	}
	receipt.ackCalls++
	receipt.state = receiptCompletionAcknowledged
	return nil
}

func coreDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

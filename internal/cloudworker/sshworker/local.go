package sshworker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type FileStore struct {
	root string
	mu   sync.Mutex
}

func NewFileStore(root string) (*FileStore, error) {
	if !filepath.IsAbs(root) {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{root: root}, nil
}

func (store *FileStore) LoadExecution(_ context.Context, executionID string) (ExecutionRecord, bool, error) {
	if !validID(executionID) {
		return ExecutionRecord{}, false, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	body, err := os.ReadFile(filepath.Join(store.root, "execution-"+executionID+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return ExecutionRecord{}, false, nil
	}
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	var record ExecutionRecord
	if json.Unmarshal(body, &record) != nil || record.ExecutionID != executionID || record.validate() != nil {
		return ExecutionRecord{}, false, ErrIdentity
	}
	return record, true, nil
}

func (store *FileStore) SaveExecution(_ context.Context, record ExecutionRecord) error {
	if record.validate() != nil {
		return ErrInvalid
	}
	return store.save("execution-"+record.ExecutionID+".json", record)
}

func (store *FileStore) LoadWorker(_ context.Context, workerID string) (WorkerRecord, bool, error) {
	if !validID(workerID) {
		return WorkerRecord{}, false, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	body, err := os.ReadFile(filepath.Join(store.root, "worker-"+workerID+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return WorkerRecord{}, false, nil
	}
	if err != nil {
		return WorkerRecord{}, false, err
	}
	var record WorkerRecord
	if json.Unmarshal(body, &record) != nil || record.WorkerID != workerID || record.validate() != nil {
		return WorkerRecord{}, false, ErrIdentity
	}
	return record, true, nil
}

func (store *FileStore) ListWorkers(_ context.Context) ([]WorkerRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.listWorkersLocked()
}

func (store *FileStore) listWorkersLocked() ([]WorkerRecord, error) {
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, err
	}
	result := make([]WorkerRecord, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "worker-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(store.root, entry.Name()))
		if err != nil {
			return nil, err
		}
		var worker WorkerRecord
		if json.Unmarshal(body, &worker) != nil || worker.validate() != nil || entry.Name() != "worker-"+worker.WorkerID+".json" {
			return nil, ErrIdentity
		}
		result = append(result, worker)
	}
	return result, nil
}

// ListCredentialIdentities returns the secret-free identities referenced by
// retained Worker records so the manager can reopen each exact revision.
func (store *FileStore) ListCredentialIdentities(ctx context.Context) ([]CredentialIdentity, error) {
	workers, err := store.ListWorkers(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[CredentialIdentity]struct{})
	result := make([]CredentialIdentity, 0)
	for _, worker := range workers {
		if worker.Phase == WorkerDestroyed {
			continue
		}
		if worker.Credential.validate() != nil {
			return nil, ErrIdentity
		}
		if _, ok := seen[worker.Credential]; ok {
			continue
		}
		seen[worker.Credential] = struct{}{}
		result = append(result, worker.Credential)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CredentialID != result[j].CredentialID {
			return result[i].CredentialID < result[j].CredentialID
		}
		return result[i].CredentialRevision < result[j].CredentialRevision
	})
	return result, nil
}

func (store *FileStore) HasManagedWorkers(ctx context.Context) bool {
	identities, err := store.ListCredentialIdentities(ctx)
	return err == nil && len(identities) > 0
}

func (store *FileStore) HasAnyRetainedWorkers(ctx context.Context) (bool, error) {
	workers, err := store.ListWorkers(ctx)
	if err != nil {
		return false, err
	}
	for _, worker := range workers {
		if worker.Phase != WorkerDestroyed {
			return true, nil
		}
	}
	return false, nil
}

func (store *FileStore) DeleteCredentialIfUnused(_ context.Context, credentialID string, deleteCredential func() error) (bool, error) {
	if strings.TrimSpace(credentialID) == "" || deleteCredential == nil {
		return false, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	workers, err := store.listWorkersLocked()
	if err != nil {
		return false, err
	}
	for _, worker := range workers {
		if worker.Phase != WorkerDestroyed && worker.Credential.CredentialID == credentialID {
			return true, nil
		}
	}
	return false, deleteCredential()
}

func (store *FileStore) SaveWorker(_ context.Context, record WorkerRecord) error {
	if record.validate() != nil {
		return ErrInvalid
	}
	return store.save("worker-"+record.WorkerID+".json", record)
}

func (store *FileStore) SaveWorkerIntent(ctx context.Context, record WorkerRecord, authorize func(context.Context) error) error {
	if record.validate() != nil || authorize == nil {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := authorize(ctx); err != nil {
		return err
	}
	return store.saveLocked("worker-"+record.WorkerID+".json", record)
}

func (store *FileStore) save(name string, value any) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.saveLocked(name, value)
}

func (store *FileStore) saveLocked(name string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(store.root, ".record-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filepath.Join(store.root, name))
}

type LocalKeyMaterial struct {
	root string
	mu   sync.Mutex
}

func NewLocalKeyMaterial(root string) (*LocalKeyMaterial, error) {
	if !filepath.IsAbs(root) {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &LocalKeyMaterial{root: root}, nil
}

func (keys *LocalKeyMaterial) Ensure(_ context.Context, executionID string) (string, []byte, error) {
	if !validID(executionID) {
		return "", nil, ErrInvalid
	}
	keys.mu.Lock()
	defer keys.mu.Unlock()
	directory := filepath.Join(keys.root, executionID)
	privatePath := filepath.Join(directory, "id_ed25519")
	publicPath := privatePath + ".pub"
	if privateInfo, err := os.Stat(privatePath); err == nil && privateInfo.Mode().Perm() == 0o600 {
		publicKey, readErr := os.ReadFile(publicPath)
		if readErr == nil && len(publicKey) > 0 {
			return privatePath, publicKey, nil
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", nil, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicWire := make([]byte, 4+len("ssh-ed25519")+4+len(public))
	binary.BigEndian.PutUint32(publicWire[0:4], uint32(len("ssh-ed25519")))
	copy(publicWire[4:], "ssh-ed25519")
	offset := 4 + len("ssh-ed25519")
	binary.BigEndian.PutUint32(publicWire[offset:offset+4], uint32(len(public)))
	copy(publicWire[offset+4:], public)
	authorized := []byte("ssh-ed25519 " + base64.StdEncoding.EncodeToString(publicWire) + " dirextalk-worker\n")
	if err := writeExclusive(privatePath, privatePEM, 0o600); err != nil {
		return "", nil, err
	}
	if err := writeExclusive(publicPath, authorized, 0o600); err != nil {
		os.Remove(privatePath)
		return "", nil, err
	}
	return privatePath, authorized, nil
}

func (keys *LocalKeyMaterial) LookupPrivate(_ context.Context, executionID string) (string, bool, error) {
	if !validID(executionID) {
		return "", false, ErrInvalid
	}
	privatePath := filepath.Join(keys.root, executionID, "id_ed25519")
	info, err := os.Stat(privatePath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", false, ErrInvalid
	}
	return privatePath, true, nil
}

func (keys *LocalKeyMaterial) Delete(_ context.Context, executionID string) error {
	if !validID(executionID) {
		return ErrInvalid
	}
	keys.mu.Lock()
	defer keys.mu.Unlock()
	return os.RemoveAll(filepath.Join(keys.root, executionID))
}

func writeExclusive(name string, body []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

type CommandSSHExecutor struct {
	SSHPath string
}

type CommandStatusSource struct {
	SSHPath string
	Keys    KeyMaterial
	Quote   func(context.Context, WorkerRecord) (HourlyQuote, error)
}

type remoteRuntimeStatus struct {
	Phase    string `json:"phase"`
	ExitCode int    `json:"exit_code"`
}

var errRuntimeNotStarted = errors.New("remote runtime is not started")
var errRetryableResultCollection = errors.New("retryable remote result collection failure")

const sshReadAttempts = 3

type remoteArtifact struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type remoteServerStatus struct {
	ObservedAt  time.Time `json:"observed_at"`
	LoadAverage string    `json:"load_average"`
}

type ServiceRuntimeStatus struct {
	WorkloadID  string    `json:"workload_id"`
	Kind        string    `json:"kind"`
	Phase       string    `json:"phase"`
	ActiveState string    `json:"active_state"`
	Health      string    `json:"health"`
	Port        uint16    `json:"port"`
	HealthPath  string    `json:"health_path"`
	ObservedAt  time.Time `json:"observed_at"`
}

func (source CommandStatusSource) ObserveService(ctx context.Context, worker WorkerRecord, taskID string) (ServiceRuntimeStatus, error) {
	if source.Keys == nil || worker.Instance.PublicIP == "" || !validID(taskID) {
		return ServiceRuntimeStatus{}, ErrInvalid
	}
	key, found, err := source.Keys.LookupPrivate(ctx, worker.WorkerID)
	if err != nil {
		return ServiceRuntimeStatus{}, err
	}
	if !found {
		return ServiceRuntimeStatus{}, ErrInvalid
	}
	sshPath := source.SSHPath
	if sshPath == "" {
		sshPath = "ssh"
	}
	base, err := sshBaseArguments(key, worker.SSHUser, worker.Instance.PublicIP)
	if err != nil {
		return ServiceRuntimeStatus{}, err
	}
	body, err := retrySSHOutput(ctx, sshPath, base, runnerCommand(RuntimeServiceStatus, taskID), 64<<10)
	if err != nil {
		return ServiceRuntimeStatus{}, err
	}
	var status ServiceRuntimeStatus
	if json.Unmarshal(body, &status) != nil || status.WorkloadID == "" || status.Kind != "service" || status.Port == 0 || status.ObservedAt.IsZero() {
		return ServiceRuntimeStatus{}, ErrInvalid
	}
	return status, nil
}

func (source CommandStatusSource) Observe(ctx context.Context, worker WorkerRecord) (RunnerMetrics, error) {
	if source.Keys == nil || worker.Instance.PublicIP == "" {
		return RunnerMetrics{}, ErrInvalid
	}
	key, found, err := source.Keys.LookupPrivate(ctx, worker.WorkerID)
	if err != nil {
		return RunnerMetrics{}, err
	}
	if !found {
		return RunnerMetrics{}, ErrInvalid
	}
	sshPath := source.SSHPath
	if sshPath == "" {
		sshPath = "ssh"
	}
	base, err := sshBaseArguments(key, worker.SSHUser, worker.Instance.PublicIP)
	if err != nil {
		return RunnerMetrics{}, err
	}
	body, err := retrySSHOutput(ctx, sshPath, base, runnerCommand(RuntimeServerStatus), 64<<10)
	if err != nil {
		return RunnerMetrics{}, err
	}
	var status remoteServerStatus
	if json.Unmarshal(body, &status) != nil || status.ObservedAt.IsZero() {
		return RunnerMetrics{}, ErrInvalid
	}
	loads := strings.Fields(status.LoadAverage)
	if len(loads) < 3 {
		return RunnerMetrics{}, ErrInvalid
	}
	var metrics RunnerMetrics
	metrics.LastSeen = status.ObservedAt.UTC()
	if _, err = fmt.Sscan(loads[0], &metrics.Load1); err != nil {
		return RunnerMetrics{}, ErrInvalid
	}
	if _, err = fmt.Sscan(loads[1], &metrics.Load5); err != nil {
		return RunnerMetrics{}, ErrInvalid
	}
	if _, err = fmt.Sscan(loads[2], &metrics.Load15); err != nil {
		return RunnerMetrics{}, ErrInvalid
	}
	return metrics, nil
}

func (source CommandStatusSource) HourlyQuote(ctx context.Context, worker WorkerRecord) (HourlyQuote, error) {
	if source.Quote == nil {
		return HourlyQuote{}, ErrInvalid
	}
	return source.Quote(ctx, worker)
}

func (executor CommandSSHExecutor) Execute(ctx context.Context, request SSHRequest) (ExecutionResult, error) {
	if request.Host == "" || request.User == "" || !filepath.IsAbs(request.PrivateKeyPath) ||
		len(request.WorkerScript) == 0 || !request.Runtime.valid() || request.Runtime.TaskID != request.ExecutionID ||
		request.MaxWorkspaceBytes <= 0 || request.MaxResultBytes <= 0 || request.Sink == nil || request.CollectOnly && !request.Resume {
		return ExecutionResult{}, ErrInvalid
	}
	sshPath := executor.SSHPath
	if sshPath == "" {
		sshPath = "ssh"
	}
	base, err := sshBaseArguments(request.PrivateKeyPath, request.User, request.Host)
	if err != nil {
		return ExecutionResult{}, err
	}
	taskRoot := "/tmp/dirextalk-worker/tasks/" + request.ExecutionID
	workspaceRoot := taskRoot + "/workspace"
	artifactRoot := taskRoot + "/artifacts"
	workerScript := taskRoot + "/worker.sh"
	var appliedSteerIDs []string
	if !request.Resume {
		prepare := "rm -rf -- " + shellQuote(taskRoot) + " && mkdir -p -- " + shellQuote(workspaceRoot) + " " + shellQuote(artifactRoot)
		if err := retrySSH(ctx, sshPath, base, prepare); err != nil {
			return ExecutionResult{}, err
		}
		if request.WorkspacePath != "" {
			archive, err := workspaceArchive(request.WorkspacePath, request.MaxWorkspaceBytes)
			if err != nil {
				return ExecutionResult{}, err
			}
			if err := sshWithInput(ctx, sshPath, base, "tar -xpf - -C "+shellQuote(workspaceRoot), archive); err != nil {
				return ExecutionResult{}, err
			}
		}
		if err := sshWithInput(ctx, sshPath, base, "cat > "+shellQuote(workerScript)+" && chmod 700 "+shellQuote(workerScript), bytes.NewReader(request.WorkerScript)); err != nil {
			return ExecutionResult{}, err
		}
		bootstrap := fmt.Sprintf("printf '%%s  %%s\\n' %s %s | sha256sum -c - && cd %s && /bin/bash %s",
			shellQuote(request.WorkerScriptSHA256), shellQuote(workerScript), shellQuote(workspaceRoot), shellQuote(workerScript))
		if output, err := exec.CommandContext(ctx, sshPath, append(base, bootstrap)...).CombinedOutput(); err != nil {
			return ExecutionResult{}, fmt.Errorf("worker bootstrap failed: %w: %s", err, output)
		}
		appliedSteerIDs, err = applyRuntimeGuidance(ctx, sshPath, base, taskRoot, request.ResolveGuidance)
		if err != nil {
			return ExecutionResult{}, err
		}
		if err = request.Runtime.DispatchStart(ctx, func(start RuntimeCommand) error {
			return sshWithInput(ctx, sshPath, base, start.Shell, bytes.NewReader(start.Stdin))
		}); err != nil {
			if reconcileErr := reconcileAmbiguousRuntimeStart(ctx, sshPath, base, request.Runtime, err); reconcileErr != nil {
				return ExecutionResult{}, reconcileErr
			}
		}
	}
	if request.ReportProgress != nil {
		if err := request.ReportProgress(ctx, "executing_remote_task", "Executing task on Worker"); err != nil {
			return ExecutionResult{}, errors.Join(ErrAmbiguous, err)
		}
	}
	status, err := executor.waitRuntime(ctx, sshPath, base, request.Runtime, request.ReportProgress)
	if request.Resume && !request.CollectOnly && errors.Is(err, errRuntimeNotStarted) {
		appliedSteerIDs, err = applyRuntimeGuidance(ctx, sshPath, base, taskRoot, request.ResolveGuidance)
		if err != nil {
			return ExecutionResult{}, err
		}
		startErr := request.Runtime.DispatchStart(ctx, func(start RuntimeCommand) error {
			return sshWithInput(ctx, sshPath, base, start.Shell, bytes.NewReader(start.Stdin))
		})
		if startErr != nil {
			if reconcileErr := reconcileAmbiguousRuntimeStart(ctx, sshPath, base, request.Runtime, startErr); reconcileErr != nil {
				return ExecutionResult{}, reconcileErr
			}
		}
		status, err = executor.waitRuntime(ctx, sshPath, base, request.Runtime, request.ReportProgress)
	}
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			stop, stopErr := request.Runtime.Stop()
			if stopErr == nil {
				stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
				stopErr = retrySSH(stopCtx, sshPath, base, stop.Shell)
				cancel()
			}
			if stopErr == nil {
				return ExecutionResult{}, context.Canceled
			}
			return ExecutionResult{}, errors.Join(ErrAmbiguous, ctx.Err(), stopErr)
		}
		return ExecutionResult{}, errors.Join(ErrAmbiguous, err)
	}
	if request.RecordCompletion != nil {
		if err := request.RecordCompletion(ctx); err != nil {
			return ExecutionResult{}, errors.Join(ErrAmbiguous, err)
		}
	}
	if request.ReportProgress != nil {
		if err := request.ReportProgress(ctx, "collecting_result", "Collecting Worker result and artifacts"); err != nil {
			return ExecutionResult{}, errors.Join(errRetryableResultCollection, err)
		}
	}
	logCommand, err := request.Runtime.Log(0)
	if err != nil {
		return ExecutionResult{}, err
	}
	logBody, err := retrySSHOutput(ctx, sshPath, base, logCommand.Shell, request.MaxResultBytes)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return ExecutionResult{}, err
		}
		return ExecutionResult{}, errors.Join(ErrAmbiguous, err)
	}
	if err := request.Sink.StoreText(ctx, logBody, nil, status.ExitCode); err != nil {
		return ExecutionResult{}, errors.Join(errRetryableResultCollection, err)
	}
	// Logs and artifacts consume one execution-wide result budget.
	artifactCount, err := executor.collectRuntimeArtifacts(ctx, sshPath, base, request, request.MaxResultBytes-int64(len(logBody)))
	if err != nil {
		return ExecutionResult{}, err
	}
	return ExecutionResult{Summary: strings.TrimSpace(string(logBody)), ExitCode: status.ExitCode, StdoutBytes: int64(len(logBody)), ArtifactCount: artifactCount,
		AppliedSteerIDs: append([]string(nil), appliedSteerIDs...)}, nil
}

// reconcileAmbiguousRuntimeStart never retries a start after the SSH write
// becomes uncertain. The task ID embedded in RuntimeProtocol is the cleanup
// identity used for the exact status and stop commands.
func reconcileAmbiguousRuntimeStart(ctx context.Context, sshPath string, base []string, protocol RuntimeProtocol, startErr error) error {
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	statusCommand, err := protocol.Status()
	if err != nil {
		return errors.Join(ErrAmbiguous, startErr, err)
	}
	body, err := retrySSHOutput(reconcileCtx, sshPath, base, statusCommand.Shell, 64<<10)
	if err != nil {
		return errors.Join(ErrAmbiguous, startErr, fmt.Errorf("runtime start status unavailable: %w", err))
	}
	var status remoteRuntimeStatus
	if json.Unmarshal(body, &status) != nil {
		return errors.Join(ErrAmbiguous, startErr, ErrInvalid)
	}
	switch status.Phase {
	case "running", "completed":
		return nil
	case "not_started", "failed":
		stopCommand, stopErr := protocol.Stop()
		if stopErr == nil {
			stopErr = retrySSH(reconcileCtx, sshPath, base, stopCommand.Shell)
		}
		return errors.Join(ErrAmbiguous, startErr, errRuntimeNotStarted, stopErr)
	default:
		return errors.Join(ErrAmbiguous, startErr, ErrInvalid)
	}
}

func applyRuntimeGuidance(ctx context.Context, sshPath string, base []string, taskRoot string, resolve func(context.Context) (RuntimeGuidance, error)) ([]string, error) {
	if resolve == nil {
		return nil, nil
	}
	guidance, err := resolve(ctx)
	if err != nil {
		return nil, err
	}
	if len(guidance.SteerIDs) == 0 || strings.TrimSpace(guidance.Text) == "" {
		return nil, nil
	}
	body := "\n\n[ADDITIONAL USER GUIDANCE RECEIVED BEFORE WORKER START]\n" + strings.TrimSpace(guidance.Text) + "\n[END ADDITIONAL USER GUIDANCE]\n"
	objective := taskRoot + "/objective.txt"
	baseObjective := taskRoot + "/objective.base.txt"
	guidancePath := taskRoot + "/guidance.txt"
	command := "umask 077; test -e " + shellQuote(baseObjective) + " || cp -- " + shellQuote(objective) + " " + shellQuote(baseObjective) +
		"; cat > " + shellQuote(guidancePath) + "; cat -- " + shellQuote(baseObjective) + " " + shellQuote(guidancePath) + " > " + shellQuote(objective)
	if err = sshWithInput(ctx, sshPath, base, command, strings.NewReader(body)); err != nil {
		return nil, err
	}
	return append([]string(nil), guidance.SteerIDs...), nil
}

func (executor CommandSSHExecutor) waitRuntime(ctx context.Context, sshPath string, base []string, protocol RuntimeProtocol, report func(context.Context, string, string) error) (remoteRuntimeStatus, error) {
	lastProgress := time.Now()
	for {
		command, err := protocol.Status()
		if err != nil {
			return remoteRuntimeStatus{}, err
		}
		body, err := retrySSHOutput(ctx, sshPath, base, command.Shell, 64<<10)
		if err != nil {
			return remoteRuntimeStatus{}, err
		}
		var status remoteRuntimeStatus
		if json.Unmarshal(body, &status) != nil {
			return remoteRuntimeStatus{}, ErrInvalid
		}
		switch status.Phase {
		case "completed", "failed":
			return status, nil
		case "running":
		case "not_started":
			return remoteRuntimeStatus{}, errRuntimeNotStarted
		default:
			return remoteRuntimeStatus{}, ErrInvalid
		}
		if report != nil && time.Since(lastProgress) >= runtimeProgressInterval {
			if err = report(ctx, "executing_remote_task", "Executing task on Worker"); err != nil {
				return remoteRuntimeStatus{}, err
			}
			lastProgress = time.Now()
		}
		select {
		case <-ctx.Done():
			return remoteRuntimeStatus{}, ctx.Err()
		case <-timeAfter(2):
		}
	}
}

func (executor CommandSSHExecutor) collectRuntimeArtifacts(ctx context.Context, sshPath string, base []string, request SSHRequest, maxArtifactBytes int64) (int, error) {
	if maxArtifactBytes < 0 {
		return 0, ErrResultTooLarge
	}
	listCommand, err := request.Runtime.Artifact("")
	if err != nil {
		return 0, err
	}
	body, err := retrySSHOutput(ctx, sshPath, base, listCommand.Shell, 1<<20)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return 0, err
		}
		return 0, errors.Join(ErrAmbiguous, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	count, total := 0, int64(0)
	for {
		var artifact remoteArtifact
		if err = decoder.Decode(&artifact); errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil || artifact.Size < 0 || artifact.Size > maxArtifactBytes-total {
			return count, ErrResultTooLarge
		}
		if artifact.Size == 0 {
			continue
		}
		if count >= MaxLinkedArtifacts-reservedTextArtifacts {
			return count, ErrResultTooLarge
		}
		command, commandErr := request.Runtime.Artifact(artifact.Name)
		if commandErr != nil {
			return count, commandErr
		}
		data, commandErr := retrySSHOutput(ctx, sshPath, base, command.Shell, artifact.Size)
		if commandErr != nil {
			if errors.Is(commandErr, ErrResultTooLarge) {
				return count, commandErr
			}
			return count, errors.Join(ErrAmbiguous, commandErr)
		}
		if int64(len(data)) != artifact.Size {
			return count, ErrInvalid
		}
		if err = request.Sink.StoreArtifact(ctx, artifact.Name, bytes.NewReader(data), artifact.Size); err != nil {
			return count, errors.Join(errRetryableResultCollection, err)
		}
		total += artifact.Size
		count++
	}
}

func sshBaseArguments(privateKeyPath, user, host string) ([]string, error) {
	if !filepath.IsAbs(privateKeyPath) || strings.TrimSpace(user) == "" || strings.TrimSpace(host) == "" {
		return nil, ErrInvalid
	}
	knownHostsPath := privateKeyPath + ".known_hosts"
	fd, err := unix.Open(knownHostsPath, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, ErrInvalid
	}
	return []string{"-i", privateKeyPath, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + knownHostsPath, user + "@" + host}, nil
}

func sshOutput(ctx context.Context, sshPath string, base []string, remote string, limit int64) ([]byte, error) {
	buffer := &limitBuffer{limit: limit}
	command := exec.CommandContext(ctx, sshPath, append(base, remote)...)
	command.Stdout = buffer
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("SSH command failed: %w: %s", err, stderr.String())
	}
	if buffer.exceeded {
		return nil, ErrResultTooLarge
	}
	return bytes.Clone(buffer.Bytes()), nil
}

func retrySSHOutput(ctx context.Context, sshPath string, base []string, remote string, limit int64) ([]byte, error) {
	var last error
	for attempt := 0; attempt < sshReadAttempts; attempt++ {
		body, err := sshOutput(ctx, sshPath, base, remote, limit)
		if err == nil {
			return body, nil
		}
		last = err
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, ErrResultTooLarge) || attempt == sshReadAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeAfter(1):
		}
	}
	return nil, last
}

func retrySSH(ctx context.Context, sshPath string, base []string, remote string) error {
	var last error
	for attempt := 0; attempt < 12; attempt++ {
		command := exec.CommandContext(ctx, sshPath, append(base, remote)...)
		if output, err := command.CombinedOutput(); err == nil {
			return nil
		} else {
			last = fmt.Errorf("SSH not ready: %w: %s", err, string(output))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeAfter(5):
		}
	}
	return last
}

var timeAfter = func(seconds int) <-chan time.Time { return time.After(time.Duration(seconds) * time.Second) }
var runtimeProgressInterval = 15 * time.Second

func sshWithInput(ctx context.Context, sshPath string, base []string, remote string, input io.Reader) error {
	command := exec.CommandContext(ctx, sshPath, append(base, remote)...)
	command.Stdin = input
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SSH transfer failed: %w: %s", err, string(output))
	}
	return nil
}

func workspaceArchive(root string, limit int64) (io.Reader, error) {
	var body bytes.Buffer
	written := int64(0)
	writer := tar.NewWriter(&body)
	paths := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil, ErrInvalid
		}
		relative, _ := filepath.Rel(root, path)
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil, err
		}
		header.Name = filepath.ToSlash(relative)
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if info.Mode().IsRegular() {
			written += info.Size()
			if written > limit {
				return nil, ErrResultTooLarge
			}
			file, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			_, copyErr := io.Copy(writer, file)
			file.Close()
			if copyErr != nil {
				return nil, copyErr
			}
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(body.Bytes()), nil
}

type limitBuffer struct {
	bytes.Buffer
	limit    int64
	exceeded bool
}

func (buffer *limitBuffer) Write(body []byte) (int, error) {
	accepted := body
	remaining := buffer.limit - int64(buffer.Len())
	if int64(len(body)) > remaining {
		buffer.exceeded = true
		if remaining < 0 {
			remaining = 0
		}
		accepted = body[:remaining]
	}
	_, _ = buffer.Buffer.Write(accepted)
	return len(body), nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

var _ Store = (*FileStore)(nil)
var _ KeyMaterial = (*LocalKeyMaterial)(nil)
var _ SSHExecutor = CommandSSHExecutor{}
var _ StatusSource = CommandStatusSource{}

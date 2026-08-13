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
	if json.Unmarshal(body, &record) != nil || record.ExecutionID != executionID {
		return ExecutionRecord{}, false, ErrIdentity
	}
	return record, true, nil
}

func (store *FileStore) SaveExecution(_ context.Context, record ExecutionRecord) error {
	if !validID(record.ExecutionID) {
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
	if json.Unmarshal(body, &record) != nil || record.WorkerID != workerID {
		return WorkerRecord{}, false, ErrIdentity
	}
	return record, true, nil
}

func (store *FileStore) ListWorkers(_ context.Context, credential CredentialIdentity) ([]WorkerRecord, error) {
	if credential.validate() != nil {
		return nil, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
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
		if json.Unmarshal(body, &worker) != nil {
			return nil, ErrIdentity
		}
		if worker.Credential == credential {
			result = append(result, worker)
		}
	}
	return result, nil
}

func (store *FileStore) SaveWorker(_ context.Context, record WorkerRecord) error {
	if !validID(record.WorkerID) {
		return ErrInvalid
	}
	return store.save("worker-"+record.WorkerID+".json", record)
}

func (store *FileStore) save(name string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
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

func (executor CommandSSHExecutor) Execute(ctx context.Context, request SSHRequest) (ExecutionResult, error) {
	if request.Host == "" || request.User == "" || !filepath.IsAbs(request.PrivateKeyPath) ||
		len(request.WorkerScript) == 0 || request.MaxWorkspaceBytes <= 0 || request.MaxResultBytes <= 0 || request.Sink == nil {
		return ExecutionResult{}, ErrInvalid
	}
	sshPath := executor.SSHPath
	if sshPath == "" {
		sshPath = "ssh"
	}
	knownHosts, err := os.CreateTemp("", "dirextalk-worker-known-hosts-*")
	if err != nil {
		return ExecutionResult{}, err
	}
	knownHosts.Close()
	defer os.Remove(knownHosts.Name())
	base := []string{"-i", request.PrivateKeyPath, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
		"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + knownHosts.Name(), request.User + "@" + request.Host}
	if err := retrySSH(ctx, sshPath, base, "mkdir -p -- /tmp/dirextalk-worker/workspace /tmp/dirextalk-worker/artifacts"); err != nil {
		return ExecutionResult{}, err
	}
	if request.WorkspacePath != "" {
		archive, err := workspaceArchive(request.WorkspacePath, request.MaxWorkspaceBytes)
		if err != nil {
			return ExecutionResult{}, err
		}
		if err := sshWithInput(ctx, sshPath, base, "tar -xpf - -C /tmp/dirextalk-worker/workspace", archive); err != nil {
			return ExecutionResult{}, err
		}
	}
	if err := sshWithInput(ctx, sshPath, base, "cat > /tmp/dirextalk-worker/worker.sh && chmod 700 /tmp/dirextalk-worker/worker.sh", bytes.NewReader(request.WorkerScript)); err != nil {
		return ExecutionResult{}, err
	}
	command := fmt.Sprintf("printf '%%s  %%s\\n' %s /tmp/dirextalk-worker/worker.sh | sha256sum -c - && cd /tmp/dirextalk-worker/workspace && /bin/bash /tmp/dirextalk-worker/worker.sh",
		shellQuote(request.WorkerScriptSHA256))
	stdout := &limitBuffer{limit: request.MaxResultBytes}
	stderr := &limitBuffer{limit: request.MaxResultBytes}
	process := exec.CommandContext(ctx, sshPath, append(base, command)...)
	process.Stdout, process.Stderr = stdout, stderr
	runErr := process.Run()
	exitCode := 0
	if runErr != nil {
		var exitError *exec.ExitError
		if errors.As(runErr, &exitError) {
			exitCode = exitError.ExitCode()
		} else {
			return ExecutionResult{}, runErr
		}
	}
	if stdout.exceeded || stderr.exceeded {
		return ExecutionResult{}, ErrResultTooLarge
	}
	if err := request.Sink.StoreText(ctx, stdout.Bytes(), stderr.Bytes(), exitCode); err != nil {
		return ExecutionResult{}, err
	}
	artifactCount, err := executor.collectArtifacts(ctx, sshPath, base, request)
	if err != nil {
		return ExecutionResult{}, err
	}
	return ExecutionResult{ExitCode: exitCode, StdoutBytes: int64(stdout.Len()), StderrBytes: int64(stderr.Len()), ArtifactCount: artifactCount}, nil
}

func (executor CommandSSHExecutor) collectArtifacts(ctx context.Context, sshPath string, base []string, request SSHRequest) (int, error) {
	command := exec.CommandContext(ctx, sshPath, append(base, "tar -cf - -C /tmp/dirextalk-worker/artifacts .")...)
	pipe, err := command.StdoutPipe()
	if err != nil {
		return 0, err
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return 0, err
	}
	reader := tar.NewReader(io.LimitReader(pipe, request.MaxResultBytes+(2<<20)))
	total := int64(0)
	count := 0
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			command.Wait()
			return count, err
		}
		entries++
		if entries > 1024 {
			command.Wait()
			return count, ErrResultTooLarge
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		if header.Typeflag != tar.TypeReg || clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) || header.Size < 0 || total+header.Size > request.MaxResultBytes {
			command.Wait()
			return count, ErrResultTooLarge
		}
		if err := request.Sink.StoreArtifact(ctx, clean, io.LimitReader(reader, header.Size), header.Size); err != nil {
			command.Wait()
			return count, err
		}
		total += header.Size
		count++
	}
	if err := command.Wait(); err != nil {
		return count, fmt.Errorf("artifact collection failed: %w: %s", err, stderr.String())
	}
	return count, nil
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

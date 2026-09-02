package sshworker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconcileServiceExposureScriptIsValidBash(t *testing.T) {
	if strings.Contains(reconcileServiceExposureScript, "apt-get") {
		t.Fatal("service exposure must rely on the worker image tool baseline")
	}
	if !strings.Contains(reconcileServiceExposureScript, "worker image is missing the required caddy baseline") {
		t.Fatal("service exposure must report a missing image tool baseline")
	}
	path := filepath.Join(t.TempDir(), "reconcile-service-exposure.sh")
	if err := os.WriteFile(path, []byte(reconcileServiceExposureScript), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("exposure script is invalid: %v: %s", err, output)
	}
}

func TestCommandStatusSourceReconcilesExactExposureOverPinnedSSH(t *testing.T) {
	root := t.TempDir()
	argumentsPath := filepath.Join(root, "arguments")
	inputPath := filepath.Join(root, "input")
	sshPath := filepath.Join(root, "ssh")
	sshStub := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\n/bin/cat > %s\n", shellQuote(argumentsPath), shellQuote(inputPath))
	if err := os.WriteFile(sshPath, []byte(sshStub), 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := &fakeKeys{path: keyPath}
	source := CommandStatusSource{SSHPath: sshPath, Keys: keys}
	worker := WorkerRecord{WorkerID: "worker-a", SSHUser: "ubuntu", Instance: Instance{PublicIP: "203.0.113.10"}}
	exposure := ServiceExposure{WorkloadID: "gitea-svc", Hostname: "GITEA.EXAMPLE.TEST.", Port: 3000}
	if err := source.ReconcileServiceExposure(context.Background(), worker, exposure); err != nil {
		t.Fatal(err)
	}
	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(arguments), "StrictHostKeyChecking=accept-new") ||
		!strings.Contains(string(arguments), "bash -s -- 'gitea-svc' 'gitea.example.test' '3000'") {
		t.Fatalf("SSH arguments=%q", arguments)
	}
	input, err := os.ReadFile(inputPath)
	if err != nil || !bytes.Equal(input, []byte(reconcileServiceExposureScript)) {
		t.Fatalf("remote script mismatch err=%v", err)
	}
	if keys.ensure != 0 || keys.lookup != 1 {
		t.Fatalf("exposure reconciliation mutated key material: ensure=%d lookup=%d", keys.ensure, keys.lookup)
	}
}

func TestCommandStatusSourceRejectsInvalidExposureBeforeSSH(t *testing.T) {
	keys := &fakeKeys{}
	source := CommandStatusSource{SSHPath: filepath.Join(t.TempDir(), "missing-ssh"), Keys: keys}
	worker := WorkerRecord{WorkerID: "worker-a", SSHUser: "ubuntu", Instance: Instance{PublicIP: "203.0.113.10"}}
	if err := source.ReconcileServiceExposure(context.Background(), worker,
		ServiceExposure{WorkloadID: "../other", Hostname: "app.example.test", Port: 3000}); err != ErrInvalid {
		t.Fatalf("invalid exposure error=%v", err)
	}
	if keys.lookup != 0 {
		t.Fatalf("invalid exposure reached key lookup: %d", keys.lookup)
	}
}

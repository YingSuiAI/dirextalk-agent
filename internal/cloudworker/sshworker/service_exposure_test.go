package sshworker

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
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

func TestExposureAdoptsOnlyUnmodifiedPackageConfigurationThroughSSH(t *testing.T) {
	const stock = "# Caddy package example\n:80 {\n file_server\n}\n"
	for _, mode := range []string{"stock", "managed", "custom", "package-query-failed", "reload-failed"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			etc := filepath.Join(root, "caddy")
			bin := filepath.Join(root, "bin")
			for _, path := range []string{etc, bin} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, body string, perm os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), perm); err != nil {
					t.Fatal(err)
				}
			}
			original := stock
			if mode == "custom" {
				original += "# user-customized route\n"
			}
			if mode == "managed" {
				original = "# Managed by Dirextalk Agent\nimport /etc/caddy/dirextalk/*.caddy\n"
			}
			main := filepath.Join(etc, "Caddyfile")
			write(main, original, 0600)
			write(filepath.Join(bin, "sudo"), "#!/bin/sh\nexec \"$@\"\n", 0700)
			caddy := "#!/bin/sh\nexit 0\n"
			if mode == "reload-failed" {
				caddy = "#!/bin/sh\n[ \"$1\" != reload ]\n"
			}
			write(filepath.Join(bin, "caddy"), caddy, 0700)
			write(filepath.Join(bin, "systemctl"), "#!/bin/sh\nexit 0\n", 0700)
			query := fmt.Sprintf("#!/bin/sh\nprintf ' %%s %%s\\n' %s %s\n", shellQuote(main), shellQuote(fmt.Sprintf("%x", md5.Sum([]byte(stock)))))
			if mode == "package-query-failed" {
				query = "#!/bin/sh\nexit 2\n"
			}
			write(filepath.Join(bin, "dpkg-query"), query, 0700)
			// The production SSH consumer forwards the actual fixed script.
			ssh := filepath.Join(bin, "ssh")
			write(ssh, "#!/bin/bash\nremote=\"${!#}\"\nsed "+shellQuote("s@/etc/caddy@"+etc+"@g")+" | /bin/bash -c \"$remote\"\n", 0700)
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			key := filepath.Join(root, "key")
			write(key, "test", 0600)
			err := (CommandStatusSource{SSHPath: ssh, Keys: &fakeKeys{path: key}}).ReconcileServiceExposure(context.Background(), WorkerRecord{WorkerID: "worker-a", SSHUser: "ubuntu", Instance: Instance{PublicIP: "203.0.113.10"}}, ServiceExposure{WorkloadID: "gitea", Hostname: "ge.example.test", Port: 3000})
			if mode == "custom" && !errors.Is(err, ErrUnmanagedCaddyConfig) {
				t.Fatalf("custom config classification: %v", err)
			}
			if mode == "package-query-failed" && !errors.Is(err, ErrCaddyBaselineUnavailable) {
				t.Fatalf("baseline read failure classification: %v", err)
			}
			body, readErr := os.ReadFile(main)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if mode == "stock" || mode == "managed" {
				if err != nil || !bytes.Contains(body, []byte("# Managed by Dirextalk Agent")) {
					t.Fatalf("stock/managed adoption failed: %v", err)
				}
				fragment, e := os.ReadFile(filepath.Join(etc, "dirextalk", "gitea.caddy"))
				if e != nil || !bytes.Contains(fragment, []byte("ge.example.test")) {
					t.Fatal("missing managed route")
				}
			} else if err == nil || string(body) != original {
				t.Fatalf("unsafe config change mode=%s err=%v body=%q", mode, err, body)
			}
		})
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

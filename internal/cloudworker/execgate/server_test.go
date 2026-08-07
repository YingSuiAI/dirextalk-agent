package execgate

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestExecutableDecisionAllowsPinnedPiOnceAndOrdinaryTools(t *testing.T) {
	pinned := fileIdentity{Device: 1, Inode: 10, SHA256: strings.Repeat("1", 64)}
	launchStat := processStatValue{ParentPID: 100, ProcessGroup: 200, StartTimeTicks: 300}
	if decision := decideExecutable(0, 100, pinned, pinned, launchStat, 200); !decision.launch || decision.violation != "" {
		t.Fatalf("first pinned Pi decision = %+v", decision)
	}
	ordinary := fileIdentity{Device: 1, Inode: 20, SHA256: strings.Repeat("2", 64)}
	if decision := decideExecutable(1, 100, pinned, ordinary, processStatValue{}, 201); decision.launch || decision.violation != "" {
		t.Fatalf("ordinary tool decision = %+v", decision)
	}
	if decision := decideExecutable(1, 100, pinned, pinned, processStatValue{}, 202); decision.violation != "duplicate_pi_exec" {
		t.Fatalf("same-inode duplicate decision = %+v", decision)
	}
	copyIdentity := fileIdentity{Device: 9, Inode: 99, SHA256: pinned.SHA256}
	if decision := decideExecutable(1, 100, pinned, copyIdentity, processStatValue{}, 203); decision.violation != "duplicate_pi_exec" {
		t.Fatalf("same-digest copy decision = %+v", decision)
	}
}

func TestExecutableDecisionRejectsSameNameReplacementBeforeBearerExec(t *testing.T) {
	pinned := fileIdentity{Device: 1, Inode: 10, SHA256: strings.Repeat("1", 64)}
	replacement := fileIdentity{Device: 1, Inode: 11, SHA256: strings.Repeat("2", 64)}
	decision := decideExecutable(0, 100, pinned, replacement,
		processStatValue{ParentPID: 100, ProcessGroup: 200, StartTimeTicks: 300}, 200)
	if decision.launch || decision.violation != "initial_pi_identity_mismatch" {
		t.Fatalf("replacement decision = %+v", decision)
	}
}

func TestPinnedPiExecutableBoundaryBlocksReadableLoaderInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pi")
	if err := os.WriteFile(path, []byte("pinned-pi"), 0o551); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !piExecutableBoundary(info, stat.Uid, stat.Gid) {
		t.Fatal("exact execute-only Pi boundary was rejected")
	}
	if piExecutableBoundary(info, stat.Uid+1, stat.Gid) ||
		piExecutableBoundary(info, stat.Uid, stat.Gid+1) {
		t.Fatal("Pi owner or Worker-readable group drift was accepted")
	}

	for name, mutate := range map[string]func() error{
		"Pi-readable mode": func() error { return os.Chmod(path, 0o555) },
		"writable mode":    func() error { return os.Chmod(path, 0o571) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); err != nil {
				t.Fatal(err)
			}
			drifted, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if piExecutableBoundary(drifted, stat.Uid, stat.Gid) {
				t.Fatal("unsafe Pi mode was accepted")
			}
			if err := os.Chmod(path, 0o551); err != nil {
				t.Fatal(err)
			}
		})
	}

	link := filepath.Join(filepath.Dir(path), "pi-hardlink")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	linked, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if piExecutableBoundary(linked, stat.Uid, stat.Gid) {
		t.Fatal("hard-linked Pi executable was accepted")
	}
}

func TestUnixPeerCredentialUsesKernelIdentity(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		defer connection.Close()
		credential, credentialErr := unixPeerCredential(connection)
		if credentialErr == nil && (credential.Pid != int32(os.Getpid()) || credential.Uid != uint32(os.Geteuid())) {
			credentialErr = ErrViolation
		}
		result <- credentialErr
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestProcessStatAndCgroupBindBootProcessIdentity(t *testing.T) {
	pid := int32(os.Getpid())
	stat, err := processStat(pid)
	if err != nil || stat.StartTimeTicks == 0 || stat.ProcessGroup < 1 {
		t.Fatalf("process stat = %+v err=%v", stat, err)
	}
	raw, digest, err := processCgroup(pid)
	if err != nil || raw == "" || !validDigest(digest) {
		t.Fatalf("process cgroup raw=%q digest=%q err=%v", raw, digest, err)
	}
}

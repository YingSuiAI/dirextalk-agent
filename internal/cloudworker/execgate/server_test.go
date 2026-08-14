package execgate

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecutableDecisionAllowsUnlimitedPinnedPiAndOrdinaryTools(t *testing.T) {
	pinned := fileIdentity{Device: 1, Inode: 10, SHA256: strings.Repeat("1", 64)}
	launchStat := processStatValue{ParentPID: 100, ProcessGroup: 200, StartTimeTicks: 300}
	if decision := decideExecutable(0, 100, pinned, pinned, launchStat, 200); !decision.launch || decision.violation != "" {
		t.Fatalf("first pinned Pi decision = %+v", decision)
	}
	ordinary := fileIdentity{Device: 1, Inode: 20, SHA256: strings.Repeat("2", 64)}
	if decision := decideExecutable(1, 100, pinned, ordinary, processStatValue{}, 201); decision.launch || decision.violation != "" {
		t.Fatalf("ordinary tool decision = %+v", decision)
	}
	if decision := decideExecutable(1, 100, pinned, pinned, processStatValue{}, 202); !decision.launch || decision.violation != "" {
		t.Fatalf("authorized child Pi decision = %+v", decision)
	}
	copyIdentity := fileIdentity{Device: 9, Inode: 99, SHA256: pinned.SHA256}
	if decision := decideExecutable(2, 100, pinned, copyIdentity, processStatValue{}, 204); decision.violation != "pi_exec_identity_mismatch" {
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

func TestMonitorTopologyAllowsOnlyBoundedPreActivationImageTransition(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	current := &policy{
		authorizedPiExecs: 1,
		createdAt:         now,
		pi: ProcessIdentity{
			PID: 200, StartTimeTicks: 300, Device: 1, Inode: 20,
			SHA256: strings.Repeat("2", 64),
		},
	}
	if violation := monitorTopologyViolation(
		current, now.Add(time.Second), 2, 0, 2, nil, false,
	); violation != "" {
		t.Fatalf("pre-activation Worker-to-Pi image transition violation=%q", violation)
	}
	if violation := monitorTopologyViolation(
		current, now.Add(time.Second), 1, 1, 2, nil, true,
	); violation != "" {
		t.Fatalf("visible Pi image before Active proof violation=%q", violation)
	}

	current.activeProof = true
	if violation := monitorTopologyViolation(
		current, now.Add(2*preActivationLifetime), 2, 0, 2, nil, false,
	); violation != "runtime_topology_invalid" {
		t.Fatalf("post-Active transition violation=%q", violation)
	}

	current.activeProof = false
	if violation := monitorTopologyViolation(
		current, now.Add(preActivationLifetime), 2, 0, 2, nil, false,
	); violation != "pre_activation_expired" {
		t.Fatalf("expired transition violation=%q", violation)
	}
	if violation := monitorTopologyViolation(
		current, now.Add(time.Second), 2, 0, 2, errors.New("scan failed"), false,
	); violation != "runtime_topology_invalid" {
		t.Fatalf("failed scan violation=%q", violation)
	}
}

func TestPiProcessTreeAllowsUnlimitedTaskCgroupAgentsAndForkTransitions(t *testing.T) {
	piIdentity := func(pid int32, started uint64) ProcessIdentity {
		return ProcessIdentity{
			PID: pid, StartTimeTicks: started, Device: 1, Inode: 20,
			SHA256: strings.Repeat("2", 64),
		}
	}
	current := &policy{
		workerPID:         100,
		activeProof:       true,
		authorizedPiExecs: 4,
		piPinned:          fileIdentity{Device: 1, Inode: 20, SHA256: strings.Repeat("2", 64)},
		pi:                piIdentity(200, 300),
	}
	members := []int32{100, 200, 201, 202, 203, 204, 205}
	// PID 202 models a forked Pi image observed before its ordinary tool exec
	// completes. It is valid even though it did not increment the Pi exec audit.
	piProcesses := []ProcessIdentity{
		piIdentity(200, 300), piIdentity(201, 301), piIdentity(202, 302),
		piIdentity(204, 304), piIdentity(205, 305),
	}
	if violation := piProcessTreeViolation(current, 1, 5, 7, members, piProcesses, nil); violation != "" {
		t.Fatalf("valid nested Pi Agent process tree was rejected: %s", violation)
	}
	if violation := monitorTopologyViolation(
		current, time.Now().UTC(), 1, 5, 7, nil, true,
	); violation != "" {
		t.Fatalf("valid nested Pi Agent topology violation=%q", violation)
	}

	copied := ProcessIdentity{
		PID: 206, StartTimeTicks: 306, Device: 9, Inode: 99,
		SHA256: current.piPinned.SHA256,
	}
	if violation := piProcessTreeViolation(current, 1, 6, 8, append(members, 206), append(piProcesses, copied), nil); violation != "pi_identity_mismatch" {
		t.Fatalf("same-digest Pi executable copy violation=%q", violation)
	}

	rootlessMembers := []int32{100, 201, 202, 203, 204, 205}
	rootlessPi := []ProcessIdentity{
		piIdentity(201, 301), piIdentity(202, 302),
		piIdentity(204, 304), piIdentity(205, 305),
	}
	if violation := piProcessTreeViolation(current, 1, 4, 6, rootlessMembers, rootlessPi, nil); violation != "" {
		t.Fatalf("authorized child Agent tree was rejected after root Pi exited: %s", violation)
	}
}

func TestPermissionEventRejectsExpiredOrViolatedPolicy(t *testing.T) {
	raw, digest, err := processCgroup(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	allowed := true
	server := &Server{policies: map[string]*policy{
		"run": {
			cgroupRaw: raw, cgroupDigest: digest,
			violation: "pre_activation_expired",
		},
	}}
	server.handlePermissionEvent(permissionEvent{
		PID: int32(os.Getpid()), File: file,
		done: func(value bool) error {
			allowed = value
			return nil
		},
	})
	if allowed {
		t.Fatal("violated policy allowed a later Pi execution")
	}
}

func TestActiveDescendantsDrainWithoutLocalLifetimeLimit(t *testing.T) {
	now := time.Date(2026, 8, 11, 1, 0, 0, 0, time.UTC)
	validPi := ProcessIdentity{
		PID: 200, StartTimeTicks: 300, Device: 1, Inode: 20,
		SHA256: strings.Repeat("2", 64),
	}
	current := &policy{
		activeProof: true, authorizedPiExecs: 1, pi: validPi,
	}
	if violation := monitorTopologyViolation(
		current, now, 1, 0, 3, nil, false,
	); violation != "" {
		t.Fatalf("initial descendant drain violation=%q", violation)
	}
	if violation := monitorTopologyViolation(
		current, now.Add(24*time.Hour), 1, 0, 2, nil, false,
	); violation != "" {
		t.Fatalf("long-running descendant drain violation=%q", violation)
	}
	if violation := monitorTopologyViolation(
		current, now.Add(7*24*time.Hour), 1, 0, 1, nil, false,
	); violation != "" {
		t.Fatalf("fully drained topology violation=%q", violation)
	}

	for _, test := range []struct {
		name                          string
		active                        bool
		workerCount, piCount, cgCount uint32
		scanErr                       error
	}{
		{name: "unauthorized Pi", active: true, workerCount: 1, piCount: 2, cgCount: 3},
		{name: "missing Worker", active: true, piCount: 0, cgCount: 2},
		{name: "scan error", active: true, workerCount: 1, cgCount: 2, scanErr: errors.New("scan failed")},
		{name: "not activated", workerCount: 1, cgCount: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := &policy{
				activeProof: test.active, authorizedPiExecs: 1,
				createdAt: now, pi: validPi,
			}
			if violation := monitorTopologyViolation(
				candidate, now, test.workerCount, test.piCount,
				test.cgCount, test.scanErr, false,
			); violation != "runtime_topology_invalid" {
				t.Fatalf("violation=%q", violation)
			}
		})
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

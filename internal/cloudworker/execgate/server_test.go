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

func TestExecutableDecisionAllowsPinnedPiProcessTreeAndOrdinaryTools(t *testing.T) {
	pinned := fileIdentity{Device: 1, Inode: 10, SHA256: strings.Repeat("1", 64)}
	launchStat := processStatValue{ParentPID: 100, ProcessGroup: 200, StartTimeTicks: 300}
	if decision := decideExecutable(0, 100, pinned, pinned, launchStat, 200, false); !decision.launch || decision.violation != "" {
		t.Fatalf("first pinned Pi decision = %+v", decision)
	}
	ordinary := fileIdentity{Device: 1, Inode: 20, SHA256: strings.Repeat("2", 64)}
	if decision := decideExecutable(1, 100, pinned, ordinary, processStatValue{}, 201, true); decision.launch || decision.violation != "" {
		t.Fatalf("ordinary tool decision = %+v", decision)
	}
	if decision := decideExecutable(1, 100, pinned, pinned, processStatValue{}, 202, true); !decision.launch || decision.violation != "" {
		t.Fatalf("authorized child Pi decision = %+v", decision)
	}
	if decision := decideExecutable(2, 100, pinned, pinned, processStatValue{}, 203, false); decision.violation != "pi_exec_outside_authorized_tree" {
		t.Fatalf("unrelated pinned Pi decision = %+v", decision)
	}
	copyIdentity := fileIdentity{Device: 9, Inode: 99, SHA256: pinned.SHA256}
	if decision := decideExecutable(2, 100, pinned, copyIdentity, processStatValue{}, 204, true); decision.violation != "pi_exec_identity_mismatch" {
		t.Fatalf("same-digest copy decision = %+v", decision)
	}
}

func TestExecutableDecisionRejectsSameNameReplacementBeforeBearerExec(t *testing.T) {
	pinned := fileIdentity{Device: 1, Inode: 10, SHA256: strings.Repeat("1", 64)}
	replacement := fileIdentity{Device: 1, Inode: 11, SHA256: strings.Repeat("2", 64)}
	decision := decideExecutable(0, 100, pinned, replacement,
		processStatValue{ParentPID: 100, ProcessGroup: 200, StartTimeTicks: 300}, 200, false)
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

func TestPiProcessTreeAllowsUnlimitedNestedAgents(t *testing.T) {
	current := &policy{
		workerPID:         100,
		activeProof:       true,
		authorizedPiExecs: 4,
		pi: ProcessIdentity{
			PID: 200, StartTimeTicks: 300, Device: 1, Inode: 20,
			SHA256: strings.Repeat("2", 64),
		},
	}
	parents := map[int32]processStatValue{
		100: {ParentPID: 1, StartTimeTicks: 100},
		200: {ParentPID: 100, StartTimeTicks: 300},
		201: {ParentPID: 200, StartTimeTicks: 301},
		202: {ParentPID: 201, StartTimeTicks: 302},
		203: {ParentPID: 202, StartTimeTicks: 303},
		204: {ParentPID: 203, StartTimeTicks: 304},
		205: {ParentPID: 200, StartTimeTicks: 305},
	}
	stat := func(pid int32) (processStatValue, error) {
		value, ok := parents[pid]
		if !ok {
			return processStatValue{}, ErrUnavailable
		}
		return value, nil
	}
	members := []int32{100, 200, 201, 202, 203, 204, 205}
	piMembers := []int32{200, 201, 204, 205}
	if !piProcessTreeValid(current, 1, 4, 7, members, piMembers, nil, stat) {
		t.Fatal("valid nested Pi Agent process tree was rejected")
	}
	memberSet := make(map[int32]bool, len(members))
	for _, pid := range members {
		memberSet[pid] = true
	}
	member := func(pid int32) bool { return memberSet[pid] }
	if !piExecCallerAuthorized(
		current, 204, parents[204], stat, member,
	) {
		t.Fatal("nested Pi Agent exec caller was rejected")
	}
	if violation := monitorTopologyViolation(
		current, time.Now().UTC(), 1, 4, 7, nil, true,
	); violation != "" {
		t.Fatalf("valid nested Pi Agent topology violation=%q", violation)
	}

	parents[206] = processStatValue{ParentPID: 100, StartTimeTicks: 306}
	for _, pid := range []int32{206} {
		members = append(members, pid)
		memberSet[pid] = true
	}
	if piProcessTreeValid(current, 1, 5, 8, members, append(piMembers, 206), nil, stat) {
		t.Fatal("Pi process outside the authorized root tree was accepted")
	}
	if piExecCallerAuthorized(current, 206, parents[206], stat, member) {
		t.Fatal("unrelated Pi exec caller was accepted")
	}
	parents[201] = processStatValue{ParentPID: 202, StartTimeTicks: 301}
	parents[202] = processStatValue{ParentPID: 201, StartTimeTicks: 302}
	if piProcessTreeValid(current, 1, 4, 7, members[:7], piMembers, nil, stat) {
		t.Fatal("cyclic process ancestry was accepted")
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

func TestActiveQuiescenceIsBoundedAndRejectsOtherTopologyDrift(t *testing.T) {
	now := time.Date(2026, 8, 11, 1, 0, 0, 0, time.UTC)
	validPi := ProcessIdentity{
		PID: 200, StartTimeTicks: 300, Device: 1, Inode: 20,
		SHA256: strings.Repeat("2", 64),
	}
	current := &policy{activeProof: true, authorizedPiExecs: 1, pi: validPi}
	waiting, expired := activeQuiescenceState(current, now, 1, 0, 3, nil)
	if !waiting || expired {
		t.Fatalf("initial quiescence waiting=%t expired=%t", waiting, expired)
	}
	if violation := monitorTopologyViolation(
		current, now, 1, 0, 3, nil, false,
	); violation != "" {
		t.Fatalf("initial active quiescence violation=%q", violation)
	}
	if current.quiescenceAt != now {
		t.Fatalf("quiescence start=%s want=%s", current.quiescenceAt, now)
	}
	if violation := monitorTopologyViolation(
		current, now.Add(terminalQuiescenceLimit-time.Nanosecond), 1, 0, 2, nil, false,
	); violation != "" {
		t.Fatalf("bounded active quiescence violation=%q", violation)
	}
	if violation := monitorTopologyViolation(
		current, now.Add(terminalQuiescenceLimit), 1, 0, 2, nil, false,
	); violation != "runtime_topology_invalid" {
		t.Fatalf("expired active quiescence violation=%q", violation)
	}
	waiting, expired = activeQuiescenceState(
		current, now.Add(terminalQuiescenceLimit), 1, 0, 2, nil,
	)
	if waiting || !expired {
		t.Fatalf("expired quiescence waiting=%t expired=%t", waiting, expired)
	}

	for _, test := range []struct {
		name                          string
		active                        bool
		workerCount, piCount, cgCount uint32
		scanErr                       error
	}{
		{name: "multiple Pi", active: true, workerCount: 1, piCount: 2, cgCount: 3},
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

package execgate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	DefaultWorkerUID uint32 = 65531
	DefaultPiUID     uint32 = 65532

	defaultWorkerExecutable = "/usr/local/bin/dirextalk-cloud-worker"
	defaultPiExecutable     = "/usr/local/lib/dirextalk-cloud-worker/pi/pi"
	preActivationLifetime   = 5 * time.Second
	terminalQuiescenceLimit = time.Second
)

type Config struct {
	SocketPath       string
	WorkerUID        uint32
	SocketGID        uint32
	WorkerExecutable string
	PiExecutable     string
	MonitorInterval  time.Duration
	Now              func() time.Time
}

func DefaultConfig() Config {
	return Config{
		SocketPath: DefaultSocketPath, WorkerUID: DefaultWorkerUID, SocketGID: DefaultWorkerUID,
		WorkerExecutable: defaultWorkerExecutable, PiExecutable: defaultPiExecutable,
		MonitorInterval: 100 * time.Millisecond,
		Now:             func() time.Time { return time.Now().UTC() },
	}
}

type permissionEvent struct {
	PID  int32
	File *os.File
	done func(bool) error
}

func (event *permissionEvent) respond(allow bool) error {
	if event == nil || event.done == nil {
		return ErrInvalid
	}
	err := event.done(allow)
	event.done = nil
	return err
}

type permissionMonitor interface {
	Events() <-chan permissionEvent
	Errors() <-chan error
	Close() error
}

type Server struct {
	config  Config
	monitor permissionMonitor
	bootID  string

	mu       sync.Mutex
	policies map[string]*policy
}

type policy struct {
	runID        string
	registration Registration
	workerPID    int32
	worker       ProcessIdentity
	cgroupRaw    string
	cgroupDigest string
	piPinned     fileIdentity
	policyDigest string
	pi           ProcessIdentity
	totalAllowed uint32
	activeProof  bool
	quiescenceAt time.Time
	terminal     *Proof
	violation    string
	createdAt    time.Time
}

type fileIdentity struct {
	Device uint64
	Inode  uint64
	SHA256 string
}

func NewServer(config Config) (*Server, error) {
	if config.WorkerUID == 0 || config.SocketGID == 0 || !cleanAbsolute(config.SocketPath) ||
		!cleanAbsolute(config.WorkerExecutable) || !cleanAbsolute(config.PiExecutable) ||
		config.MonitorInterval < 10*time.Millisecond || config.MonitorInterval > time.Second ||
		config.Now == nil {
		return nil, ErrInvalid
	}
	bootIDRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, ErrUnavailable
	}
	bootID := strings.TrimSpace(string(bootIDRaw))
	clear(bootIDRaw)
	if !canonicalUUID(bootID) {
		return nil, ErrUnavailable
	}
	monitor, err := newPermissionMonitor(config.PiExecutable)
	if err != nil {
		return nil, err
	}
	return &Server{config: config, monitor: monitor, bootID: bootID, policies: make(map[string]*policy)}, nil
}

func (server *Server) Close() error {
	if server == nil || server.monitor == nil {
		return nil
	}
	return server.monitor.Close()
}

func (server *Server) Serve(ctx context.Context) error {
	if server == nil || ctx == nil || server.monitor == nil {
		return ErrInvalid
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: server.config.SocketPath, Net: "unix"})
	if err != nil {
		return ErrUnavailable
	}
	defer listener.Close()
	if os.Chown(server.config.SocketPath, 0, int(server.config.SocketGID)) != nil ||
		os.Chmod(server.config.SocketPath, 0o660) != nil {
		return ErrUnavailable
	}
	acceptErrors := make(chan error, 1)
	go func() {
		for {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				acceptErrors <- acceptErr
				return
			}
			go server.serveConnection(connection)
		}
	}()
	ticker := time.NewTicker(server.config.MonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-server.monitor.Events():
			if !ok {
				return ErrUnavailable
			}
			server.handlePermissionEvent(event)
		case monitorErr := <-server.monitor.Errors():
			if monitorErr != nil {
				return ErrUnavailable
			}
		case <-ticker.C:
			server.monitorPolicies()
		case <-acceptErrors:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrUnavailable
		}
	}
}

func (server *Server) serveConnection(connection *net.UnixConn) {
	defer connection.Close()
	credential, err := unixPeerCredential(connection)
	if err != nil || credential.Uid != server.config.WorkerUID || credential.Pid < 1 {
		server.writeResponse(connection, wireResponse{Schema: ProtocolSchemaV1, Code: "rejected"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(connection, MaximumWireBytes+1))
	if err != nil || len(raw) > MaximumWireBytes {
		clear(raw)
		server.writeResponse(connection, wireResponse{Schema: ProtocolSchemaV1, Code: "invalid"})
		return
	}
	defer clear(raw)
	var request wireRequest
	if decodeCanonical(raw, &request) != nil || request.validate() != nil {
		server.writeResponse(connection, wireResponse{Schema: ProtocolSchemaV1, Code: "invalid"})
		return
	}
	response := server.dispatch(request, int32(credential.Pid))
	server.writeResponse(connection, response)
}

func (server *Server) writeResponse(connection *net.UnixConn, response wireResponse) {
	if !response.OK && response.Code == "" {
		response.Code = "unavailable"
	}
	raw, err := encodeCanonical(response)
	if err != nil {
		return
	}
	defer clear(raw)
	_, _ = connection.Write(raw)
}

func (server *Server) dispatch(request wireRequest, peerPID int32) wireResponse {
	switch request.Operation {
	case operationPing:
		if _, err := processIdentity(peerPID); err != nil {
			return failedResponse(err)
		}
		return wireResponse{Schema: ProtocolSchemaV1, OK: true}
	case operationRegister:
		runID, err := server.register(peerPID, *request.Registration)
		if err != nil {
			return failedResponse(err)
		}
		return wireResponse{Schema: ProtocolSchemaV1, OK: true, RunID: runID}
	case operationActivate:
		proof, err := server.proof(peerPID, request.RunID, request.PiPID, ProofActive)
		if err != nil {
			return failedResponse(err)
		}
		return wireResponse{Schema: ProtocolSchemaV1, OK: true, RunID: request.RunID, Proof: &proof}
	case operationProof:
		proof, err := server.proof(peerPID, request.RunID, 0, ProofActive)
		if err != nil {
			return failedResponse(err)
		}
		return wireResponse{Schema: ProtocolSchemaV1, OK: true, RunID: request.RunID, Proof: &proof}
	case operationTerminal:
		proof, err := server.proof(peerPID, request.RunID, 0, ProofTerminal)
		if err != nil {
			return failedResponse(err)
		}
		return wireResponse{Schema: ProtocolSchemaV1, OK: true, RunID: request.RunID, Proof: &proof}
	case operationCancel:
		if err := server.cancel(peerPID, request.RunID); err != nil {
			return failedResponse(err)
		}
		return wireResponse{Schema: ProtocolSchemaV1, OK: true, RunID: request.RunID}
	default:
		return failedResponse(ErrInvalid)
	}
}

func failedResponse(err error) wireResponse {
	code := "unavailable"
	switch {
	case errors.Is(err, ErrInvalid):
		code = "invalid"
	case errors.Is(err, ErrViolation):
		code = "violation"
	}
	return wireResponse{Schema: ProtocolSchemaV1, Code: code}
}

func (server *Server) register(peerPID int32, registration Registration) (string, error) {
	if registration.Validate() != nil || registration.PiExecutable != server.config.PiExecutable {
		return "", ErrInvalid
	}
	worker, err := processIdentity(peerPID)
	if err != nil {
		return "", err
	}
	expectedWorker, err := pathIdentity(server.config.WorkerExecutable)
	if err != nil || worker.Device != expectedWorker.Device || worker.Inode != expectedWorker.Inode ||
		worker.SHA256 != expectedWorker.SHA256 {
		return "", ErrViolation
	}
	cgroupRaw, cgroupDigest, err := processCgroup(peerPID)
	if err != nil {
		return "", err
	}
	piPinned, err := pinnedPiPathIdentity(registration.PiExecutable, server.config.SocketGID)
	if err != nil || piPinned.SHA256 != registration.PiSHA256 {
		return "", ErrViolation
	}
	runID := uuid.NewString()
	policyDigest, err := computePolicyDigest(runID, server.bootID, cgroupDigest, registration, worker, piPinned)
	if err != nil {
		return "", err
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, current := range server.policies {
		if current.workerPID == peerPID && current.terminal == nil {
			return "", ErrViolation
		}
	}
	server.policies[runID] = &policy{
		runID: runID, registration: registration, workerPID: peerPID, worker: worker,
		cgroupRaw: cgroupRaw, cgroupDigest: cgroupDigest, piPinned: piPinned,
		policyDigest: policyDigest, createdAt: server.config.Now().UTC(),
	}
	return runID, nil
}

func computePolicyDigest(runID, bootID, cgroupDigest string, registration Registration, worker ProcessIdentity, pi fileIdentity) (string, error) {
	payload := struct {
		Schema       string          `json:"schema"`
		RunID        string          `json:"run_id"`
		BootID       string          `json:"boot_id"`
		CgroupSHA256 string          `json:"cgroup_sha256"`
		Registration Registration    `json:"registration"`
		Worker       ProcessIdentity `json:"worker"`
		Pi           fileIdentity    `json:"pi"`
	}{ProofSchemaV1, runID, bootID, cgroupDigest, registration, worker, pi}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(digest[:]), nil
}

func (server *Server) handlePermissionEvent(event permissionEvent) {
	allow := true
	defer func() {
		_ = event.respond(allow)
		if event.File != nil {
			_ = event.File.Close()
		}
	}()
	if event.PID < 1 || event.File == nil {
		allow = false
		return
	}
	cgroupRaw, cgroupDigest, err := processCgroup(event.PID)
	if err != nil {
		// An event that cannot be attributed is allowed only when no registered
		// Worker run exists. Once a run exists, attribution failure is fail closed.
		server.mu.Lock()
		registered := len(server.policies) != 0
		server.mu.Unlock()
		allow = !registered
		return
	}
	server.mu.Lock()
	var current *policy
	for _, candidate := range server.policies {
		if candidate.cgroupDigest == cgroupDigest && candidate.cgroupRaw == cgroupRaw && candidate.terminal == nil {
			current = candidate
			break
		}
	}
	if current == nil {
		server.mu.Unlock()
		return
	}
	if current.violation != "" {
		server.mu.Unlock()
		allow = false
		return
	}
	identity, identityErr := openedFileIdentity(event.File)
	stat, statErr := processStat(event.PID)
	if identityErr != nil || statErr != nil {
		current.violateLocked("event_identity_unreadable", event.PID)
		server.mu.Unlock()
		allow = false
		return
	}
	decision := decideExecutable(current.totalAllowed, current.workerPID, current.piPinned, identity, stat, event.PID)
	if decision.violation != "" {
		current.violateLocked(decision.violation, event.PID)
		server.mu.Unlock()
		allow = false
		return
	}
	if decision.launch {
		current.totalAllowed = 1
		current.pi = ProcessIdentity{
			PID: event.PID, StartTimeTicks: stat.StartTimeTicks,
			Device: identity.Device, Inode: identity.Inode, SHA256: identity.SHA256,
		}
	}
	server.mu.Unlock()
}

type executableDecision struct {
	launch    bool
	violation string
}

func decideExecutable(totalAllowed uint32, workerPID int32, pinned, candidate fileIdentity, stat processStatValue, pid int32) executableDecision {
	if totalAllowed == 0 {
		if stat.ParentPID != workerPID || stat.ProcessGroup != pid {
			return executableDecision{}
		}
		if candidate != pinned {
			return executableDecision{violation: "initial_pi_identity_mismatch"}
		}
		return executableDecision{launch: true}
	}
	if candidate.Device == pinned.Device && candidate.Inode == pinned.Inode || candidate.SHA256 == pinned.SHA256 {
		return executableDecision{violation: "duplicate_pi_exec"}
	}
	return executableDecision{}
}

func (policy *policy) violateLocked(code string, offendingPID int32) {
	if policy.violation == "" {
		policy.violation = code
		slog.Error(
			"[cloud-worker-exec-gate] outcome=violation",
			"code", code,
		)
	}
	group := policy.pi.PID
	if group < 1 {
		group = offendingPID
	}
	if group > 0 {
		_ = unix.Kill(-int(group), unix.SIGKILL)
	}
}

func (server *Server) proof(peerPID int32, runID string, requestedPiPID int32, state ProofState) (Proof, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	current := server.policies[runID]
	if current == nil || current.workerPID != peerPID {
		return Proof{}, ErrViolation
	}
	if current.terminal != nil {
		if state != ProofTerminal {
			return Proof{}, ErrViolation
		}
		return *current.terminal, nil
	}
	if current.violation != "" {
		return Proof{}, ErrViolation
	}
	workerCount, piCount, cgroupCount, members, _, err := scanExactTopology(current.cgroupRaw, current.worker, current.piPinned)
	if err != nil || workerCount != 1 || current.totalAllowed != 1 || current.pi.validate() != nil {
		logTopologyFailure(
			"proof_"+string(state), err == nil, workerCount, piCount,
			cgroupCount, current.totalAllowed, current.pi.validate() == nil,
			current.activeProof,
		)
		current.violateLocked("runtime_topology_invalid", current.pi.PID)
	}
	if requestedPiPID != 0 && requestedPiPID != current.pi.PID {
		current.violateLocked("pi_pid_mismatch", requestedPiPID)
	}
	if piCount > 1 {
		current.violateLocked("multiple_pi_processes", current.pi.PID)
	}
	if current.violation != "" {
		return Proof{}, ErrViolation
	}
	proof := Proof{
		SchemaVersion: ProofSchemaV1, State: state, RunID: current.runID,
		ExecutionID: current.registration.ExecutionID, TaskID: current.registration.TaskID,
		Attempt: current.registration.Attempt, LeaseEpoch: current.registration.LeaseEpoch,
		RuntimeTaskSHA256: current.registration.RuntimeTaskSHA256,
		BootID:            server.bootID, CgroupSHA256: current.cgroupDigest, PolicySHA256: current.policyDigest,
		Worker: current.worker, Pi: current.pi, WorkerProcessCount: workerCount,
		CgroupProcessCount: cgroupCount, ActiveDescendants: cgroupCount - workerCount,
		ActivePiProcesses: piCount, TotalAllowedPiExecs: current.totalAllowed,
		ObservedAtUnixNano: server.config.Now().UTC().UnixNano(),
	}
	if state == ProofActive {
		if piCount != 1 {
			current.violateLocked("pi_not_active", current.pi.PID)
			return Proof{}, ErrViolation
		}
		if proof.Validate() != nil {
			return Proof{}, ErrViolation
		}
		current.quiescenceAt = time.Time{}
		current.activeProof = true
		return proof, nil
	}
	if state == ProofTerminal {
		if !current.activeProof {
			current.violateLocked("terminal_before_active", current.pi.PID)
			killMembers(members, current.workerPID)
			return Proof{}, ErrViolation
		}
		waiting, expired := activeQuiescenceState(
			current, server.config.Now().UTC(), workerCount, piCount,
			cgroupCount, err,
		)
		if waiting {
			return Proof{}, ErrUnavailable
		}
		if expired || cgroupCount != 1 {
			logTopologyFailure(
				"proof_terminal", err == nil, workerCount, piCount,
				cgroupCount, current.totalAllowed, current.pi.validate() == nil,
				current.activeProof,
			)
			current.violateLocked("orphan_descendants", current.pi.PID)
			killMembers(members, current.workerPID)
			return Proof{}, ErrViolation
		}
		if piCount != 0 {
			return Proof{}, ErrViolation
		}
		if proof.ValidateTerminal() != nil {
			return Proof{}, ErrViolation
		}
		copy := proof
		current.terminal = &copy
		return proof, nil
	}
	return Proof{}, ErrViolation
}

func (server *Server) cancel(peerPID int32, runID string) error {
	server.mu.Lock()
	defer server.mu.Unlock()
	current := server.policies[runID]
	if current == nil || current.workerPID != peerPID {
		return ErrViolation
	}
	for attempt := 0; attempt < 20; attempt++ {
		_, _, cgroupCount, members, _, scanErr := scanExactTopology(current.cgroupRaw, current.worker, current.piPinned)
		if scanErr == nil && cgroupCount == 1 {
			delete(server.policies, runID)
			return nil
		}
		killMembers(members, current.workerPID)
		time.Sleep(10 * time.Millisecond)
	}
	return ErrViolation
}

func (server *Server) monitorPolicies() {
	server.mu.Lock()
	defer server.mu.Unlock()
	now := server.config.Now().UTC()
	for _, current := range server.policies {
		if current.terminal != nil || current.violation != "" {
			continue
		}
		if current.totalAllowed == 0 && !preActivationExpired(current, now) {
			continue
		}
		workerCount, piCount, cgroupCount, members, piMembers, err := scanExactTopology(current.cgroupRaw, current.worker, current.piPinned)
		if activePiForkHelperAllowed(
			current, workerCount, piCount, cgroupCount, piMembers, err, processStat,
		) {
			continue
		}
		violation := monitorTopologyViolation(
			current, now, workerCount, piCount, cgroupCount, err,
		)
		if violation != "" {
			logTopologyFailure(
				"monitor", err == nil, workerCount, piCount,
				cgroupCount, current.totalAllowed, current.pi.validate() == nil,
				current.activeProof,
			)
			current.violateLocked(violation, current.pi.PID)
			killMembers(members, current.workerPID)
		}
	}
}

func activePiForkHelperAllowed(
	current *policy,
	workerCount, piCount, cgroupCount uint32,
	piMembers []int32,
	scanErr error,
	stat func(int32) (processStatValue, error),
) bool {
	if current == nil || !current.activeProof || current.totalAllowed != 1 ||
		current.pi.validate() != nil || scanErr != nil || workerCount != 1 ||
		piCount != 2 || cgroupCount < 3 || len(piMembers) != 2 || stat == nil {
		return false
	}
	mainFound := false
	helperPID := int32(0)
	for _, pid := range piMembers {
		if pid == current.pi.PID {
			mainFound = true
			continue
		}
		if helperPID != 0 {
			return false
		}
		helperPID = pid
	}
	value, err := stat(helperPID)
	return mainFound && helperPID > 0 && err == nil && value.ParentPID == current.pi.PID
}

func monitorTopologyViolation(
	current *policy,
	now time.Time,
	workerCount, piCount, cgroupCount uint32,
	scanErr error,
) string {
	if current == nil || preActivationExpired(current, now) {
		return "pre_activation_expired"
	}
	if !current.activeProof && scanErr == nil && current.totalAllowed == 1 &&
		current.pi.validate() == nil && workerCount == 2 && piCount == 0 &&
		cgroupCount == 2 {
		// FAN_ALLOW resumes execve before /proc exposes the new image. During
		// this exact window the child still has the Worker image even though
		// the one permitted Pi identity and process identity are already bound.
		return ""
	}
	waiting, expired := activeQuiescenceState(
		current, now, workerCount, piCount, cgroupCount, scanErr,
	)
	if waiting {
		return ""
	}
	if expired {
		return "runtime_topology_invalid"
	}
	if scanErr != nil || workerCount != 1 || current.totalAllowed != 1 ||
		current.pi.validate() != nil || piCount > 1 ||
		(piCount == 0 && cgroupCount != 1) {
		return "runtime_topology_invalid"
	}
	return ""
}

func activeQuiescenceState(
	current *policy,
	now time.Time,
	workerCount, piCount, cgroupCount uint32,
	scanErr error,
) (waiting, expired bool) {
	if current == nil || !current.activeProof || current.totalAllowed != 1 ||
		current.pi.validate() != nil || scanErr != nil || workerCount != 1 {
		return false, false
	}
	if piCount == 1 {
		current.quiescenceAt = time.Time{}
		return false, false
	}
	if piCount != 0 || cgroupCount <= 1 {
		return false, false
	}
	if now.IsZero() {
		return false, true
	}
	if current.quiescenceAt.IsZero() {
		current.quiescenceAt = now
	}
	if now.Before(current.quiescenceAt) ||
		!now.Before(current.quiescenceAt.Add(terminalQuiescenceLimit)) {
		return false, true
	}
	return true, false
}

func preActivationExpired(current *policy, now time.Time) bool {
	if current == nil || current.activeProof {
		return false
	}
	return current.createdAt.IsZero() || now.Before(current.createdAt) ||
		!now.Before(current.createdAt.Add(preActivationLifetime))
}

func logTopologyFailure(
	phase string,
	scanOK bool,
	workerCount, piCount, cgroupCount, totalAllowed uint32,
	piIdentityOK, activeProof bool,
) {
	// Only fixed phases, booleans, and bounded counts are emitted. Process IDs,
	// paths, cgroup names, digests, and task material remain private.
	slog.Error(
		"[cloud-worker-exec-gate] outcome=topology_invalid",
		"phase", phase, "scan_ok", scanOK,
		"worker_count", workerCount, "pi_count", piCount,
		"cgroup_count", cgroupCount, "total_allowed", totalAllowed,
		"pi_identity_ok", piIdentityOK, "active_proof", activeProof,
	)
}

func unixPeerCredential(connection *net.UnixConn) (*unix.Ucred, error) {
	if connection == nil {
		return nil, ErrInvalid
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, ErrUnavailable
	}
	var credential *unix.Ucred
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || socketErr != nil || credential == nil {
		return nil, ErrUnavailable
	}
	return credential, nil
}

type processStatValue struct {
	ParentPID      int32
	ProcessGroup   int32
	StartTimeTicks uint64
}

func processStat(pid int32) (processStatValue, error) {
	if pid < 1 {
		return processStatValue{}, ErrInvalid
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/stat")
	if err != nil || len(raw) > 8192 {
		clear(raw)
		return processStatValue{}, ErrUnavailable
	}
	defer clear(raw)
	end := strings.LastIndex(string(raw), ") ")
	if end < 1 {
		return processStatValue{}, ErrUnavailable
	}
	fields := strings.Fields(string(raw[end+2:]))
	if len(fields) < 20 {
		return processStatValue{}, ErrUnavailable
	}
	parent, err1 := strconv.ParseInt(fields[1], 10, 32)
	group, err2 := strconv.ParseInt(fields[2], 10, 32)
	start, err3 := strconv.ParseUint(fields[19], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || parent < 0 || group < 1 || start == 0 {
		return processStatValue{}, ErrUnavailable
	}
	return processStatValue{ParentPID: int32(parent), ProcessGroup: int32(group), StartTimeTicks: start}, nil
}

func processCgroup(pid int32) (string, string, error) {
	if pid < 1 {
		return "", "", ErrInvalid
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cgroup")
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 || raw[len(raw)-1] != '\n' {
		clear(raw)
		return "", "", ErrUnavailable
	}
	value := string(raw)
	digest := sha256.Sum256(raw)
	clear(raw)
	return value, hex.EncodeToString(digest[:]), nil
}

func processIdentity(pid int32) (ProcessIdentity, error) {
	stat, err := processStat(pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	file, err := os.Open("/proc/" + strconv.Itoa(int(pid)) + "/exe")
	if err != nil {
		return ProcessIdentity{}, ErrUnavailable
	}
	defer file.Close()
	identity, err := openedFileIdentity(file)
	if err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{PID: pid, StartTimeTicks: stat.StartTimeTicks, Device: identity.Device, Inode: identity.Inode, SHA256: identity.SHA256}, nil
}

func pathIdentity(path string) (fileIdentity, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o022 != 0 {
		return fileIdentity{}, ErrViolation
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fileIdentity{}, ErrUnavailable
	}
	defer file.Close()
	identity, err := openedFileIdentity(file)
	after, afterErr := os.Lstat(path)
	if err != nil || afterErr != nil || !os.SameFile(before, after) {
		return fileIdentity{}, ErrViolation
	}
	return identity, nil
}

// pinnedPiPathIdentity makes the execute-permission monitor's one-Pi count a
// closed boundary for dynamically linked executables. FAN_OPEN_EXEC_PERM does
// not observe an ELF interpreter opening its argv[1] as ordinary data. The Pi
// executable is therefore readable only by root and the Worker group: the
// Worker can hash it before registration, while the Pi identity can execve it
// but cannot pass it to PT_INTERP or another loader as a readable input.
func pinnedPiPathIdentity(path string, workerGID uint32) (fileIdentity, error) {
	before, err := os.Lstat(path)
	if err != nil || !piExecutableBoundary(before, 0, workerGID) {
		return fileIdentity{}, ErrViolation
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fileIdentity{}, ErrUnavailable
	}
	defer file.Close()
	identity, identityErr := openedFileIdentity(file)
	after, afterErr := os.Lstat(path)
	if identityErr != nil || afterErr != nil || !os.SameFile(before, after) ||
		!piExecutableBoundary(after, 0, workerGID) {
		return fileIdentity{}, ErrViolation
	}
	return identity, nil
}

func piExecutableBoundary(info os.FileInfo, ownerUID, workerGID uint32) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o551 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == ownerUID && stat.Gid == workerGID && stat.Nlink == 1
}

func openedFileIdentity(file *os.File) (fileIdentity, error) {
	if file == nil {
		return fileIdentity{}, ErrInvalid
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 512<<20 {
		return fileIdentity{}, ErrViolation
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return fileIdentity{}, ErrUnavailable
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return fileIdentity{}, ErrUnavailable
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, 512<<20+1))
	if err != nil || written != info.Size() {
		return fileIdentity{}, ErrUnavailable
	}
	return fileIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func scanExactTopology(cgroupRaw string, worker ProcessIdentity, pi fileIdentity) (uint32, uint32, uint32, []int32, []int32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, 0, nil, nil, ErrUnavailable
	}
	var workerCount, piCount, cgroupCount uint32
	var members, piMembers []int32
	for _, entry := range entries {
		pidValue, parseErr := strconv.ParseInt(entry.Name(), 10, 32)
		if parseErr != nil || pidValue < 1 {
			continue
		}
		pid := int32(pidValue)
		raw, readErr := os.ReadFile("/proc/" + entry.Name() + "/cgroup")
		if readErr != nil {
			continue
		}
		matches := string(raw) == cgroupRaw
		clear(raw)
		if !matches {
			continue
		}
		cgroupCount++
		members = append(members, pid)
		identity, identityErr := processIdentity(pid)
		if identityErr != nil {
			continue
		}
		if identity.SHA256 == worker.SHA256 {
			workerCount++
		}
		if identity.SHA256 == pi.SHA256 {
			piCount++
			piMembers = append(piMembers, pid)
		}
	}
	return workerCount, piCount, cgroupCount, members, piMembers, nil
}

func killMembers(members []int32, workerPID int32) {
	for _, pid := range members {
		if pid > 0 && pid != workerPID {
			_ = unix.Kill(int(pid), unix.SIGKILL)
		}
	}
}

package extensionrunner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Phase string

const (
	PhaseReceived   Phase = "received"
	PhaseAdmitted   Phase = "admitted"
	PhasePrepared   Phase = "prepared"
	PhaseRunning    Phase = "running"
	PhaseCollecting Phase = "collecting"
	PhaseExited     Phase = "exited"
	PhaseCleaned    Phase = "cleaned"
	PhaseTombstone  Phase = "tombstone"
	PhaseFailed     Phase = "failed"
)

func ValidErrorCode(c ErrorCode) bool {
	switch c {
	case ErrorNone, ErrorInvalidRequest, ErrorDeniedRequest, ErrorUnavailableBackend, ErrorTimeout, ErrorCancelled, ErrorExecution, ErrorProtocolViolation, ErrorReplay, ErrorCleanup:
		return true
	default:
		return false
	}
}

type StatusV1 struct {
	RunID       string       `json:"run_id"`
	Phase       Phase        `json:"phase"`
	Error       ErrorCode    `json:"error,omitempty"`
	Status      string       `json:"status,omitempty"`
	Stdout      []byte       `json:"stdout,omitempty"`
	Stderr      []byte       `json:"stderr,omitempty"`
	ExitCode    *int         `json:"exit_code,omitempty"`
	ResultFiles []ResultFile `json:"result_files,omitempty"`
}
type ErrorCode string

const (
	ErrorNone               ErrorCode = ""
	ErrorInvalidRequest     ErrorCode = "invalid_request"
	ErrorDeniedRequest      ErrorCode = "denied_request"
	ErrorUnavailableBackend ErrorCode = "unavailable_backend"
	ErrorTimeout            ErrorCode = "timeout"
	ErrorCancelled          ErrorCode = "cancelled"
	ErrorExecution          ErrorCode = "execution_failed"
	ErrorProtocolViolation  ErrorCode = "protocol_violation"
	ErrorReplay             ErrorCode = "replay"
	ErrorCleanup            ErrorCode = "cleanup_failed"
)

var transitions = map[Phase]map[Phase]bool{
	PhaseReceived: {PhaseAdmitted: true, PhaseFailed: true}, PhaseAdmitted: {PhasePrepared: true, PhaseFailed: true}, PhasePrepared: {PhaseRunning: true, PhaseFailed: true}, PhaseRunning: {PhaseCollecting: true, PhaseExited: true, PhaseFailed: true}, PhaseCollecting: {PhaseExited: true, PhaseFailed: true}, PhaseExited: {PhaseCleaned: true, PhaseFailed: true}, PhaseCleaned: {PhaseTombstone: true}, PhaseFailed: {PhaseCleaned: true, PhaseTombstone: true},
}

func ValidTransition(from, to Phase) bool { return transitions[from][to] }
func ValidPhase(p Phase) bool {
	switch p {
	case PhaseReceived, PhaseAdmitted, PhasePrepared, PhaseRunning, PhaseCollecting, PhaseExited, PhaseCleaned, PhaseTombstone, PhaseFailed:
		return true
	default:
		return false
	}
}

type Lifecycle interface {
	Claim(string) error
	Transition(string, Phase, ErrorCode) error
	PhaseOf(string) (Phase, bool)
	TombstoneOf(string) (Tombstone, bool)
}

type Tombstone struct {
	RunID  string
	At     time.Time
	Status StatusV1
}
type runRecord struct {
	RunID         string   `json:"run_id"`
	RequestDigest string   `json:"request_digest"`
	Status        StatusV1 `json:"status"`
}
type registryDisk struct {
	Records map[string]runRecord `json:"records"`
	Active  map[string]runRecord `json:"active"`
}
type RunRegistry struct {
	mu         sync.Mutex
	active     map[string]Phase
	tombstones map[string]Tombstone
	records    map[string]runRecord
	path       string
}

func NewRunRegistry() *RunRegistry {
	return &RunRegistry{active: map[string]Phase{}, tombstones: map[string]Tombstone{}, records: map[string]runRecord{}}
}
func NewPersistentRunRegistry(root string) (*RunRegistry, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	r := NewRunRegistry()
	r.path = filepath.Join(root, "runs-v2.json")
	b, err := os.ReadFile(r.path)
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var disk registryDisk
	if err = json.Unmarshal(b, &disk); err != nil {
		return nil, ErrInvalid
	}
	if disk.Records != nil {
		r.records = disk.Records
	}
	for id, rec := range disk.Active {
		r.tombstones[id] = Tombstone{RunID: id, At: time.Now().UTC(), Status: StatusV1{RunID: id, Phase: PhaseTombstone, Error: ErrorExecution, Status: "recovered nonterminal run"}}
		r.records[id] = rec
	}
	for id, rec := range r.records {
		r.tombstones[id] = Tombstone{RunID: id, At: time.Now().UTC(), Status: rec.Status}
	}
	return r, nil
}
func (r *RunRegistry) persistLocked() error {
	if r.path == "" {
		return nil
	}
	active := map[string]runRecord{}
	for id := range r.active {
		active[id] = runRecord{RunID: id}
	}
	b, e := json.Marshal(registryDisk{Records: r.records, Active: active})
	if e != nil {
		return e
	}
	tmp := r.path + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	_ = f.Close()
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, r.path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(r.path))
	if e == nil {
		e = d.Sync()
		_ = d.Close()
	}
	return e
}
func (r *RunRegistry) ClaimDigest(runID, digest string) (StatusV1, bool, error) {
	if _, e := idPathPart(runID); e != nil {
		return StatusV1{}, false, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.records[runID]; ok {
		if rec.RequestDigest != digest {
			return StatusV1{}, false, ErrReplay
		}
		return rec.Status, true, nil
	}
	if _, ok := r.active[runID]; ok {
		return StatusV1{}, false, ErrReplay
	}
	r.active[runID] = PhaseReceived
	r.records[runID] = runRecord{RunID: runID, RequestDigest: digest}
	if err := r.persistLocked(); err != nil {
		delete(r.active, runID)
		return StatusV1{}, false, err
	}
	return StatusV1{}, false, nil
}
func (r *RunRegistry) Record(runID, digest string, status StatusV1) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.records[runID]; ok && old.RequestDigest != digest {
		return ErrReplay
	}
	if old, ok := r.records[runID]; ok && old.Status.RunID != "" {
		return nil
	}
	r.records[runID] = runRecord{RunID: runID, RequestDigest: digest, Status: status}
	r.tombstones[runID] = Tombstone{RunID: runID, At: time.Now().UTC(), Status: status}
	delete(r.active, runID)
	return r.persistLocked()
}
func (r *RunRegistry) Claim(runID string) error {
	if _, e := idPathPart(runID); e != nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.active[runID]; ok {
		return ErrReplay
	}
	if _, ok := r.tombstones[runID]; ok {
		return ErrReplay
	}
	r.active[runID] = PhaseReceived
	return nil
}
func (r *RunRegistry) Transition(runID string, to Phase, code ErrorCode) error {
	if !ValidPhase(to) || !ValidErrorCode(code) {
		return ErrState
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	from, ok := r.active[runID]
	if !ok || !ValidTransition(from, to) {
		return ErrState
	}
	r.active[runID] = to
	if to == PhaseTombstone {
		r.tombstones[runID] = Tombstone{RunID: runID, At: time.Now().UTC(), Status: StatusV1{RunID: runID, Phase: to, Error: code}}
		delete(r.active, runID)
	}
	return nil
}
func (r *RunRegistry) PhaseOf(runID string) (Phase, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.active[runID]
	return p, ok
}
func (r *RunRegistry) TombstoneOf(runID string) (Tombstone, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tombstones[runID]
	return t, ok
}

// Tombstone records terminal cleanup even when setup failed before the normal
// phase sequence could be completed.
func (r *RunRegistry) Tombstone(runID string, code ErrorCode) error {
	if !ValidErrorCode(code) {
		return ErrState
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tombstones[runID]; ok {
		return ErrReplay
	}
	if _, ok := r.active[runID]; !ok {
		return ErrState
	}
	r.tombstones[runID] = Tombstone{RunID: runID, At: time.Now().UTC(), Status: StatusV1{RunID: runID, Phase: PhaseTombstone, Error: code}}
	delete(r.active, runID)
	return nil
}

func (r *RunRegistry) Abort(runID string, code ErrorCode) error {
	if p, ok := r.PhaseOf(runID); ok {
		if p != PhaseFailed {
			_ = r.Transition(runID, PhaseFailed, code)
		}
		if p, ok = r.PhaseOf(runID); ok && p == PhaseFailed {
			_ = r.Transition(runID, PhaseCleaned, code)
			_ = r.Transition(runID, PhaseTombstone, code)
			return nil
		}
	}
	return r.Tombstone(runID, code)
}

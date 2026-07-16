package installer

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

const (
	executionJournalSchema = "dirextalk.agent.installer-execution-journal/v1"
	journalStateRunning    = "running"
	journalStateTerminal   = "terminal"
	journalStateLeaseFence = "lease_fence"
	maxJournalRecordBytes  = 64 << 10
	maxJournalBytes        = 16 << 20
	maxJournalEntries      = 8192
)

type executionJournalRecord struct {
	SchemaVersion  string     `json:"schema_version"`
	IdempotencyKey string     `json:"idempotency_key"`
	RequestDigest  string     `json:"request_digest"`
	State          string     `json:"state"`
	LeaseEpoch     int64      `json:"lease_epoch,omitempty"`
	Response       ResponseV1 `json:"response"`
}

type executionJournalEntry struct {
	requestDigest string
	state         string
	response      ResponseV1
}

type ExecutionJournal interface {
	FenceLease(leaseEpoch int64) error
	Lookup(idempotencyKey, requestDigest string) (ResponseV1, bool, error)
	Begin(idempotencyKey, requestDigest string, response ResponseV1) (ResponseV1, bool, error)
	Complete(idempotencyKey, requestDigest string, response ResponseV1) error
}

// FileExecutionJournal is append-only. A running record is fsynced before the
// process starts and a terminal record after it exits. A truncated final frame
// is discarded on startup; any remaining running record is durably converted
// to interrupted so it can never be executed automatically after a restart.
type FileExecutionJournal struct {
	path string

	mu            sync.Mutex
	entries       map[string]executionJournalEntry
	maxLeaseEpoch int64
	failed        bool
}

func OpenRootOwnedExecutionJournal(name string) (*FileExecutionJournal, error) {
	return openExecutionJournal(name, true)
}

func openExecutionJournal(name string, requireRootOwnership bool) (*FileExecutionJournal, error) {
	clean := filepath.Clean(name)
	if name == "" || !filepath.IsAbs(clean) || clean != name {
		return nil, errorf(CodeJournalUnavailable, "execution journal path is invalid")
	}
	if requireRootOwnership {
		if err := validateRootOwnedJournalParent(filepath.Dir(clean)); err != nil {
			return nil, errorf(CodeJournalUnavailable, "execution journal parent is not trusted")
		}
	}
	if err := createJournalIfMissing(clean); err != nil {
		return nil, errorf(CodeJournalUnavailable, "create execution journal")
	}
	if requireRootOwnership {
		if err := validateRootOwnedJournalFile(clean); err != nil {
			return nil, errorf(CodeJournalUnavailable, "execution journal is not trusted")
		}
	}
	journal := &FileExecutionJournal{path: clean, entries: make(map[string]executionJournalEntry)}
	if err := journal.loadAndRecover(); err != nil {
		return nil, err
	}
	return journal, nil
}

func createJournalIfMissing(name string) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (j *FileExecutionJournal) loadAndRecover() error {
	info, err := os.Stat(j.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxJournalBytes {
		return errorf(CodeJournalUnavailable, "inspect execution journal")
	}
	content, err := os.ReadFile(j.path)
	if err != nil || int64(len(content)) != info.Size() {
		return errorf(CodeJournalUnavailable, "read execution journal")
	}
	offset := 0
	for offset < len(content) {
		frameStart := offset
		if len(content)-offset < 4 {
			if err := repairJournalTail(j.path, int64(frameStart)); err != nil {
				return errorf(CodeJournalUnavailable, "repair execution journal")
			}
			break
		}
		size := int(binary.BigEndian.Uint32(content[offset : offset+4]))
		offset += 4
		if size < 1 || size > maxJournalRecordBytes {
			return errorf(CodeJournalUnavailable, "execution journal record is invalid")
		}
		if len(content)-offset < size {
			if err := repairJournalTail(j.path, int64(frameStart)); err != nil {
				return errorf(CodeJournalUnavailable, "repair execution journal")
			}
			break
		}
		var record executionJournalRecord
		if err := DecodeCanonical(content[offset:offset+size], &record); err != nil || j.applyRecord(record) != nil {
			return errorf(CodeJournalUnavailable, "execution journal record is invalid")
		}
		offset += size
	}
	if len(j.entries) > maxJournalEntries {
		return errorf(CodeJournalUnavailable, "execution journal entry limit exceeded")
	}
	for key, entry := range j.entries {
		if entry.state != journalStateRunning {
			continue
		}
		response := entry.response
		response.Status = StatusInterrupted
		response.ErrorCode = CodeExecutionInterrupted
		record := executionJournalRecord{
			SchemaVersion: executionJournalSchema, IdempotencyKey: key,
			RequestDigest: entry.requestDigest, State: journalStateTerminal, Response: response,
		}
		if err := j.appendRecord(record); err != nil {
			return err
		}
		j.entries[key] = executionJournalEntry{requestDigest: entry.requestDigest, state: journalStateTerminal, response: response}
	}
	return nil
}

func repairJournalTail(name string, size int64) error {
	file, err := os.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err = file.Truncate(size); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (j *FileExecutionJournal) applyRecord(record executionJournalRecord) error {
	if record.SchemaVersion != executionJournalSchema {
		return errors.New("invalid journal record")
	}
	if record.State == journalStateLeaseFence {
		if record.LeaseEpoch < 1 || record.LeaseEpoch <= j.maxLeaseEpoch || record.IdempotencyKey != "" || record.RequestDigest != "" || record.Response != (ResponseV1{}) {
			return errors.New("invalid lease fence record")
		}
		j.maxLeaseEpoch = record.LeaseEpoch
		return nil
	}
	if record.LeaseEpoch != 0 || !digestPattern.MatchString(record.RequestDigest) || !isCanonicalUUID(record.IdempotencyKey) {
		return errors.New("invalid journal record")
	}
	if record.Response.SchemaVersion != ResponseSchemaV1 || record.Response.Action != ActionExecute || !namePattern.MatchString(record.Response.CommandID) ||
		record.Response.ArtifactName != "" || record.Response.SHA256 != "" {
		return errors.New("invalid journal response")
	}
	if !isCanonicalUUID(record.Response.RequestID) || record.Response.Replayed {
		return errors.New("invalid journal response identity")
	}
	previous, exists := j.entries[record.IdempotencyKey]
	switch record.State {
	case journalStateRunning:
		if exists || record.Response.Status != "" || record.Response.ErrorCode != "" {
			return errors.New("invalid running transition")
		}
	case journalStateTerminal:
		if !exists || previous.state != journalStateRunning || previous.requestDigest != record.RequestDigest ||
			previous.response.RequestID != record.Response.RequestID || previous.response.CommandID != record.Response.CommandID ||
			!terminalExecutionResponse(record.Response) {
			return errors.New("invalid terminal transition")
		}
	default:
		return errors.New("invalid journal state")
	}
	j.entries[record.IdempotencyKey] = executionJournalEntry{requestDigest: record.RequestDigest, state: record.State, response: record.Response}
	return nil
}

func (j *FileExecutionJournal) FenceLease(leaseEpoch int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return errorf(CodeJournalUnavailable, "execution journal requires restart")
	}
	if leaseEpoch < j.maxLeaseEpoch {
		return errorf(CodeLeaseRejected, "installer lease epoch is stale")
	}
	if leaseEpoch == j.maxLeaseEpoch {
		return nil
	}
	record := executionJournalRecord{SchemaVersion: executionJournalSchema, State: journalStateLeaseFence, LeaseEpoch: leaseEpoch}
	if err := j.appendRecord(record); err != nil {
		j.failed = true
		return err
	}
	j.maxLeaseEpoch = leaseEpoch
	return nil
}

func isCanonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func terminalExecutionResponse(response ResponseV1) bool {
	switch response.Status {
	case StatusExecuted:
		return response.ErrorCode == ""
	case StatusFailed:
		return response.ErrorCode == CodeExecutionFailed || response.ErrorCode == CodeExecutionTimedOut
	case StatusInterrupted:
		return response.ErrorCode == CodeExecutionInterrupted
	default:
		return false
	}
}

func (j *FileExecutionJournal) Lookup(idempotencyKey, requestDigest string) (ResponseV1, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return ResponseV1{}, false, errorf(CodeJournalUnavailable, "execution journal requires restart")
	}
	entry, exists := j.entries[idempotencyKey]
	if !exists {
		return ResponseV1{}, false, nil
	}
	if entry.requestDigest != requestDigest {
		return ResponseV1{}, false, errorf(CodeIdempotencyConflict, "idempotency key is bound to another request")
	}
	if entry.state != journalStateTerminal {
		return ResponseV1{}, false, errorf(CodeJournalUnavailable, "execution journal contains an unfinished operation")
	}
	response := entry.response
	response.Replayed = true
	return response, true, nil
}

func (j *FileExecutionJournal) Begin(idempotencyKey, requestDigest string, response ResponseV1) (ResponseV1, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return ResponseV1{}, false, errorf(CodeJournalUnavailable, "execution journal requires restart")
	}
	if entry, exists := j.entries[idempotencyKey]; exists {
		if entry.requestDigest != requestDigest {
			return ResponseV1{}, false, errorf(CodeIdempotencyConflict, "idempotency key is bound to another request")
		}
		if entry.state != journalStateTerminal {
			return ResponseV1{}, false, errorf(CodeJournalUnavailable, "execution journal contains an unfinished operation")
		}
		replayed := entry.response
		replayed.Replayed = true
		return replayed, true, nil
	}
	if len(j.entries) >= maxJournalEntries || response.SchemaVersion != ResponseSchemaV1 || response.Action != ActionExecute || !namePattern.MatchString(response.CommandID) || response.Status != "" || response.ErrorCode != "" {
		return ResponseV1{}, false, errorf(CodeJournalUnavailable, "execution journal cannot accept operation")
	}
	record := executionJournalRecord{SchemaVersion: executionJournalSchema, IdempotencyKey: idempotencyKey, RequestDigest: requestDigest, State: journalStateRunning, Response: response}
	if err := j.appendRecord(record); err != nil {
		j.failed = true
		return ResponseV1{}, false, err
	}
	j.entries[idempotencyKey] = executionJournalEntry{requestDigest: requestDigest, state: journalStateRunning, response: response}
	return ResponseV1{}, false, nil
}

func (j *FileExecutionJournal) Complete(idempotencyKey, requestDigest string, response ResponseV1) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return errorf(CodeJournalUnavailable, "execution journal requires restart")
	}
	entry, exists := j.entries[idempotencyKey]
	if !exists || entry.requestDigest != requestDigest || entry.state != journalStateRunning ||
		entry.response.RequestID != response.RequestID || entry.response.CommandID != response.CommandID || !terminalExecutionResponse(response) {
		return errorf(CodeJournalUnavailable, "execution journal completion is invalid")
	}
	record := executionJournalRecord{SchemaVersion: executionJournalSchema, IdempotencyKey: idempotencyKey, RequestDigest: requestDigest, State: journalStateTerminal, Response: response}
	if err := j.appendRecord(record); err != nil {
		j.failed = true
		return err
	}
	j.entries[idempotencyKey] = executionJournalEntry{requestDigest: requestDigest, state: journalStateTerminal, response: response}
	return nil
}

func (j *FileExecutionJournal) appendRecord(record executionJournalRecord) error {
	payload, err := canonical.Marshal(record)
	if err != nil || len(payload) > maxJournalRecordBytes {
		return errorf(CodeJournalUnavailable, "encode execution journal record")
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	info, err := os.Stat(j.path)
	if err != nil || info.Size()+int64(4+len(payload)) > maxJournalBytes {
		return errorf(CodeJournalUnavailable, "execution journal size limit reached")
	}
	file, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return errorf(CodeJournalUnavailable, "open execution journal")
	}
	var written int
	if written, err = file.Write(frame); err == nil && written != len(frame) {
		err = errors.New("short execution journal write")
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errorf(CodeJournalUnavailable, "persist execution journal")
	}
	return nil
}

package roothelper

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
)

const (
	restartJournalSchema   = "dirextalk.agent.root-helper-restart-journal/v1"
	restartJournalRunning  = "running"
	restartJournalTerminal = "terminal"
	maxRestartJournalFrame = 32 << 10
	maxRestartJournalBytes = 16 << 20
)

type RestartJournal interface {
	Begin(string, string) (workeroperation.RootHelperReceipt, bool, error)
	Complete(string, string, workeroperation.RootHelperReceipt) error
}

type restartJournalRecord struct {
	SchemaVersion string                            `json:"schema_version"`
	CapabilityID  string                            `json:"capability_id"`
	RequestDigest string                            `json:"request_digest"`
	State         string                            `json:"state"`
	Receipt       workeroperation.RootHelperReceipt `json:"receipt"`
}

type restartJournalEntry struct {
	digest  string
	state   string
	receipt workeroperation.RootHelperReceipt
}

type FileRestartJournal struct {
	path    string
	mu      sync.Mutex
	entries map[string]restartJournalEntry
}

func OpenRootOwnedRestartJournal(path string) (*FileRestartJournal, error) {
	return openRestartJournal(path, true)
}

func openRestartJournal(name string, requireRootOwnership bool) (*FileRestartJournal, error) {
	parentSync := syncDirectory
	if !requireRootOwnership {
		parentSync = func(string) error { return nil }
	}
	return openRestartJournalWithSync(name, requireRootOwnership, parentSync)
}

func openRestartJournalWithSync(name string, requireRootOwnership bool, parentSync func(string) error) (*FileRestartJournal, error) {
	clean := filepath.Clean(name)
	if name == "" || !filepath.IsAbs(clean) || clean != name || parentSync == nil {
		return nil, ErrInvalid
	}
	if requireRootOwnership && validateRootOwnedRestartJournalParent(filepath.Dir(clean)) != nil {
		return nil, ErrUnavailable
	}
	file, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		syncErr, closeErr := file.Sync(), file.Close()
		if syncErr != nil || closeErr != nil || parentSync(filepath.Dir(clean)) != nil {
			return nil, ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, ErrUnavailable
	}
	if requireRootOwnership && validateRootOwnedRestartJournalFile(clean) != nil {
		return nil, ErrUnavailable
	}
	journal := &FileRestartJournal{path: clean, entries: make(map[string]restartJournalEntry)}
	if err := journal.load(); err != nil {
		return nil, err
	}
	return journal, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr, closeErr := directory.Sync(), directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (journal *FileRestartJournal) load() error {
	content, err := os.ReadFile(journal.path)
	if err != nil || len(content) > maxRestartJournalBytes {
		return ErrUnavailable
	}
	defer clear(content)
	for offset := 0; offset < len(content); {
		if len(content)-offset < 4 {
			return ErrUnavailable
		}
		size := int(binary.BigEndian.Uint32(content[offset : offset+4]))
		offset += 4
		if size < 1 || size > maxRestartJournalFrame || len(content)-offset < size {
			return ErrUnavailable
		}
		var record restartJournalRecord
		if installer.DecodeCanonical(content[offset:offset+size], &record) != nil || journal.apply(record) != nil {
			return ErrUnavailable
		}
		offset += size
	}
	return nil
}

func (journal *FileRestartJournal) apply(record restartJournalRecord) error {
	if record.SchemaVersion != restartJournalSchema || record.CapabilityID == "" || record.RequestDigest == "" {
		return ErrInvalid
	}
	current, found := journal.entries[record.CapabilityID]
	if found && current.digest != record.RequestDigest {
		return ErrUnauthorized
	}
	switch record.State {
	case restartJournalRunning:
		if found {
			return ErrInvalid
		}
		journal.entries[record.CapabilityID] = restartJournalEntry{digest: record.RequestDigest, state: record.State}
	case restartJournalTerminal:
		if !found || current.state != restartJournalRunning || len(record.Receipt.Signature) == 0 {
			return ErrInvalid
		}
		journal.entries[record.CapabilityID] = restartJournalEntry{
			digest: record.RequestDigest, state: record.State, receipt: cloneReceipt(record.Receipt),
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (journal *FileRestartJournal) Begin(capabilityID, requestDigest string) (workeroperation.RootHelperReceipt, bool, error) {
	if journal == nil || capabilityID == "" || requestDigest == "" {
		return workeroperation.RootHelperReceipt{}, false, ErrInvalid
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if current, found := journal.entries[capabilityID]; found {
		if current.digest != requestDigest {
			return workeroperation.RootHelperReceipt{}, false, ErrUnauthorized
		}
		if current.state == restartJournalTerminal {
			return cloneReceipt(current.receipt), true, nil
		}
		return workeroperation.RootHelperReceipt{}, false, ErrUnavailable
	}
	record := restartJournalRecord{
		SchemaVersion: restartJournalSchema, CapabilityID: capabilityID,
		RequestDigest: requestDigest, State: restartJournalRunning,
	}
	if err := journal.append(record); err != nil {
		return workeroperation.RootHelperReceipt{}, false, err
	}
	journal.entries[capabilityID] = restartJournalEntry{digest: requestDigest, state: restartJournalRunning}
	return workeroperation.RootHelperReceipt{}, false, nil
}

func (journal *FileRestartJournal) Complete(capabilityID, requestDigest string, receipt workeroperation.RootHelperReceipt) error {
	if journal == nil || len(receipt.Signature) == 0 {
		return ErrInvalid
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	current, found := journal.entries[capabilityID]
	if !found || current.digest != requestDigest || current.state != restartJournalRunning {
		return ErrUnauthorized
	}
	record := restartJournalRecord{
		SchemaVersion: restartJournalSchema, CapabilityID: capabilityID,
		RequestDigest: requestDigest, State: restartJournalTerminal, Receipt: cloneReceipt(receipt),
	}
	if err := journal.append(record); err != nil {
		return err
	}
	journal.entries[capabilityID] = restartJournalEntry{
		digest: requestDigest, state: restartJournalTerminal, receipt: cloneReceipt(receipt),
	}
	return nil
}

func (journal *FileRestartJournal) append(record restartJournalRecord) error {
	payload, err := canonical.Marshal(record)
	if err != nil || len(payload) > maxRestartJournalFrame {
		return ErrUnavailable
	}
	defer clear(payload)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	file, err := os.OpenFile(journal.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	if _, err := file.Write(header[:]); err != nil {
		return ErrUnavailable
	}
	if _, err := file.Write(payload); err != nil || file.Sync() != nil || file.Close() != nil {
		return ErrUnavailable
	}
	return nil
}

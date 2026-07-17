package roothelper

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

const (
	pairingJournalSchema   = "dirextalk.agent.root-helper-pairing-journal/v1"
	pairingJournalRunning  = "running"
	pairingJournalTerminal = "terminal"
	maxPairingJournalFrame = 192 << 10
	maxPairingJournalBytes = 32 << 20
)

type pairingJournalReceipt struct {
	Begin  *PairingBeginReceiptV1  `json:"begin,omitempty"`
	Resume *PairingResumeReceiptV1 `json:"resume,omitempty"`
}

type PairingJournal interface {
	Begin(string, string) (pairingJournalReceipt, bool, error)
	Complete(string, string, pairingJournalReceipt) error
}

type pairingJournalRecord struct {
	SchemaVersion string                `json:"schema_version"`
	OperationKey  string                `json:"operation_key"`
	RequestDigest string                `json:"request_digest"`
	State         string                `json:"state"`
	Receipt       pairingJournalReceipt `json:"receipt"`
}

type pairingJournalEntry struct {
	digest  string
	state   string
	receipt pairingJournalReceipt
}

type FilePairingJournal struct {
	path    string
	mu      sync.Mutex
	entries map[string]pairingJournalEntry
}

type memoryPairingJournal struct {
	mu      sync.Mutex
	entries map[string]pairingJournalEntry
}

func newMemoryPairingJournal() PairingJournal {
	return &memoryPairingJournal{entries: make(map[string]pairingJournalEntry)}
}

func (journal *memoryPairingJournal) Begin(operationKey, requestDigest string) (pairingJournalReceipt, bool, error) {
	if journal == nil || operationKey == "" || requestDigest == "" {
		return pairingJournalReceipt{}, false, ErrInvalid
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	current, found := journal.entries[operationKey]
	if !found {
		journal.entries[operationKey] = pairingJournalEntry{digest: requestDigest, state: pairingJournalRunning}
		return pairingJournalReceipt{}, false, nil
	}
	if current.digest != requestDigest {
		return pairingJournalReceipt{}, false, ErrUnauthorized
	}
	if current.state != pairingJournalTerminal {
		return pairingJournalReceipt{}, false, ErrUnavailable
	}
	return clonePairingJournalReceipt(current.receipt), true, nil
}

func (journal *memoryPairingJournal) Complete(operationKey, requestDigest string, receipt pairingJournalReceipt) error {
	if journal == nil || !validPairingJournalReceipt(receipt) {
		return ErrInvalid
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	current, found := journal.entries[operationKey]
	if !found || current.digest != requestDigest || current.state != pairingJournalRunning {
		return ErrUnauthorized
	}
	journal.entries[operationKey] = pairingJournalEntry{
		digest: requestDigest, state: pairingJournalTerminal, receipt: clonePairingJournalReceipt(receipt),
	}
	return nil
}

func openPairingJournal(name string, requireRootOwnership bool, parentSync func(string) error) (*FilePairingJournal, error) {
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
	journal := &FilePairingJournal{path: clean, entries: make(map[string]pairingJournalEntry)}
	if err := journal.load(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *FilePairingJournal) load() error {
	content, err := os.ReadFile(journal.path)
	if err != nil || len(content) > maxPairingJournalBytes {
		return ErrUnavailable
	}
	defer clear(content)
	for offset := 0; offset < len(content); {
		if len(content)-offset < 4 {
			return ErrUnavailable
		}
		size := int(binary.BigEndian.Uint32(content[offset : offset+4]))
		offset += 4
		if size < 1 || size > maxPairingJournalFrame || len(content)-offset < size {
			return ErrUnavailable
		}
		var record pairingJournalRecord
		if installer.DecodeCanonical(content[offset:offset+size], &record) != nil || journal.apply(record) != nil {
			return ErrUnavailable
		}
		offset += size
	}
	return nil
}

func (journal *FilePairingJournal) apply(record pairingJournalRecord) error {
	if record.SchemaVersion != pairingJournalSchema || record.OperationKey == "" || record.RequestDigest == "" {
		return ErrInvalid
	}
	current, found := journal.entries[record.OperationKey]
	if found && current.digest != record.RequestDigest {
		return ErrUnauthorized
	}
	switch record.State {
	case pairingJournalRunning:
		if found || !emptyPairingReceipt(record.Receipt) {
			return ErrInvalid
		}
		journal.entries[record.OperationKey] = pairingJournalEntry{digest: record.RequestDigest, state: record.State}
	case pairingJournalTerminal:
		if !found || current.state != pairingJournalRunning || !validPairingJournalReceipt(record.Receipt) {
			return ErrInvalid
		}
		journal.entries[record.OperationKey] = pairingJournalEntry{
			digest: record.RequestDigest, state: record.State, receipt: clonePairingJournalReceipt(record.Receipt),
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (journal *FilePairingJournal) Begin(operationKey, requestDigest string) (pairingJournalReceipt, bool, error) {
	if journal == nil || operationKey == "" || requestDigest == "" {
		return pairingJournalReceipt{}, false, ErrInvalid
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if current, found := journal.entries[operationKey]; found {
		if current.digest != requestDigest {
			return pairingJournalReceipt{}, false, ErrUnauthorized
		}
		if current.state == pairingJournalTerminal {
			return clonePairingJournalReceipt(current.receipt), true, nil
		}
		return pairingJournalReceipt{}, false, ErrUnavailable
	}
	record := pairingJournalRecord{
		SchemaVersion: pairingJournalSchema, OperationKey: operationKey,
		RequestDigest: requestDigest, State: pairingJournalRunning,
	}
	if err := journal.append(record); err != nil {
		return pairingJournalReceipt{}, false, err
	}
	journal.entries[operationKey] = pairingJournalEntry{digest: requestDigest, state: pairingJournalRunning}
	return pairingJournalReceipt{}, false, nil
}

func (journal *FilePairingJournal) Complete(operationKey, requestDigest string, receipt pairingJournalReceipt) error {
	if journal == nil || !validPairingJournalReceipt(receipt) {
		return ErrInvalid
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	current, found := journal.entries[operationKey]
	if !found || current.digest != requestDigest || current.state != pairingJournalRunning {
		return ErrUnauthorized
	}
	record := pairingJournalRecord{
		SchemaVersion: pairingJournalSchema, OperationKey: operationKey,
		RequestDigest: requestDigest, State: pairingJournalTerminal, Receipt: clonePairingJournalReceipt(receipt),
	}
	if err := journal.append(record); err != nil {
		return err
	}
	journal.entries[operationKey] = pairingJournalEntry{
		digest: requestDigest, state: pairingJournalTerminal, receipt: clonePairingJournalReceipt(receipt),
	}
	return nil
}

func (journal *FilePairingJournal) append(record pairingJournalRecord) error {
	payload, err := canonical.Marshal(record)
	if err != nil || len(payload) > maxPairingJournalFrame {
		return ErrUnavailable
	}
	defer clear(payload)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	file, err := os.OpenFile(journal.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return ErrUnavailable
	}
	if _, err := file.Write(header[:]); err != nil {
		_ = file.Close()
		return ErrUnavailable
	}
	if _, err := file.Write(payload); err != nil || file.Sync() != nil || file.Close() != nil {
		return ErrUnavailable
	}
	return nil
}

func validPairingJournalReceipt(value pairingJournalReceipt) bool {
	return (value.Begin != nil) != (value.Resume != nil) &&
		((value.Begin != nil && len(value.Begin.Signature) == 64) ||
			(value.Resume != nil && len(value.Resume.Signature) == 64))
}

func emptyPairingReceipt(value pairingJournalReceipt) bool {
	return value.Begin == nil && value.Resume == nil
}

func clonePairingJournalReceipt(value pairingJournalReceipt) pairingJournalReceipt {
	if value.Begin != nil {
		cloned := clonePairingBeginReceipt(*value.Begin)
		value.Begin = &cloned
	}
	if value.Resume != nil {
		cloned := clonePairingResumeReceipt(*value.Resume)
		value.Resume = &cloned
	}
	return value
}

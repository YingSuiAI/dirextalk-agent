//go:build darwin || linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"golang.org/x/sys/unix"
)

type receiptJournal struct {
	root string
	uid  uint32
}

type lockedReceipt struct {
	key         receiptKey
	receiptName string
	uid         uint32
	rootFD      int
	lockFD      int
}

func newReceiptJournal(root string, uid uint32) (*receiptJournal, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errInput
	}
	state, err := os.Lstat(root)
	if err != nil || !state.IsDir() || state.Mode().Perm() != 0o700 {
		return nil, errInput
	}
	system, ok := state.Sys().(*syscall.Stat_t)
	if !ok || uint32(system.Uid) != uid {
		return nil, errInput
	}
	return &receiptJournal{root: root, uid: uid}, nil
}

func (journal *receiptJournal) lock(ctx context.Context, key receiptKey) (*lockedReceipt, error) {
	if journal == nil || ctx == nil || key.validate() != nil {
		return nil, errInput
	}
	rootFD, err := unix.Open(journal.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt root open: %v", errInput, err)
	}
	name := receiptFileName(key)
	lockFD := -1
	for {
		lockFD, err = unix.Openat(rootFD, name+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINTR) {
			_ = unix.Close(rootFD)
			return nil, fmt.Errorf("%w: receipt lock open: %v", errInput, err)
		}
		select {
		case <-ctx.Done():
			_ = unix.Close(rootFD)
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = validateOwnedFile(lockFD, journal.uid, 0, false); err != nil {
		if lockFD >= 0 {
			_ = unix.Close(lockFD)
		}
		_ = unix.Close(rootFD)
		return nil, fmt.Errorf("%w: receipt lock validation: %v", errInput, err)
	}
	for {
		err = unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &lockedReceipt{key: key, receiptName: name, uid: journal.uid, rootFD: rootFD, lockFD: lockFD}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = unix.Close(lockFD)
			_ = unix.Close(rootFD)
			return nil, fmt.Errorf("%w: receipt lock acquisition: %v", errInput, err)
		}
		select {
		case <-ctx.Done():
			_ = unix.Close(lockFD)
			_ = unix.Close(rootFD)
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (locked *lockedReceipt) close() error {
	if locked == nil {
		return nil
	}
	var result error
	if locked.lockFD >= 0 {
		if err := unix.Flock(locked.lockFD, unix.LOCK_UN); err != nil {
			result = errInput
		}
		if err := unix.Close(locked.lockFD); err != nil {
			result = errInput
		}
		locked.lockFD = -1
	}
	if locked.rootFD >= 0 {
		if err := unix.Close(locked.rootFD); err != nil {
			result = errInput
		}
		locked.rootFD = -1
	}
	return result
}

func (locked *lockedReceipt) load() (executionReceipt, bool, error) {
	if locked == nil || locked.rootFD < 0 || locked.lockFD < 0 {
		return executionReceipt{}, false, errInput
	}
	fd, err := unix.Openat(locked.rootFD, locked.receiptName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return executionReceipt{}, false, nil
	}
	if err != nil || validateOwnedFile(fd, locked.uid, maxReceiptBytes, true) != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return executionReceipt{}, false, errInput
	}
	file := os.NewFile(uintptr(fd), "worker-receipt")
	raw, err := io.ReadAll(io.LimitReader(file, maxReceiptBytes+1))
	_ = file.Close()
	if err != nil {
		clear(raw)
		return executionReceipt{}, false, errInput
	}
	receipt, err := decodeReceipt(raw, locked.key)
	clear(raw)
	if err != nil {
		return executionReceipt{}, false, errInput
	}
	return receipt, true, nil
}

func (locked *lockedReceipt) commitLaunch(request *agentv1.CoreTeamWorkerServiceCompleteRequest) error {
	if _, found, err := locked.load(); err != nil || found {
		return errInput
	}
	raw, err := marshalCompleteRequest(request, locked.key)
	if err != nil || request.GetOutcome() != agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_FAILED ||
		request.GetFailureCode() != agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_EXECUTION_UNCERTAIN {
		clear(raw)
		return errInput
	}
	defer clear(raw)
	return locked.write(newExecutionReceipt(locked.key, receiptLaunchCommitted, raw))
}

func (locked *lockedReceipt) commitPending(request *agentv1.CoreTeamWorkerServiceCompleteRequest) error {
	receipt, found, err := locked.load()
	if err != nil || !found || receipt.State != receiptLaunchCommitted {
		return errInput
	}
	raw, err := marshalCompleteRequest(request, locked.key)
	if err != nil {
		return err
	}
	defer clear(raw)
	return locked.write(newExecutionReceipt(locked.key, receiptCompletionPending, raw))
}

func (locked *lockedReceipt) commitAcknowledged() error {
	receipt, found, err := locked.load()
	if err != nil || !found || receipt.State != receiptCompletionPending {
		return errInput
	}
	return locked.write(newExecutionReceipt(locked.key, receiptCompletionAcknowledged, receipt.CompletionRequest))
}

func (locked *lockedReceipt) write(receipt executionReceipt) error {
	if locked == nil || locked.rootFD < 0 || locked.lockFD < 0 || receipt.validate(locked.key) != nil {
		return errInput
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) == 0 || len(raw) > maxReceiptBytes {
		clear(raw)
		return errInput
	}
	defer clear(raw)
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		return errInput
	}
	temporaryName := ".receipt-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := unix.Openat(locked.rootFD, temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errInput
	}
	temporary := os.NewFile(uintptr(fd), "worker-receipt-temporary")
	if _, err = temporary.Write(raw); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = unix.Unlinkat(locked.rootFD, temporaryName, 0)
		return errInput
	}
	if err = unix.Renameat(locked.rootFD, temporaryName, locked.rootFD, locked.receiptName); err != nil {
		_ = unix.Unlinkat(locked.rootFD, temporaryName, 0)
		return errInput
	}
	if err = unix.Fsync(locked.rootFD); err != nil {
		return errInput
	}
	return nil
}

func receiptFileName(key receiptKey) string {
	digest := sha256.Sum256([]byte(key.String()))
	return "receipt-" + hex.EncodeToString(digest[:]) + ".json"
}

func validateOwnedFile(fd int, uid uint32, maximum int64, requireContent bool) error {
	if fd < 0 {
		return errInput
	}
	var state unix.Stat_t
	if unix.Fstat(fd, &state) != nil || state.Mode&unix.S_IFMT != unix.S_IFREG || state.Uid != uid ||
		state.Mode&0o777 != 0o600 || state.Nlink != 1 {
		return errInput
	}
	if requireContent && (state.Size <= 0 || state.Size > maximum) {
		return errInput
	}
	return nil
}

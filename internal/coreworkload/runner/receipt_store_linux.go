//go:build linux

package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReceiptStore is a tiny append-free supervisor journal, not an Agent DB.
// Each immutable receipt is atomically written, fsynced and named by a digest
// of its fence key; Agent workload records remain the durable authority.
type ReceiptStore struct {
	root string
	uid  uint32
}

// OperationIntent is a fsynced per-operation journal record. It is distinct
// from the workload receipt so a later Destroy can find the ready service
// without treating a stale Apply operation as replayable.
type OperationIntent struct {
	Request Request `json:"request"`
	State   string  `json:"state"` // applying, ready, destroying, destroyed, unknown
	Receipt Receipt `json:"receipt,omitempty"`
}

func intentName(key string) string { return "intent-" + receiptName(key) }
func (s *ReceiptStore) GetIntent(key string) (OperationIntent, bool, error) {
	b, ok, err := s.readFile(intentName(key))
	if err != nil || !ok {
		return OperationIntent{}, ok, err
	}
	var in OperationIntent
	if json.Unmarshal(b, &in) != nil || in.Request.Validate() != nil || in.Request.Key() != key {
		return OperationIntent{}, false, ErrDenied
	}
	return in, true, nil
}
func (s *ReceiptStore) PutIntent(in OperationIntent) error {
	if in.Request.Validate() != nil || (in.State != "applying" && in.State != "ready" && in.State != "destroying" && in.State != "destroyed" && in.State != "unknown") {
		return ErrDenied
	}
	b, e := json.Marshal(in)
	if e != nil {
		return ErrDenied
	}
	return s.writeFile(intentName(in.Request.Key()), b, false)
}
func (s *ReceiptStore) ReplaceIntent(in OperationIntent) error {
	if in.Request.Validate() != nil {
		return ErrDenied
	}
	b, e := json.Marshal(in)
	if e != nil {
		return ErrDenied
	}
	return s.writeFile(intentName(in.Request.Key()), b, true)
}

func (s *ReceiptStore) readFile(name string) ([]byte, bool, error) {
	root, e := unix.Open(s.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, false, ErrDenied
	}
	defer unix.Close(root)
	fd, e := unix.Openat2(root, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e == unix.ENOENT {
		return nil, false, nil
	}
	if e != nil {
		return nil, false, ErrDenied
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != s.uid || st.Mode&0o077 != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > MaxPacketBytes {
		return nil, false, ErrDenied
	}
	f := os.NewFile(uintptr(fd), "intent")
	b, e := io.ReadAll(io.LimitReader(f, MaxPacketBytes+1))
	_ = f.Close()
	if e != nil || int64(len(b)) != st.Size {
		return nil, false, ErrDenied
	}
	return b, true, nil
}
func (s *ReceiptStore) writeFile(name string, b []byte, replace bool) error {
	if len(b) == 0 || len(b) > MaxPacketBytes {
		return ErrDenied
	}
	target := filepath.Join(s.root, name)
	if !replace {
		if _, ok, e := s.readFile(name); e != nil {
			return e
		} else if ok {
			return ErrReplay
		}
	}
	tmp := target + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrDenied
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	_ = f.Close()
	if e != nil {
		_ = os.Remove(tmp)
		return ErrDenied
	}
	if e = os.Rename(tmp, target); e != nil {
		_ = os.Remove(tmp)
		return ErrDenied
	}
	d, e := os.Open(s.root)
	if e == nil {
		e = d.Sync()
		_ = d.Close()
	}
	return e
}

func NewReceiptStore(root string, uid uint32) (*ReceiptStore, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || uid == 0 {
		return nil, ErrDenied
	}
	st, e := os.Stat(root)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return nil, ErrDenied
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || uint32(sys.Uid) != uid {
		return nil, ErrDenied
	}
	return &ReceiptStore{root, uid}, nil
}
func receiptName(key string) string {
	s := sha256.Sum256([]byte(key))
	return hex.EncodeToString(s[:]) + ".json"
}
func (s *ReceiptStore) Get(key string) (Receipt, bool, error) {
	root, e := unix.Open(s.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return Receipt{}, false, ErrDenied
	}
	defer unix.Close(root)
	fd, e := unix.Openat2(root, receiptName(key), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e == unix.ENOENT {
		return Receipt{}, false, nil
	}
	if e != nil {
		return Receipt{}, false, ErrDenied
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != s.uid || st.Mode&0o077 != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > MaxPacketBytes {
		return Receipt{}, false, ErrDenied
	}
	f := os.NewFile(uintptr(fd), "receipt")
	b, e := io.ReadAll(io.LimitReader(f, MaxPacketBytes+1))
	_ = f.Close()
	fd = -1
	if e != nil || int64(len(b)) != st.Size {
		return Receipt{}, false, ErrDenied
	}
	var r Receipt
	if json.Unmarshal(b, &r) != nil {
		return Receipt{}, false, ErrDenied
	}
	if r.Digest == "" {
		return Receipt{}, false, ErrDenied
	}
	return r, true, nil
}
func (s *ReceiptStore) Put(key string, r Receipt) error {
	target := filepath.Join(s.root, receiptName(key))
	if old, ok, e := s.Get(key); e != nil {
		return e
	} else if ok {
		if old.Digest != r.Digest {
			return ErrReplay
		}
		return nil
	}
	b, e := json.Marshal(r)
	if e != nil {
		return ErrDenied
	}
	tmp := target + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrDenied
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	_ = f.Close()
	if e != nil {
		_ = os.Remove(tmp)
		return ErrDenied
	}
	if e = os.Rename(tmp, target); e != nil {
		_ = os.Remove(tmp)
		return ErrDenied
	}
	d, e := os.Open(s.root)
	if e == nil {
		e = d.Sync()
		_ = d.Close()
	}
	return e
}

// Replace is only for a verified lifecycle transition (ready -> destroyed).
// It retains the original admission digest and uses the same fsync/rename
// durability boundary as Put.
func (s *ReceiptStore) Replace(key string, oldDigest string, r Receipt) error {
	old, ok, err := s.Get(key)
	if err != nil || !ok || old.Digest != oldDigest || old.ApplyDigest == "" || !r.Destroyed || r.ApplyDigest != old.ApplyDigest {
		return ErrDenied
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) == 0 || len(b) > MaxPacketBytes {
		return ErrDenied
	}
	target := filepath.Join(s.root, receiptName(key))
	tmp := target + ".replace.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrDenied
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return ErrDenied
	}
	if err = os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return ErrDenied
	}
	d, err := os.Open(s.root)
	if err == nil {
		err = d.Sync()
		_ = d.Close()
	}
	return err
}

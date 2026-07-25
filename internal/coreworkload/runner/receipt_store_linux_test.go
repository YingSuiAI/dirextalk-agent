//go:build linux

package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReceiptStoreRestartReplayAndConflict(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	s, e := NewReceiptStore(root, uint32(os.Geteuid()))
	if e != nil {
		t.Fatal(e)
	}
	r := Receipt{WorkloadID: "w", PlanDigest: "p", DispatchClaim: "c", DispatchEpoch: 1, Action: "apply", State: "ready", Digest: "digest"}
	if e = s.Put("w:p:c:apply", r); e != nil {
		t.Fatal(e)
	}
	// A fresh process sees the same immutable receipt; a changed request digest
	// cannot overwrite it.
	s, e = NewReceiptStore(root, uint32(os.Geteuid()))
	if e != nil {
		t.Fatal(e)
	}
	got, ok, e := s.Get("w:p:c:apply")
	if e != nil || !ok || got.Digest != r.Digest {
		t.Fatalf("got=%+v ok=%v err=%v", got, ok, e)
	}
	r.Digest = "other"
	if e = s.Put("w:p:c:apply", r); e == nil {
		t.Fatal("conflicting replay overwritten")
	}
}

func TestReceiptStoreRejectsTamperAndPathSwap(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	s, err := NewReceiptStore(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	key := "fence"
	if err = s.Put(key, Receipt{Digest: "d", ApplyDigest: "d", State: "ready"}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, receiptName(key))
	if err = os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Get(key); err == nil {
		t.Fatal("world-readable receipt accepted")
	}
	if err = os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/etc/passwd", p); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Get(key); err == nil {
		t.Fatal("symlink receipt accepted")
	}
}

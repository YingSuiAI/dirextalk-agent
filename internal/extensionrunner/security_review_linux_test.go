//go:build linux

package extensionrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSeqpacketCanonicalAndTruncation(t *testing.T) {
	r := sandboxRequest()
	packet, err := EncodeRequestV2(r)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sv[0])
	defer unix.Close(sv[1])
	if _, err = unix.SendmsgN(sv[0], append(packet, packet...), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(packet)*2)
	n, _, flags, _, err := unix.Recvmsg(sv[1], buf, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.MSG_TRUNC != 0 {
		t.Fatal("unexpected truncation")
	}
	if _, err = ReadRequestV2Datagram(buf[:n], nil); err == nil {
		t.Fatal("concatenated datagram accepted")
	}
	if _, err = unix.SendmsgN(sv[0], packet, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	short := make([]byte, len(packet)-1)
	n, _, flags, _, err = unix.Recvmsg(sv[1], short, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.MSG_TRUNC == 0 {
		t.Fatal("missing truncation flag")
	}
	if _, err = ReadRequestV2Datagram(short[:n], nil); err == nil {
		t.Fatal("truncated datagram accepted")
	}
	fd, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err = unix.SendmsgN(sv[0], packet, unix.UnixRights(fd), nil, 0); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len(packet))
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(sv[1], buf, oob, 0)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	var received []int
	for _, m := range msgs {
		x, e := unix.ParseUnixRights(&m)
		if e != nil {
			t.Fatal(e)
		}
		received = append(received, x...)
	}
	if _, err = ReadRequestV2Datagram(buf[:n], received); err == nil {
		t.Fatal("extra FD accepted")
	}
	closeReceivedFDs(received)
	for _, x := range received {
		if err := unix.Close(x); !errors.Is(err, unix.EBADF) {
			t.Fatalf("received fd leak: %v", err)
		}
	}
}

func TestListenFileListenerFailureTransfersOwnershipOnce(t *testing.T) {
	old := fileListener
	defer func() { fileListener = old }()
	called := false
	fileListener = func(f *os.File) (net.Listener, error) {
		called = true
		if _, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0); err != nil {
			t.Fatalf("fd not owned by file: %v", err)
		}
		return nil, errors.New("injected")
	}
	path := filepath.Join(t.TempDir(), "runner.sock")
	if _, err := Listen(path, 0o700); err == nil || !called {
		t.Fatalf("err=%v called=%v", err, called)
	}
	_ = os.Remove(path)
}

func TestServeV2ConnectionClosesReceivedFDs(t *testing.T) {
	base, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	packet, err := EncodeRequestV2(sandboxRequest())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		payload, oob []byte
	}{
		{"success", packet, nil},
		{"malformed", []byte("not-json"), nil},
		{"unexpected-cmsg", []byte("bad"), unix.UnixCredentials(&unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 8; i++ {
				sv, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
				if e != nil {
					t.Fatal(e)
				}
				fd, e := unix.Dup(0)
				if e != nil {
					t.Fatal(e)
				}
				oob := tc.oob
				if oob == nil {
					oob = unix.UnixRights(fd)
				}
				if _, e = unix.SendmsgN(sv[0], tc.payload, oob, nil, 0); e != nil {
					unix.Close(fd)
					unix.Close(sv[0])
					unix.Close(sv[1])
					if tc.name == "unexpected-cmsg" || tc.name == "truncated" {
						t.Skip(e)
					}
					t.Fatal(e)
				}
				unix.Close(fd)
				f := os.NewFile(uintptr(sv[1]), "server")
				c, e := net.FileConn(f)
				_ = f.Close()
				if e != nil {
					t.Fatal(e)
				}
				s := Server{Authorizer: UIDAllowlist{uint32(os.Getuid()): {}}, Registry: NewRunRegistry()}
				s.serveV2Connection(context.Background(), c.(*net.UnixConn), make(chan struct{}, serverMaxExecutions))
				unix.Close(sv[0])
			}
			after, e := os.ReadDir("/proc/self/fd")
			if e != nil {
				t.Fatal(e)
			}
			if len(after) != len(base) {
				t.Fatalf("fd leak: before=%d after=%d", len(base), len(after))
			}
		})
	}
}

func TestServeV2ConnectionAcceptsSealedRightsAndClosesReceivedFD(t *testing.T) {
	stdin := []byte("sealed stdin")
	fd, err := unix.MemfdCreate("stdin", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, stdin); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(stdin)
	r := sandboxRequest()
	r.Stdin = &FDRef{Index: 0, Size: int64(len(stdin)), SHA256: hex.EncodeToString(sum[:])}
	packet, err := EncodeRequestV2(r)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sv[0])
	if _, err = unix.SendmsgN(sv[0], packet, unix.UnixRights(fd), nil, 0); err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(sv[1]), "server")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	reg := NewRunRegistry()
	s := Server{Authorizer: UIDAllowlist{uint32(os.Getuid()): {}}, Registry: reg}
	s.serveV2Connection(context.Background(), c.(*net.UnixConn), make(chan struct{}, serverMaxExecutions))
	if _, ok := reg.TombstoneOf(r.RunID); !ok {
		t.Fatal("valid rights request did not reach Runner")
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(base)-1 { // server connection itself is closed by Serve.
		t.Fatalf("received fd leak: before=%d after=%d", len(base), len(after))
	}
}

func TestServeV2ConnectionRejectsNonRightsCmsgBeforeRunner(t *testing.T) {
	packet, err := EncodeRequestV2(sandboxRequest())
	if err != nil {
		t.Fatal(err)
	}
	sv, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sv[0])
	if err := unix.SetsockoptInt(sv[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	oob := unix.UnixCredentials(&unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())})
	if _, err = unix.SendmsgN(sv[0], packet, oob, nil, 0); err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(sv[1]), "server")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRunRegistry()
	s := Server{Authorizer: UIDAllowlist{uint32(os.Getuid()): {}}, Registry: reg}
	s.serveV2Connection(context.Background(), c.(*net.UnixConn), make(chan struct{}, serverMaxExecutions))
	if _, ok := reg.TombstoneOf(sandboxRequest().RunID); ok {
		t.Fatal("non-rights cmsg reached Runner")
	}
	if _, ok := reg.PhaseOf(sandboxRequest().RunID); ok {
		t.Fatal("non-rights cmsg reached Runner")
	}
}

func TestServeV2ConnectionClosesRightsOnTruncation(t *testing.T) {
	fd, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	oob := unix.UnixRights(fd)
	old := readMsgUnix
	defer func() { readMsgUnix = old }()
	readMsgUnix = func(_ *net.UnixConn, _ []byte, dst []byte) (int, int, int, *net.UnixAddr, error) {
		copy(dst, oob)
		return 0, len(oob), unix.MSG_TRUNC, nil, nil
	}
	sv, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	defer unix.Close(sv[0])
	f := os.NewFile(uintptr(sv[1]), "server")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	s := Server{Authorizer: UIDAllowlist{uint32(os.Getuid()): {}}, Registry: NewRunRegistry()}
	s.serveV2Connection(context.Background(), c.(*net.UnixConn), make(chan struct{}, serverMaxExecutions))
	if err := unix.Close(fd); !errors.Is(err, unix.EBADF) {
		t.Fatalf("truncated rights fd leak: %v", err)
	}
}

func TestListenUsesSeqpacket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runner.sock")
	ln, err := Listen(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = ln.Close()
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatalf("socket not unlinked: %v", e)
		}
	}()
	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var typ int
	if err := raw.Control(func(fd uintptr) { typ, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE) }); err != nil {
		t.Fatal(err)
	}
	if typ != unix.SOCK_SEQPACKET {
		t.Fatalf("socket type=%d", typ)
	}
}

func TestCanonicalUUIDAndFDLeakClose(t *testing.T) {
	r := sandboxRequest()
	r.RunID = "11111111-1111-4111-8111-111111111111"
	if err := ValidateRequestV2(r); err != nil {
		t.Fatal(err)
	}
	r.RunID = "11111111-1111-4111-8111-11111111111A"
	if err := ValidateRequestV2(r); err == nil {
		t.Fatal("noncanonical UUID accepted")
	}
	fd, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	closeReceivedFDs([]int{fd})
	if err := unix.Close(fd); !errors.Is(err, unix.EBADF) {
		t.Fatalf("fd was not closed: %v", err)
	}
}

func TestForeignAndDynamicELFRejected(t *testing.T) {
	b, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	p := filepath.Join(root, "entry")
	if err := os.WriteFile(p, b, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	m := []ManifestEntry{{Path: "entry", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))}}
	if err := AdmitInstall(root, ManifestDigest(m), m); err == nil {
		t.Fatal("dynamic ELF accepted")
	}
	if len(b) > 20 {
		b[18] = 3
		b[19] = 0
	}
	if err := os.WriteFile(p, b, 0o700); err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256(b)
	m[0].SHA256 = hex.EncodeToString(sum[:])
	if err := AdmitInstall(root, ManifestDigest(m), m); err == nil {
		t.Fatal("foreign ELF accepted")
	}
}

func TestAdmissionRejectsSymlinkedRoot(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "install")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	m := []ManifestEntry{{Path: "entry", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 0}}
	if err := AdmitInstall(link, ManifestDigest(m), m); err == nil {
		t.Fatal("symlinked root accepted")
	}
}

func TestAdmittedInstallCloseIsExactlyOnce(t *testing.T) {
	rootFD, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	entryFD, err := unix.Dup(0)
	if err != nil {
		unix.Close(rootFD)
		t.Fatal(err)
	}
	a := &AdmittedInstall{rootFile: os.NewFile(uintptr(rootFD), "root"), entryFile: os.NewFile(uintptr(entryFD), "entry")}
	runtime.GC()
	dup, err := a.DupEntryFD()
	if err != nil {
		t.Fatalf("entry fd lost to finalizer: %v", err)
	}
	if err := unix.Close(dup); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{rootFD, entryFD} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("fd %d remained open: %v", fd, err)
		}
	}
	if _, err := a.DupEntryFD(); err == nil {
		t.Fatal("closed entry fd duplicated")
	}
}

func TestAdmissionRejectsFIFONonblocking(t *testing.T) {
	root := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(root, "entry"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := []ManifestEntry{{Path: "entry", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 0}}
	done := make(chan error, 1)
	go func() { done <- AdmitInstall(root, ManifestDigest(m), m) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO admission blocked")
	}
}

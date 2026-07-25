//go:build linux

package extensionrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// PeerAuthorizer is normally configured with the dedicated Agent service UID.
// Socket filesystem mode is defense in depth; credentials are authoritative.
type PeerAuthorizer interface{ Allow(uid uint32) bool }
type UIDAllowlist map[uint32]struct{}

func (a UIDAllowlist) Allow(uid uint32) bool { _, ok := a[uid]; return ok }

type Server struct {
	Listener        UnixListener
	Authorizer      PeerAuthorizer
	Runner          Runner
	Registry        *RunRegistry
	PublicationRoot string
}
type UnixListener interface {
	AcceptUnix() (*net.UnixConn, error)
	Close() error
}
type ManagedUnixListener struct {
	*net.UnixListener
	path string
	once sync.Once
}

// fileListener is a seam for exercising ownership failures. net.FileListener
// duplicates the descriptor; ownership of the os.File stays with this caller.
var fileListener = net.FileListener
var readMsgUnix = readMsgUnixCloexec

func readMsgUnixCloexec(conn *net.UnixConn, b, oob []byte) (int, int, int, *net.UnixAddr, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	var n, oobn, flags int
	var from unix.Sockaddr
	var recvErr error
	err = raw.Read(func(fd uintptr) bool {
		n, oobn, flags, from, recvErr = unix.Recvmsg(int(fd), b, oob, unix.MSG_CMSG_CLOEXEC)
		return recvErr != unix.EAGAIN && recvErr != unix.EWOULDBLOCK
	})
	if err != nil {
		return 0, 0, 0, nil, err
	}
	return n, oobn, flags, sockaddrUnixAddr(from), recvErr
}

func sockaddrUnixAddr(addr unix.Sockaddr) *net.UnixAddr {
	if a, ok := addr.(*unix.SockaddrUnix); ok {
		return &net.UnixAddr{Name: a.Name, Net: "unixpacket"}
	}
	return nil
}

func (l *ManagedUnixListener) Close() error {
	var err error
	l.once.Do(func() {
		err = l.UnixListener.Close()
		if st, e := os.Lstat(l.path); e == nil && st.Mode()&os.ModeSocket != 0 {
			if s, ok := st.Sys().(*syscall.Stat_t); ok && uint32(s.Uid) == uint32(os.Getuid()) {
				_ = os.Remove(l.path)
			}
		}
	})
	return err
}

// ServeV2 is the production descriptor-only protocol entry point. It consumes
// exactly one length-prefixed seqpacket-style message plus SCM_RIGHTS descriptors.
func (s Server) ServeV2(ctx context.Context) error {
	if s.Listener == nil || s.Authorizer == nil || s.Registry == nil {
		return ErrUnavailable
	}
	go func() { <-ctx.Done(); _ = s.Listener.Close() }()
	for {
		conn, err := s.Listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveV2Connection(ctx, conn)
	}
}

func (s Server) serveV2Connection(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil || !s.Authorizer.Allow(uid) {
		return
	}
	buf := make([]byte, MaxV2PacketBytes)
	oob := make([]byte, unix.CmsgSpace(4096*4))
	n, oobn, flags, _, err := readMsgUnix(conn, buf, oob)
	fds := []int{}
	defer func() { closeReceivedFDs(fds) }()
	fds, controlErr := collectRightsCmsgs(oob[:oobn])
	// Parse every complete control message before considering truncation so that
	// descriptors already installed by the kernel are always closed.
	if err != nil || controlErr != nil || flags&unix.MSG_TRUNC != 0 || flags&unix.MSG_CTRUNC != 0 {
		return
	}
	packet := buf[:n]
	if len(bytes.TrimSpace(packet)) > 0 && bytes.TrimSpace(packet)[0] == '{' {
		var envelope struct {
			Op string `json:"op"`
		}
		if json.Unmarshal(packet, &envelope) != nil {
			return
		}
		switch envelope.Op {
		case "publish_v1":
			resp := s.publish(packet, fds)
			writePublicationResponse(conn, resp, -1)
			return
		case "remove_v1":
			if len(fds) != 0 {
				return
			}
			var q RemoveRequest
			if decodeCanonicalPublication(packet, &q) != nil {
				return
			}
			resp, removeErr := s.remove(q)
			if removeErr != nil {
				return
			}
			writePublicationResponse(conn, resp, -1)
			return
		case "read_v1":
			if len(fds) != 0 {
				return
			}
			var q ReadInstallRequest
			if decodeCanonicalPublication(packet, &q) != nil {
				return
			}
			resp, file, readErr := s.read(q)
			if readErr != nil {
				return
			}
			defer file.Close()
			writePublicationResponse(conn, resp, int(file.Fd()))
			return
		default:
			return
		}
	}
	r, err := ReadRequestV2Datagram(buf[:n], fds)
	if err != nil {
		return
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	runDone := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		monitorPeerDisconnect(conn, runDone, cancelRun)
		close(monitorDone)
	}()
	status, err := s.Runner.RunV2(runCtx, r, fds, s.Registry)
	close(runDone)
	cancelRun()
	<-monitorDone
	if err != nil {
		status.Error = errorCodeFor(err)
		if status.Phase == "" {
			status.Phase = PhaseFailed
		}
	}
	status = fitStatusV1Packet(status)
	payload, e := EncodeStatusV1(status)
	if e != nil {
		return
	}
	if n, writeErr := conn.Write(payload); writeErr != nil || n != len(payload) {
		return
	}
}

func writePublicationResponse(conn *net.UnixConn, response any, fd int) {
	payload, err := encodeCanonicalPublication(response)
	if err != nil {
		return
	}
	if fd >= 0 {
		n, _, err := conn.WriteMsgUnix(payload, unix.UnixRights(fd), nil)
		if err != nil || n != len(payload) {
			return
		}
		return
	}
	_, _ = conn.Write(payload)
}

func (s Server) publicationRootFD() (int, error) {
	if !filepath.IsAbs(s.PublicationRoot) || filepath.Clean(s.PublicationRoot) != s.PublicationRoot || s.PublicationRoot == "/" {
		return -1, ErrPublicationDenied
	}
	fd, err := unix.Open(s.PublicationRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrPublicationDenied
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return -1, ErrPublicationDenied
	}
	return fd, nil
}

func (s Server) remove(q RemoveRequest) (RemoveResponse, error) {
	if q.Validate() != nil {
		return RemoveResponse{}, ErrPublicationDenied
	}
	rootFD, err := s.publicationRootFD()
	if err != nil {
		return RemoveResponse{}, err
	}
	defer unix.Close(rootFD)
	tombstone := ".remove-" + q.Digest
	_ = removePublishedTree(filepath.Join(s.PublicationRoot, tombstone))
	admitted, err := (DiskBundleResolver{Root: s.PublicationRoot}).ResolveBundle(q.Digest)
	if errors.Is(err, os.ErrNotExist) {
		_ = unix.Fsync(rootFD)
		return RemoveResponse{Digest: q.Digest}, nil
	}
	if err != nil {
		var stat unix.Stat_t
		if unix.Fstatat(rootFD, q.Digest, &stat, unix.AT_SYMLINK_NOFOLLOW) == unix.ENOENT {
			_ = unix.Fsync(rootFD)
			return RemoveResponse{Digest: q.Digest}, nil
		}
		return RemoveResponse{}, ErrPublicationDenied
	}
	_ = admitted.Close()
	if err = unix.Renameat(rootFD, q.Digest, rootFD, tombstone); err != nil {
		if err == unix.ENOENT {
			return RemoveResponse{Digest: q.Digest}, nil
		}
		return RemoveResponse{}, ErrPublicationDenied
	}
	if err = removePublishedTree(filepath.Join(s.PublicationRoot, tombstone)); err != nil {
		return RemoveResponse{}, ErrPublicationDenied
	}
	if err = unix.Fsync(rootFD); err != nil {
		return RemoveResponse{}, ErrPublicationDenied
	}
	return RemoveResponse{Digest: q.Digest}, nil
}

func (s Server) read(q ReadInstallRequest) (ReadInstallResponse, *os.File, error) {
	if q.Validate() != nil {
		return ReadInstallResponse{}, nil, ErrPublicationDenied
	}
	rootFD, err := s.publicationRootFD()
	if err != nil {
		return ReadInstallResponse{}, nil, err
	}
	_ = unix.Close(rootFD)
	admitted, err := (DiskBundleResolver{Root: s.PublicationRoot}).ResolveBundle(q.Digest)
	if err != nil {
		return ReadInstallResponse{}, nil, ErrPublicationDenied
	}
	defer admitted.Close()
	installFD, err := admitted.DupRootFD()
	if err != nil {
		return ReadInstallResponse{}, nil, ErrPublicationDenied
	}
	defer unix.Close(installFD)
	fd, err := openInstallEntry(installFD, q.Path)
	if err != nil {
		return ReadInstallResponse{}, nil, ErrPublicationDenied
	}
	file := os.NewFile(uintptr(fd), q.Path)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) ||
		stat.Mode&0o222 != 0 || stat.Mode&0o6000 != 0 || stat.Nlink != 1 || stat.Size < 0 || stat.Size > MaxOutputBytes {
		_ = file.Close()
		return ReadInstallResponse{}, nil, ErrPublicationDenied
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, MaxOutputBytes+1))
	if err != nil || n != stat.Size || n > MaxOutputBytes {
		_ = file.Close()
		return ReadInstallResponse{}, nil, ErrPublicationDenied
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return ReadInstallResponse{}, nil, ErrPublicationDenied
	}
	return ReadInstallResponse{Digest: q.Digest, Path: q.Path, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: n}, file, nil
}

func (s Server) publish(payload []byte, fds []int) any {
	r, err := DecodePublishRequest(payload)
	if err != nil || ValidatePublishRequest(r, len(fds)) != nil {
		return struct {
			Error string `json:"error"`
		}{Error: "denied"}
	}
	rootFD, err := s.publicationRootFD()
	if err != nil {
		return struct {
			Error string `json:"error"`
		}{Error: "denied"}
	}
	defer unix.Close(rootFD)
	if admitted, resolveErr := (DiskBundleResolver{Root: s.PublicationRoot}).ResolveBundle(r.Digest); resolveErr == nil {
		_ = admitted.Close()
		return PublishResponse{Digest: r.Digest, Replayed: true}
	} else {
		var stat unix.Stat_t
		if unix.Fstatat(rootFD, r.Digest, &stat, unix.AT_SYMLINK_NOFOLLOW) == nil {
			return struct {
				Error string `json:"error"`
			}{Error: "denied"}
		}
	}
	_ = removePublishedTree(filepath.Join(s.PublicationRoot, ".remove-"+r.Digest))
	tmp, err := os.MkdirTemp(s.PublicationRoot, ".publish-")
	if err != nil {
		return struct {
			Error string `json:"error"`
		}{Error: "unavailable"}
	}
	defer removePublishedTree(tmp)
	for i, e := range r.Entries {
		if fds[i] < 0 {
			return struct {
				Error string `json:"error"`
			}{Error: "denied"}
		}
		dup, dupErr := unix.Dup(fds[i])
		if dupErr != nil {
			return struct {
				Error string `json:"error"`
			}{Error: "denied"}
		}
		f := os.NewFile(uintptr(dup), e.Path)
		b, er := io.ReadAll(io.LimitReader(f, e.Size+1))
		_ = f.Close()
		if er != nil || int64(len(b)) != e.Size {
			return struct {
				Error string `json:"error"`
			}{Error: "denied"}
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != e.SHA256 {
			return struct {
				Error string `json:"error"`
			}{Error: "denied"}
		}
		p := filepath.Join(tmp, filepath.FromSlash(e.Path))
		if er = os.MkdirAll(filepath.Dir(p), 0700); er != nil {
			return struct {
				Error string `json:"error"`
			}{Error: "denied"}
		}
		mode := os.FileMode(0400)
		if e.Path == "entry" {
			mode = 0500
		}
		if er = os.WriteFile(p, b, 0600); er != nil || os.Chmod(p, mode) != nil {
			return struct {
				Error string `json:"error"`
			}{Error: "denied"}
		}
	}
	manifest, _ := json.Marshal(DiskInstallManifestV1{SchemaVersion: installManifestSchemaV1, Entries: r.Entries})
	if err = os.WriteFile(filepath.Join(tmp, installManifestName), append(manifest, '\n'), 0400); err != nil {
		return struct {
			Error string `json:"error"`
		}{Error: "denied"}
	}
	if err = makePublishedTreeImmutable(tmp); err != nil {
		return struct {
			Error string `json:"error"`
		}{Error: "denied"}
	}
	admitted, err := OpenAdmittedBundle(tmp, r.Digest, r.Entries)
	if err != nil {
		return struct {
			Error string `json:"error"`
		}{Error: "denied"}
	}
	_ = admitted.Close()
	if err = os.Rename(tmp, filepath.Join(s.PublicationRoot, r.Digest)); err != nil {
		if existing, resolveErr := (DiskBundleResolver{Root: s.PublicationRoot}).ResolveBundle(r.Digest); resolveErr == nil {
			_ = existing.Close()
			return PublishResponse{Digest: r.Digest, Replayed: true}
		}
		return struct {
			Error string `json:"error"`
		}{Error: "denied"}
	}
	if err = unix.Fsync(rootFD); err != nil {
		return struct {
			Error string `json:"error"`
		}{Error: "unavailable"}
	}
	return PublishResponse{Digest: r.Digest}
}

func makePublishedTreeImmutable(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrPublicationDenied
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		err = file.Sync()
		closeErr := file.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		return err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		dir, err := os.Open(directories[i])
		if err != nil {
			return err
		}
		if err = dir.Sync(); err != nil {
			_ = dir.Close()
			return err
		}
		if err = dir.Close(); err != nil {
			return err
		}
		if err = os.Chmod(directories[i], 0500); err != nil {
			return err
		}
	}
	return nil
}

func removePublishedTree(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return ErrPublicationDenied
	}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if errors.Is(walkErr, os.ErrNotExist) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return os.Chmod(path, 0700)
		}
		return nil
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(root); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// fitStatusV1Packet preserves the terminal outcome while truncating optional
// diagnostics to the fixed seqpacket ABI bound.  EncodeStatusV1 remains the
// final canonical check, so an impossible metadata-only response is not sent.
func fitStatusV1Packet(status StatusV1) StatusV1 {
	for {
		if _, err := EncodeStatusV1(status); err == nil {
			return status
		}
		if len(status.Stderr) > 0 {
			status.Stderr = status.Stderr[:trimDiagnosticLength(len(status.Stderr))]
			continue
		}
		if len(status.Stdout) > 0 {
			status.Stdout = status.Stdout[:trimDiagnosticLength(len(status.Stdout))]
			continue
		}
		if len(status.Status) > 0 {
			status.Status = status.Status[:trimDiagnosticLength(len(status.Status))]
			continue
		}
		return status
	}
}

func trimDiagnosticLength(n int) int {
	if n > 1024 {
		return n - 1024
	}
	return n - 1
}

func monitorPeerDisconnect(conn *net.UnixConn, done <-chan struct{}, cancel context.CancelFunc) {
	raw, err := conn.SyscallConn()
	if err != nil {
		cancel()
		return
	}
	peerFD := -1
	if err = raw.Control(func(fd uintptr) {
		peerFD, err = unix.Dup(int(fd))
	}); err != nil || peerFD < 0 {
		cancel()
		return
	}
	defer unix.Close(peerFD)
	poll := []unix.PollFd{{Fd: int32(peerFD), Events: unix.POLLERR | unix.POLLHUP | unix.POLLRDHUP}}
	for {
		select {
		case <-done:
			return
		default:
		}
		n, pollErr := unix.Poll(poll, 25)
		if pollErr == unix.EINTR {
			continue
		}
		if pollErr != nil {
			cancel()
			return
		}
		if n > 0 && poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLRDHUP|unix.POLLNVAL) != 0 {
			cancel()
			return
		}
	}
}

func closeReceivedFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}
func errorCodeFor(err error) ErrorCode {
	switch {
	case errors.Is(err, ErrReplay):
		return ErrorReplay
	case errors.Is(err, ErrProtocol):
		return ErrorProtocolViolation
	case errors.Is(err, ErrDenied):
		return ErrorDeniedRequest
	case errors.Is(err, ErrInvalid):
		return ErrorInvalidRequest
	default:
		return ErrorUnavailableBackend
	}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	err = raw.Control(func(fd uintptr) { credential, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || credential == nil {
		return 0, ErrDenied
	}
	return credential.Uid, nil
}

// Listen creates a mode-restricted filesystem socket. The parent directory is
// deployment-owned; callers must also run the process under its dedicated UID.
func Listen(path string, mode os.FileMode) (*ManagedUnixListener, error) {
	if mode.Perm()&0o007 != 0 {
		return nil, ErrInvalid
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, ErrInvalid
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint32(st.Uid) != uint32(os.Getuid()) {
			return nil, ErrInvalid
		}
		probe, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		e = unix.Connect(probe, &unix.SockaddrUnix{Name: path})
		_ = unix.Close(probe)
		if e == nil {
			return nil, ErrInvalid
		}
		if e != unix.ECONNREFUSED && e != unix.ENOENT {
			return nil, ErrInvalid
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	addr := &unix.SockaddrUnix{Name: path}
	if err = unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err = unix.Listen(fd, 128); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	listener, err := fileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, ErrUnavailable
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = unixListener.Close()
		return nil, err
	}
	return &ManagedUnixListener{UnixListener: unixListener, path: path}, nil
}

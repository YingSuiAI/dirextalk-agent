//go:build linux

package extensionrunner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Client is the Agent-side V2 runner client. It exposes only the descriptor
// protocol and never starts a subprocess itself.
type Client struct {
	path string
	uid  uint32
}

// Probe verifies socket identity, peer UID, and the runner's nonce-bound
// readiness response without submitting an execution request.
func (c *Client) Probe(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrDenied
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	fd, before, err := c.connect(ctx, deadline)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	after, err := socketIdentity(c.path, c.uid)
	if err != nil || before != after {
		return ErrDenied
	}
	var nonceBytes [32]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return ErrDenied
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes[:])
	payload, err := EncodeProbeRequest(ProbeRequest{Op: "probe", Version: ProbeProtocolV1, Nonce: nonce})
	nSent, sendErr := unix.SendmsgN(fd, payload, nil, nil, 0)
	if err != nil || sendErr != nil || nSent != len(payload) {
		return ErrDenied
	}
	if err := waitFD(ctx, fd, unix.POLLIN, deadline); err != nil {
		return err
	}
	buf := make([]byte, MaxV2PacketBytes)
	n, err := unix.Read(fd, buf)
	if err != nil || n <= 0 || DecodeProbeResponse(buf[:n], nonce) != nil {
		return ErrDenied
	}
	return nil
}

const runnerTransportFinalizationGrace = 30 * time.Second

func NewClient(socketPath string, expectedRunnerUID uint32) (*Client, error) {
	if socketPath == "" || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, ErrInvalid
	}
	if _, err := socketIdentity(socketPath, expectedRunnerUID); err != nil {
		return nil, err
	}
	return &Client{path: socketPath, uid: expectedRunnerUID}, nil
}

// RunV2 sends one descriptor-only request.  Caller-owned files remain open:
// SCM_RIGHTS duplicates them in the kernel and this method never closes them.
func (c *Client) RunV2(ctx context.Context, request RequestV2, files []*os.File) (StatusV1, error) {
	status, results, err := c.RunV2WithResultFiles(ctx, request, files)
	for _, result := range results {
		_ = result.Close()
	}
	return status, err
}

// RunV2WithResultFiles returns read-only descriptors that the runner reopened
// beneath its verified workspace after execution. Descriptor order is bound
// to StatusV1.ResultFiles and every descriptor is re-hashed by this client.
func (c *Client) RunV2WithResultFiles(ctx context.Context, request RequestV2, files []*os.File) (StatusV1, []*os.File, error) {
	if c == nil || ctx == nil || ValidateFDSet(request, len(files)) != nil {
		return StatusV1{}, nil, ErrInvalid
	}
	if err := ValidateRequestV2(request); err != nil {
		return StatusV1{}, nil, err
	}
	fds := make([]int, len(files))
	for i, f := range files {
		if f == nil {
			return StatusV1{}, nil, ErrInvalid
		}
		fds[i] = int(f.Fd())
		if fds[i] < 0 {
			return StatusV1{}, nil, ErrInvalid
		}
	}
	if err := ValidateRequestFDs(request, fds); err != nil {
		return StatusV1{}, nil, err
	}
	payload, err := EncodeRequestV2(request)
	if err != nil {
		return StatusV1{}, nil, err
	}
	// TimeoutMS is enforced by the runner.  Keep the transport alive long
	// enough for its kill, reap, collection, cleanup, and terminal status write;
	// an earlier caller deadline/cancellation still wins immediately.
	deadline := time.Now().Add(time.Duration(request.TimeoutMS)*time.Millisecond + runnerTransportFinalizationGrace)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	fd, before, err := c.connect(ctx, deadline)
	if err != nil {
		return StatusV1{}, nil, err
	}
	defer unix.Close(fd) // Closing on cancellation/disconnect is the server cancel signal.
	after, err := socketIdentity(c.path, c.uid)
	if err != nil || before != after {
		return StatusV1{}, nil, ErrDenied
	}
	if err := waitFD(ctx, fd, unix.POLLOUT, deadline); err != nil {
		return StatusV1{}, nil, err
	}
	if n, err := unix.SendmsgN(fd, payload, unix.UnixRights(fds...), nil, 0); err != nil || n != len(payload) {
		if err != nil {
			return StatusV1{}, nil, err
		}
		return StatusV1{}, nil, ErrProtocol
	}
	if err := waitFD(ctx, fd, unix.POLLIN, deadline); err != nil {
		return StatusV1{}, nil, err
	}
	buf := make([]byte, MaxV2PacketBytes)
	oob := make([]byte, unix.CmsgSpace(4*maxV2ResultFiles))
	n, oobn, flags, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_CMSG_CLOEXEC)
	received, controlErr := collectRightsCmsgs(oob[:oobn])
	closeReceived := func() {
		for _, resultFD := range received {
			_ = unix.Close(resultFD)
		}
	}
	if err != nil || controlErr != nil || n <= 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeReceived()
		return StatusV1{}, nil, ErrProtocol
	}
	status, err := ReadStatusV1Datagram(buf[:n])
	if err != nil {
		closeReceived()
		return StatusV1{}, nil, err
	}
	if err := ValidateStatusV1(request, status); err != nil {
		closeReceived()
		return StatusV1{}, nil, err
	}
	if len(received) != len(status.ResultFiles) {
		closeReceived()
		return StatusV1{}, nil, ErrProtocol
	}
	resultFiles := make([]*os.File, len(received))
	for index, resultFD := range received {
		resultFiles[index] = os.NewFile(uintptr(resultFD), status.ResultFiles[index].Path)
	}
	for index, result := range resultFiles {
		var stat unix.Stat_t
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(result, MaxOutputBytes+1))
		metadata := status.ResultFiles[index]
		if unix.Fstat(int(result.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size != metadata.Size ||
			readErr != nil || n != metadata.Size || hex.EncodeToString(hash.Sum(nil)) != metadata.SHA256 {
			for _, file := range resultFiles {
				_ = file.Close()
			}
			return StatusV1{}, nil, ErrProtocol
		}
		if _, err = result.Seek(0, io.SeekStart); err != nil {
			for _, file := range resultFiles {
				_ = file.Close()
			}
			return StatusV1{}, nil, ErrProtocol
		}
	}
	return status, resultFiles, nil
}

type socketID struct{ dev, ino uint64 }

func socketIdentity(path string, uid uint32) (socketID, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o002 != 0 {
		return socketID{}, ErrDenied
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(st.Uid) != uid {
		return socketID{}, ErrDenied
	}
	if err := trustedSocketParent(filepath.Dir(path), uid); err != nil {
		return socketID{}, err
	}
	return socketID{dev: uint64(st.Dev), ino: st.Ino}, nil
}

// trustedSocketParent prevents replacement of a verified socket between
// lstat/connect.  Group-readable 0660 sockets are intentional; the directory
// that names them must not be writable by group or world.
func trustedSocketParent(parent string, runnerUID uint32) error {
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return ErrDenied
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (uint32(st.Uid) != runnerUID && uint32(st.Uid) != uint32(os.Geteuid())) {
		return ErrDenied
	}
	return nil
}

func (c *Client) connect(ctx context.Context, deadline time.Time) (int, socketID, error) {
	id, err := socketIdentity(c.path, c.uid)
	if err != nil {
		return -1, socketID{}, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return -1, socketID{}, err
	}
	if err = unix.Connect(fd, &unix.SockaddrUnix{Name: c.path}); err != nil && err != unix.EINPROGRESS {
		unix.Close(fd)
		return -1, socketID{}, err
	}
	if err == unix.EINPROGRESS {
		if err = waitFD(ctx, fd, unix.POLLOUT, deadline); err != nil {
			unix.Close(fd)
			return -1, socketID{}, err
		}
		if so, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); e != nil || so != 0 {
			unix.Close(fd)
			if e != nil {
				return -1, socketID{}, e
			}
			return -1, socketID{}, syscall.Errno(so)
		}
	}
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || cred == nil || cred.Uid != c.uid {
		unix.Close(fd)
		return -1, socketID{}, ErrDenied
	}
	return fd, id, nil
}

func waitFD(ctx context.Context, fd int, events int16, deadline time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		ms := int(remaining.Milliseconds())
		if ms < 1 {
			ms = 1
		}
		if ms > 50 {
			ms = 50
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(p, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			if p[0].Revents&(events|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				if p[0].Revents&events != 0 {
					return nil
				}
				return errors.New("extension runner socket closed")
			}
		}
	}
}

func closeControlFDs(oob []byte) {
	_ = closeRightsCmsgs(oob)
}

//go:build linux

package extensionrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func (c *Client) Publish(ctx context.Context, entries []ManifestEntry, files []PublishFile) (PublishResponse, error) {
	if c == nil || ctx == nil || len(entries) == 0 || len(entries) != len(files) {
		return PublishResponse{}, ErrInvalid
	}
	digest := ManifestDigest(entries)
	req := PublishRequest{Op: "publish_v1", Digest: digest, Entries: entries}
	payload, err := EncodePublishRequest(req)
	if err != nil {
		return PublishResponse{}, err
	}
	osFiles := make([]*os.File, len(files))
	fds := make([]int, len(files))
	defer func() {
		for _, f := range osFiles {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	for i, file := range files {
		if file.Path != entries[i].Path || int64(len(file.Data)) != entries[i].Size || DigestBytes(file.Data) != entries[i].SHA256 {
			return PublishResponse{}, ErrInvalid
		}
		fd, e := unix.MemfdCreate("dirextalk-publish", unix.MFD_CLOEXEC)
		if e != nil {
			return PublishResponse{}, e
		}
		f := os.NewFile(uintptr(fd), file.Path)
		if _, e = f.Write(file.Data); e != nil {
			_ = f.Close()
			return PublishResponse{}, e
		}
		_, _ = f.Seek(0, 0)
		osFiles[i] = f
		fds[i] = fd
	}
	raw := make([]int, len(fds))
	for i := range fds {
		raw[i] = fds[i]
	}
	response, received, err := c.publicationRoundTrip(ctx, payload, raw, 0)
	closeReceivedFDs(received)
	if err != nil {
		return PublishResponse{}, err
	}
	var resp PublishResponse
	if decodeCanonicalPublication(response, &resp) != nil || resp.Digest != digest {
		return PublishResponse{}, ErrProtocol
	}
	return resp, nil
}

func (c *Client) Remove(ctx context.Context, digest string) error {
	if c == nil || ctx == nil || !digestRE.MatchString(digest) {
		return ErrInvalid
	}
	payload, err := encodeCanonicalPublication(RemoveRequest{Op: "remove_v1", Digest: digest})
	if err != nil {
		return err
	}
	response, received, err := c.publicationRoundTrip(ctx, payload, nil, 0)
	closeReceivedFDs(received)
	if err != nil {
		return err
	}
	var value RemoveResponse
	if decodeCanonicalPublication(response, &value) != nil || value.Digest != digest {
		return ErrProtocol
	}
	return nil
}

func (c *Client) ReadSkill(ctx context.Context, digest, path string) ([]byte, error) {
	request := ReadInstallRequest{Op: "read_v1", Digest: digest, Path: path}
	if c == nil || ctx == nil || request.Validate() != nil {
		return nil, ErrInvalid
	}
	payload, err := encodeCanonicalPublication(request)
	if err != nil {
		return nil, err
	}
	response, received, err := c.publicationRoundTrip(ctx, payload, nil, 1)
	if err != nil {
		closeReceivedFDs(received)
		return nil, err
	}
	defer closeReceivedFDs(received)
	var value ReadInstallResponse
	if decodeCanonicalPublication(response, &value) != nil || value.Digest != digest || value.Path != path ||
		!digestRE.MatchString(value.SHA256) || value.Size < 0 || value.Size > MaxOutputBytes {
		return nil, ErrProtocol
	}
	var stat unix.Stat_t
	if unix.Fstat(received[0], &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size != value.Size {
		return nil, ErrProtocol
	}
	readFD, err := unix.Dup(received[0])
	if err != nil {
		return nil, ErrProtocol
	}
	file := os.NewFile(uintptr(readFD), path)
	if file == nil {
		_ = unix.Close(readFD)
		return nil, ErrProtocol
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxOutputBytes+1))
	if err != nil || int64(len(data)) != value.Size {
		return nil, ErrProtocol
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != value.SHA256 {
		return nil, ErrProtocol
	}
	return data, nil
}

func (c *Client) publicationRoundTrip(ctx context.Context, payload []byte, sendFDs []int, expectedFDs int) ([]byte, []int, error) {
	if c == nil || ctx == nil || len(payload) == 0 || len(payload) > MaxV2PacketBytes || expectedFDs < 0 {
		return nil, nil, ErrInvalid
	}
	deadline := time.Now().Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	fd, before, err := c.connect(ctx, deadline)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(fd)
	after, err := socketIdentity(c.path, c.uid)
	if err != nil || before != after {
		return nil, nil, ErrDenied
	}
	if err = waitFD(ctx, fd, unix.POLLOUT, deadline); err != nil {
		return nil, nil, err
	}
	var control []byte
	if len(sendFDs) > 0 {
		control = unix.UnixRights(sendFDs...)
	}
	if n, sendErr := unix.SendmsgN(fd, payload, control, nil, 0); sendErr != nil || n != len(payload) {
		if sendErr != nil {
			return nil, nil, sendErr
		}
		return nil, nil, ErrProtocol
	}
	if err = waitFD(ctx, fd, unix.POLLIN, deadline); err != nil {
		return nil, nil, err
	}
	buffer := make([]byte, MaxV2PacketBytes)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, flags, _, receiveErr := unix.Recvmsg(fd, buffer, oob, unix.MSG_CMSG_CLOEXEC)
	received, controlErr := collectRightsCmsgs(oob[:oobn])
	if receiveErr != nil || controlErr != nil || n <= 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(received) != expectedFDs {
		closeReceivedFDs(received)
		return nil, nil, ErrProtocol
	}
	return append([]byte(nil), buffer[:n]...), received, nil
}

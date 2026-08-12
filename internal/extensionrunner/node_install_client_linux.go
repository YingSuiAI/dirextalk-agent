//go:build linux

package extensionrunner

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

func (c *Client) BuildNode(ctx context.Context, request NodeBuildRequestV1, content []byte) (NodeBuildReceiptV1, error) {
	if c == nil || ctx == nil || request.Validate(1) != nil || int64(len(content)) != request.ContentSize || DigestBytes(content) != request.ContentSHA256 {
		return NodeBuildReceiptV1{}, ErrInvalid
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) > MaxV2PacketBytes {
		return NodeBuildReceiptV1{}, ErrInvalid
	}
	fd, err := sealedMemfd("dirextalk-node-source", content)
	if err != nil {
		return NodeBuildReceiptV1{}, err
	}
	defer unix.Close(fd)
	response, received, err := c.nodeRoundTrip(ctx, payload, []int{fd})
	closeReceivedFDs(received)
	if err != nil {
		return NodeBuildReceiptV1{}, err
	}
	var value NodeBuildResponseV1
	if decodeCanonicalNode(response, &value) != nil {
		return NodeBuildReceiptV1{}, ErrProtocol
	}
	if value.Error == "capacity" {
		return NodeBuildReceiptV1{}, ErrNodeInstallCapacity
	}
	if value.Error != "" || value.Receipt == nil || value.Receipt.Validate() != nil || value.Receipt.InputDigest != request.InputDigest || value.Receipt.EntryPath != request.EntryPath || value.Receipt.EntrySHA256 != request.EntrySHA256 || value.Receipt.PackageName != request.PackageName || value.Receipt.PackageVersion != request.PackageVersion || value.Receipt.LockSHA256 != request.LockSHA256 {
		return NodeBuildReceiptV1{}, ErrDenied
	}
	return *value.Receipt, nil
}

func (c *Client) PromoteNode(ctx context.Context, cleanupToken string, receipt NodeBuildReceiptV1) error {
	request := NodePromoteRequestV1{Op: "promote_node_v1", CleanupToken: cleanupToken, Receipt: receipt}
	if c == nil || ctx == nil || request.Validate() != nil {
		return ErrInvalid
	}
	payload, _ := json.Marshal(request)
	response, received, err := c.nodeRoundTrip(ctx, payload, nil)
	closeReceivedFDs(received)
	if err != nil {
		return err
	}
	var value NodeMutationResponseV1
	if decodeCanonicalNode(response, &value) != nil || value.Digest != receipt.ArtifactDigest {
		return ErrProtocol
	}
	return nil
}

func (c *Client) RemoveNode(ctx context.Context, scope, digest, cleanupToken string) error {
	request := NodeRemoveRequestV1{Op: "remove_node_v1", Scope: scope, Digest: digest, CleanupToken: cleanupToken}
	if c == nil || ctx == nil || request.Validate() != nil {
		return ErrInvalid
	}
	payload, _ := json.Marshal(request)
	response, received, err := c.nodeRoundTrip(ctx, payload, nil)
	closeReceivedFDs(received)
	if err != nil {
		return err
	}
	var value NodeMutationResponseV1
	if decodeCanonicalNode(response, &value) != nil || value.Digest != digest {
		return ErrProtocol
	}
	return nil
}

func (c *Client) nodeRoundTrip(ctx context.Context, payload []byte, sendFDs []int) ([]byte, []int, error) {
	if len(payload) == 0 || len(payload) > MaxV2PacketBytes {
		return nil, nil, ErrInvalid
	}
	deadline := time.Now().Add(130 * time.Second)
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
	control := []byte(nil)
	if len(sendFDs) > 0 {
		control = unix.UnixRights(sendFDs...)
	}
	if n, sendErr := unix.SendmsgN(fd, payload, control, nil, 0); sendErr != nil || n != len(payload) {
		return nil, nil, errors.Join(ErrProtocol, sendErr)
	}
	if err = waitFD(ctx, fd, unix.POLLIN, deadline); err != nil {
		return nil, nil, err
	}
	buffer := make([]byte, MaxV2PacketBytes)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, _, receiveErr := unix.Recvmsg(fd, buffer, oob, unix.MSG_CMSG_CLOEXEC)
	received, controlErr := collectRightsCmsgs(oob[:oobn])
	if receiveErr != nil || controlErr != nil || n <= 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(received) != 0 {
		closeReceivedFDs(received)
		return nil, nil, ErrProtocol
	}
	return append([]byte(nil), buffer[:n]...), received, nil
}

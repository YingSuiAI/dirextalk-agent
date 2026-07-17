package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
)

const maxInstallerSocketFrame = 512 << 10

type localHandler interface {
	Handle(context.Context, io.Reader, io.Writer) error
}

// socketDispatcher keeps the existing single root-owned systemd socket while
// separating the original installer contract from the root-helper contract by
// their exact schema. Each owning handler still performs its own strict size,
// canonical-CBOR, union, trust and authorization checks.
type socketDispatcher struct {
	installer localHandler
	helper    localHandler
}

func (dispatcher socketDispatcher) Serve(ctx context.Context, listener net.Listener) error {
	if dispatcher.installer == nil || dispatcher.helper == nil || ctx == nil || listener == nil {
		return installer.Error(installer.CodeInvalidRequest)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
		_ = dispatcher.Handle(ctx, connection, connection)
		_ = connection.Close()
	}
}

func (dispatcher socketDispatcher) Handle(ctx context.Context, input io.Reader, output io.Writer) error {
	var header [4]byte
	if binary.Read(input, binary.BigEndian, &header) != nil {
		return installer.Error(installer.CodeInvalidRequest)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxInstallerSocketFrame {
		return installer.Error(installer.CodeRequestTooLarge)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(input, payload); err != nil {
		return installer.Error(installer.CodeInvalidRequest)
	}
	defer clear(payload)
	framed := func() io.Reader {
		return io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(payload))
	}
	var helperRequest roothelper.LocalRequestV1
	if installer.DecodeCanonical(payload, &helperRequest) == nil &&
		helperRequest.SchemaVersion == roothelper.LocalProtocolSchemaV1 {
		return dispatcher.helper.Handle(ctx, framed(), output)
	}
	return dispatcher.installer.Handle(ctx, framed(), output)
}

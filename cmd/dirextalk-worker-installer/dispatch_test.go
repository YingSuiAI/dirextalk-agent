package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/google/uuid"
)

func TestSocketDispatcherRoutesOnlyExactRootHelperSchema(t *testing.T) {
	installerHandler := &dispatchHandler{}
	helperHandler := &dispatchHandler{}
	dispatcher := socketDispatcher{installer: installerHandler, helper: helperHandler}

	request := roothelper.LocalRequestV1{
		SchemaVersion: roothelper.LocalProtocolSchemaV1, RequestID: uuid.NewString(),
		Action: roothelper.ActionBootstrap, DeliveryCBOR: []byte{1}, BootstrapCapabilityCBOR: []byte{2},
	}
	payload, err := canonical.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Handle(context.Background(), framedPayload(payload), io.Discard); err != nil {
		t.Fatal(err)
	}
	if helperHandler.calls != 1 || installerHandler.calls != 0 {
		t.Fatalf("helper=%d installer=%d", helperHandler.calls, installerHandler.calls)
	}

	payload, _ = canonical.Marshal(installer.RequestV1{SchemaVersion: installer.RequestSchemaV1})
	if err := dispatcher.Handle(context.Background(), framedPayload(payload), io.Discard); err != nil {
		t.Fatal(err)
	}
	if helperHandler.calls != 1 || installerHandler.calls != 1 {
		t.Fatalf("helper=%d installer=%d", helperHandler.calls, installerHandler.calls)
	}
}

type dispatchHandler struct{ calls int }

func (handler *dispatchHandler) Handle(_ context.Context, input io.Reader, _ io.Writer) error {
	handler.calls++
	var size uint32
	if binary.Read(input, binary.BigEndian, &size) != nil || size == 0 {
		return io.ErrUnexpectedEOF
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(input, payload)
	return err
}

func framedPayload(payload []byte) io.Reader {
	var framed bytes.Buffer
	_ = binary.Write(&framed, binary.BigEndian, uint32(len(payload)))
	_, _ = framed.Write(payload)
	return &framed
}

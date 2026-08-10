package execgate

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestTerminalRetriesBoundedUnavailableUntilTerminalProof(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gate.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	proof := testTerminalProof()
	var calls atomic.Int32
	done := make(chan struct{})
	serverErrors := make(chan error, 1)
	go func() {
		defer close(done)
		for {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				return
			}
			raw, readErr := io.ReadAll(io.LimitReader(connection, MaximumWireBytes+1))
			var request wireRequest
			if readErr != nil || decodeCanonical(raw, &request) != nil ||
				request.Operation != operationTerminal || request.RunID != proof.RunID {
				clear(raw)
				_ = connection.Close()
				select {
				case serverErrors <- errors.New("invalid terminal request"):
				default:
				}
				return
			}
			clear(raw)
			response := wireResponse{Schema: ProtocolSchemaV1, Code: "unavailable"}
			if calls.Add(1) >= 3 {
				response = wireResponse{
					Schema: ProtocolSchemaV1, OK: true,
					RunID: proof.RunID, Proof: &proof,
				}
			}
			encoded, encodeErr := encodeCanonical(response)
			if encodeErr == nil {
				_, encodeErr = connection.Write(encoded)
			}
			clear(encoded)
			_ = connection.Close()
			if encodeErr != nil {
				select {
				case serverErrors <- encodeErr:
				default:
				}
				return
			}
		}
	}()

	client := &Client{socketPath: socketPath, timeout: 100 * time.Millisecond}
	run := &Run{client: client, id: proof.RunID}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got, err := run.Terminal(ctx)
	_ = listener.Close()
	<-done
	select {
	case serverErr := <-serverErrors:
		t.Fatal(serverErr)
	default:
	}
	if err != nil || got.RunID != proof.RunID || got.ValidateTerminal() != nil {
		t.Fatalf("proof=%+v err=%v", got, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("terminal calls=%d want=3", calls.Load())
	}
}

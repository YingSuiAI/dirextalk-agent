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

func TestTerminalRetriesUnavailableUntilTerminalProofOrTaskContext(t *testing.T) {
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

func TestTerminalHasNoLocalChildAgentLifetimeDeadline(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gate.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	proof := testTerminalProof()
	done := make(chan error, 1)
	go func() {
		defer listener.Close()
		for call := 0; call < 2; call++ {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				done <- acceptErr
				return
			}
			raw, readErr := io.ReadAll(io.LimitReader(connection, MaximumWireBytes+1))
			var request wireRequest
			if readErr != nil || decodeCanonical(raw, &request) != nil ||
				request.Operation != operationTerminal || request.RunID != proof.RunID {
				clear(raw)
				_ = connection.Close()
				done <- errors.New("invalid terminal request")
				return
			}
			clear(raw)
			response := wireResponse{Schema: ProtocolSchemaV1, Code: "unavailable"}
			if call == 0 {
				time.Sleep(1600 * time.Millisecond)
			} else {
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
				done <- encodeErr
				return
			}
		}
		done <- nil
	}()

	client := &Client{socketPath: socketPath, timeout: 2 * time.Second}
	run := &Run{client: client, id: proof.RunID}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	started := time.Now()
	got, err := run.Terminal(ctx)
	serverErr := <-done
	if serverErr != nil {
		t.Fatal(serverErr)
	}
	if err != nil || got.ValidateTerminal() != nil {
		t.Fatalf("proof=%+v err=%v", got, err)
	}
	if elapsed := time.Since(started); elapsed < 1500*time.Millisecond {
		t.Fatalf("terminal returned before delayed child drain: %s", elapsed)
	}
}

func TestClientPreservesClosedViolationReason(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gate.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer listener.Close()
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		raw, readErr := io.ReadAll(io.LimitReader(connection, MaximumWireBytes+1))
		var request wireRequest
		if readErr != nil || decodeCanonical(raw, &request) != nil || request.Operation != operationTerminal {
			clear(raw)
			done <- errors.New("invalid terminal request")
			return
		}
		clear(raw)
		response, encodeErr := encodeCanonical(wireResponse{
			Schema: ProtocolSchemaV1, Code: wireViolationPrefix + "runtime_topology_invalid",
		})
		if encodeErr == nil {
			_, encodeErr = connection.Write(response)
		}
		clear(response)
		done <- encodeErr
	}()

	client := &Client{socketPath: socketPath, timeout: time.Second}
	run := &Run{client: client, id: "11111111-1111-4111-8111-111111111111"}
	_, err = run.Terminal(t.Context())
	if serverErr := <-done; serverErr != nil {
		t.Fatal(serverErr)
	}
	if !errors.Is(err, ErrViolation) {
		t.Fatalf("call() error=%v, want violation", err)
	}
	if code, ok := ViolationCode(err); !ok || code != "runtime_topology_invalid" {
		t.Fatalf("violation code=%q ok=%t", code, ok)
	}
}

package execgate

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string) (*Client, error) {
	if !cleanAbsolute(socketPath) {
		return nil, ErrInvalid
	}
	return &Client{socketPath: socketPath, timeout: 2 * time.Second}, nil
}

func (client *Client) Ping(ctx context.Context) error {
	response, err := client.call(ctx, wireRequest{Schema: ProtocolSchemaV1, Operation: operationPing})
	if err != nil || !response.OK || response.RunID != "" || response.Proof != nil {
		return ErrUnavailable
	}
	return nil
}

func (client *Client) Register(ctx context.Context, registration Registration) (*Run, error) {
	if registration.Validate() != nil {
		return nil, ErrInvalid
	}
	response, err := client.call(ctx, wireRequest{
		Schema: ProtocolSchemaV1, Operation: operationRegister, Registration: &registration,
	})
	if err != nil {
		return nil, err
	}
	if !response.OK || !canonicalUUID(response.RunID) || response.Proof != nil {
		return nil, ErrUnavailable
	}
	return &Run{client: client, id: response.RunID}, nil
}

type Run struct {
	client *Client
	id     string
}

func (run *Run) Activate(ctx context.Context, piPID int) (Proof, error) {
	if run == nil || run.client == nil || piPID < 1 {
		return Proof{}, ErrInvalid
	}
	return run.proofCall(ctx, wireRequest{
		Schema: ProtocolSchemaV1, Operation: operationActivate, RunID: run.id, PiPID: int32(piPID),
	}, ProofActive)
}

func (run *Run) Proof(ctx context.Context) (Proof, error) {
	if run == nil || run.client == nil {
		return Proof{}, ErrInvalid
	}
	return run.proofCall(ctx, wireRequest{
		Schema: ProtocolSchemaV1, Operation: operationProof, RunID: run.id,
	}, ProofActive)
}

func (run *Run) Terminal(ctx context.Context) (Proof, error) {
	if run == nil || run.client == nil {
		return Proof{}, ErrInvalid
	}
	proof, err := run.proofCall(ctx, wireRequest{
		Schema: ProtocolSchemaV1, Operation: operationTerminal, RunID: run.id,
	}, ProofTerminal)
	if err != nil || proof.ValidateTerminal() != nil {
		return Proof{}, ErrViolation
	}
	return proof, nil
}

func (run *Run) Cancel(ctx context.Context) error {
	if run == nil || run.client == nil {
		return ErrInvalid
	}
	response, err := run.client.call(ctx, wireRequest{
		Schema: ProtocolSchemaV1, Operation: operationCancel, RunID: run.id,
	})
	if err != nil {
		return err
	}
	if !response.OK || response.RunID != run.id || response.Proof != nil {
		return ErrUnavailable
	}
	return nil
}

func (run *Run) proofCall(ctx context.Context, request wireRequest, expected ProofState) (Proof, error) {
	response, err := run.client.call(ctx, request)
	if err != nil {
		return Proof{}, err
	}
	if !response.OK || response.RunID != run.id || response.Proof == nil {
		return Proof{}, ErrUnavailable
	}
	proof := *response.Proof
	if proof.RunID != run.id || proof.State == ProofViolated {
		return Proof{}, ErrViolation
	}
	if proof.State != expected || proof.Validate() != nil {
		return Proof{}, ErrUnavailable
	}
	return proof, nil
}

func (client *Client) call(ctx context.Context, request wireRequest) (wireResponse, error) {
	if client == nil || ctx == nil || request.validate() != nil {
		return wireResponse{}, ErrInvalid
	}
	raw, err := encodeCanonical(request)
	if err != nil {
		return wireResponse{}, err
	}
	defer clear(raw)
	dialer := net.Dialer{Timeout: client.timeout}
	connection, err := dialer.DialContext(ctx, "unix", client.socketPath)
	if err != nil {
		return wireResponse{}, ErrUnavailable
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	} else {
		_ = connection.SetDeadline(time.Now().Add(client.timeout))
	}
	written, err := connection.Write(raw)
	if err != nil || written != len(raw) {
		return wireResponse{}, ErrUnavailable
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || unixConnection.CloseWrite() != nil {
		return wireResponse{}, ErrUnavailable
	}
	responseRaw, err := io.ReadAll(io.LimitReader(connection, MaximumWireBytes+1))
	if err != nil || len(responseRaw) > MaximumWireBytes {
		clear(responseRaw)
		return wireResponse{}, ErrUnavailable
	}
	defer clear(responseRaw)
	var response wireResponse
	if decodeCanonical(responseRaw, &response) != nil || response.validate() != nil {
		return wireResponse{}, ErrUnavailable
	}
	if !response.OK {
		switch response.Code {
		case "invalid":
			return wireResponse{}, ErrInvalid
		case "violation":
			return wireResponse{}, ErrViolation
		default:
			return wireResponse{}, ErrUnavailable
		}
	}
	return response, nil
}

func IsUnavailable(err error) bool { return errors.Is(err, ErrUnavailable) }

package installer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

const DefaultSocketPath = "/run/dirextalk-installer/installer.sock"

type ExecuteClient interface {
	Execute(context.Context, DeliveryV1, SignedLeaseGrantV1, string) (ResponseV1, error)
}

type socketDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type SocketClient struct {
	path   string
	dialer socketDialer
	now    func() time.Time
}

func NewSocketClient(socketPath string) (*SocketClient, error) {
	return newSocketClient(socketPath, &net.Dialer{}, time.Now)
}

func newSocketClient(socketPath string, dialer socketDialer, now func() time.Time) (*SocketClient, error) {
	if socketPath == "" || !path.IsAbs(socketPath) || path.Clean(socketPath) != socketPath || dialer == nil || now == nil {
		return nil, errorf(CodeInvalidRequest, "installer socket client configuration is invalid")
	}
	return &SocketClient{path: socketPath, dialer: dialer, now: now}, nil
}

func (client *SocketClient) Execute(ctx context.Context, delivery DeliveryV1, leaseGrant SignedLeaseGrantV1, commandID string) (ResponseV1, error) {
	if client == nil || ctx == nil {
		return ResponseV1{}, errorf(CodeInvalidRequest, "installer client is unavailable")
	}
	request, err := delivery.ExecuteRequest(commandID, leaseGrant, client.now().UTC())
	if err != nil {
		return ResponseV1{}, err
	}
	payload, err := canonical.Marshal(request)
	if err != nil || len(payload) == 0 || len(payload) > defaultMaxRequestBytes {
		clear(payload)
		return ResponseV1{}, errorf(CodeRequestTooLarge, "installer request exceeds local protocol limit")
	}
	defer clear(payload)
	connection, err := client.dialer.DialContext(ctx, "unix", client.path)
	if err != nil {
		return ResponseV1{}, errorf(CodeInternal, "installer socket is unavailable")
	}
	defer connection.Close()
	planExpiresAt, _ := time.Parse(time.RFC3339Nano, delivery.SignedPlan.Plan.ExpiresAt)
	leaseExpiresAt, _ := time.Parse(time.RFC3339Nano, leaseGrant.Grant.ExpiresAt)
	deadline := earlierTime(planExpiresAt, leaseExpiresAt).Add(executionResponseGrace)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	if err := writeFrame(connection, payload); err != nil {
		return ResponseV1{}, errorf(CodeInternal, "write installer request")
	}
	responsePayload, err := readFrame(connection, defaultMaxResponseBytes)
	if err != nil {
		return ResponseV1{}, errorf(CodeInternal, "read installer response")
	}
	defer clear(responsePayload)
	var response ResponseV1
	if err := DecodeCanonical(responsePayload, &response); err != nil {
		return ResponseV1{}, err
	}
	if err := validateExecuteResponse(request, response); err != nil {
		return response, err
	}
	return response, nil
}

func writeFrame(writer io.Writer, payload []byte) error {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	defer clear(frame)
	_, err := io.Copy(writer, bytes.NewReader(frame))
	return err
}

func readFrame(reader io.Reader, maximum uint32) ([]byte, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil || size == 0 || size > maximum {
		return nil, errors.New("invalid installer frame")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return nil, err
	}
	return payload, nil
}

func validateExecuteResponse(request RequestV1, response ResponseV1) error {
	if response.SchemaVersion != ResponseSchemaV1 || response.RequestID != request.RequestID || response.Action != ActionExecute ||
		response.CommandID != request.CommandID || response.ArtifactName != "" || response.SHA256 != "" {
		return errorf(CodeInvalidRequest, "installer response does not match request")
	}
	switch response.Status {
	case StatusExecuted:
		if response.ErrorCode != "" {
			return errorf(CodeInvalidRequest, "executed response contains an error")
		}
		return nil
	case StatusFailed:
		if response.ErrorCode != CodeExecutionFailed && response.ErrorCode != CodeExecutionTimedOut {
			return errorf(CodeInvalidRequest, "failed response code is invalid")
		}
	case StatusInterrupted:
		if response.ErrorCode != CodeExecutionInterrupted {
			return errorf(CodeInvalidRequest, "interrupted response code is invalid")
		}
	case StatusRejected:
		if response.ErrorCode == "" {
			return errorf(CodeInvalidRequest, "rejected response lacks an error code")
		}
	default:
		return errorf(CodeInvalidRequest, "installer response status is invalid")
	}
	return Error(response.ErrorCode)
}

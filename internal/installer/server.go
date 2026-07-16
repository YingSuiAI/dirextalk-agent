package installer

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

const (
	defaultMaxRequestBytes  = 256 << 10
	defaultMaxResponseBytes = 16 << 10
)

type ServerConfig struct {
	MaxRequestBytes   uint32
	MaxResponseBytes  uint32
	ConnectionTimeout time.Duration
}

type Server struct {
	verifier          *Verifier
	maxRequestBytes   uint32
	maxResponseBytes  uint32
	connectionTimeout time.Duration
}

func NewServer(verifier *Verifier, config ServerConfig) *Server {
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.ConnectionTimeout <= 0 {
		config.ConnectionTimeout = 30 * time.Second
	}
	return &Server{verifier: verifier, maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes, connectionTimeout: config.ConnectionTimeout}
}

// Handle reads exactly one big-endian length-prefixed canonical-CBOR request
// and writes exactly one length-prefixed, de-secreted response.
func (s *Server) Handle(ctx context.Context, input io.Reader, output io.Writer) error {
	response := ResponseV1{SchemaVersion: ResponseSchemaV1, Action: ActionVerify, Status: StatusRejected}
	var size uint32
	if err := binary.Read(input, binary.BigEndian, &size); err != nil {
		response.ErrorCode = CodeInvalidRequest
		return s.writeResponse(output, response)
	}
	if size == 0 || size > s.maxRequestBytes {
		response.ErrorCode = CodeRequestTooLarge
		return s.writeResponse(output, response)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(input, payload); err != nil {
		response.ErrorCode = CodeInvalidRequest
		return s.writeResponse(output, response)
	}
	var request RequestV1
	if err := DecodeCanonical(payload, &request); err != nil {
		response.ErrorCode = ErrorCodeOf(err)
		return s.writeResponse(output, response)
	}
	response.RequestID = request.RequestID
	verified, err := s.verifier.Verify(ctx, request)
	if err != nil {
		response.ErrorCode = ErrorCodeOf(err)
		return s.writeResponse(output, response)
	}
	return s.writeResponse(output, verified)
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		_ = connection.SetDeadline(time.Now().Add(s.connectionTimeout))
		_ = s.Handle(ctx, connection, connection)
		_ = connection.Close()
	}
}

func (s *Server) writeResponse(output io.Writer, response ResponseV1) error {
	payload, err := canonical.Marshal(response)
	if err != nil {
		return err
	}
	if len(payload) > int(s.maxResponseBytes) {
		return errorf(CodeInternal, "installer response exceeds configured maximum")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := output.Write(header[:]); err != nil {
		return err
	}
	_, err = output.Write(payload)
	return err
}

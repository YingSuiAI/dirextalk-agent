package roothelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

const (
	LocalProtocolSchemaV1 = "dirextalk.agent.root-helper-local-protocol/v1"
	DefaultSocketPath     = installer.DefaultSocketPath

	ActionBootstrap     = "root_helper.bootstrap"
	ActionCanary        = "root_helper.canary"
	ActionRestart       = "root_helper.restart"
	ActionPairingBegin  = "root_helper.pairing.begin"
	ActionPairingResume = "root_helper.pairing.resume"

	StatusSucceeded = "succeeded"
	StatusRejected  = "rejected"

	ErrorInvalid      = "invalid_request"
	ErrorUnauthorized = "unauthorized"
	ErrorUnavailable  = "unavailable"
	ErrorNotReady     = "not_ready"

	maxLocalRequestBytes  = 512 << 10
	maxLocalResponseBytes = 192 << 10
)

// LocalRequestV1 is an intentionally strict union. DeliveryCBOR is present on
// every call so the daemon never relies on mutable in-memory trust.
type LocalRequestV1 struct {
	SchemaVersion           string `json:"schema_version"`
	RequestID               string `json:"request_id"`
	Action                  string `json:"action"`
	DeliveryCBOR            []byte `json:"delivery_cbor"`
	BootstrapCapabilityCBOR []byte `json:"bootstrap_capability_cbor,omitempty"`
	RestartCapabilityCBOR   []byte `json:"restart_capability_cbor,omitempty"`
	PairingCapabilityCBOR   []byte `json:"pairing_capability_cbor,omitempty"`
	RecipientPublicKey      string `json:"recipient_public_key,omitempty"`
}

type LocalResponseV1 struct {
	SchemaVersion            string `json:"schema_version"`
	RequestID                string `json:"request_id"`
	Action                   string `json:"action"`
	Status                   string `json:"status"`
	ErrorCode                string `json:"error_code,omitempty"`
	PossessionProofCBOR      []byte `json:"possession_proof_cbor,omitempty"`
	CanaryProofCBOR          []byte `json:"canary_proof_cbor,omitempty"`
	RestartReceiptCBOR       []byte `json:"restart_receipt_cbor,omitempty"`
	PairingBeginReceiptCBOR  []byte `json:"pairing_begin_receipt_cbor,omitempty"`
	PairingResumeReceiptCBOR []byte `json:"pairing_resume_receipt_cbor,omitempty"`
}

type LocalControl interface {
	Bootstrap(context.Context, installer.SignedRootHelperBootstrapCapabilityV1) (PossessionProof, error)
	Canary(context.Context, installer.SignedRootHelperBootstrapCapabilityV1) (CanaryProof, error)
	Restart(context.Context, installer.SignedRootHelperRestartCapabilityV1) (workeroperation.RootHelperReceipt, error)
	PairingBegin(context.Context, installer.SignedRootHelperPairingCapabilityV1, string) (PairingBeginReceiptV1, error)
	PairingResume(context.Context, installer.SignedRootHelperPairingCapabilityV1) (PairingResumeReceiptV1, error)
}

type ControlFactory interface {
	ForDelivery(context.Context, installer.DeliveryV1) (LocalControl, error)
}

type ControlFactoryFunc func(context.Context, installer.DeliveryV1) (LocalControl, error)

func (function ControlFactoryFunc) ForDelivery(ctx context.Context, delivery installer.DeliveryV1) (LocalControl, error) {
	return function(ctx, delivery)
}

type LocalServer struct {
	trust   installer.RootTrustMaterialV1
	factory ControlFactory
}

func NewLocalServer(trust installer.RootTrustMaterialV1, factory ControlFactory) (*LocalServer, error) {
	if factory == nil || installer.ValidateRootTrustMaterial(trust) != nil {
		return nil, ErrInvalid
	}
	encoded, err := canonical.Marshal(trust)
	if err != nil {
		return nil, ErrInvalid
	}
	var cloned installer.RootTrustMaterialV1
	if installer.DecodeCanonical(encoded, &cloned) != nil {
		return nil, ErrInvalid
	}
	return &LocalServer{trust: cloned, factory: factory}, nil
}

func (server *LocalServer) Handle(ctx context.Context, input io.Reader, output io.Writer) error {
	payload, err := readLocalFrame(input, maxLocalRequestBytes)
	if err != nil {
		return writeLocalFrame(output, mustResponse(LocalResponseV1{
			SchemaVersion: LocalProtocolSchemaV1, Status: StatusRejected, ErrorCode: ErrorInvalid,
		}))
	}
	defer clear(payload)
	var request LocalRequestV1
	if installer.DecodeCanonical(payload, &request) != nil {
		return writeLocalFrame(output, mustResponse(LocalResponseV1{
			SchemaVersion: LocalProtocolSchemaV1, Status: StatusRejected, ErrorCode: ErrorInvalid,
		}))
	}
	response := LocalResponseV1{
		SchemaVersion: LocalProtocolSchemaV1, RequestID: request.RequestID,
		Action: request.Action, Status: StatusRejected,
	}
	if validateLocalRequest(request) != nil {
		response.ErrorCode = ErrorInvalid
		return writeLocalFrame(output, mustResponse(response))
	}
	var delivery installer.DeliveryV1
	if installer.DecodeCanonical(request.DeliveryCBOR, &delivery) != nil ||
		installer.ValidateDeliveryAgainstRootTrust(delivery, server.trust) != nil {
		response.ErrorCode = ErrorUnauthorized
		return writeLocalFrame(output, mustResponse(response))
	}
	control, err := server.factory.ForDelivery(ctx, delivery)
	if err != nil || control == nil {
		response.ErrorCode = localErrorCode(err)
		return writeLocalFrame(output, mustResponse(response))
	}
	switch request.Action {
	case ActionBootstrap:
		var capability installer.SignedRootHelperBootstrapCapabilityV1
		if installer.DecodeCanonical(request.BootstrapCapabilityCBOR, &capability) != nil {
			response.ErrorCode = ErrorInvalid
			break
		}
		value, callErr := control.Bootstrap(ctx, capability)
		if callErr != nil {
			response.ErrorCode = localErrorCode(callErr)
			break
		}
		response.PossessionProofCBOR, err = canonical.Marshal(value)
	case ActionCanary:
		var capability installer.SignedRootHelperBootstrapCapabilityV1
		if installer.DecodeCanonical(request.BootstrapCapabilityCBOR, &capability) != nil {
			response.ErrorCode = ErrorInvalid
			break
		}
		value, callErr := control.Canary(ctx, capability)
		if callErr != nil {
			response.ErrorCode = localErrorCode(callErr)
			break
		}
		response.CanaryProofCBOR, err = canonical.Marshal(value)
	case ActionRestart:
		var capability installer.SignedRootHelperRestartCapabilityV1
		if installer.DecodeCanonical(request.RestartCapabilityCBOR, &capability) != nil {
			response.ErrorCode = ErrorInvalid
			break
		}
		value, callErr := control.Restart(ctx, capability)
		if callErr != nil {
			response.ErrorCode = localErrorCode(callErr)
			break
		}
		response.RestartReceiptCBOR, err = canonical.Marshal(value)
	case ActionPairingBegin:
		var capability installer.SignedRootHelperPairingCapabilityV1
		if installer.DecodeCanonical(request.PairingCapabilityCBOR, &capability) != nil {
			response.ErrorCode = ErrorInvalid
			break
		}
		value, callErr := control.PairingBegin(ctx, capability, request.RecipientPublicKey)
		if callErr != nil {
			response.ErrorCode = localErrorCode(callErr)
			break
		}
		response.PairingBeginReceiptCBOR, err = canonical.Marshal(value)
	case ActionPairingResume:
		var capability installer.SignedRootHelperPairingCapabilityV1
		if installer.DecodeCanonical(request.PairingCapabilityCBOR, &capability) != nil {
			response.ErrorCode = ErrorInvalid
			break
		}
		value, callErr := control.PairingResume(ctx, capability)
		if callErr != nil {
			response.ErrorCode = localErrorCode(callErr)
			break
		}
		response.PairingResumeReceiptCBOR, err = canonical.Marshal(value)
	}
	if err != nil {
		response = LocalResponseV1{
			SchemaVersion: LocalProtocolSchemaV1, RequestID: request.RequestID,
			Action: request.Action, Status: StatusRejected, ErrorCode: ErrorUnavailable,
		}
	} else if response.ErrorCode == "" {
		response.Status = StatusSucceeded
	}
	return writeLocalFrame(output, mustResponse(response))
}

func (server *LocalServer) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || ctx == nil || listener == nil {
		return ErrInvalid
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
		_ = server.Handle(ctx, connection, connection)
		_ = connection.Close()
	}
}

func validateLocalRequest(value LocalRequestV1) error {
	id, idErr := uuid.Parse(value.RequestID)
	if value.SchemaVersion != LocalProtocolSchemaV1 || idErr != nil || id == uuid.Nil ||
		id.String() != value.RequestID || len(value.DeliveryCBOR) == 0 {
		return ErrInvalid
	}
	switch value.Action {
	case ActionBootstrap, ActionCanary:
		if len(value.BootstrapCapabilityCBOR) == 0 || len(value.RestartCapabilityCBOR) != 0 ||
			len(value.PairingCapabilityCBOR) != 0 || value.RecipientPublicKey != "" {
			return ErrInvalid
		}
	case ActionRestart:
		if len(value.RestartCapabilityCBOR) == 0 || len(value.BootstrapCapabilityCBOR) != 0 ||
			len(value.PairingCapabilityCBOR) != 0 || value.RecipientPublicKey != "" {
			return ErrInvalid
		}
	case ActionPairingBegin:
		if len(value.PairingCapabilityCBOR) == 0 || len(value.BootstrapCapabilityCBOR) != 0 ||
			len(value.RestartCapabilityCBOR) != 0 || value.RecipientPublicKey == "" {
			return ErrInvalid
		}
	case ActionPairingResume:
		if len(value.PairingCapabilityCBOR) == 0 || len(value.BootstrapCapabilityCBOR) != 0 ||
			len(value.RestartCapabilityCBOR) != 0 || value.RecipientPublicKey != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validateLocalResponse(value LocalResponseV1, request LocalRequestV1) error {
	if value.SchemaVersion != LocalProtocolSchemaV1 || value.RequestID != request.RequestID || value.Action != request.Action {
		return ErrInvalid
	}
	results := 0
	if len(value.PossessionProofCBOR) != 0 {
		results++
	}
	if len(value.CanaryProofCBOR) != 0 {
		results++
	}
	if len(value.RestartReceiptCBOR) != 0 {
		results++
	}
	if len(value.PairingBeginReceiptCBOR) != 0 {
		results++
	}
	if len(value.PairingResumeReceiptCBOR) != 0 {
		results++
	}
	if value.Status == StatusRejected {
		if value.ErrorCode == "" || results != 0 {
			return ErrInvalid
		}
		return localError(value.ErrorCode)
	}
	if value.Status != StatusSucceeded || value.ErrorCode != "" || results != 1 {
		return ErrInvalid
	}
	switch request.Action {
	case ActionBootstrap:
		if len(value.PossessionProofCBOR) == 0 {
			return ErrInvalid
		}
	case ActionCanary:
		if len(value.CanaryProofCBOR) == 0 {
			return ErrInvalid
		}
	case ActionRestart:
		if len(value.RestartReceiptCBOR) == 0 {
			return ErrInvalid
		}
	case ActionPairingBegin:
		if len(value.PairingBeginReceiptCBOR) == 0 {
			return ErrInvalid
		}
	case ActionPairingResume:
		if len(value.PairingResumeReceiptCBOR) == 0 {
			return ErrInvalid
		}
	}
	return nil
}

type localDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type SocketClient struct {
	path   string
	dialer localDialer
}

func NewSocketClient(socketPath string) (*SocketClient, error) {
	return newSocketClient(socketPath, &net.Dialer{})
}

func newSocketClient(socketPath string, dialer localDialer) (*SocketClient, error) {
	if socketPath == "" || !path.IsAbs(socketPath) || path.Clean(socketPath) != socketPath || dialer == nil {
		return nil, ErrInvalid
	}
	return &SocketClient{path: socketPath, dialer: dialer}, nil
}

func (client *SocketClient) Bootstrap(ctx context.Context, delivery installer.DeliveryV1, capability installer.SignedRootHelperBootstrapCapabilityV1) (PossessionProof, error) {
	if len(capability.Capability.HelperPublicKey) != ed25519.PublicKeySize {
		return PossessionProof{}, ErrUnauthorized
	}
	request, err := newLocalRequest(ActionBootstrap, delivery, capability, nil, nil, "")
	if err != nil {
		return PossessionProof{}, err
	}
	response, err := client.call(ctx, request)
	if err != nil {
		return PossessionProof{}, err
	}
	var value PossessionProof
	if installer.DecodeCanonical(response.PossessionProofCBOR, &value) != nil {
		return PossessionProof{}, ErrInvalid
	}
	payload, payloadErr := helperPossessionPayload(capability)
	if payloadErr != nil || value.CapabilityID != capability.Capability.CapabilityID ||
		value.DeliveryID != capability.Capability.HelperBinding.DeliveryID ||
		value.DeploymentID != capability.Capability.HelperBinding.DeploymentID ||
		value.InstanceID != capability.Capability.HelperBinding.InstanceID ||
		value.PrincipalID != capability.Capability.HelperBinding.WorkerPrincipalID ||
		!ed25519.Verify(ed25519.PublicKey(capability.Capability.HelperPublicKey), payload, value.Signature) {
		clear(payload)
		return PossessionProof{}, ErrUnauthorized
	}
	clear(payload)
	return value, nil
}

func (client *SocketClient) Canary(ctx context.Context, delivery installer.DeliveryV1, capability installer.SignedRootHelperBootstrapCapabilityV1) (CanaryProof, error) {
	if len(capability.Capability.HelperPublicKey) != ed25519.PublicKeySize {
		return CanaryProof{}, ErrUnauthorized
	}
	request, err := newLocalRequest(ActionCanary, delivery, capability, nil, nil, "")
	if err != nil {
		return CanaryProof{}, err
	}
	response, err := client.call(ctx, request)
	if err != nil {
		return CanaryProof{}, err
	}
	var value CanaryProof
	if installer.DecodeCanonical(response.CanaryProofCBOR, &value) != nil {
		return CanaryProof{}, ErrInvalid
	}
	payload, payloadErr := helperCanaryPayload(capability, value.ObservedAt)
	if payloadErr != nil || value.CapabilityID != capability.Capability.CapabilityID ||
		value.DeliveryID != capability.Capability.HelperBinding.DeliveryID ||
		value.DeploymentID != capability.Capability.HelperBinding.DeploymentID ||
		value.InstanceID != capability.Capability.HelperBinding.InstanceID ||
		value.PrincipalID != capability.Capability.HelperBinding.WorkerPrincipalID ||
		value.ErrorCode != accessDeniedCode ||
		!ed25519.Verify(ed25519.PublicKey(capability.Capability.HelperPublicKey), payload, value.Signature) {
		clear(payload)
		return CanaryProof{}, ErrUnauthorized
	}
	clear(payload)
	return value, nil
}

func (client *SocketClient) Restart(ctx context.Context, delivery installer.DeliveryV1, capability installer.SignedRootHelperRestartCapabilityV1, helperPublicKey ed25519.PublicKey) (workeroperation.RootHelperReceipt, error) {
	if len(helperPublicKey) != ed25519.PublicKeySize ||
		publicKeyDigest(helperPublicKey) != capability.Capability.HelperPublicKeyDigest {
		return workeroperation.RootHelperReceipt{}, ErrUnauthorized
	}
	request, err := newLocalRequest(ActionRestart, delivery, nil, capability, nil, "")
	if err != nil {
		return workeroperation.RootHelperReceipt{}, err
	}
	response, err := client.call(ctx, request)
	if err != nil {
		return workeroperation.RootHelperReceipt{}, err
	}
	var value workeroperation.RootHelperReceipt
	if installer.DecodeCanonical(response.RestartReceiptCBOR, &value) != nil {
		return workeroperation.RootHelperReceipt{}, ErrInvalid
	}
	if validateRestartReceipt(value, capability.Capability, helperPublicKey) != nil {
		return workeroperation.RootHelperReceipt{}, ErrUnauthorized
	}
	return value, nil
}

func (client *SocketClient) PairingBegin(ctx context.Context, delivery installer.DeliveryV1, capability installer.SignedRootHelperPairingCapabilityV1, recipientPublicKey string, helperPublicKey ed25519.PublicKey) (PairingBeginReceiptV1, error) {
	if len(helperPublicKey) != ed25519.PublicKeySize ||
		publicKeyDigest(helperPublicKey) != capability.Capability.HelperPublicKeyDigest {
		return PairingBeginReceiptV1{}, ErrUnauthorized
	}
	request, err := newLocalRequest(ActionPairingBegin, delivery, nil, nil, capability, recipientPublicKey)
	if err != nil {
		return PairingBeginReceiptV1{}, err
	}
	response, err := client.call(ctx, request)
	if err != nil {
		return PairingBeginReceiptV1{}, err
	}
	var value PairingBeginReceiptV1
	if installer.DecodeCanonical(response.PairingBeginReceiptCBOR, &value) != nil ||
		validatePairingBeginReceipt(value, capability.Capability, recipientPublicKey, helperPublicKey) != nil {
		return PairingBeginReceiptV1{}, ErrUnauthorized
	}
	return value, nil
}

func (client *SocketClient) PairingResume(ctx context.Context, delivery installer.DeliveryV1, capability installer.SignedRootHelperPairingCapabilityV1, helperPublicKey ed25519.PublicKey) (PairingResumeReceiptV1, error) {
	if len(helperPublicKey) != ed25519.PublicKeySize ||
		publicKeyDigest(helperPublicKey) != capability.Capability.HelperPublicKeyDigest {
		return PairingResumeReceiptV1{}, ErrUnauthorized
	}
	request, err := newLocalRequest(ActionPairingResume, delivery, nil, nil, capability, "")
	if err != nil {
		return PairingResumeReceiptV1{}, err
	}
	response, err := client.call(ctx, request)
	if err != nil {
		return PairingResumeReceiptV1{}, err
	}
	var value PairingResumeReceiptV1
	if installer.DecodeCanonical(response.PairingResumeReceiptCBOR, &value) != nil ||
		validatePairingResumeReceipt(value, capability.Capability, helperPublicKey) != nil {
		return PairingResumeReceiptV1{}, ErrUnauthorized
	}
	return value, nil
}

func newLocalRequest(action string, delivery installer.DeliveryV1, bootstrap any, restart any, pairing any, recipientPublicKey string) (LocalRequestV1, error) {
	deliveryCBOR, err := canonical.Marshal(delivery)
	if err != nil {
		return LocalRequestV1{}, ErrInvalid
	}
	request := LocalRequestV1{
		SchemaVersion: LocalProtocolSchemaV1, RequestID: uuid.NewString(), Action: action, DeliveryCBOR: deliveryCBOR,
		RecipientPublicKey: recipientPublicKey,
	}
	if bootstrap != nil {
		request.BootstrapCapabilityCBOR, err = canonical.Marshal(bootstrap)
	}
	if restart != nil && err == nil {
		request.RestartCapabilityCBOR, err = canonical.Marshal(restart)
	}
	if pairing != nil && err == nil {
		request.PairingCapabilityCBOR, err = canonical.Marshal(pairing)
	}
	if err != nil || validateLocalRequest(request) != nil {
		return LocalRequestV1{}, ErrInvalid
	}
	return request, nil
}

func (client *SocketClient) call(ctx context.Context, request LocalRequestV1) (LocalResponseV1, error) {
	if client == nil || ctx == nil {
		return LocalResponseV1{}, ErrInvalid
	}
	payload, err := canonical.Marshal(request)
	if err != nil {
		return LocalResponseV1{}, ErrInvalid
	}
	connection, err := client.dialer.DialContext(ctx, "unix", client.path)
	if err != nil {
		return LocalResponseV1{}, ErrUnavailable
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	} else {
		_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	}
	if err := writeLocalFrame(connection, payload); err != nil {
		return LocalResponseV1{}, ErrUnavailable
	}
	responsePayload, err := readLocalFrame(connection, maxLocalResponseBytes)
	if err != nil {
		return LocalResponseV1{}, ErrUnavailable
	}
	var response LocalResponseV1
	if installer.DecodeCanonical(responsePayload, &response) != nil {
		return LocalResponseV1{}, ErrInvalid
	}
	if err := validateLocalResponse(response, request); err != nil {
		return response, err
	}
	return response, nil
}

func readLocalFrame(reader io.Reader, maximum uint32) ([]byte, error) {
	var size uint32
	if binary.Read(reader, binary.BigEndian, &size) != nil || size == 0 || size > maximum {
		return nil, ErrInvalid
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		clear(value)
		return nil, ErrInvalid
	}
	return value, nil
}

func writeLocalFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return ErrInvalid
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err := io.Copy(writer, bytes.NewReader(payload))
	return err
}

func mustResponse(value LocalResponseV1) []byte {
	payload, _ := canonical.Marshal(value)
	return payload
}

func localErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return ErrorUnauthorized
	case errors.Is(err, ErrNotReady):
		return ErrorNotReady
	case errors.Is(err, ErrInvalid):
		return ErrorInvalid
	default:
		return ErrorUnavailable
	}
}

func localError(code string) error {
	switch code {
	case ErrorInvalid:
		return ErrInvalid
	case ErrorUnauthorized:
		return ErrUnauthorized
	case ErrorNotReady:
		return ErrNotReady
	case ErrorUnavailable:
		return ErrUnavailable
	default:
		return ErrInvalid
	}
}

func helperPossessionPayload(capability installer.SignedRootHelperBootstrapCapabilityV1) ([]byte, error) {
	return helperkey.PossessionPayload(capability.Capability.HelperBinding, capability.Capability.Nonce)
}

func helperCanaryPayload(capability installer.SignedRootHelperBootstrapCapabilityV1, observedAt time.Time) ([]byte, error) {
	return helperkey.CanaryPayload(capability.Capability.HelperBinding, observedAt)
}

package execgate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type operation string

const (
	operationPing     operation = "ping"
	operationRegister operation = "register"
	operationActivate operation = "activate"
	operationProof    operation = "proof"
	operationTerminal operation = "terminal"
	operationCancel   operation = "cancel"
)

type wireRequest struct {
	Schema       string        `json:"schema"`
	Operation    operation     `json:"operation"`
	RunID        string        `json:"run_id,omitempty"`
	Registration *Registration `json:"registration,omitempty"`
	PiPID        int32         `json:"pi_pid,omitempty"`
}

func (request wireRequest) validate() error {
	if request.Schema != ProtocolSchemaV1 {
		return ErrInvalid
	}
	switch request.Operation {
	case operationPing:
		if request.RunID != "" || request.Registration != nil || request.PiPID != 0 {
			return ErrInvalid
		}
	case operationRegister:
		if request.RunID != "" || request.Registration == nil ||
			request.Registration.Validate() != nil || request.PiPID != 0 {
			return ErrInvalid
		}
	case operationActivate:
		if !canonicalUUID(request.RunID) || request.Registration != nil || request.PiPID < 1 {
			return ErrInvalid
		}
	case operationProof, operationTerminal, operationCancel:
		if !canonicalUUID(request.RunID) || request.Registration != nil || request.PiPID != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type wireResponse struct {
	Schema string `json:"schema"`
	OK     bool   `json:"ok"`
	Code   string `json:"code,omitempty"`
	RunID  string `json:"run_id,omitempty"`
	Proof  *Proof `json:"proof,omitempty"`
}

func (response wireResponse) validate() error {
	if response.Schema != ProtocolSchemaV1 || len(response.Code) > 64 {
		return ErrInvalid
	}
	if !response.OK {
		if response.Code == "" || response.RunID != "" || response.Proof != nil {
			return ErrInvalid
		}
		return nil
	}
	if response.Code != "" {
		return ErrInvalid
	}
	if response.RunID != "" && !canonicalUUID(response.RunID) {
		return ErrInvalid
	}
	if response.Proof != nil && response.Proof.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func encodeCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > MaximumWireBytes {
		clear(raw)
		return nil, ErrInvalid
	}
	return raw, nil
}

func decodeCanonical(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > MaximumWireBytes ||
		!bytes.Equal(bytes.TrimSpace(raw), raw) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return ErrInvalid
	}
	clear(canonical)
	return nil
}

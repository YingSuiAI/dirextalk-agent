package workerprotocol

import "time"

const ControlFrameSchemaV1 = "dirextalk.worker.control-frame/v1"

type ControlDirection string

const (
	DirectionCentralToWorker ControlDirection = "central_to_worker"
	DirectionWorkerToCentral ControlDirection = "worker_to_central"
)

type ControlKind string

const (
	ControlAssignment       ControlKind = "assignment"
	ControlHello            ControlKind = "hello"
	ControlHeartbeat        ControlKind = "heartbeat"
	ControlProgress         ControlKind = "progress"
	ControlCancel           ControlKind = "cancel"
	ControlLeaseUpdate      ControlKind = "lease_update"
	ControlCredentialRevoke ControlKind = "credential_revoke"
	ControlCheckpoint       ControlKind = "checkpoint"
	ControlResult           ControlKind = "result"
	ControlCleanup          ControlKind = "cleanup"
	ControlError            ControlKind = "error"
)

type ControlReferenceV1 struct {
	ReferenceID string `json:"reference_id"`
	Digest      string `json:"digest"`
}

func (value ControlReferenceV1) Validate() error {
	if !canonicalUUID(value.ReferenceID) ||
		!validDigest(value.Digest) {
		return ErrInvalid
	}
	return nil
}

type ControlProgressV1 struct {
	BasisPoints uint32 `json:"basis_points"`
	Stage       string `json:"stage"`
	Message     string `json:"message"`
}

func (value ControlProgressV1) Validate() error {
	if value.BasisPoints > 10_000 ||
		!validToken(value.Stage, 64) ||
		!validText(value.Message, 1024) {
		return ErrInvalid
	}
	return nil
}

type ControlLeaseV1 struct {
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

func (value ControlLeaseV1) Validate(sentAt time.Time) error {
	if !utcSecond(value.LeaseExpiresAt) ||
		!value.LeaseExpiresAt.After(sentAt) ||
		value.LeaseExpiresAt.After(sentAt.Add(24*time.Hour)) {
		return ErrInvalid
	}
	return nil
}

type ControlErrorV1 struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (value ControlErrorV1) Validate() error {
	if !validToken(value.Code, 64) ||
		!validText(value.Message, 2048) {
		return ErrInvalid
	}
	return nil
}

// ControlFrameV1 is the message envelope for one ordered bidirectional stream.
// Reference points to an immutable contract such as an ExecutionEnvelope,
// Checkpoint, ResultManifest, or CleanupReceipt.
type ControlFrameV1 struct {
	SchemaVersion   string              `json:"schema_version"`
	ProtocolVersion string              `json:"protocol_version"`
	StreamID        string              `json:"stream_id"`
	Sequence        uint64              `json:"sequence"`
	Direction       ControlDirection    `json:"direction"`
	Kind            ControlKind         `json:"kind"`
	ExecutionID     string              `json:"execution_id"`
	WorkerID        string              `json:"worker_id"`
	Attempt         uint32              `json:"attempt"`
	LeaseEpoch      uint64              `json:"lease_epoch"`
	SentAt          time.Time           `json:"sent_at"`
	Reference       *ControlReferenceV1 `json:"reference,omitempty"`
	Progress        *ControlProgressV1  `json:"progress,omitempty"`
	Lease           *ControlLeaseV1     `json:"lease,omitempty"`
	Error           *ControlErrorV1     `json:"error,omitempty"`
}

func (value ControlFrameV1) Validate() error {
	if value.SchemaVersion != ControlFrameSchemaV1 ||
		value.ProtocolVersion != ProtocolVersion ||
		!canonicalUUID(value.StreamID) ||
		value.Sequence == 0 ||
		(value.Direction != DirectionCentralToWorker &&
			value.Direction != DirectionWorkerToCentral) ||
		!canonicalUUID(value.ExecutionID) ||
		!canonicalUUID(value.WorkerID) ||
		value.Attempt == 0 ||
		value.LeaseEpoch == 0 ||
		!utcSecond(value.SentAt) {
		return ErrInvalid
	}
	payloadCount := btoi(value.Reference != nil) +
		btoi(value.Progress != nil) +
		btoi(value.Lease != nil) +
		btoi(value.Error != nil)
	switch value.Kind {
	case ControlAssignment,
		ControlHello,
		ControlCheckpoint,
		ControlResult,
		ControlCleanup,
		ControlCredentialRevoke:
		if value.Reference == nil ||
			value.Reference.Validate() != nil ||
			payloadCount != 1 {
			return ErrInvalid
		}
	case ControlProgress:
		if value.Progress == nil ||
			value.Progress.Validate() != nil ||
			payloadCount != 1 {
			return ErrInvalid
		}
	case ControlLeaseUpdate:
		if value.Lease == nil ||
			value.Lease.Validate(value.SentAt) != nil ||
			payloadCount != 1 {
			return ErrInvalid
		}
	case ControlError:
		if value.Error == nil ||
			value.Error.Validate() != nil ||
			payloadCount != 1 {
			return ErrInvalid
		}
	case ControlHeartbeat, ControlCancel:
		if payloadCount != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if value.Direction == DirectionCentralToWorker {
		switch value.Kind {
		case ControlAssignment,
			ControlCancel,
			ControlLeaseUpdate,
			ControlCredentialRevoke:
		default:
			return ErrInvalid
		}
	} else {
		switch value.Kind {
		case ControlHello,
			ControlHeartbeat,
			ControlProgress,
			ControlCheckpoint,
			ControlResult,
			ControlCleanup,
			ControlError:
		default:
			return ErrInvalid
		}
	}
	return nil
}

func (value ControlFrameV1) Digest() (string, error) {
	return digestValidated(value, value.Validate)
}

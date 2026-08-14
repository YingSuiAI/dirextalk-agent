// Package execgate defines the private Linux execution-permission gate used by
// one ephemeral Cloud Worker. The gate is deliberately separate from the
// Worker process: only the gate receives CAP_SYS_ADMIN for fanotify.
package execgate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	ProtocolSchemaV1 = "dirextalk.agent.pi-exec-gate/v1"
	ProofSchemaV2    = "dirextalk.agent.pi-runtime-topology/v2"

	DefaultSocketPath = "/run/dirextalk-cloud-worker-exec-gate/control.sock"
	MaximumWireBytes  = 64 << 10
)

var (
	ErrInvalid     = errors.New("invalid Pi execution gate contract")
	ErrUnavailable = errors.New("Pi execution gate unavailable")
	ErrViolation   = errors.New("Pi execution topology violated")

	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type ProofState string

const (
	ProofActive   ProofState = "active"
	ProofTerminal ProofState = "terminal"
	ProofViolated ProofState = "violated"
)

// Registration is supplied by compiled Worker code after a claim and before
// fork. Paths are local immutable-image paths, never task/model input.
type Registration struct {
	ExecutionID       string `json:"execution_id"`
	TaskID            string `json:"task_id"`
	Attempt           uint32 `json:"attempt"`
	LeaseEpoch        uint64 `json:"lease_epoch"`
	RuntimeTaskSHA256 string `json:"runtime_task_sha256"`
	PiExecutable      string `json:"pi_executable"`
	PiSHA256          string `json:"pi_sha256"`
}

func (value Registration) Validate() error {
	if !canonicalUUID(value.ExecutionID) || !canonicalUUID(value.TaskID) ||
		value.Attempt == 0 || value.LeaseEpoch == 0 ||
		!validDigest(value.RuntimeTaskSHA256) || !cleanAbsolute(value.PiExecutable) ||
		!validDigest(value.PiSHA256) {
		return ErrInvalid
	}
	return nil
}

type ProcessIdentity struct {
	PID            int32  `json:"pid"`
	StartTimeTicks uint64 `json:"start_time_ticks"`
	Device         uint64 `json:"device"`
	Inode          uint64 `json:"inode"`
	SHA256         string `json:"sha256"`
}

func (value ProcessIdentity) validate() error {
	if value.PID < 1 || value.StartTimeTicks == 0 || value.Inode == 0 ||
		!validDigest(value.SHA256) {
		return ErrInvalid
	}
	return nil
}

// Proof is a private WorkerControl fact. WorkerProcessCount and
// ActivePiProcesses use the pinned executable identities. TotalAllowedPiExecs
// is an audit count of authorized pinned-image execs, not a concurrency limit.
// CgroupProcessCount and ActiveDescendants cover every process in the Worker
// cgroup so a terminal proof cannot ignore a surviving Pi/bash/git/tool child.
type Proof struct {
	SchemaVersion       string          `json:"schema_version"`
	State               ProofState      `json:"state"`
	RunID               string          `json:"run_id"`
	ExecutionID         string          `json:"execution_id"`
	TaskID              string          `json:"task_id"`
	Attempt             uint32          `json:"attempt"`
	LeaseEpoch          uint64          `json:"lease_epoch"`
	RuntimeTaskSHA256   string          `json:"runtime_task_sha256"`
	BootID              string          `json:"boot_id"`
	CgroupSHA256        string          `json:"cgroup_sha256"`
	PolicySHA256        string          `json:"policy_sha256"`
	Worker              ProcessIdentity `json:"worker"`
	Pi                  ProcessIdentity `json:"pi"`
	WorkerProcessCount  uint32          `json:"worker_process_count"`
	CgroupProcessCount  uint32          `json:"cgroup_process_count"`
	ActiveDescendants   uint32          `json:"active_descendants"`
	ActivePiProcesses   uint32          `json:"active_pi_processes"`
	TotalAllowedPiExecs uint32          `json:"total_allowed_pi_execs"`
	ObservedAtUnixNano  int64           `json:"observed_at_unix_nano"`
	ViolationCode       string          `json:"violation_code,omitempty"`
}

func (proof Proof) Validate() error {
	if proof.SchemaVersion != ProofSchemaV2 || !canonicalUUID(proof.RunID) ||
		!canonicalUUID(proof.ExecutionID) || !canonicalUUID(proof.TaskID) ||
		proof.Attempt == 0 || proof.LeaseEpoch == 0 ||
		!validDigest(proof.RuntimeTaskSHA256) || !canonicalUUID(proof.BootID) ||
		!validDigest(proof.CgroupSHA256) || !validDigest(proof.PolicySHA256) ||
		proof.Worker.validate() != nil || proof.Pi.validate() != nil ||
		proof.ObservedAtUnixNano <= 0 || proof.WorkerProcessCount != 1 ||
		proof.TotalAllowedPiExecs == 0 || len(proof.ViolationCode) > 64 {
		return ErrInvalid
	}
	switch proof.State {
	case ProofActive:
		if proof.ActivePiProcesses == 0 || proof.CgroupProcessCount < 2 ||
			proof.ActiveDescendants != proof.CgroupProcessCount-1 || proof.ActiveDescendants < 1 ||
			proof.ActivePiProcesses > proof.ActiveDescendants ||
			proof.ViolationCode != "" {
			return ErrInvalid
		}
	case ProofTerminal:
		if proof.ActivePiProcesses != 0 || proof.CgroupProcessCount != 1 ||
			proof.ActiveDescendants != 0 || proof.ViolationCode != "" {
			return ErrInvalid
		}
	case ProofViolated:
		if proof.ViolationCode == "" || strings.TrimSpace(proof.ViolationCode) != proof.ViolationCode {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (proof Proof) ValidateTerminal() error {
	if proof.Validate() != nil || proof.State != ProofTerminal ||
		proof.TotalAllowedPiExecs == 0 || proof.ActivePiProcesses != 0 {
		return ErrInvalid
	}
	return nil
}

func (proof Proof) Digest() (string, error) {
	if proof.Validate() != nil {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(digest[:]), nil
}

func UnixNanoUTC(value int64) (time.Time, error) {
	if value <= 0 {
		return time.Time{}, ErrInvalid
	}
	return time.Unix(0, value).UTC(), nil
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func cleanAbsolute(value string) bool {
	return strings.HasPrefix(value, "/") && value == strings.TrimSpace(value) &&
		!strings.ContainsAny(value, "\r\n\x00") && len(value) <= 4096
}

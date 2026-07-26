// Package runner is the Core Runner provider boundary.  It deliberately owns
// no database: durable workload, task, confirmation and dispatch state remain
// in coreworkload's Agent store.
package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
)

const (
	MaxPacketBytes = 64 << 10
	ProtocolV1     = 1
)

// ProbeRequest and ProbeResponse are private Unix-socket messages.  They are
// intentionally not part of the Agent gRPC contract: the random nonce proves
// that the process which passed SO_PEERCRED actually owns this supervisor.
type ProbeRequest struct {
	Version int    `json:"version"`
	Probe   string `json:"probe"`
	Nonce   string `json:"nonce"`
}
type ProbeResponse struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	Ready   bool   `json:"ready"`
}

var (
	ErrDenied = errors.New("core runner request denied")
	ErrReplay = errors.New("core runner receipt replay conflict")
)

// Request is descriptor-only. SecretFDs are ordinal descriptors received by
// SCM_RIGHTS; neither secret bytes nor Agent credentials can enter this ABI.
type Request struct {
	Action            string                      `json:"action"`
	WorkloadID        string                      `json:"workload_id"`
	OperationID       string                      `json:"operation_id"`
	PlanDigest        string                      `json:"plan_digest"`
	PlanRevision      uint64                      `json:"plan_revision"`
	DispatchClaim     string                      `json:"dispatch_claim"`
	DispatchEpoch     uint64                      `json:"dispatch_epoch"`
	Artifact          string                      `json:"artifact,omitempty"`
	CommandSteps      []string                    `json:"command_steps,omitempty"`
	Limits            coreworkload.ResourceLimits `json:"limits"`
	NetworkGrants     []string                    `json:"network_grants,omitempty"`
	SecretDescriptors []string                    `json:"secret_descriptors,omitempty"`
	Service           string                      `json:"service,omitempty"`
}
type Receipt struct {
	WorkloadID    string    `json:"workload_id"`
	PlanDigest    string    `json:"plan_digest"`
	DispatchClaim string    `json:"dispatch_claim"`
	DispatchEpoch uint64    `json:"dispatch_epoch"`
	Action        string    `json:"action"`
	State         string    `json:"state"`
	Digest        string    `json:"digest"`
	At            time.Time `json:"at"`
	ServiceDigest string    `json:"service_digest,omitempty"`
	PID           int       `json:"pid,omitempty"`
	StartTime     uint64    `json:"start_time,omitempty"`
	Cgroup        string    `json:"cgroup,omitempty"`
	// ApplyDigest binds the durable lifecycle record to the only request that
	// may start a service. Digest remains the response digest for this action.
	ApplyDigest  string `json:"apply_digest,omitempty"`
	Destroyed    bool   `json:"destroyed,omitempty"`
	OperationID  string `json:"operation_id,omitempty"`
	PlanRevision uint64 `json:"plan_revision,omitempty"`
	Service      string `json:"service,omitempty"`
}

func (r Request) Digest() string {
	b, _ := json.Marshal(r)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func (r Request) Validate() error {
	if r.Action != "apply" && r.Action != "destroy" && r.Action != "read" || !coreworkload.ValidUUID(r.WorkloadID) || !coreworkload.ValidUUID(r.OperationID) || !coreworkload.ValidDigest(r.PlanDigest) || r.PlanRevision == 0 || !coreworkload.ValidUUID(r.DispatchClaim) || r.DispatchEpoch == 0 {
		return ErrDenied
	}
	if r.Action == "apply" && len(r.CommandSteps) == 0 && strings.TrimSpace(r.Artifact) == "" {
		return ErrDenied
	}
	if r.Action == "apply" && (!servicePathRE.MatchString(r.Service) || strings.Contains(r.Service, "..") || strings.HasPrefix(r.Service, "/")) {
		return ErrDenied
	}
	if r.Limits.CPU < 0 || r.Limits.MemoryMB < 0 || r.Limits.Processes < 0 || r.Limits.DiskMB < 0 || r.Limits.TimeoutS < 0 || r.Limits.OutputMB < 0 {
		return ErrDenied
	}
	for _, group := range [][]string{r.CommandSteps, r.NetworkGrants} {
		for _, value := range group {
			if strings.TrimSpace(value) == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
				return ErrDenied
			}
		}
	}
	for _, value := range r.SecretDescriptors {
		if !secretDescriptorRE.MatchString(value) {
			return ErrDenied
		}
	}
	// Canonical order prevents a caller from changing grants under the same
	// dispatch fence. Secret descriptors are opaque, one-use names only.
	if !sort.StringsAreSorted(r.NetworkGrants) || !sort.StringsAreSorted(r.SecretDescriptors) {
		return ErrDenied
	}
	return nil
}
func (r Request) Key() string {
	return r.WorkloadID + ":" + r.PlanDigest + ":" + r.DispatchClaim + ":" + string(r.Action)
}
func (r Request) LifecycleKey() string {
	// The service receipt belongs to the durable workload identity, not to an
	// individual apply/destroy dispatch fence.  Each operation still has its
	// own Digest and is validated by the caller/provider.
	return r.WorkloadID + ":" + r.PlanDigest + ":" + r.Service
}

var secretDescriptorRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
var servicePathRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)

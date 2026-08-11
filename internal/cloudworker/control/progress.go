package control

import "time"

const (
	MaximumProgressElapsedMS       = uint64((24 * time.Hour) / time.Millisecond)
	MaximumProgressCPUTimeMS       = uint64((7 * 24 * time.Hour) / time.Millisecond)
	MaximumProgressMemoryBytes     = uint64(64 << 30)
	MaximumProgressInvocationCount = uint64(1_000_000)
	MaximumProgressUploadedBytes   = uint64(9 << 20)
)

type ProgressPhase string

const (
	ProgressClaimed         ProgressPhase = "claimed"
	ProgressPreparingInputs ProgressPhase = "preparing_inputs"
	ProgressRunningPi       ProgressPhase = "running_pi"
	ProgressUploadingResult ProgressPhase = "uploading_result"
	ProgressCompleting      ProgressPhase = "completing"
)

// ProgressSnapshot contains only bounded counters and a closed phase. It must
// never contain model text, stderr, file paths, environment values, or object
// storage identities.
type ProgressSnapshot struct {
	Phase                ProgressPhase `json:"phase"`
	ElapsedMS            uint64        `json:"elapsed_ms"`
	LastActivityAt       time.Time     `json:"last_activity_at"`
	CPUTimeMS            uint64        `json:"cpu_time_ms"`
	MemoryHighWaterBytes uint64        `json:"memory_high_water_bytes"`
	InvocationCount      uint64        `json:"invocation_count"`
	UploadedBytes        uint64        `json:"uploaded_bytes"`
	OutputTruncated      bool          `json:"output_truncated"`
}

func (snapshot ProgressSnapshot) validateAt(at time.Time) error {
	if progressPhaseRank(snapshot.Phase) == 0 || snapshot.ElapsedMS > MaximumProgressElapsedMS ||
		snapshot.LastActivityAt.IsZero() || snapshot.LastActivityAt.Location() != time.UTC ||
		snapshot.LastActivityAt.After(at.UTC()) || snapshot.CPUTimeMS > MaximumProgressCPUTimeMS ||
		snapshot.MemoryHighWaterBytes > MaximumProgressMemoryBytes ||
		snapshot.InvocationCount > MaximumProgressInvocationCount ||
		snapshot.UploadedBytes > MaximumProgressUploadedBytes {
		return ErrInvalid
	}
	return nil
}

func validateProgressAdvance(previous *ProgressSnapshot, next ProgressSnapshot, claimedAt, at time.Time) error {
	if next.validateAt(at) != nil || claimedAt.IsZero() || claimedAt.Location() != time.UTC || at.Before(claimedAt) ||
		next.LastActivityAt.Before(claimedAt) || next.ElapsedMS > uint64(at.Sub(claimedAt)/time.Millisecond) {
		return ErrInvalid
	}
	if previous == nil {
		if next.Phase != ProgressClaimed {
			return ErrConflict
		}
		return nil
	}
	if progressPhaseRank(next.Phase) < progressPhaseRank(previous.Phase) ||
		next.ElapsedMS < previous.ElapsedMS || next.LastActivityAt.Before(previous.LastActivityAt) ||
		next.CPUTimeMS < previous.CPUTimeMS || next.MemoryHighWaterBytes < previous.MemoryHighWaterBytes ||
		next.InvocationCount < previous.InvocationCount || next.UploadedBytes < previous.UploadedBytes ||
		(previous.OutputTruncated && !next.OutputTruncated) {
		return ErrConflict
	}
	return nil
}

// ValidateProgressAdvance is shared by durable stores so every implementation
// applies exactly the same closed phases, bounds, and monotonicity rules.
func ValidateProgressAdvance(previous *ProgressSnapshot, next ProgressSnapshot, claimedAt, at time.Time) error {
	return validateProgressAdvance(previous, next, claimedAt, at)
}

// ValidateProgressSnapshot validates a standalone persisted/public snapshot
// without imposing the first-heartbeat phase rule.
func ValidateProgressSnapshot(snapshot ProgressSnapshot, at time.Time) error {
	return snapshot.validateAt(at)
}

func progressPhaseRank(phase ProgressPhase) int {
	switch phase {
	case ProgressClaimed:
		return 1
	case ProgressPreparingInputs:
		return 2
	case ProgressRunningPi:
		return 3
	case ProgressUploadingResult:
		return 4
	case ProgressCompleting:
		return 5
	default:
		return 0
	}
}

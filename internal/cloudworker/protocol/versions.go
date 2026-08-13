// Package protocol owns the exact private Agent/Cloud Worker handshake.
package protocol

const (
	WorkerProtocolVersion    = "dirextalk.agent.cloud-worker-control/v1"
	RuntimeContractVersionV1 = "dirextalk.agent.ephemeral-pi-runtime/v1"
	RuntimeContractVersion   = "dirextalk.agent.ephemeral-pi-runtime/v2"
)

// Versions is declared by both peers during Claim. Only the current exact
// pair is accepted; absent and unknown versions have no compatibility path.
type Versions struct {
	WorkerProtocolVersion  string
	RuntimeContractVersion string
}

func Current() Versions {
	return Versions{
		WorkerProtocolVersion:  WorkerProtocolVersion,
		RuntimeContractVersion: RuntimeContractVersion,
	}
}

func (versions Versions) IsCurrent() bool {
	return versions == Current()
}

// IsReadable permits the previous runtime contract only while recovering an
// already-authorized execution. Claim always requires IsCurrent, so this path
// cannot launch a v1 Worker after the v2 rollout.
func (versions Versions) IsReadable() bool {
	return versions.WorkerProtocolVersion == WorkerProtocolVersion &&
		(versions.RuntimeContractVersion == RuntimeContractVersion ||
			versions.RuntimeContractVersion == RuntimeContractVersionV1)
}

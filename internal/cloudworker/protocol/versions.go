// Package protocol owns the exact private Agent/Cloud Worker handshake.
package protocol

const (
	WorkerProtocolVersion  = "dirextalk.agent.cloud-worker-control/v1"
	RuntimeContractVersion = "dirextalk.agent.ephemeral-pi-runtime/v1"
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

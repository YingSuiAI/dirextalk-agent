// Package workerimage owns the shared EC2 image compatibility and sizing
// contract used before quoting and again immediately before launch.
package workerimage

import "strings"

const (
	OfficialUbuntuGPUOwner       = "amazon"
	OfficialUbuntuGPUNamePattern = "Deep Learning Base OSS Nvidia Driver GPU AMI (Ubuntu 24.04) ????????"
)

// SupportsOfficialUbuntuGPU reports the x86_64 EC2 families documented for
// the official Ubuntu 24.04 OSS NVIDIA Driver GPU DLAMI.
func SupportsOfficialUbuntuGPU(instanceType string) bool {
	family, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(instanceType)), ".")
	if !ok {
		return false
	}
	switch family {
	case "g4dn", "g5", "g6", "gr6", "g6e", "g7", "g7e",
		"p4d", "p4de", "p5", "p5e", "p5en", "p6-b200", "p6-b300":
		return true
	default:
		return false
	}
}

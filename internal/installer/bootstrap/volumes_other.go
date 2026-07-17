//go:build !linux

package bootstrap

// Non-Linux bootstrap binaries deliberately cannot materialize an approved
// EBS filesystem. unavailableVolumes succeeds only for the empty capability.
func NewLinuxVolumeMaterializer() VolumeMaterializer { return unavailableVolumes{} }

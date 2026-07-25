//go:build linux && !amd64 && !arm64

package extensionrunner

// The admission layer rejects unsupported executable architectures, and the
// sandbox has no syscall table for them.
const sandboxAuditArch = 0

func sandboxAllowedSyscalls() []uint32 { return nil }

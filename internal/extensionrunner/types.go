// Package extensionrunner defines the closed, fail-closed local extension
// execution boundary.  It deliberately contains no Agent-side command runner.
package extensionrunner

import (
	"context"
	"errors"
	"time"
)

const (
	MaxMessageBytes = 1 << 20
	MaxStdinBytes   = 256 << 10
	MaxOutputBytes  = 256 << 10
	// MaxV2PacketBytes is deliberately below Linux AF_UNIX SOCK_SEQPACKET's
	// minimum practical packet ceiling.  The V2 ABI is one datagram, not a
	// stream, so larger canonical payloads are rejected before sendmsg.
	MaxV2PacketBytes = 64 << 10
)

var (
	ErrUnavailable = errors.New("extension runner unavailable")
	ErrInvalid     = errors.New("invalid extension invocation")
	ErrDenied      = errors.New("extension runner request denied")
)

type ResultFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// SandboxInvocationV2 is descriptor-only.  StartV2 implementations must take
// ownership of no descriptor: each is closed by Runner exactly once after the
// child has either been fully prepared or setup has failed.
type SandboxInvocationV2 struct {
	Request     RequestV2
	Install     *AdmittedInstall
	WorkspaceFD int
	StdinFD     int
	SecretFDs   []int
	// PersistentOutputLimit is an internal persistent-service-only budget.
	// When non-zero LinuxBackend discards raw stdout/stderr and accounts both
	// streams against this one shared limit from process start.
	PersistentOutputLimit int64
	// CoreTmpfsBytes and CoreResultPath select the internal Core-only manager
	// mode. They are never serialized in RequestV2 and therefore cannot be
	// selected by an extension caller.
	CoreTmpfsBytes int64
	CoreResultPath string
	CoreResultFD   int
}

// V2Backend is the descriptor-only backend boundary.
type V2Backend interface {
	Probe(context.Context) error
	StartV2(context.Context, SandboxInvocationV2) (Process, error)
}

type InstallResolver interface {
	ResolveInstall(string) (*AdmittedInstall, error)
}
type WorkspaceResolver interface {
	ResolveWorkspace(taskID, taskFence string) (int, error)
}

type Process interface {
	Wait() (stdout, stderr []byte, status string, err error)
	KillGroup() error
}

type Clock interface {
	After(time.Duration) <-chan time.Time
}
type realClock struct{}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

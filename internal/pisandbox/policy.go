// Package pisandbox applies the fail-closed filesystem view inherited by the
// official Pi process and all of its tool children.
package pisandbox

import (
	"errors"
	"path/filepath"
	"strings"
)

var (
	ErrInvalid     = errors.New("Pi sandbox policy is invalid")
	ErrUnsupported = errors.New("Pi sandbox is unavailable")
)

const (
	OfficialWorkerUID = 65532
	OfficialWorkerGID = 65532
	OfficialPiUID     = 65533
	OfficialPiGID     = OfficialWorkerGID
)

type Access uint8

const (
	ReadOnly Access = iota + 1
	ReadWrite
	ReadExecute
	ReadWriteExecute
)

type PathRule struct {
	Path   string
	Access Access
}

type Policy struct {
	MinimumABI uint32
	Paths      []PathRule
}

func (policy Policy) Validate() error {
	if policy.MinimumABI != 2 || len(policy.Paths) == 0 || len(policy.Paths) > 64 {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(policy.Paths))
	for _, rule := range policy.Paths {
		if !cleanAbsolute(rule.Path) || rule.Path == "/" || rule.Access < ReadOnly || rule.Access > ReadWriteExecute ||
			forbiddenControlPath(rule.Path) {
			return ErrInvalid
		}
		if _, duplicate := seen[rule.Path]; duplicate {
			return ErrInvalid
		}
		seen[rule.Path] = struct{}{}
	}
	return nil
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}

func forbiddenControlPath(path string) bool {
	if path == "/proc/self" {
		return false
	}
	for _, root := range []string{
		"/proc", "/run/credentials", "/run/dirextalk-worker", "/etc/dirextalk-worker",
		"/var/lib/dirextalk-worker/receipts",
	} {
		separator := string(filepath.Separator)
		if path == root || strings.HasPrefix(path, root+separator) || strings.HasPrefix(root, path+separator) {
			return true
		}
	}
	return false
}

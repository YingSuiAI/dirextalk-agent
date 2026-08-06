//go:build linux

package pisandbox

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	landlockCreateRulesetVersion = 1
	landlockRulePathBeneath      = 1

	accessFSExecute    = uint64(1 << 0)
	accessFSWriteFile  = uint64(1 << 1)
	accessFSReadFile   = uint64(1 << 2)
	accessFSReadDir    = uint64(1 << 3)
	accessFSRemoveDir  = uint64(1 << 4)
	accessFSRemoveFile = uint64(1 << 5)
	accessFSMakeChar   = uint64(1 << 6)
	accessFSMakeDir    = uint64(1 << 7)
	accessFSMakeReg    = uint64(1 << 8)
	accessFSMakeSock   = uint64(1 << 9)
	accessFSMakeFIFO   = uint64(1 << 10)
	accessFSMakeBlock  = uint64(1 << 11)
	accessFSMakeSym    = uint64(1 << 12)
	accessFSRefer      = uint64(1 << 13)
	accessFSTruncate   = uint64(1 << 14)
)

const handledAccessFSV2 = accessFSExecute | accessFSWriteFile | accessFSReadFile | accessFSReadDir |
	accessFSRemoveDir | accessFSRemoveFile | accessFSMakeChar | accessFSMakeDir | accessFSMakeReg |
	accessFSMakeSock | accessFSMakeFIFO | accessFSMakeBlock | accessFSMakeSym | accessFSRefer

type rulesetAttribute struct {
	HandledAccessFS uint64
}

type pathBeneathAttribute struct {
	AllowedAccess uint64
	ParentFD      int32
	Reserved      uint32
}

func CurrentABI() (uint32, error) {
	version, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 || version == 0 {
		return 0, ErrUnsupported
	}
	return uint32(version), nil
}

// Apply restricts the calling thread. Callers must lock it to an OS thread and
// immediately exec the target process after this function returns.
func Apply(policy Policy) error {
	if policy.Validate() != nil {
		return ErrInvalid
	}
	version, err := CurrentABI()
	if err != nil || version < policy.MinimumABI {
		return ErrUnsupported
	}
	handled := handledAccessFSV2
	if version >= 3 {
		handled |= accessFSTruncate
	}
	attribute := rulesetAttribute{HandledAccessFS: handled}
	ruleset, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute),
		0,
	)
	if errno != 0 {
		return ErrUnsupported
	}
	defer unix.Close(int(ruleset))
	for _, rule := range policy.Paths {
		if err := addPathRule(int(ruleset), rule, version); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return ErrUnsupported
	}
	if version < 3 && installTruncateFilter() != nil {
		return ErrUnsupported
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0, 0)
	if errno != 0 {
		return ErrUnsupported
	}
	return nil
}

func addPathRule(ruleset int, rule PathRule, version uint32) error {
	fd, err := unix.Open(rule.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrInvalid
	}
	defer unix.Close(fd)
	var state unix.Stat_t
	if unix.Fstat(fd, &state) != nil {
		return ErrInvalid
	}
	allowed, err := allowedAccess(rule.Access, state.Mode&unix.S_IFMT == unix.S_IFDIR, version)
	if err != nil {
		return err
	}
	attribute := pathBeneathAttribute{AllowedAccess: allowed, ParentFD: int32(fd)}
	_, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(ruleset),
		landlockRulePathBeneath,
		uintptr(unsafe.Pointer(&attribute)),
		0, 0, 0,
	)
	if errno != 0 {
		return ErrUnsupported
	}
	return nil
}

func allowedAccess(access Access, directory bool, version uint32) (uint64, error) {
	allowed := accessFSReadFile
	if directory {
		allowed |= accessFSReadDir
	}
	switch access {
	case ReadOnly:
	case ReadWrite, ReadWriteExecute:
		allowed |= accessFSWriteFile
		if version >= 3 {
			allowed |= accessFSTruncate
		}
		if directory {
			allowed |= accessFSRemoveDir | accessFSRemoveFile | accessFSMakeChar | accessFSMakeDir |
				accessFSMakeReg | accessFSMakeSock | accessFSMakeFIFO | accessFSMakeBlock | accessFSMakeSym | accessFSRefer
		}
	case ReadExecute:
	default:
		return 0, ErrInvalid
	}
	if access == ReadExecute || access == ReadWriteExecute {
		allowed |= accessFSExecute
	}
	handled := handledAccessFSV2
	if version >= 3 {
		handled |= accessFSTruncate
	}
	if allowed&^handled != 0 {
		return 0, errors.New("Pi sandbox access exceeds handled rights")
	}
	return allowed, nil
}

func installTruncateFilter() error {
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: uint32(unix.SYS_TRUNCATE)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)), 0, 0)
}

//go:build linux

package extensionrunner

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const seccompDataArgsOffset = 16

func installSandboxSeccomp() error {
	filters := sandboxSeccompFilters()
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	_, _, errno := unix.Syscall6(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&program)),
		0,
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func sandboxSeccompFilters() []unix.SockFilter {
	deny := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: sandboxAuditArch},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		// clone is needed by language runtimes, but it may not create another
		// user/mount/network namespace or request tracing.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 4, K: uint32(unix.SYS_CLONE)},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataArgsOffset},
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 1, K: forbiddenCloneFlags},
		{Code: unix.BPF_RET | unix.BPF_K, K: allow},
		{Code: unix.BPF_RET | unix.BPF_K, K: deny},
		// Go first attempts clone3 for os/exec. Returning ENOSYS makes it use
		// clone, whose namespace and tracing flags are filtered above; allowing
		// clone3 directly would leave its pointed-to flags uninterpreted.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: uint32(unix.SYS_CLONE3)},
		{Code: unix.BPF_RET | unix.BPF_K, K: uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.ENOSYS)},
	}
	for _, number := range sandboxAllowedSyscalls() {
		if number == uint32(unix.SYS_CLONE) {
			continue
		}
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: number},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: allow},
		)
	}
	filters = append(filters, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: deny})
	return filters
}

const forbiddenCloneFlags = uint32(
	unix.CLONE_NEWCGROUP |
		unix.CLONE_NEWIPC |
		unix.CLONE_NEWNET |
		unix.CLONE_NEWNS |
		unix.CLONE_NEWPID |
		unix.CLONE_NEWTIME |
		unix.CLONE_NEWUSER |
		unix.CLONE_NEWUTS |
		unix.CLONE_PTRACE |
		unix.CLONE_UNTRACED,
)

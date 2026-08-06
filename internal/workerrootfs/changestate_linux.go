//go:build linux

package workerrootfs

import (
	"os"
	"syscall"
)

func sameFileChangeState(left, right os.FileInfo) bool {
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Ctim.Sec == rightStat.Ctim.Sec &&
		leftStat.Ctim.Nsec == rightStat.Ctim.Nsec
}

//go:build darwin

package workerrootfs

import (
	"os"
	"syscall"
)

func sameFileChangeState(left, right os.FileInfo) bool {
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Ctimespec.Sec == rightStat.Ctimespec.Sec &&
		leftStat.Ctimespec.Nsec == rightStat.Ctimespec.Nsec
}

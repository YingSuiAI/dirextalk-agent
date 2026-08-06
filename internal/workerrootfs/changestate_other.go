//go:build !darwin && !linux

package workerrootfs

import "os"

func sameFileChangeState(os.FileInfo, os.FileInfo) bool {
	return false
}

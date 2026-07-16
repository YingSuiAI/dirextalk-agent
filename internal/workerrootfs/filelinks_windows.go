//go:build windows

package workerrootfs

import (
	"os"

	"golang.org/x/sys/windows"
)

func regularFileLinkCount(file *os.File, _ os.FileInfo) (uint64, error) {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return 0, err
	}
	return uint64(information.NumberOfLinks), nil
}

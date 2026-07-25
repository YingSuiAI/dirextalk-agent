//go:build linux

package extensionrunner

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// collectRightsCmsgs walks raw cmsghdr records rather than relying on a whole
// buffer parser.  Thus descriptors in each complete SCM_RIGHTS record remain
// recoverable even when a later record is malformed or MSG_CTRUNC is set.
func collectRightsCmsgs(oob []byte) ([]int, error) {
	var fds []int
	header := unix.CmsgLen(0)
	align := uintptr(unsafe.Sizeof(uintptr(0)))
	for off := 0; off < len(oob); {
		if len(oob)-off < header {
			for _, b := range oob[off:] {
				if b != 0 {
					return fds, ErrProtocol
				}
			}
			return fds, nil
		}
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[off]))
		length := int(h.Len)
		if length < header || length > len(oob)-off {
			return fds, ErrProtocol
		}
		if h.Level != unix.SOL_SOCKET || h.Type != unix.SCM_RIGHTS {
			return fds, ErrProtocol
		}
		{
			data := oob[off+header : off+length]
			if len(data)%int(unsafe.Sizeof(int32(0))) != 0 {
				return fds, ErrProtocol
			}
			for len(data) > 0 {
				fd := int(*(*int32)(unsafe.Pointer(&data[0])))
				fds = append(fds, fd)
				data = data[unsafe.Sizeof(int32(0)):]
			}
		}
		next := int((uintptr(length) + align - 1) &^ (align - 1))
		if next >= len(oob) {
			return fds, nil
		}
		off += next
	}
	return fds, nil
}

func closeRightsCmsgs(oob []byte) error {
	fds, err := collectRightsCmsgs(oob)
	closeReceivedFDs(fds)
	return err
}

//go:build linux

package execgate

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type fanotifyMonitor struct {
	fd     int
	events chan permissionEvent
	errors chan error
	done   chan struct{}
	once   sync.Once
}

func newPermissionMonitor(markPath string) (permissionMonitor, error) {
	if !cleanAbsolute(markPath) {
		return nil, ErrInvalid
	}
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err = unix.FanotifyMark(
		fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
		unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, markPath,
	); err != nil {
		_ = unix.Close(fd)
		return nil, ErrUnavailable
	}
	monitor := &fanotifyMonitor{
		fd: fd, events: make(chan permissionEvent), errors: make(chan error, 1), done: make(chan struct{}),
	}
	go monitor.readLoop()
	return monitor, nil
}

func (monitor *fanotifyMonitor) Events() <-chan permissionEvent { return monitor.events }
func (monitor *fanotifyMonitor) Errors() <-chan error           { return monitor.errors }

func (monitor *fanotifyMonitor) Close() error {
	if monitor == nil {
		return nil
	}
	var err error
	monitor.once.Do(func() {
		close(monitor.done)
		err = unix.Close(monitor.fd)
	})
	return err
}

func (monitor *fanotifyMonitor) readLoop() {
	defer close(monitor.events)
	buffer := make([]byte, 64<<10)
	for {
		count, err := unix.Read(monitor.fd, buffer)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			select {
			case <-monitor.done:
				return
			default:
				monitor.reportError(err)
				return
			}
		}
		metadata, parseErr := parseFanotifyEvents(buffer[:count])
		if parseErr != nil {
			monitor.reportError(parseErr)
			return
		}
		for _, item := range metadata {
			if item.Mask&unix.FAN_Q_OVERFLOW != 0 || item.Fd < 0 || item.Pid < 1 {
				monitor.reportError(ErrViolation)
				return
			}
			file := os.NewFile(uintptr(item.Fd), "fanotify-executable")
			fd := item.Fd
			event := permissionEvent{
				PID: item.Pid, File: file,
				done: func(allow bool) error { return writeFanotifyResponse(monitor.fd, fd, allow) },
			}
			select {
			case monitor.events <- event:
			case <-monitor.done:
				_ = writeFanotifyResponse(monitor.fd, fd, false)
				_ = file.Close()
				return
			}
		}
	}
}

func (monitor *fanotifyMonitor) reportError(err error) {
	select {
	case monitor.errors <- err:
	default:
	}
}

type fanotifyMetadata struct {
	Mask uint64
	Fd   int32
	Pid  int32
}

func parseFanotifyEvents(raw []byte) ([]fanotifyMetadata, error) {
	const metadataLength = 24
	var result []fanotifyMetadata
	for len(raw) > 0 {
		if len(raw) < metadataLength {
			return nil, ErrInvalid
		}
		eventLength := int(binary.NativeEndian.Uint32(raw[0:4]))
		metadataLen := int(binary.NativeEndian.Uint16(raw[6:8]))
		if eventLength < metadataLength || eventLength > len(raw) || metadataLen < metadataLength ||
			raw[4] != unix.FANOTIFY_METADATA_VERSION {
			return nil, ErrInvalid
		}
		result = append(result, fanotifyMetadata{
			Mask: binary.NativeEndian.Uint64(raw[8:16]),
			Fd:   int32(binary.NativeEndian.Uint32(raw[16:20])),
			Pid:  int32(binary.NativeEndian.Uint32(raw[20:24])),
		})
		raw = raw[eventLength:]
	}
	return result, nil
}

func writeFanotifyResponse(fanotifyFD int, eventFD int32, allow bool) error {
	response := uint32(unix.FAN_DENY)
	if allow {
		response = unix.FAN_ALLOW
	}
	raw := make([]byte, 8)
	binary.NativeEndian.PutUint32(raw[0:4], uint32(eventFD))
	binary.NativeEndian.PutUint32(raw[4:8], response)
	written, err := unix.Write(fanotifyFD, raw)
	clear(raw)
	if err != nil || written != 8 {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	return nil
}

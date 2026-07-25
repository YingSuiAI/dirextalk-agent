//go:build linux

package extensionrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/sys/unix"
)

func VerifySealedFD(fd int, size int64, digest string) error {
	if fd < 0 || size < 0 || size > MaxStdinBytes || !digestRE.MatchString(digest) {
		return ErrInvalid
	}
	st := &unix.Stat_t{}
	if err := unix.Fstat(fd, st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != size {
		return ErrInvalid
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || seals&(unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE) != (unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE) {
		return ErrInvalid
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return ErrInvalid
	}
	defer unix.Close(dup)
	h := sha256.New()
	var off int64
	buf := make([]byte, 32<<10)
	for off < size {
		want := int64(len(buf))
		if remain := size - off; remain < want {
			want = remain
		}
		n, e := unix.Pread(dup, buf[:want], off)
		if e != nil || n == 0 {
			return ErrInvalid
		}
		if _, e = h.Write(buf[:n]); e != nil {
			return ErrInvalid
		}
		off += int64(n)
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrInvalid
	}
	return nil
}

func ValidateSealedFD(fd int, size int64, digest string) error {
	return VerifySealedFD(fd, size, digest)
}

package extensionrunner

import (
	"io"
	"os"
)

func readRegularFile(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, ErrInvalid
	}
	return io.ReadAll(io.LimitReader(f, int64(limit)+1))
}

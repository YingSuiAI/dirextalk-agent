package extensionrunner

import "io"

func ioCopyLimit(dst io.Writer, src io.Reader, n int64) (int64, error) { return io.CopyN(dst, src, n) }

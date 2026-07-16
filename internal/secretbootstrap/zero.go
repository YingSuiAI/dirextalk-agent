package secretbootstrap

import "runtime"

// Wipe performs best-effort zeroization of caller-owned byte buffers. Go's
// cryptographic implementations may retain internal copies that are outside
// the package's control.
func Wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

//go:build linux

package extensionrunner

import (
	"os"
	"strconv"
	"strings"
)

func processStartTime(pid int) (uint64, error) {
	b, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if e != nil {
		return 0, e
	}
	x := strings.Fields(string(b))
	if len(x) < 22 {
		return 0, ErrInvalid
	}
	return strconv.ParseUint(x[21], 10, 64)
}

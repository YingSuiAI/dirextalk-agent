package extensionrunner

import (
	"regexp"
	"strings"
)

var digestRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

func safeName(s string) bool {
	return len(s) > 0 && len(s) <= 64 && !strings.ContainsAny(s, "/\\\x00") && s != "." && s != ".."
}

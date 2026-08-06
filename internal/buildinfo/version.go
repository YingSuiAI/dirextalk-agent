package buildinfo

import (
	"errors"
	"regexp"
	"strings"
)

// ReleaseVersion is replaced by the unified image build with -ldflags -X.
// Local developer builds deliberately report "dev" rather than pretending to
// be an immutable release.
var ReleaseVersion = "dev"

var releaseVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func Version() string {
	return strings.TrimSpace(ReleaseVersion)
}

func Validate() error {
	version := Version()
	if version == "dev" || releaseVersionPattern.MatchString(version) {
		return nil
	}
	return errors.New("Agent release version must be dev or a v-prefixed semantic version")
}

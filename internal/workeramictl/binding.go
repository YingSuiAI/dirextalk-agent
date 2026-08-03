package workeramictl

import (
	"path/filepath"
	"strings"
)

// BuildRequestBinding is the operator-approved identity and local artifact
// scope for one v2 build request.
type BuildRequestBinding struct {
	AccountID           string
	Region              string
	AgentInstanceID     string
	ReleaseManifestPath string
	RootFSArchivePath   string
}

// VerifyBuildRequestBinding prevents a persisted recovery request from being
// substituted before the operator-only publisher resumes it.
func VerifyBuildRequestBinding(
	requestPath string,
	binding BuildRequestBinding,
) error {
	if !accountPattern.MatchString(binding.AccountID) ||
		!regionPattern.MatchString(binding.Region) ||
		strings.TrimSpace(binding.AgentInstanceID) == "" ||
		!validLocalPath(binding.ReleaseManifestPath) ||
		!validLocalPath(binding.RootFSArchivePath) {
		return errInvalidInput
	}
	prepared, err := parseBuildRequest(requestPath, false)
	if err != nil ||
		prepared.request.AccountID != binding.AccountID ||
		prepared.request.Region != binding.Region ||
		prepared.request.AgentInstanceID != binding.AgentInstanceID ||
		filepath.Clean(prepared.releaseManifestPath) !=
			filepath.Clean(binding.ReleaseManifestPath) ||
		filepath.Clean(prepared.rootFSArchivePath) !=
			filepath.Clean(binding.RootFSArchivePath) {
		return errInvalidInput
	}
	return nil
}

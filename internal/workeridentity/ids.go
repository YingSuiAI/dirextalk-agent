package workeridentity

import (
	"errors"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalidDeploymentID = errors.New("invalid Worker deployment identity")

// DeriveWorkerID is the single stable Worker identity contract shared by
// launchers and pre-authorized Team Execution roles.
func DeriveWorkerID(deploymentID string) (string, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != deploymentID {
		return "", ErrInvalidDeploymentID
	}
	return uuid.NewSHA1(parsed, []byte("worker")).String(), nil
}

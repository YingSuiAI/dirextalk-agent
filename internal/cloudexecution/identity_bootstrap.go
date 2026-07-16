package cloudexecution

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/google/uuid"
)

// IdentityBootstrapPublisher selects the production enrollment mode. It does
// not publish or retain the generated fallback token; the Worker must prove
// its EC2 instance-role identity to WorkerControlService and the caller wipes
// the token immediately after this method returns.
type IdentityBootstrapPublisher struct{}

func NewIdentityBootstrapPublisher() *IdentityBootstrapPublisher {
	return &IdentityBootstrapPublisher{}
}

func (*IdentityBootstrapPublisher) PublishBootstrap(ctx context.Context, connection cloudapp.Connection, request BootstrapRequest) (BootstrapArtifact, error) {
	if ctx == nil || connection.Status != "active" || validateLaunchArtifact(request.Launch) != nil || len(request.EnrollmentCredential) < 32 || len(request.EnrollmentCredential) > 128 || request.EnrollmentRevision < 1 {
		return BootstrapArtifact{}, ErrInvalid
	}
	for _, value := range []string{request.DeploymentID, request.WorkerID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return BootstrapArtifact{}, ErrInvalid
		}
	}
	target, err := url.Parse(strings.TrimSpace(request.ControlPlaneTarget))
	if err != nil || target.Scheme != "grpcs" || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return BootstrapArtifact{}, ErrInvalid
	}
	result := request.Launch
	result.EnrollmentMaterialRef = fmt.Sprintf("identity://aws-sts/%s", request.DeploymentID)
	return result, nil
}

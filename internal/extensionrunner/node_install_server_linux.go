//go:build linux

package extensionrunner

import (
	"context"
	"time"
)

func (s Server) buildNode(ctx context.Context, payload []byte, fds []int) NodeBuildResponseV1 {
	var request NodeBuildRequestV1
	if s.NodeBuilder == nil || s.NodeInstallSlots == nil || decodeCanonicalNode(payload, &request) != nil || request.Validate(len(fds)) != nil {
		if s.NodeBuilder != nil {
			s.NodeBuilder.logAdmissionFailure("request_validate")
		}
		return NodeBuildResponseV1{Error: "denied"}
	}
	select {
	case s.NodeInstallSlots <- struct{}{}:
		defer func() { <-s.NodeInstallSlots }()
	default:
		return NodeBuildResponseV1{Error: "capacity"}
	}
	buildCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	receipt, err := s.NodeBuilder.Build(buildCtx, request, fds[0])
	if err != nil {
		if err == ErrNodeInstallCapacity {
			return NodeBuildResponseV1{Error: "capacity"}
		}
		return NodeBuildResponseV1{Error: "denied"}
	}
	return NodeBuildResponseV1{Receipt: &receipt}
}

func (s Server) promoteNode(payload []byte) (NodeMutationResponseV1, error) {
	var request NodePromoteRequestV1
	if s.NodeBuilder == nil || decodeCanonicalNode(payload, &request) != nil || request.Validate() != nil || s.NodeBuilder.Promote(request) != nil {
		return NodeMutationResponseV1{}, ErrPublicationDenied
	}
	return NodeMutationResponseV1{Digest: request.Receipt.ArtifactDigest}, nil
}

func (s Server) removeNode(payload []byte) (NodeMutationResponseV1, error) {
	var request NodeRemoveRequestV1
	if s.NodeBuilder == nil || decodeCanonicalNode(payload, &request) != nil || request.Validate() != nil || s.NodeBuilder.Remove(request) != nil {
		return NodeMutationResponseV1{}, ErrPublicationDenied
	}
	return NodeMutationResponseV1{Digest: request.Digest}, nil
}

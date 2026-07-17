package app

import (
	"context"
	"errors"

	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
)

// destroyResourceApprovalStore is intentionally limited to the one durable
// verification query needed by automatic and manual destruction.  It keeps
// generic Store reads and all provider access out of both controllers.
type destroyResourceApprovalStore interface {
	VerifyResourceApproval(context.Context, clouddestroy.ResourceApprovalProofV1) error
}

type destroyResourceApprovalAdapter struct{ store destroyResourceApprovalStore }

func (adapter destroyResourceApprovalAdapter) VerifyResourceApproval(ctx context.Context, proof clouddestroy.ResourceApprovalProofV1) error {
	if adapter.store == nil || ctx == nil || proof.Validate() != nil {
		return clouddestroy.ErrInvalid
	}
	err := adapter.store.VerifyResourceApproval(ctx, proof)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, clouddestroy.ErrUnavailable):
		return err
	default:
		// A lifecycle controller must not receive persistence/provider details
		// about a failed authorization source.  It only needs a fail-closed
		// decision and will retain the resources for later remediation.
		return clouddestroy.ErrInvalid
	}
}

var _ clouddestroy.ResourceApprovalVerifier = destroyResourceApprovalAdapter{}

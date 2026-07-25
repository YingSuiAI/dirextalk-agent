package runner

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
)

// Transport must enforce a dedicated SOCK_SEQPACKET endpoint and peer UID.
// It accepts only descriptor metadata; descriptors themselves are supplied by
// the privileged Agent integration seam, never stored by this Provider.
type Transport interface {
	Call(context.Context, Request) (Receipt, error)
}
type Provider struct{ transport Transport }

func NewProvider(t Transport) (*Provider, error) {
	if t == nil {
		return nil, coreworkload.ErrInvalid
	}
	return &Provider{transport: t}, nil
}
func (p *Provider) Apply(ctx context.Context, plan coreworkload.Plan, op coreworkload.Operation) (coreworkload.Readback, error) {
	return p.call(ctx, "apply", plan, op)
}
func (p *Provider) Destroy(ctx context.Context, plan coreworkload.Plan, op coreworkload.Operation) (coreworkload.Readback, error) {
	return p.call(ctx, "destroy", plan, op)
}
func (p *Provider) Read(ctx context.Context, plan coreworkload.Plan, op coreworkload.Operation) (coreworkload.Readback, error) {
	return p.call(ctx, "read", plan, op)
}
func (p *Provider) call(ctx context.Context, action string, plan coreworkload.Plan, op coreworkload.Operation) (coreworkload.Readback, error) {
	if plan.TargetKind != coreworkload.TargetCoreRunner || op.TargetKind != coreworkload.TargetCoreRunner || plan.Digest != op.PlanDigest || plan.Revision != op.PlanRevision || op.DispatchClaim == "" || op.DispatchEpoch == 0 {
		return coreworkload.Readback{}, coreworkload.ErrStale
	}
	// The Provider interface has no SCM_RIGHTS input yet. Rejecting secret
	// grants is the only safe behavior: silently dropping one would run with a
	// different confirmed plan, while serializing it would expose secret data.
	if len(plan.SecretGrants) != 0 || len(plan.SecretGrantRefs) != 0 {
		return coreworkload.Readback{}, coreworkload.ErrProvider
	}
	r := Request{Action: action, WorkloadID: op.WorkloadID, OperationID: op.ID, PlanDigest: plan.Digest, PlanRevision: plan.Revision, DispatchClaim: op.DispatchClaim, DispatchEpoch: op.DispatchEpoch, Artifact: plan.Artifact, CommandSteps: append([]string(nil), plan.CommandSteps...), Limits: plan.ResourceLimits, NetworkGrants: append([]string(nil), plan.NetworkGrants...), Service: plan.Target.Identity.CoreRunnerService}
	if err := r.Validate(); err != nil {
		return coreworkload.Readback{}, coreworkload.ErrInvalid
	}
	receipt, err := p.transport.Call(ctx, r)
	if err != nil {
		return coreworkload.Readback{}, coreworkload.ErrProvider
	}
	if receipt.WorkloadID != r.WorkloadID || receipt.PlanDigest != r.PlanDigest || receipt.DispatchClaim != r.DispatchClaim || receipt.DispatchEpoch != r.DispatchEpoch || receipt.Action != action || receipt.Digest != r.Digest() {
		return coreworkload.Readback{}, coreworkload.ErrProvider
	}
	state := strings.TrimSpace(receipt.State)
	if action == "apply" && state != "ready" || action == "destroy" && state != "destroyed" || action == "read" && state == "" {
		return coreworkload.Readback{}, coreworkload.ErrProvider
	}
	return coreworkload.Readback{TargetKind: coreworkload.TargetCoreRunner, WorkloadID: op.WorkloadID, State: state, Identity: plan.Target.Identity, ProviderVersion: "core-runner-v1", At: time.Now().UTC()}, nil
}

var _ coreworkload.Provider = (*Provider)(nil)
var _ = errors.Is

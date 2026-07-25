package runner

import (
	"context"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/google/uuid"
	"testing"
	"time"
)

type fake struct {
	request Request
	receipt Receipt
	err     error
}

func (f *fake) Call(_ context.Context, r Request) (Receipt, error) {
	f.request = r
	if f.err != nil {
		return Receipt{}, f.err
	}
	x := f.receipt
	if x.Digest == "" {
		x.Digest = r.Digest()
	}
	return x, nil
}
func runPlan(t *testing.T) (coreworkload.Plan, coreworkload.Operation) {
	t.Helper()
	id := uuid.NewString()
	p := coreworkload.Plan{ID: uuid.NewString(), Revision: 1, Summary: "run", CommandSteps: []string{"/bin/true"}, TargetKind: coreworkload.TargetCoreRunner, Target: coreworkload.TargetSettings{Identity: coreworkload.TargetIdentity{Kind: coreworkload.TargetCoreRunner, CoreRunnerID: "runner", CoreRunnerService: "service"}}, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	p, _ = p.Normalize()
	return p, coreworkload.Operation{ID: uuid.NewString(), WorkloadID: id, PlanID: p.ID, PlanDigest: p.Digest, PlanRevision: 1, TargetKind: coreworkload.TargetCoreRunner, DispatchClaim: uuid.NewString(), DispatchEpoch: 1}
}
func TestProviderBindsExactFence(t *testing.T) {
	p, o := runPlan(t)
	f := &fake{receipt: Receipt{WorkloadID: o.WorkloadID, PlanDigest: p.Digest, DispatchClaim: o.DispatchClaim, DispatchEpoch: o.DispatchEpoch, Action: "apply", State: "ready"}}
	x, _ := NewProvider(f)
	if _, e := x.Apply(context.Background(), p, o); e != nil {
		t.Fatal(e)
	}
	f.receipt.DispatchEpoch++
	if _, e := x.Apply(context.Background(), p, o); e == nil {
		t.Fatal("accepted replay conflict")
	}
}
func TestRequestRejectsUnorderedOrSecretText(t *testing.T) {
	p, o := runPlan(t)
	r := Request{Action: "apply", WorkloadID: o.WorkloadID, OperationID: o.ID, PlanDigest: p.Digest, PlanRevision: 1, DispatchClaim: "c", DispatchEpoch: 1, CommandSteps: []string{"x"}, NetworkGrants: []string{"b", "a"}}
	if r.Validate() == nil {
		t.Fatal("unordered grants")
	}
	r.NetworkGrants = []string{"a"}
	r.SecretDescriptors = []string{"secret=value"}
	if r.Validate() == nil {
		t.Fatal("secret value accepted")
	}
}

//go:build linux

package runner

import (
	"context"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeExecutor struct{ calls []Request }

func (f *fakeExecutor) Execute(_ context.Context, q Request) (string, error) {
	f.calls = append(f.calls, q)
	if q.Action == "destroy" {
		return "destroyed", nil
	}
	return "ready", nil
}

type fakePersistentExecutor struct{ applies, destroys int }

func (f *fakePersistentExecutor) Execute(context.Context, Request) (string, error) {
	return "unknown", nil
}
func (f *fakePersistentExecutor) ApplyPersistent(_ context.Context, _ Request) (Receipt, error) {
	f.applies++
	return Receipt{State: "ready", ServiceDigest: "service", PID: 123, StartTime: 456, Cgroup: "/cg/op"}, nil
}
func (f *fakePersistentExecutor) ReadPersistent(_ context.Context, _ Request, r Receipt) (Receipt, error) {
	return Receipt{State: r.State, ServiceDigest: r.ServiceDigest, PID: r.PID, StartTime: r.StartTime, Cgroup: r.Cgroup}, nil
}
func (f *fakePersistentExecutor) DestroyPersistent(_ context.Context, _ Request, r Receipt) (Receipt, error) {
	f.destroys++
	return Receipt{State: "destroyed", ServiceDigest: r.ServiceDigest, PID: r.PID, StartTime: r.StartTime, Cgroup: r.Cgroup}, nil
}

func TestSocketRejectsReplacementAndForeignUID(t *testing.T) {
	d := t.TempDir()
	if os.Chmod(d, 0700) != nil {
		t.Fatal("chmod")
	}
	p := filepath.Join(d, "runner.sock")
	if _, e := NewSocketTransport(p, uint32(os.Geteuid())); e == nil {
		t.Fatal("missing socket")
	}
	l, e := Listen(p, uint32(os.Geteuid()))
	if e != nil {
		t.Skip(e)
	}
	defer l.Close()
	if os.Chmod(p, 0666) != nil {
		t.Fatal(e)
	}
	if _, e = NewSocketTransport(p, uint32(os.Geteuid())); e == nil {
		t.Fatal("world writable socket")
	}
}

func TestSocketTransportRoundTrip(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	p := filepath.Join(d, "runner.sock")
	l, err := Listen(p, uint32(os.Geteuid()))
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewSupervisor(uint32(os.Geteuid())).Serve(ctx, l) }()
	plan, op := runPlan(t)
	client, err := NewSocketTransport(p, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Action: "apply", WorkloadID: op.WorkloadID, OperationID: op.ID, PlanDigest: plan.Digest, PlanRevision: plan.Revision, DispatchClaim: uuid.NewString(), DispatchEpoch: 1, CommandSteps: []string{"/bin/true"}, Service: "service"}
	result, err := client.Call(context.Background(), request)
	if err != nil || result.State != "unknown" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestProbeRequiresNonceBackedSupervisorResponse(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	p := filepath.Join(d, "runner.sock")
	l, err := Listen(p, uint32(os.Geteuid()))
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewSupervisor(uint32(os.Geteuid())).Serve(ctx, l) }()
	client, err := NewSocketTransport(p, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Probe(context.Background()); err != nil {
		t.Fatalf("supervisor probe: %v", err)
	}
}

func TestSupervisorPeerAuthorizationSeparatesSelfProbeAndMutation(t *testing.T) {
	s := &Supervisor{uid: 65532, runnerUID: 65530}
	if !s.allowPeer(65530, true) {
		t.Fatal("runner self probe was denied")
	}
	if s.allowPeer(65530, false) {
		t.Fatal("runner self mutation was allowed")
	}
	if !s.allowPeer(65532, false) {
		t.Fatal("Agent mutation was denied")
	}
	if s.allowPeer(65531, true) {
		t.Fatal("foreign probe was allowed")
	}
}

func TestProbeRejectsInertSameUIDListener(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	p := filepath.Join(d, "runner.sock")
	l, err := Listen(p, uint32(os.Geteuid()))
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	go func() {
		c, e := l.AcceptUnix()
		if e == nil {
			defer c.Close()
			b := make([]byte, MaxPacketBytes)
			_, _ = c.Read(b)
		}
	}()
	client, err := NewSocketTransport(p, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err = client.Probe(ctx); err == nil {
		t.Fatal("inert listener passed probe")
	}
}

func TestReapIntentClearsPartialStagingWithoutTouchingBundles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"work", "cg", "install"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	plan, op := runPlan(t)
	q := Request{Action: "apply", WorkloadID: op.WorkloadID, OperationID: op.ID, PlanDigest: plan.Digest, PlanRevision: plan.Revision, DispatchClaim: uuid.NewString(), DispatchEpoch: 1, CommandSteps: []string{"x"}, Service: "service", Limits: coreworkload.ResourceLimits{CPU: 1, MemoryMB: 1, Processes: 1, DiskMB: 1, TimeoutS: 1, OutputMB: 1}}
	if q.Validate() != nil {
		t.Fatal("invalid fixture")
	}
	stage := filepath.Join(root, "work", q.OperationID, q.DispatchClaim)
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "service"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(root, "install", "unrelated")
	if err := os.Mkdir(unrelated, 0700); err != nil {
		t.Fatal(err)
	}
	e := LinuxExecutor{InstallRoot: filepath.Join(root, "install"), WorkspaceRoot: filepath.Join(root, "work"), CgroupRoot: filepath.Join(root, "cg"), StaticShell: "/bin/sh"}
	if err := e.ReapIntent(context.Background(), q); err != nil {
		t.Fatalf("reap partial: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("staging remains: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated bundle removed: %v", err)
	}
}

func TestOfflineServiceLifecycleUsesExactRequest(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	p := filepath.Join(d, "runner.sock")
	l, err := Listen(p, uint32(os.Geteuid()))
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exec := &fakeExecutor{}
	go func() { _ = NewSupervisor(uint32(os.Geteuid()), exec).Serve(ctx, l) }()
	plan, op := runPlan(t)
	client, err := NewSocketTransport(p, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	base := Request{WorkloadID: op.WorkloadID, OperationID: op.ID, PlanDigest: plan.Digest, PlanRevision: plan.Revision, DispatchClaim: uuid.NewString(), DispatchEpoch: 7, CommandSteps: []string{"install -d /work/service", "echo started"}, Service: "service"}
	base.Action = "apply"
	applied, err := client.Call(context.Background(), base)
	if err != nil || applied.State != "ready" {
		t.Fatalf("apply: %+v %v", applied, err)
	}
	base.Action = "destroy"
	destroyed, err := client.Call(context.Background(), base)
	if err != nil || destroyed.State != "destroyed" {
		t.Fatalf("destroy state=%q action=%q digestMatch=%v err=%v", destroyed.State, destroyed.Action, destroyed.Digest == base.Digest(), err)
	}
	if len(exec.calls) != 2 || exec.calls[0].PlanDigest != plan.Digest || exec.calls[1].DispatchEpoch != 7 {
		t.Fatalf("fence lost: %+v", exec.calls)
	}
}
func TestSupervisorRejectsFenceConflict(t *testing.T) {
	p, o := runPlan(t)
	s := NewSupervisor(uint32(os.Geteuid()))
	q := Request{Action: "apply", WorkloadID: o.WorkloadID, OperationID: o.ID, PlanDigest: p.Digest, PlanRevision: p.Revision, DispatchClaim: uuid.NewString(), DispatchEpoch: 1, CommandSteps: []string{"x"}, Service: "service"}
	if q.Validate() != nil {
		t.Fatal("test request")
	}
	s.mu.Lock()
	s.receipts[q.Key()] = Receipt{Digest: "other"}
	s.mu.Unlock()
	if s.receipts[q.Key()].Digest == q.Digest() {
		t.Fatal("conflict accepted")
	}
}

func TestPersistentReceiptSurvivesRestartAndTombstonesReplay(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	plan, op := runPlan(t)
	base := Request{WorkloadID: op.WorkloadID, OperationID: op.ID, PlanDigest: plan.Digest, PlanRevision: plan.Revision, DispatchClaim: uuid.NewString(), DispatchEpoch: 1, CommandSteps: []string{"x"}, Service: "service"}
	f := &fakePersistentExecutor{}
	s, err := NewPersistentSupervisor(uint32(os.Geteuid()), root, f)
	if err != nil {
		t.Fatal(err)
	}
	call := func(q Request) Receipt {
		s.mu.Lock()
		defer s.mu.Unlock()
		key := q.LifecycleKey()
		r, ok := s.receipts[key]
		if !ok {
			var e error
			r, ok, e = s.store.Get(key)
			if e != nil {
				t.Fatal(e)
			}
			if ok {
				s.receipts[key] = r
			}
		}
		if q.Action == "apply" && !ok {
			r, e := f.ApplyPersistent(context.Background(), q)
			if e != nil {
				t.Fatal(e)
			}
			r.WorkloadID, r.PlanDigest, r.DispatchClaim, r.DispatchEpoch, r.OperationID, r.PlanRevision, r.Service = q.WorkloadID, q.PlanDigest, q.DispatchClaim, q.DispatchEpoch, q.OperationID, q.PlanRevision, q.Service
			r.Action, r.Digest, r.ApplyDigest = "apply", q.Digest(), q.Digest()
			if e = s.store.Put(key, r); e != nil {
				t.Fatal(e)
			}
			s.receipts[key] = r
			return r
		}
		return r
	}
	base.Action = "apply"
	got := call(base)
	if got.State != "ready" || f.applies != 1 {
		t.Fatalf("apply %#v", got)
	}
	// A new supervisor sees the exact durable admission and does not apply again.
	s, err = NewPersistentSupervisor(uint32(os.Geteuid()), root, f)
	if err != nil {
		t.Fatal(err)
	}
	got = call(base)
	if got.ApplyDigest != base.Digest() || f.applies != 1 {
		t.Fatalf("replay %#v applies=%d", got, f.applies)
	}
	base.Action = "destroy"
	s.mu.Lock()
	prior, ok, _ := s.store.Get(base.LifecycleKey())
	if !ok {
		t.Fatal("missing receipt")
	}
	out, err := f.DestroyPersistent(context.Background(), base, prior)
	if err != nil {
		t.Fatal(err)
	}
	out.WorkloadID, out.PlanDigest, out.DispatchClaim, out.DispatchEpoch, out.OperationID, out.PlanRevision, out.Service = base.WorkloadID, base.PlanDigest, base.DispatchClaim, base.DispatchEpoch, base.OperationID, base.PlanRevision, base.Service
	out.Action, out.Digest, out.ApplyDigest, out.Destroyed = "destroy", base.Digest(), prior.ApplyDigest, true
	if err = s.store.Replace(base.LifecycleKey(), prior.Digest, out); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	base.Action = "apply"
	after, ok, err := s.store.Get(base.LifecycleKey())
	if err != nil || !ok || !after.Destroyed || f.applies != 1 {
		t.Fatalf("tombstone=%#v err=%v", after, err)
	}
}

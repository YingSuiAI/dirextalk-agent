//go:build linux

package runner

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"golang.org/x/sys/unix"
)

// SocketTransport revalidates a protected pathname before and after connect,
// then checks SO_PEERCRED. Unixpacket maps to SOCK_SEQPACKET on Linux.
type SocketTransport struct {
	path      string
	runnerUID uint32
}

func NewSocketTransport(path string, runnerUID uint32) (*SocketTransport, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || runnerUID == 0 {
		return nil, ErrDenied
	}
	if _, e := socketID(path, runnerUID); e != nil {
		return nil, e
	}
	return &SocketTransport{path: path, runnerUID: runnerUID}, nil
}

// Probe verifies the protected endpoint and authenticated peer identity
// without sending a workload request.
func (t *SocketTransport) Probe(ctx context.Context) error {
	if t == nil {
		return ErrDenied
	}
	if _, err := socketID(t.path, t.runnerUID); err != nil {
		return err
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unixpacket", t.path)
	if err != nil {
		return err
	}
	defer c.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	uc, ok := c.(*net.UnixConn)
	if !ok || peerUID(uc) != t.runnerUID {
		return ErrDenied
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrDenied
	}
	want := base64.RawURLEncoding.EncodeToString(nonce[:])
	raw, err := json.Marshal(ProbeRequest{Version: ProtocolV1, Probe: "ready", Nonce: want})
	if err != nil || len(raw) > MaxPacketBytes {
		return ErrDenied
	}
	if _, err = c.Write(raw); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, MaxPacketBytes)
	n, err := c.Read(b)
	if err != nil || n == 0 {
		return ErrDenied
	}
	var out ProbeResponse
	if json.Unmarshal(b[:n], &out) != nil || out.Version != ProtocolV1 || out.Nonce != want || !out.Ready {
		return ErrDenied
	}
	return nil
}
func (t *SocketTransport) Call(ctx context.Context, q Request) (Receipt, error) {
	if q.Validate() != nil {
		return Receipt{}, ErrDenied
	}
	before, e := socketID(t.path, t.runnerUID)
	if e != nil {
		return Receipt{}, e
	}
	d := net.Dialer{}
	c, e := d.DialContext(ctx, "unixpacket", t.path)
	if e != nil {
		return Receipt{}, e
	}
	// DialContext only covers connect.  Once a packet has been sent, closing
	// the fd is the only prompt cancellation signal the server can observe;
	// do not leave a thirty-second read deadline owning a provider mutation.
	done := make(chan struct{})
	defer close(done)
	defer c.Close()
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	if _, e = socketID(t.path, t.runnerUID); e != nil {
		return Receipt{}, ErrDenied
	}
	if before != mustSocketID(t.path, t.runnerUID) {
		return Receipt{}, ErrDenied
	}
	uc, ok := c.(*net.UnixConn)
	if !ok || peerUID(uc) != t.runnerUID {
		return Receipt{}, ErrDenied
	}
	raw, e := json.Marshal(q)
	if e != nil || len(raw) > MaxPacketBytes {
		return Receipt{}, ErrDenied
	}
	if _, e = c.Write(raw); e != nil {
		return Receipt{}, e
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	b := make([]byte, MaxPacketBytes)
	n, e := c.Read(b)
	if e != nil || n == 0 {
		return Receipt{}, e
	}
	var out Receipt
	if json.Unmarshal(b[:n], &out) != nil {
		return Receipt{}, ErrDenied
	}
	return out, nil
}

type inode struct{ dev, ino uint64 }

func mustSocketID(path string, uid uint32) inode { x, _ := socketID(path, uid); return x }
func socketID(path string, uid uint32) (inode, error) {
	info, e := os.Lstat(path)
	if e != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o002 != 0 {
		return inode{}, ErrDenied
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(st.Uid) != uid {
		return inode{}, ErrDenied
	}
	d, e := os.Lstat(filepath.Dir(path))
	if e != nil || !d.IsDir() || d.Mode()&os.ModeSymlink != 0 || d.Mode().Perm()&0o002 != 0 || (d.Mode().Perm()&0o020 != 0 && d.Mode()&(os.ModeSetgid|os.ModeSticky) != (os.ModeSetgid|os.ModeSticky)) {
		return inode{}, ErrDenied
	}
	dst, ok := d.Sys().(*syscall.Stat_t)
	if !ok || uint32(dst.Uid) != uid {
		return inode{}, ErrDenied
	}
	return inode{uint64(st.Dev), st.Ino}, nil
}
func peerUID(c *net.UnixConn) uint32 {
	raw, e := c.SyscallConn()
	if e != nil {
		return 0
	}
	var uid uint32
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err == nil && cred != nil {
			uid = cred.Uid
		}
	})
	return uid
}

// Supervisor is intentionally in-memory. A restart loses only supervision;
// it cannot manufacture a completed mutation, so Read returns unavailable and
// the Agent's durable operation becomes uncertain rather than redispatched.
type Supervisor struct {
	uid      uint32
	executor Executor
	store    *ReceiptStore
	mu       sync.Mutex
	receipts map[string]Receipt
	ready    bool
}

func NewPersistentSupervisor(agentUID uint32, stateRoot string, executor Executor) (*Supervisor, error) {
	store, e := NewReceiptStore(stateRoot, uint32(os.Geteuid()))
	if e != nil {
		return nil, e
	}
	return &Supervisor{uid: agentUID, executor: executor, store: store, receipts: map[string]Receipt{}}, nil
}

func NewSupervisor(agentUID uint32, executors ...Executor) *Supervisor {
	s := &Supervisor{uid: agentUID, receipts: map[string]Receipt{}}
	if len(executors) == 1 {
		s.executor = executors[0]
	}
	return s
}
func (s *Supervisor) Serve(ctx context.Context, l *net.UnixListener) error {
	if err := s.reconcileStartup(); err != nil {
		return err
	}
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		go s.serve(ctx, c)
	}
}
func (s *Supervisor) serve(parent context.Context, c *net.UnixConn) {
	defer c.Close()
	if peerUID(c) != s.uid {
		return
	}
	b := make([]byte, MaxPacketBytes)
	n, e := c.Read(b)
	if e != nil || n == 0 {
		return
	}
	var probe ProbeRequest
	if json.Unmarshal(b[:n], &probe) == nil && probe.Probe != "" {
		s.mu.Lock()
		ready := s.ready && probe.Version == ProtocolV1 && len(probe.Nonce) >= 32
		s.mu.Unlock()
		if !ready || s.store != nil && s.store.Sync() != nil {
			return
		}
		raw, _ := json.Marshal(ProbeResponse{Version: ProtocolV1, Nonce: probe.Nonce, Ready: true})
		_, _ = c.Write(raw)
		return
	}
	var q Request
	if json.Unmarshal(b[:n], &q) != nil || q.Validate() != nil {
		return
	}
	s.mu.Lock()
	ready := s.ready
	s.mu.Unlock()
	if !ready {
		return
	}
	// A socket context governs dispatch only. Persistent lifetime enforcement
	// is deliberately detached: a successful Apply must outlive its response.
	execCtx, cancel := context.WithCancel(parent)
	defer cancel()
	s.mu.Lock()
	// The watcher can fail-close between admission and this serialized point.
	// No journal or provider side effect may cross that transition.
	if !s.ready {
		s.mu.Unlock()
		return
	}
	key := q.Key()
	lifecycleKey := q.LifecycleKey()
	// Persistent services have one durable record for all three verbs.  The
	// action-specific response digest is still checked by the Agent provider.
	if pe, yes := s.executor.(persistentExecutor); yes {
		base, found := s.receipts[lifecycleKey]
		if !found && s.store != nil {
			base, found, e = s.store.Get(lifecycleKey)
			if e != nil {
				s.mu.Unlock()
				return
			}
			if found {
				s.receipts[lifecycleKey] = base
			}
		}
		if found && !sameLifecycleRequest(q, base) {
			s.mu.Unlock()
			return
		}
		var out Receipt
		var executionErr error
		// Per-operation intents are checked before touching a provider.  A
		// surviving applying/destroying intent after restart is deliberately
		// unknown: it may be reconciled, but it is never redispatched.
		if s.store != nil && q.Action != "read" {
			if in, ok, ie := s.store.GetIntent(key); ie != nil {
				s.mu.Unlock()
				return
			} else if ok {
				if in.Request.Digest() != q.Digest() {
					s.mu.Unlock()
					return
				}
				if in.State != "ready" && in.State != "destroyed" {
					out = Receipt{State: "unknown"}
					out.WorkloadID, out.PlanDigest, out.DispatchClaim, out.DispatchEpoch, out.Action, out.Digest = q.WorkloadID, q.PlanDigest, q.DispatchClaim, q.DispatchEpoch, q.Action, q.Digest()
					s.mu.Unlock()
					raw, _ := json.Marshal(out)
					_, _ = c.Write(raw)
					return
				}
			} else {
				state := "applying"
				if q.Action == "destroy" {
					state = "destroying"
				}
				if ie = s.store.PutIntent(OperationIntent{Request: q, State: state}); ie != nil {
					s.mu.Unlock()
					return
				}
			}
		}
		switch q.Action {
		case "apply":
			if found {
				if base.ApplyDigest != q.Digest() {
					s.mu.Unlock()
					return
				}
				out = base
				if base.Destroyed {
					out.State = "destroyed"
				}
			} else {
				out, executionErr = pe.ApplyPersistent(execCtx, q)
				if executionErr == nil && out.State == "ready" {
					out.WorkloadID, out.PlanDigest, out.DispatchClaim, out.DispatchEpoch, out.OperationID, out.PlanRevision, out.Service = q.WorkloadID, q.PlanDigest, q.DispatchClaim, q.DispatchEpoch, q.OperationID, q.PlanRevision, q.Service
					out.Action, out.Digest, out.ApplyDigest, out.At = "apply", q.Digest(), q.Digest(), time.Now().UTC()
					if s.store != nil && s.store.Put(lifecycleKey, out) != nil {
						// Ready receipt durability is the commit point.  If it cannot
						// be recorded, persist cleanup before the deterministic reap.
						if s.store.ReplaceIntent(OperationIntent{Request: q, State: "cleanup_required", Receipt: out}) != nil {
							s.ready = false
							s.mu.Unlock()
							return
						}
						ir, ok := s.executor.(intentReaper)
						if !ok || ir.ReapIntent(context.Background(), q) != nil {
							s.ready = false
							s.mu.Unlock()
							return
						}
						_ = s.store.ReplaceIntent(OperationIntent{Request: q, State: "unknown", Receipt: out})
						s.mu.Unlock()
						return
					}
					s.receipts[lifecycleKey] = out
					go s.watchPersistent(q, out)
					if s.store != nil {
						_ = s.store.ReplaceIntent(OperationIntent{Request: q, State: "ready", Receipt: out})
					}
				}
			}
		case "read":
			if !found {
				out.State = "unknown"
			} else {
				out, executionErr = pe.ReadPersistent(execCtx, q, base)
			}
		case "destroy":
			if !found || base.ApplyDigest == "" {
				out.State = "unknown"
			} else if base.Destroyed {
				out = base
			} else {
				if s.store != nil {
					if e := s.store.MarkCleanupRequired(lifecycleKey, base); e != nil {
						s.ready = false
						s.mu.Unlock()
						return
					}
					_ = s.store.ReplaceIntent(OperationIntent{Request: q, State: "cleanup_required", Receipt: base})
				}
				out, executionErr = pe.DestroyPersistent(execCtx, q, base)
				if executionErr == nil && out.State == "destroyed" {
					out.WorkloadID, out.PlanDigest, out.DispatchClaim, out.DispatchEpoch, out.OperationID, out.PlanRevision, out.Service = q.WorkloadID, q.PlanDigest, q.DispatchClaim, q.DispatchEpoch, q.OperationID, q.PlanRevision, q.Service
					out.Action, out.Digest, out.ApplyDigest, out.Destroyed, out.At = "destroy", q.Digest(), base.ApplyDigest, true, time.Now().UTC()
					if s.store != nil && s.store.Replace(lifecycleKey, base.Digest, out) != nil {
						s.mu.Unlock()
						return
					}
					s.receipts[lifecycleKey] = out
					if s.store != nil {
						_ = s.store.ReplaceIntent(OperationIntent{Request: q, State: "destroyed", Receipt: out})
					}
				}
			}
		}
		if executionErr != nil {
			if s.store != nil && q.Action != "read" {
				_ = s.store.ReplaceIntent(OperationIntent{Request: q, State: "cleanup_required"})
			}
			s.ready = false
			s.mu.Unlock()
			return
		}
		out.WorkloadID, out.PlanDigest, out.DispatchClaim, out.DispatchEpoch = q.WorkloadID, q.PlanDigest, q.DispatchClaim, q.DispatchEpoch
		out.Action, out.Digest, out.At = q.Action, q.Digest(), time.Now().UTC()
		s.mu.Unlock()
		raw, _ := json.Marshal(out)
		_, _ = c.Write(raw)
		return
	}
	r, ok := s.receipts[key]
	if !ok && s.store != nil {
		r, ok, e = s.store.Get(key)
		if e != nil {
			s.mu.Unlock()
			return
		}
		if ok {
			s.receipts[key] = r
		}
	}
	if ok && r.Digest != q.Digest() {
		s.mu.Unlock()
		return
	}
	if !ok {
		// This supervisor has no workload-root/cgroup executor wired yet.  It
		// must never mint a successful Apply receipt: unknown makes the Agent
		// reconcile via Read and prevents a blind redispatch after a crash.
		state := "unknown"
		if s.executor != nil && q.Action != "read" {
			var executionErr error
			state, executionErr = s.executor.Execute(execCtx, q)
			if executionErr != nil {
				state = "unknown"
			}
		}
		if q.Action == "read" {
			state = "unknown"
		}
		r = Receipt{WorkloadID: q.WorkloadID, PlanDigest: q.PlanDigest, DispatchClaim: q.DispatchClaim, DispatchEpoch: q.DispatchEpoch, Action: q.Action, State: state, Digest: q.Digest(), At: time.Now().UTC()}
		if s.store != nil && s.store.Put(key, r) != nil {
			s.mu.Unlock()
			return
		}
		s.receipts[key] = r
	}
	s.mu.Unlock()
	raw, _ := json.Marshal(r)
	_, _ = c.Write(raw)
}
func sameLifecycleRequest(q Request, r Receipt) bool {
	return r.WorkloadID == q.WorkloadID && r.PlanDigest == q.PlanDigest && r.PlanRevision == q.PlanRevision && r.Service == q.Service
}

// restartReaper is deliberately narrower than the execution interface: only
// the production executor knows how to prove ownership and reap a cgroup.
type restartReaper interface {
	ReapPersistent(context.Context, Receipt) error
}
type intentReaper interface {
	ReapIntent(context.Context, Request) error
}

func (s *Supervisor) reconcileStartup() error {
	if probe, ok := s.executor.(interface{ Probe() error }); ok && probe.Probe() != nil {
		return ErrDenied
	}
	if s.store == nil {
		return nil
	}
	intents, err := s.store.ListIntents()
	if err != nil {
		return err
	}
	ir, productionIntent := s.executor.(intentReaper)
	for _, in := range intents {
		if in.State == "destroyed" || in.State == "unknown" {
			continue
		}
		if !productionIntent {
			return ErrDenied
		}
		// Persist the obligation before touching the exact deterministic cgroup.
		if in.State != "cleanup_required" {
			in.State = "cleanup_required"
			if err := s.store.ReplaceIntent(in); err != nil {
				return err
			}
		}
		if err := ir.ReapIntent(context.Background(), in.Request); err != nil {
			return err
		}
		in.State = "unknown"
		if err := s.store.ReplaceIntent(in); err != nil {
			return err
		}
	}
	all, err := s.store.List()
	if err != nil {
		return err
	}
	reaper, production := s.executor.(restartReaper)
	for _, r := range all {
		if (r.State != "ready" && r.State != "cleanup_required") || r.Destroyed {
			continue
		}
		if !production {
			return ErrDenied
		}
		key := Request{WorkloadID: r.WorkloadID, PlanDigest: r.PlanDigest, Service: r.Service}.LifecycleKey()
		if key == "::" || s.store.MarkCleanupRequired(key, r) != nil {
			return ErrDenied
		}
		if err := reaper.ReapPersistent(context.Background(), r); err != nil {
			return err
		}
		if key == "::" || s.store.MarkUnknown(key, r) != nil {
			return ErrDenied
		}
		s.mu.Lock()
		r.State = "unknown"
		s.receipts[key] = r
		s.mu.Unlock()
	}
	return s.store.Sync()
}

// watchPersistent turns a vanished managed service into durable uncertainty.
// It never writes a destroy receipt because neither a timeout nor an output
// overrun is a fenced Destroy operation.
func (s *Supervisor) watchPersistent(q Request, receipt Receipt) {
	for {
		time.Sleep(100 * time.Millisecond)
		if extensionrunner.ValidatePersistentIdentity(extensionrunner.PersistentIdentity{PID: receipt.PID, StartTime: receipt.StartTime, Cgroup: receipt.Cgroup}) == nil {
			continue
		}
		key := q.LifecycleKey()
		s.mu.Lock()
		current, ok := s.receipts[key]
		if ok && current.State == "ready" && current.Digest == receipt.Digest {
			if s.store != nil && s.store.MarkCleanupRequired(key, current) != nil {
				s.ready = false
				s.mu.Unlock()
				return
			}
			reaper, production := s.executor.(restartReaper)
			if !production || reaper.ReapPersistent(context.Background(), current) != nil {
				s.ready = false
				s.mu.Unlock()
				return
			}
			if s.store == nil || s.store.MarkUnknown(key, current) == nil {
				current.State = "unknown"
				s.receipts[key] = current
			} else {
				s.ready = false
			}
		}
		s.mu.Unlock()
		return
	}
}

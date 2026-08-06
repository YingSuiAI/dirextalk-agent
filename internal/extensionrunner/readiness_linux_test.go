//go:build linux

package extensionrunner

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type readinessBackend struct{ err error }

func (b readinessBackend) Probe(context.Context) error { return b.err }
func (b readinessBackend) StartV2(context.Context, SandboxInvocationV2) (Process, error) {
	return nil, ErrUnavailable
}

func TestServerReadyRejectsUnavailableBackendAndUnsafeRoots(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	base := Server{Runner: Runner{V2Backend: readinessBackend{}}, Registry: &RunRegistry{}, PublicationRoot: root}
	if !base.ready(context.Background()) {
		t.Fatal("ready rejected usable backend and private publication root")
	}
	base.Runner.V2Backend = readinessBackend{err: ErrUnavailable}
	if base.ready(context.Background()) {
		t.Fatal("ready accepted an unavailable isolation backend")
	}
	base.Runner.V2Backend = readinessBackend{}
	if err := os.Chmod(root, 0o775); err != nil {
		t.Fatal(err)
	}
	if base.ready(context.Background()) {
		t.Fatal("ready accepted a group/world-accessible publication root")
	}
}

func TestServerPeerAuthorizationSeparatesProbeAndMutation(t *testing.T) {
	s := Server{Authorizer: UIDAllowlist{65532: {}}, RunnerUID: 65531}
	if !s.allowPeer(65531, true) {
		t.Fatal("runner self UID probe was denied")
	}
	if s.allowPeer(65531, false) {
		t.Fatal("runner self UID was allowed to mutate")
	}
	if !s.allowPeer(65532, false) {
		t.Fatal("Agent UID mutation path was denied")
	}
	if s.allowPeer(65530, true) {
		t.Fatal("unexpected UID was allowed to probe")
	}
}

func TestLinuxBackendProbeRejectsPartialCgroupDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "partial-cgroup")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (LinuxBackend{CgroupRoot: root}).Probe(context.Background()); err == nil {
		t.Fatal("probe accepted a non-cgroup directory")
	}
}

func TestProbeRootMustBePrivateRunnerOwnedDirectory(t *testing.T) {
	root := t.TempDir()
	if !trustedProbeRoot(root) {
		t.Fatal("private runner-owned probe root rejected")
	}
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if trustedProbeRoot(root) {
		t.Fatal("group-writable probe root accepted")
	}
	if trustedProbeRoot(filepath.Join(root, "missing")) {
		t.Fatal("missing probe root accepted")
	}
}

func TestProbeIDsConcurrentAreFresh(t *testing.T) {
	const count = 32
	seen := make(map[string]struct{}, count*3)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, b, c, err := probeIDs()
			if err != nil {
				t.Errorf("probe IDs: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range []string{a, b, c} {
				if _, exists := seen[id]; exists {
					t.Errorf("probe ID collision: %s", id)
				}
				seen[id] = struct{}{}
			}
		}()
	}
	wg.Wait()
	if len(seen) != count*3 {
		t.Fatalf("fresh probe ID count=%d, want %d", len(seen), count*3)
	}
}

package source

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

const (
	managedNodeRuntimeRoot = "/usr/local/libexec/dirextalk-node-runtime"
	managedNodeLoader      = managedNodeRuntimeRoot + "/lib/ld-musl-x86_64.so.1"
	managedNodeBinary      = managedNodeRuntimeRoot + "/usr/local/bin/node"
	managedNPMCLI          = managedNodeRuntimeRoot + "/usr/local/lib/node_modules/npm/bin/npm-cli.js"
	nodeResolveTimeout     = 120 * time.Second
	nodeResolveOutputBytes = 64 << 10
)

// ProductionNodeDependencyResolver is the network-enabled, scripts-disabled
// half of managed Node installation. It may generate a lock and fetch exact
// tarballs, but it never expands node_modules or executes package code.
type ProductionNodeDependencyResolver struct {
	loader, node, npmCLI string
	http                 *http.Client
	timeout              time.Duration
	maxOutput            int
	installSlot          chan struct{}
	logger               *slog.Logger
	heartbeatEvery       time.Duration
}

type NodeDependencyResolverConfig struct {
	// The following seams are accepted only when TestOnly is true. Production
	// always uses the digest-pinned runtime copied into the Agent image.
	Loader     string
	Node       string
	NPMCLI     string
	HTTPClient *http.Client
	Resolver   Resolver
	Timeout    time.Duration
	TestOnly   bool
	Logger     *slog.Logger
}

func NewProductionNodeDependencyResolver(cfg NodeDependencyResolverConfig) (*ProductionNodeDependencyResolver, error) {
	loader, node, npmCLI := managedNodeLoader, managedNodeBinary, managedNPMCLI
	if cfg.TestOnly {
		if cfg.Loader != "" {
			loader = cfg.Loader
		}
		if cfg.Node != "" {
			node = cfg.Node
		}
		if cfg.NPMCLI != "" {
			npmCLI = cfg.NPMCLI
		}
	} else if cfg.Loader != "" || cfg.Node != "" || cfg.NPMCLI != "" || cfg.HTTPClient != nil {
		return nil, errors.New("managed Node resolver production paths are fixed")
	}
	for _, value := range []string{loader, node, npmCLI} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return nil, errors.New("invalid managed Node runtime path")
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = nodeResolveTimeout
	}
	if timeout > nodeResolveTimeout {
		return nil, errors.New("managed Node resolver timeout exceeds limit")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext:     safeDialer(cfg.Resolver),
		}
		httpClient = &http.Client{Transport: transport}
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return ErrRedirect }
	return &ProductionNodeDependencyResolver{
		loader: loader, node: node, npmCLI: npmCLI, http: &copyClient,
		timeout: timeout, maxOutput: nodeResolveOutputBytes, installSlot: make(chan struct{}, 1), logger: cfg.Logger, heartbeatEvery: 10 * time.Second,
	}, nil
}

func (r *ProductionNodeDependencyResolver) Resolve(ctx context.Context, request NodeDependencyRequest) (NodeDependencyResolution, error) {
	if r == nil || r.http == nil || ctx == nil || !canonicalNPMPackageName(request.PackageName) || !exactNodeSemver(request.PackageVersion) || len(request.RootPackageJSON) == 0 {
		return NodeDependencyResolution{}, ErrMalformed
	}
	select {
	case r.installSlot <- struct{}{}:
		defer func() { <-r.installSlot }()
	default:
		return NodeDependencyResolution{}, core.ErrInstallBusy
	}
	resolveCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	resolveStarted := time.Now()
	r.log("resolve_lock", "start", 0, 0, 0)
	stopResolveHeartbeat := r.startHeartbeat(resolveCtx, "resolve_lock", resolveStarted)
	lock := append([]byte(nil), request.ExistingPackageLock...)
	if len(lock) == 0 {
		var err error
		lock, err = r.generateLock(resolveCtx, request.RootPackageJSON)
		if err != nil {
			stopResolveHeartbeat()
			r.log("resolve_lock", "failed", time.Since(resolveStarted), 0, 0)
			return NodeDependencyResolution{}, err
		}
	}
	stopResolveHeartbeat()
	r.log("resolve_lock", "complete", time.Since(resolveStarted), 0, len(lock))
	parsed, err := parseAndValidateNodeLock(lock, requestRootName(request.RootPackageJSON), requestRootVersion(request.RootPackageJSON))
	if err != nil {
		return NodeDependencyResolution{}, err
	}
	paths := make([]string, 0, len(parsed.Packages))
	for lockPath, pkg := range parsed.Packages {
		if lockPath != "" && !pkg.Dev {
			paths = append(paths, lockPath)
		}
	}
	sort.Strings(paths)
	resolution := NodeDependencyResolution{PackageLock: lock, Tarballs: make([]NodeResolvedTarball, 0, len(paths))}
	downloadStarted := time.Now()
	r.log("download_cache", "start", 0, 0, 0)
	stopDownloadHeartbeat := r.startHeartbeat(resolveCtx, "download_cache", downloadStarted)
	defer stopDownloadHeartbeat()
	var total int64
	usedDirect := false
	for _, lockPath := range paths {
		pkg := parsed.Packages[lockPath]
		var content []byte
		if !usedDirect && len(request.DirectTarball) > 0 && (pkg.Name == request.PackageName || lockPath == "node_modules/"+request.PackageName) && pkg.Version == request.PackageVersion {
			sum := sha256.Sum256(request.DirectTarball)
			if hex.EncodeToString(sum[:]) != request.DirectTarballSHA256 {
				return NodeDependencyResolution{}, ErrMalformed
			}
			content = append([]byte(nil), request.DirectTarball...)
			usedDirect = true
		} else {
			content, err = r.download(resolveCtx, pkg.Resolved, nodeMaxInputBytes-total)
			if err != nil {
				return NodeDependencyResolution{}, err
			}
		}
		total += int64(len(content))
		if total > nodeMaxInputBytes || verifySRI(pkg.Integrity, content) != nil {
			return NodeDependencyResolution{}, ErrMalformed
		}
		resolution.Tarballs = append(resolution.Tarballs, NodeResolvedTarball{LockPath: lockPath, Content: content})
	}
	if len(request.DirectTarball) > 0 && !usedDirect {
		return NodeDependencyResolution{}, ErrMalformed
	}
	stopDownloadHeartbeat()
	r.log("download_cache", "complete", time.Since(downloadStarted), len(resolution.Tarballs), int(total))
	return resolution, nil
}

func (r *ProductionNodeDependencyResolver) startHeartbeat(ctx context.Context, phase string, started time.Time) func() {
	done := make(chan struct{})
	exited := make(chan struct{})
	every := r.heartbeatEvery
	if every <= 0 {
		every = 10 * time.Second
	}
	go func() {
		defer close(exited)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				r.log(phase, "running", time.Since(started), 0, 0)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-exited
	}
}

func (r *ProductionNodeDependencyResolver) log(phase, state string, elapsed time.Duration, files, bytes int) {
	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("managed Node resolve", "phase", phase, "state", state, "elapsed_ms", elapsed.Milliseconds(), "file_count", files, "artifact_bytes", bytes)
}

func (r *ProductionNodeDependencyResolver) generateLock(ctx context.Context, packageJSON []byte) ([]byte, error) {
	root, err := os.MkdirTemp("", "dirextalk-node-resolve-")
	if err != nil {
		return nil, errors.New("managed Node resolver unavailable")
	}
	defer os.RemoveAll(root)
	if err = os.WriteFile(filepath.Join(root, "package.json"), packageJSON, 0o600); err != nil {
		return nil, errors.New("managed Node resolver unavailable")
	}
	args := managedNodeResolverArguments(r.node, r.npmCLI)
	cmd := exec.CommandContext(ctx, r.loader, args...)
	cmd.Dir = root
	cmd.Env = managedNodeResolverEnvironment(root)
	output := &boundedNodeResolverOutput{limit: r.maxOutput}
	cmd.Stdout, cmd.Stderr = output, output
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("managed Node dependency resolution failed")
	}
	lock, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil || len(lock) == 0 || int64(len(lock)) > nodeMaxInputBytes {
		return nil, ErrMalformed
	}
	return lock, nil
}

func managedNodeResolverEnvironment(root string) []string {
	return []string{
		"HOME=" + root,
		"TMPDIR=" + root,
		"npm_config_cache=" + filepath.Join(root, ".npm-cache"),
		"npm_config_ignore_scripts=true",
		"npm_config_update_notifier=false",
		"NODE_OPTIONS=--max-old-space-size=192",
	}
}

func managedNodeResolverArguments(node, npmCLI string) []string {
	return []string{
		"--library-path", managedNodeRuntimeRoot + "/usr/lib",
		node, npmCLI, "install", "--package-lock-only", "--ignore-scripts", "--omit=dev",
		"--no-audit", "--no-fund", "--workspaces=false", "--package-lock=true",
	}
}

func (r *ProductionNodeDependencyResolver) download(ctx context.Context, raw string, remaining int64) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(strings.ToLower(u.Path), ".tgz") || remaining <= 0 {
		return nil, ErrUnsupported
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrMalformed
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := r.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return nil, ErrRedirect
		}
		return nil, fmt.Errorf("managed Node tarball fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.ContentLength > remaining {
		return nil, ErrMalformed
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, remaining+1))
	if err != nil || int64(len(body)) > remaining {
		return nil, ErrOversize
	}
	return body, nil
}

type boundedNodeResolverOutput struct {
	mu    sync.Mutex
	limit int
	used  int
}

func (w *boundedNodeResolverOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.used+len(p) > w.limit {
		return 0, errors.New("managed Node resolver output limit exceeded")
	}
	w.used += len(p)
	return len(p), nil
}

var _ NodeDependencyResolver = (*ProductionNodeDependencyResolver)(nil)
var _ io.Writer = (*boundedNodeResolverOutput)(nil)

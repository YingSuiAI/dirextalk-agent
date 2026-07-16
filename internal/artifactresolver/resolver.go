package artifactresolver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
)

const (
	DefaultMaxSizeBytes int64 = 1 << 30
	maximumSizeBytes    int64 = 8 << 30
	artifactRoot              = "/usr/local/share/dirextalk-worker/artifacts"
)

var (
	ErrInvalid     = errors.New("official installer artifact request is invalid")
	ErrDenied      = errors.New("official installer artifact source is denied")
	ErrTooLarge    = errors.New("official installer artifact exceeds the configured size limit")
	ErrUnavailable = errors.New("official installer artifact is unavailable")
	ErrIntegrity   = errors.New("official installer artifact integrity verification failed")
	ErrCleanup     = errors.New("official installer artifact cleanup failed")

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	deniedRanges  = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

type Config struct {
	MaxSizeBytes   int64
	FetchTimeout   time.Duration
	ConnectTimeout time.Duration
	TempDir        string
}

func DefaultConfig() Config {
	return Config{MaxSizeBytes: DefaultMaxSizeBytes, FetchTimeout: 15 * time.Minute, ConnectTimeout: 10 * time.Second}
}

type netIPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type httpClientFactory func(Config, string, []netip.Addr) (*http.Client, func(), error)

type Resolver struct {
	config        Config
	resolver      netIPResolver
	dialer        contextDialer
	clientFactory httpClientFactory
}

func New(config Config) (*Resolver, error) {
	if config.MaxSizeBytes < 1 || config.MaxSizeBytes > maximumSizeBytes || config.FetchTimeout <= 0 || config.ConnectTimeout <= 0 {
		return nil, ErrInvalid
	}
	if config.TempDir != "" {
		info, err := os.Stat(config.TempDir)
		if err != nil || !info.IsDir() {
			return nil, ErrInvalid
		}
	}
	return &Resolver{
		config: config, resolver: net.DefaultResolver,
		dialer:        &net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: 30 * time.Second},
		clientFactory: newPinnedClient,
	}, nil
}

func (resolver *Resolver) Resolve(ctx context.Context, request cloudexecution.InstallerArtifactResolveRequest) (cloudexecution.InstallerArtifactContent, error) {
	if resolver == nil || ctx == nil || resolver.resolver == nil || resolver.dialer == nil || resolver.clientFactory == nil {
		return nil, ErrInvalid
	}
	if err := validateRequest(request, resolver.config.MaxSizeBytes); err != nil {
		return nil, err
	}
	endpoint, err := parseSourceURL(request.SourceURL)
	if err != nil {
		return nil, err
	}

	fetchContext, cancel := context.WithTimeout(ctx, resolver.config.FetchTimeout)
	defer cancel()
	addresses, err := resolvePublicAddresses(fetchContext, resolver.resolver, endpoint.Hostname())
	if err != nil {
		return nil, err
	}
	client, closeClient, err := resolver.clientFactory(resolver.config, normalizedHost(endpoint.Hostname()), addresses)
	if err != nil || client == nil || closeClient == nil {
		return nil, ErrUnavailable
	}
	defer closeClient()

	httpRequest, err := http.NewRequestWithContext(fetchContext, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, ErrDenied
	}
	httpRequest.Header = make(http.Header)
	response, err := client.Do(httpRequest)
	if err != nil {
		if fetchContext.Err() != nil {
			return nil, fetchContext.Err()
		}
		return nil, ErrUnavailable
	}
	if response == nil || response.Body == nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrUnavailable
	}
	if response.ContentLength >= 0 && response.ContentLength != request.SizeBytes {
		return nil, ErrIntegrity
	}
	if encoding := strings.TrimSpace(response.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, ErrIntegrity
	}

	temporary, err := os.CreateTemp(resolver.config.TempDir, ".dirextalk-installer-artifact-*")
	if err != nil {
		return nil, ErrUnavailable
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return nil, ErrUnavailable
	}

	hasher := sha256.New()
	written, err := copyBounded(fetchContext, io.MultiWriter(temporary, hasher), response.Body, request.SizeBytes)
	if err != nil {
		return nil, err
	}
	if written != request.SizeBytes {
		return nil, ErrIntegrity
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(request.SHA256, "sha256:"))
	if err != nil || !equalBytes(expected, hasher.Sum(nil)) {
		return nil, ErrIntegrity
	}
	if err := temporary.Sync(); err != nil {
		return nil, ErrUnavailable
	}
	if err := temporary.Close(); err != nil {
		return nil, ErrUnavailable
	}
	keep = true
	return &artifactFile{path: temporaryPath, size: request.SizeBytes}, nil
}

func validateRequest(request cloudexecution.InstallerArtifactResolveRequest, maxSize int64) error {
	if !request.Official || strings.TrimSpace(request.SourceID) == "" || len(request.SourceID) > 128 ||
		!digestPattern.MatchString(request.SHA256) || !digestPattern.MatchString(request.RecipeDigest) || request.SizeBytes < 1 ||
		request.TargetPath == "" || path.Clean(request.TargetPath) != request.TargetPath ||
		!strings.HasPrefix(request.TargetPath, artifactRoot+"/") || strings.ContainsAny(request.SourceID, "\r\n\x00") {
		return ErrInvalid
	}
	if request.SizeBytes > maxSize {
		return ErrTooLarge
	}
	return nil
}

func parseSourceURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 2048 || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, ErrDenied
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || !parsed.IsAbs() || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, ErrDenied
	}
	host := parsed.Hostname()
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return nil, ErrDenied
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return nil, ErrDenied
	}
	return parsed, nil
}

func resolvePublicAddresses(ctx context.Context, resolver netIPResolver, host string) ([]netip.Addr, error) {
	host = normalizedHost(host)
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !publicAddress(address) {
			return nil, ErrDenied
		}
		return []netip.Addr{address}, nil
	}
	if deniedHost(host) || !validDNSName(host) || resolver == nil {
		return nil, ErrDenied
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !publicAddress(address) {
			return nil, ErrDenied
		}
		if _, duplicate := seen[address]; !duplicate {
			seen[address] = struct{}{}
			result = append(result, address)
		}
	}
	if len(result) == 0 {
		return nil, ErrUnavailable
	}
	return result, nil
}

func newPinnedClient(config Config, host string, addresses []netip.Addr) (*http.Client, func(), error) {
	if host == "" || len(addresses) == 0 {
		return nil, nil, ErrInvalid
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&pinnedDialer{host: host, addresses: append([]netip.Addr(nil), addresses...), dialer: &net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: 30 * time.Second}}).DialContext,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxConnsPerHost:        2,
		ResponseHeaderTimeout:  config.ConnectTimeout,
		TLSHandshakeTimeout:    config.ConnectTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrDenied
		},
	}
	return client, transport.CloseIdleConnections, nil
}

type pinnedDialer struct {
	host      string
	addresses []netip.Addr
	dialer    contextDialer
}

func (dialer *pinnedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if dialer == nil || dialer.dialer == nil || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, ErrDenied
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || normalizedHost(host) != dialer.host || port != "443" {
		return nil, ErrDenied
	}
	for _, candidate := range dialer.addresses {
		if network == "tcp4" && !candidate.Is4() || network == "tcp6" && !candidate.Is6() {
			continue
		}
		connection, dialErr := dialer.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, ErrUnavailable
}

func copyBounded(ctx context.Context, destination io.Writer, source io.Reader, expected int64) (int64, error) {
	limited := &io.LimitedReader{R: source, N: expected + 1}
	buffer := make([]byte, 128<<10)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := limited.Read(buffer)
		if read > 0 {
			count, writeErr := destination.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil || count != read {
				return written, ErrUnavailable
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if limited.N == 0 {
					return written, ErrIntegrity
				}
				return written, nil
			}
			return written, ErrUnavailable
		}
	}
}

type artifactFile struct {
	mu      sync.Mutex
	path    string
	size    int64
	cleaned bool
}

func (artifact *artifactFile) Open(ctx context.Context) (io.ReadSeekCloser, error) {
	if artifact == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	artifact.mu.Lock()
	if artifact.cleaned || artifact.path == "" {
		artifact.mu.Unlock()
		return nil, ErrUnavailable
	}
	filePath, expectedSize := artifact.path, artifact.size
	artifact.mu.Unlock()

	before, err := os.Lstat(filePath)
	if err != nil || !validTemporaryFile(before, expectedSize) {
		return nil, ErrIntegrity
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, ErrUnavailable
	}
	after, err := file.Stat()
	if err != nil || !validTemporaryFile(after, expectedSize) || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, ErrIntegrity
	}
	return file, nil
}

func (artifact *artifactFile) Cleanup() error {
	if artifact == nil {
		return nil
	}
	artifact.mu.Lock()
	defer artifact.mu.Unlock()
	if artifact.cleaned || artifact.path == "" {
		return nil
	}
	if err := os.Remove(artifact.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrCleanup
	}
	artifact.cleaned = true
	artifact.path = ""
	return nil
}

func validTemporaryFile(info os.FileInfo, expectedSize int64) bool {
	permissionsValid := info != nil && (info.Mode().Perm() == 0o600 || runtime.GOOS == "windows")
	return permissionsValid && info.Mode().IsRegular() && info.Size() == expectedSize
}

func normalizedHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

func deniedHost(host string) bool {
	if host == "" || strings.Contains(host, "%") || !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{"localhost", ".localhost", ".local", ".internal", ".home", ".lan", ".test", ".invalid", ".example"} {
		if host == suffix || strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return host == "metadata.google.internal" || host == "instance-data.ec2.internal"
}

func validDNSName(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedRanges {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

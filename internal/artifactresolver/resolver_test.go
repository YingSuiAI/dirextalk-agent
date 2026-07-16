package artifactresolver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
)

func TestResolverMaterializesVerifiedReplayableArtifactAndCleansIt(t *testing.T) {
	payload := []byte("official-installer")
	digest := sha256.Sum256(payload)
	resolver, err := New(Config{MaxSizeBytes: 1024, FetchTimeout: time.Second, ConnectTimeout: time.Second, TempDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	resolver.resolver = staticResolver{netip.MustParseAddr("93.184.216.34")}
	resolver.clientFactory = func(_ Config, host string, addresses []netip.Addr) (*http.Client, func(), error) {
		if host != "downloads.example.com" || len(addresses) != 1 || addresses[0].String() != "93.184.216.34" {
			t.Fatalf("unpinned source: host=%q addresses=%v", host, addresses)
		}
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("Authorization") != "" || request.URL.RawQuery != "" {
				t.Fatal("resolver added credential-bearing request state")
			}
			return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(payload)), Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(payload)), Request: request}, nil
		})}, func() {}, nil
	}
	content, err := resolver.Resolve(context.Background(), cloudexecution.InstallerArtifactResolveRequest{
		SourceID: "release", SourceURL: "https://downloads.example.com/releases/installer", Official: true,
		SHA256: "sha256:" + hex.EncodeToString(digest[:]), SizeBytes: int64(len(payload)),
		TargetPath: artifactRoot + "/installer", RecipeDigest: "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved := content.(*artifactFile)
	info, err := os.Lstat(resolved.path)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("temporary artifact metadata: info=%v err=%v", info, err)
	}
	reader, err := content.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("replayed bytes=%q err=%v", got, err)
	}
	path := resolved.path
	if err := content.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary artifact remains: %v", err)
	}
	if _, err := content.Open(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("open after cleanup error=%v", err)
	}
}

func TestResolverRejectsUnapprovedOrSSRFSourceBeforeHTTP(t *testing.T) {
	resolver, err := New(Config{MaxSizeBytes: 32, FetchTimeout: time.Second, ConnectTimeout: time.Second, TempDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	request := cloudexecution.InstallerArtifactResolveRequest{
		SourceID: "release", SourceURL: "https://downloads.example.com/installer", Official: true,
		SHA256: "sha256:" + strings.Repeat("a", 64), SizeBytes: 16,
		TargetPath: artifactRoot + "/installer", RecipeDigest: "sha256:" + strings.Repeat("b", 64),
	}
	tests := []struct {
		name     string
		url      string
		official bool
		address  netip.Addr
		want     error
	}{
		{name: "not official", url: request.SourceURL, address: netip.MustParseAddr("93.184.216.34"), want: ErrInvalid},
		{name: "metadata address", url: "https://169.254.169.254/latest/meta-data", official: true, want: ErrDenied},
		{name: "private DNS", url: request.SourceURL, official: true, address: netip.MustParseAddr("10.0.0.1"), want: ErrDenied},
		{name: "userinfo", url: "https://token@downloads.example.com/installer", official: true, address: netip.MustParseAddr("93.184.216.34"), want: ErrDenied},
		{name: "query", url: request.SourceURL + "?token=secret", official: true, address: netip.MustParseAddr("93.184.216.34"), want: ErrDenied},
		{name: "non TLS port", url: "https://downloads.example.com:8443/installer", official: true, address: netip.MustParseAddr("93.184.216.34"), want: ErrDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			candidate.SourceURL, candidate.Official = test.url, test.official
			resolver.resolver = staticResolver{test.address}
			resolver.clientFactory = func(Config, string, []netip.Addr) (*http.Client, func(), error) {
				t.Fatal("denied source reached HTTP")
				return nil, nil, nil
			}
			if _, err := resolver.Resolve(context.Background(), candidate); !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestPinnedDialerUsesOnlyApprovedAddressAndPort(t *testing.T) {
	recorder := &recordingDialer{}
	dialer := &pinnedDialer{host: "downloads.example.com", addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, dialer: recorder}
	if _, err := dialer.DialContext(context.Background(), "tcp", "downloads.example.com:443"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dial error=%v", err)
	}
	if recorder.address != "93.184.216.34:443" {
		t.Fatalf("dialed address=%q", recorder.address)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:443"); !errors.Is(err, ErrDenied) {
		t.Fatalf("host drift error=%v", err)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "downloads.example.com:80"); !errors.Is(err, ErrDenied) {
		t.Fatalf("port drift error=%v", err)
	}
}

type staticResolver []netip.Addr

func (resolver staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver...), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type recordingDialer struct{ address string }

func (dialer *recordingDialer) DialContext(_ context.Context, _ string, stringAddress string) (net.Conn, error) {
	dialer.address = stringAddress
	return nil, errors.New("dial stopped")
}

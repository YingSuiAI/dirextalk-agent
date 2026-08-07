package worker

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

const (
	maximumPiProxyConnections = 16
	maximumPiProxyHeaderBytes = 8 << 10
	piProxyHeaderTimeout      = 5 * time.Second
	piProxyDialTimeout        = 10 * time.Second
)

// TunnelDialer is the only upstream available to the Pi loopback bridge.
// Production supplies the sealed TLS OutboundProxy; there is no direct dial
// implementation or fallback in the bridge.
type TunnelDialer interface {
	DialTunnel(context.Context, string) (net.Conn, error)
}

type piTunnelPair struct {
	client   net.Conn
	upstream net.Conn
}

// PiCONNECTBridge is owned by the Worker process and exposes only a bounded
// loopback HTTP CONNECT endpoint to the untrusted Pi UID.
type PiCONNECTBridge struct {
	server                 *http.Server
	listener               net.Listener
	upstream               TunnelDialer
	plannedRelayServerName string
	slots                  chan struct{}
	errors                 chan error

	mu               sync.Mutex
	closed           bool
	allowedAuthority string
	active           map[*piTunnelPair]struct{}
	closeOnce        sync.Once
}

func StartPiCONNECTBridge(
	ctx context.Context,
	upstream TunnelDialer,
	plannedRelayServerName string,
) (*PiCONNECTBridge, error) {
	if ctx == nil || upstream == nil {
		return nil, ErrInvalid
	}
	listener, err := (&net.ListenConfig{}).Listen(
		ctx, "tcp4", cloudruntime.PiLoopbackProxyAddress,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	bridge, err := startPiCONNECTBridge(ctx, listener, upstream, plannedRelayServerName)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	if bridge.listener.Addr().String() != cloudruntime.PiLoopbackProxyAddress {
		_ = bridge.Close()
		return nil, ErrInvalid
	}
	return bridge, nil
}

func startPiCONNECTBridge(
	ctx context.Context,
	listener net.Listener,
	upstream TunnelDialer,
	plannedRelayServerName string,
) (*PiCONNECTBridge, error) {
	plannedRelayServerName = strings.ToLower(strings.TrimSpace(plannedRelayServerName))
	if ctx == nil || listener == nil || upstream == nil ||
		!hostnamePattern.MatchString(plannedRelayServerName) || net.ParseIP(plannedRelayServerName) != nil {
		return nil, ErrInvalid
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP == nil || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) ||
		address.Port < 1 || address.Port > 65535 {
		return nil, ErrInvalid
	}
	bridge := &PiCONNECTBridge{
		listener: listener, upstream: upstream, plannedRelayServerName: plannedRelayServerName,
		slots:  make(chan struct{}, maximumPiProxyConnections),
		errors: make(chan error, 1), active: make(map[*piTunnelPair]struct{}),
	}
	bridge.server = &http.Server{
		Handler: bridge, ReadHeaderTimeout: piProxyHeaderTimeout,
		MaxHeaderBytes: maximumPiProxyHeaderBytes,
		ErrorLog:       log.New(io.Discard, "", 0),
	}
	go bridge.serve(ctx)
	return bridge, nil
}

func (bridge *PiCONNECTBridge) URL() string {
	if bridge == nil {
		return ""
	}
	return cloudruntime.PiLoopbackProxyURL
}

// AuthorizeRelay seals the bridge to the exact claimed relay. It may be
// called only after WorkerControl claim validation. A later task or hostname
// cannot replace the first authority.
func (bridge *PiCONNECTBridge) AuthorizeRelay(endpoint string) error {
	if bridge == nil {
		return ErrInvalid
	}
	authority, err := exactRelayAuthority(endpoint, bridge.plannedRelayServerName)
	if err != nil {
		return err
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return ErrUnavailable
	}
	if bridge.allowedAuthority != "" {
		return ErrIdentityChanged
	}
	bridge.allowedAuthority = authority
	return nil
}

func (bridge *PiCONNECTBridge) Errors() <-chan error {
	if bridge == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return bridge.errors
}

func (bridge *PiCONNECTBridge) serve(ctx context.Context) {
	contextDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = bridge.Close()
		case <-contextDone:
		}
	}()
	err := bridge.server.Serve(bridge.listener)
	close(contextDone)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		err = nil
	} else if err != nil {
		err = ErrUnavailable
	}
	bridge.errors <- err
	close(bridge.errors)
}

func (bridge *PiCONNECTBridge) Close() error {
	if bridge == nil {
		return nil
	}
	bridge.closeOnce.Do(func() {
		bridge.mu.Lock()
		bridge.closed = true
		pairs := make([]*piTunnelPair, 0, len(bridge.active))
		for pair := range bridge.active {
			pairs = append(pairs, pair)
		}
		bridge.mu.Unlock()
		_ = bridge.server.Close()
		for _, pair := range pairs {
			_ = pair.client.Close()
			_ = pair.upstream.Close()
		}
	})
	return nil
}

func (bridge *PiCONNECTBridge) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if bridge == nil || response == nil || !validPiCONNECTRequest(request, bridge.expectedAuthority()) {
		rejectPiProxyRequest(response, http.StatusMethodNotAllowed)
		return
	}
	select {
	case bridge.slots <- struct{}{}:
		defer func() { <-bridge.slots }()
	default:
		rejectPiProxyRequest(response, http.StatusServiceUnavailable)
		return
	}

	dialCtx, cancel := context.WithTimeout(request.Context(), piProxyDialTimeout)
	upstream, err := bridge.upstream.DialTunnel(dialCtx, request.Host)
	cancel()
	if err != nil || upstream == nil {
		if upstream != nil {
			_ = upstream.Close()
		}
		rejectPiProxyRequest(response, http.StatusBadGateway)
		return
	}
	controller := http.NewResponseController(response)
	client, buffered, err := controller.Hijack()
	if err != nil || client == nil || buffered == nil || buffered.Reader.Buffered() != 0 {
		_ = upstream.Close()
		if client != nil {
			_ = client.Close()
		}
		return
	}
	pair := &piTunnelPair{client: client, upstream: upstream}
	if !bridge.track(pair) {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	defer bridge.untrack(pair)

	_ = client.SetDeadline(time.Now().Add(piProxyHeaderTimeout))
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})
	bridge.copyTunnel(client, upstream)
}

func validPiCONNECTRequest(request *http.Request, expectedAuthority string) bool {
	if request == nil || request.Method != http.MethodConnect ||
		request.ProtoMajor != 1 || request.ProtoMinor != 1 ||
		request.RequestURI != request.Host || request.Host != expectedAuthority ||
		!validPiCONNECTAuthority(request.Host) ||
		request.URL == nil || request.URL.Scheme != "" || request.URL.Host != request.Host ||
		request.URL.Path != "" || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || request.ContentLength > 0 ||
		len(request.TransferEncoding) != 0 || request.Header.Get("Proxy-Authorization") != "" {
		return false
	}
	return true
}

func exactRelayAuthority(endpoint, plannedRelayServerName string) (string, error) {
	if endpoint == "" || endpoint != strings.TrimSpace(endpoint) {
		return "", ErrInvalid
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/v1" ||
		parsed.RawPath != "" || parsed.Hostname() != plannedRelayServerName ||
		parsed.Hostname() != strings.ToLower(parsed.Hostname()) || net.ParseIP(parsed.Hostname()) != nil ||
		!hostnamePattern.MatchString(parsed.Hostname()) ||
		(parsed.Port() != "" && parsed.Port() != "443") || parsed.String() != endpoint {
		return "", ErrInvalid
	}
	return net.JoinHostPort(parsed.Hostname(), "443"), nil
}

func validPiCONNECTAuthority(authority string) bool {
	if authority == "" || authority != strings.ToLower(authority) ||
		strings.ContainsAny(authority, "\r\n\x00") {
		return false
	}
	host, port, err := net.SplitHostPort(authority)
	return err == nil && port == "443" && hostnamePattern.MatchString(host) &&
		net.ParseIP(host) == nil
}

func rejectPiProxyRequest(response http.ResponseWriter, status int) {
	response.Header().Set("Connection", "close")
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(status)
}

func (bridge *PiCONNECTBridge) expectedAuthority() string {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return ""
	}
	return bridge.allowedAuthority
}

func (bridge *PiCONNECTBridge) track(pair *piTunnelPair) bool {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return false
	}
	bridge.active[pair] = struct{}{}
	return true
}

func (bridge *PiCONNECTBridge) untrack(pair *piTunnelPair) {
	bridge.mu.Lock()
	delete(bridge.active, pair)
	bridge.mu.Unlock()
}

func (bridge *PiCONNECTBridge) copyTunnel(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	copyOneWay := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		done <- struct{}{}
	}
	go copyOneWay(upstream, client)
	go copyOneWay(client, upstream)
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

var _ http.Handler = (*PiCONNECTBridge)(nil)

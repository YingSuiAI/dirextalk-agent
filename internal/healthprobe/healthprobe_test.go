package healthprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProbeDigestBindsDeploymentPlanRecipeAndExecutableScope(t *testing.T) {
	spec := mustBind(t, baseSpec(PurposeLiveness, ProtocolHTTPS, "https://probe.example.com/health/live"))
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*SpecV1)
	}{
		{name: "deployment", edit: func(value *SpecV1) { value.Binding.DeploymentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }},
		{name: "plan", edit: func(value *SpecV1) { value.Binding.PlanHash = digestOfText("other-plan") }},
		{name: "recipe", edit: func(value *SpecV1) { value.Binding.RecipeDigest = digestOfText("other-recipe") }},
		{name: "purpose", edit: func(value *SpecV1) { value.Purpose = PurposeReadiness }},
		{name: "target", edit: func(value *SpecV1) { value.Target = "https://probe.example.com/health/other" }},
		{name: "timeout", edit: func(value *SpecV1) { value.TimeoutMillis++ }},
		{name: "attempts", edit: func(value *SpecV1) { value.MaxAttempts++ }},
		{name: "retry", edit: func(value *SpecV1) { value.RetryDelayMillis++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := spec
			test.edit(&changed)
			if changed.Validate() == nil {
				t.Fatal("changed probe retained the old digest")
			}
		})
	}
}

func TestProbeContractRejectsSSRFSecretsAndArbitraryRequestSurfaces(t *testing.T) {
	targets := []struct {
		protocol Protocol
		target   string
	}{
		{ProtocolHTTPS, "http://probe.example.com/health"},
		{ProtocolHTTPS, "https://user@probe.example.com/health"},
		{ProtocolHTTPS, "https://probe.example.com/health?mode=full"},
		{ProtocolHTTPS, "https://probe.example.com/health#detail"},
		{ProtocolHTTPS, "https://probe.example.com/a/../health"},
		{ProtocolHTTPS, "https://LOCALHOST/health"},
		{ProtocolHTTPS, "https://127.0.0.1/health"},
		{ProtocolHTTPS, "https://169.254.169.254/latest/meta-data"},
		{ProtocolHTTPS, "https://probe.example.com:0443/health"},
		{ProtocolTCP, "127.0.0.1:443"},
		{ProtocolTCP, "10.0.0.1:443"},
		{ProtocolTCP, "*:443"},
		{ProtocolTCP, "probe.example.com"},
		{ProtocolTCP, "probe.example.com:0"},
	}
	for _, test := range targets {
		spec := baseSpec(PurposeLiveness, test.protocol, test.target)
		if _, err := Bind(spec); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("Bind(%s) error = %v", test.target, err)
		}
	}
	typeOfSpec := reflect.TypeOf(SpecV1{})
	for index := 0; index < typeOfSpec.NumField(); index++ {
		name := strings.ToLower(typeOfSpec.Field(index).Name)
		if strings.Contains(name, "header") || strings.Contains(name, "body") || strings.Contains(name, "method") || strings.Contains(name, "credential") || strings.Contains(name, "command") {
			t.Fatalf("probe spec exposes arbitrary request surface %q", name)
		}
	}
}

func TestEngineRetriesWithFakeClockAndStoresOnlyRedactedEvidence(t *testing.T) {
	spec := baseSpec(PurposeReadiness, ProtocolHTTPS, "https://probe.example.com/health/ready")
	spec.MaxAttempts = 3
	spec = mustBind(t, spec)
	transport := &scriptedTransport{results: []scriptedResult{
		{err: errors.New("opaque remote detail must not persist")},
		{observation: Observation{StatusCode: 503, SummaryDigest: digestOfText("warming"), Latency: 12 * time.Millisecond}},
		{observation: Observation{StatusCode: 200, SummaryDigest: digestOfText("ready"), Latency: 7 * time.Millisecond}},
	}}
	clock := &fakeClock{now: time.Date(2026, time.July, 17, 10, 0, 0, 0, time.UTC)}
	engine, err := newEngine(transport, clock)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Healthy || evidence.Status != StatusHealthy || len(evidence.Attempts) != 3 || transport.calls != 3 || len(clock.sleeps) != 2 ||
		evidence.Attempts[0].FailureCode != FailureTransport || evidence.Attempts[1].FailureCode != FailureHTTPStatus || evidence.Attempts[2].FailureCode != FailureNone {
		t.Fatalf("retry evidence = %+v calls=%d sleeps=%v", evidence, transport.calls, clock.sleeps)
	}
	encoded, _ := json.Marshal(evidence)
	if bytes.Contains(encoded, []byte("opaque remote detail")) {
		t.Fatalf("raw transport error leaked into evidence: %s", encoded)
	}
}

func TestEngineRecordsSemanticMismatchTimeoutAndCancellation(t *testing.T) {
	t.Run("semantic mismatch", func(t *testing.T) {
		spec := baseSpec(PurposeSemantic, ProtocolHTTPS, "https://probe.example.com/health/semantic")
		spec.ExpectedSummaryDigest = digestOfText("expected")
		spec.MaxAttempts = 2
		spec = mustBind(t, spec)
		transport := &scriptedTransport{results: []scriptedResult{{observation: Observation{StatusCode: 200, SummaryDigest: digestOfText("other")}}, {observation: Observation{StatusCode: 200, SummaryDigest: digestOfText("other")}}}}
		engine, _ := newEngine(transport, &fakeClock{now: time.Now().UTC()})
		evidence, err := engine.Run(context.Background(), spec)
		if err != nil || evidence.Healthy || evidence.Status != StatusUnhealthy || len(evidence.Attempts) != 2 || evidence.Attempts[1].FailureCode != FailureSemanticMismatch {
			t.Fatalf("semantic evidence = %+v error=%v", evidence, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		spec := mustBind(t, baseSpec(PurposeLiveness, ProtocolTCP, "probe.example.com:443"))
		transport := &scriptedTransport{results: []scriptedResult{{err: context.DeadlineExceeded}, {err: context.DeadlineExceeded}}}
		engine, _ := newEngine(transport, &fakeClock{now: time.Now().UTC()})
		evidence, err := engine.Run(context.Background(), spec)
		if err != nil || len(evidence.Attempts) != 2 || evidence.Attempts[0].FailureCode != FailureTimeout {
			t.Fatalf("timeout evidence = %+v error=%v", evidence, err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		spec := mustBind(t, baseSpec(PurposeLiveness, ProtocolTCP, "probe.example.com:443"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		engine, _ := newEngine(&scriptedTransport{}, &fakeClock{now: time.Now().UTC()})
		evidence, err := engine.Run(ctx, spec)
		if err != nil || evidence.Status != StatusCanceled || len(evidence.Attempts) != 0 {
			t.Fatalf("canceled evidence = %+v error=%v", evidence, err)
		}
	})
}

func TestSuiteValidatesAllBindingsBeforeIOAndAggregatesDeterministically(t *testing.T) {
	liveness := mustBind(t, baseSpec(PurposeLiveness, ProtocolHTTPS, "https://probe.example.com/live"))
	readiness := mustBind(t, baseSpec(PurposeReadiness, ProtocolHTTPS, "https://probe.example.com/ready"))
	semantic := baseSpec(PurposeSemantic, ProtocolHTTPS, "https://probe.example.com/semantic")
	semantic.ExpectedSummaryDigest = digestOfText("semantic-ok")
	semantic = mustBind(t, semantic)
	transport := &routeTransport{results: map[string]Observation{
		liveness.Target:  {StatusCode: 200, SummaryDigest: digestOfText("live")},
		readiness.Target: {StatusCode: 503, SummaryDigest: digestOfText("not-ready")},
		semantic.Target:  {StatusCode: 200, SummaryDigest: semantic.ExpectedSummaryDigest},
	}}
	engine, _ := newEngine(transport, &fakeClock{now: time.Now().UTC()})
	evidence, err := engine.RunSuite(context.Background(), SuiteV1{SchemaVersion: SuiteSchemaV1, Probes: []SpecV1{semantic, readiness, liveness}})
	if err != nil || evidence.Status != AggregateDegraded || evidence.Healthy || len(evidence.Probes) != 3 ||
		evidence.Probes[0].Purpose != PurposeLiveness || evidence.Probes[1].Purpose != PurposeReadiness || evidence.Probes[2].Purpose != PurposeSemantic {
		t.Fatalf("suite evidence = %+v error=%v", evidence, err)
	}
	tampered := readiness
	tampered.Binding.DeploymentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	before := transport.calls
	if _, err := engine.RunSuite(context.Background(), SuiteV1{SchemaVersion: SuiteSchemaV1, Probes: []SpecV1{liveness, tampered}}); !errors.Is(err, ErrInvalidSpec) || transport.calls != before {
		t.Fatalf("invalid suite reached transport: error=%v calls=%d/%d", err, before, transport.calls)
	}
}

func TestNetworkTransportPinsPublicDNSAndNeverWritesTCPData(t *testing.T) {
	resolver := &fakeResolver{addresses: []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("8.8.8.8")}}
	connection := &recordingConn{}
	dialer := &recordingDialer{connection: connection}
	transport, _ := newNetworkTransport(resolver, dialer, monotonicNow())
	observation, err := transport.Probe(context.Background(), Request{Protocol: ProtocolTCP, Target: "probe.example.com:443", Timeout: time.Second})
	if err != nil || observation.SummaryDigest != digestOfText("dirextalk.external-tcp-connect/v1") || dialer.address != "8.8.8.8:443" || connection.writes != 0 || !connection.closed {
		t.Fatalf("TCP observation=%+v dial=%s conn=%+v error=%v", observation, dialer.address, connection, err)
	}
	resolver.addresses = []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.1")}
	if _, err := transport.Probe(context.Background(), Request{Protocol: ProtocolTCP, Target: "probe.example.com:443", Timeout: time.Second}); failureCode(err, nil) != FailureTargetRejected {
		t.Fatalf("mixed private DNS answer error = %v", err)
	}
}

func TestNetworkHTTPSUsesFixedGETNoRedirectAndDigestOnlyBody(t *testing.T) {
	var requests int
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.Body == nil || request.Header.Get("Authorization") != "" ||
			request.Header.Get("Accept") != "application/octet-stream" || request.Header.Get("User-Agent") != "dirextalk-agent-healthprobe/1" {
			t.Errorf("unsafe HTTP request: method=%s headers=%v", request.Method, request.Header)
		}
		switch request.URL.Path {
		case "/health":
			_, _ = io.WriteString(writer, "healthy")
		case "/redirect":
			http.Redirect(writer, request, "/health", http.StatusFound)
		case "/large":
			_, _ = writer.Write(bytes.Repeat([]byte{'x'}, maxResponseBytes+1))
		}
	}))
	server.StartTLS()
	defer server.Close()
	certificate := server.Certificate()
	if len(certificate.DNSNames) == 0 {
		t.Fatal("httptest certificate has no DNS identity")
	}
	host := strings.ToLower(certificate.DNSNames[0])
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	resolver := &fakeResolver{addresses: []net.IP{net.ParseIP("93.184.216.34")}}
	dialer := &redirectDialer{target: server.Listener.Addr().String()}
	transport, _ := newNetworkTransport(resolver, dialer, monotonicNow())
	transport.rootCAs = pool
	observation, err := transport.Probe(context.Background(), Request{Protocol: ProtocolHTTPS, Target: "https://" + host + ":" + port + "/health", Timeout: 2 * time.Second})
	if err != nil || observation.StatusCode != 200 || observation.SummaryDigest != digestOfText("healthy") || requests != 1 || dialer.address != "93.184.216.34:"+port {
		t.Fatalf("HTTPS observation=%+v requests=%d dial=%s error=%v", observation, requests, dialer.address, err)
	}
	redirect, err := transport.Probe(context.Background(), Request{Protocol: ProtocolHTTPS, Target: "https://" + host + ":" + port + "/redirect", Timeout: 2 * time.Second})
	if err != nil || redirect.StatusCode != http.StatusFound || requests != 2 {
		t.Fatalf("redirect was followed: observation=%+v requests=%d error=%v", redirect, requests, err)
	}
	_, err = transport.Probe(context.Background(), Request{Protocol: ProtocolHTTPS, Target: "https://" + host + ":" + port + "/large", Timeout: 2 * time.Second})
	if failureCode(err, nil) != FailureResponseTooLarge {
		t.Fatalf("large response error = %v", err)
	}
}

func baseSpec(purpose Purpose, protocol Protocol, target string) SpecV1 {
	return SpecV1{
		SchemaVersion: SchemaV1,
		Binding: BindingV1{
			DeploymentID: "11111111-1111-4111-8111-111111111111",
			PlanHash:     digestOfText("plan"), RecipeDigest: digestOfText("recipe"),
		},
		Purpose: purpose, Protocol: protocol, Target: target,
		TimeoutMillis: 500, MaxAttempts: 2, RetryDelayMillis: 25,
	}
}

func mustBind(t *testing.T, spec SpecV1) SpecV1 {
	t.Helper()
	bound, err := Bind(spec)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func digestOfText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", digest[:])
}

type scriptedResult struct {
	observation Observation
	err         error
}

type scriptedTransport struct {
	results []scriptedResult
	calls   int
}

func (transport *scriptedTransport) Probe(context.Context, Request) (Observation, error) {
	transport.calls++
	if transport.calls > len(transport.results) {
		return Observation{}, errors.New("unexpected probe")
	}
	result := transport.results[transport.calls-1]
	return result.observation, result.err
}

type routeTransport struct {
	results map[string]Observation
	calls   int
}

func (transport *routeTransport) Probe(_ context.Context, request Request) (Observation, error) {
	transport.calls++
	observation, ok := transport.results[request.Target]
	if !ok {
		return Observation{}, errors.New("missing route")
	}
	return observation, nil
}

type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (clock *fakeClock) Now() time.Time { return clock.now }
func (clock *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	clock.sleeps = append(clock.sleeps, duration)
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		clock.now = clock.now.Add(duration)
		return nil
	}
}

type fakeResolver struct {
	addresses []net.IP
	err       error
}

func (resolver *fakeResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return append([]net.IP(nil), resolver.addresses...), resolver.err
}

type recordingDialer struct {
	connection net.Conn
	address    string
}

func (dialer *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	dialer.address = address
	return dialer.connection, nil
}

type redirectDialer struct {
	target  string
	address string
}

func (dialer *redirectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer.address = address
	return (&net.Dialer{}).DialContext(ctx, network, dialer.target)
}

type recordingConn struct {
	closed bool
	writes int
}

func (connection *recordingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (connection *recordingConn) Write(buffer []byte) (int, error) {
	connection.writes++
	return len(buffer), nil
}
func (connection *recordingConn) Close() error                     { connection.closed = true; return nil }
func (connection *recordingConn) LocalAddr() net.Addr              { return stubAddr("local") }
func (connection *recordingConn) RemoteAddr() net.Addr             { return stubAddr("remote") }
func (connection *recordingConn) SetDeadline(time.Time) error      { return nil }
func (connection *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type stubAddr string

func (address stubAddr) Network() string { return "tcp" }
func (address stubAddr) String() string  { return string(address) }

func monotonicNow() func() time.Time {
	var mutex sync.Mutex
	current := time.Date(2026, time.July, 17, 10, 0, 0, 0, time.UTC)
	return func() time.Time {
		mutex.Lock()
		defer mutex.Unlock()
		current = current.Add(time.Millisecond)
		return current
	}
}

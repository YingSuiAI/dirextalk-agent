package roothelper

import (
	"bytes"
	"context"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/google/uuid"
)

func TestLocalProtocolStrictDeliveryBindingAndDurableRestartReplay(t *testing.T) {
	fixture := newFixture(t)
	material, err := fixture.delivery.RootTrustMaterial(fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	factoryCalls := 0
	pairingRunner := &pairingRunnerFake{output: []byte("pairing-secret")}
	factory := ControlFactoryFunc(func(_ context.Context, delivery installer.DeliveryV1) (LocalControl, error) {
		factoryCalls++
		control, newErr := New(
			delivery, fixture.secrets, fixture.keys, fixture.runner, fixture.observer,
			fixture.journal, fixture.fence, func() time.Time { return fixture.clock },
		)
		if newErr == nil {
			control.pairingRunner = pairingRunner
		}
		return control, newErr
	})
	server, err := NewLocalServer(material, factory)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newSocketClient(DefaultSocketPath, pipeDialer{server: server})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 2,
		fixture.now.Add(10*time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstProof, err := client.Bootstrap(context.Background(), fixture.delivery, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	replayedProof, err := client.Bootstrap(context.Background(), fixture.delivery, bootstrap)
	if err != nil || !bytes.Equal(firstProof.Signature, replayedProof.Signature) {
		t.Fatalf("bootstrap response-loss replay: err=%v", err)
	}
	firstCanary, err := client.Canary(context.Background(), fixture.delivery, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	replayedCanary, err := client.Canary(context.Background(), fixture.delivery, bootstrap)
	if err != nil || !bytes.Equal(firstCanary.Signature, replayedCanary.Signature) {
		t.Fatalf("canary response-loss replay: err=%v", err)
	}
	restart, err := fixture.issuer.IssueRootHelperRestartCapability(
		fixture.delivery, fixture.binding, installer.RootHelperRestartGrantV1{
			OperationID: uuid.NewString(), DeploymentID: fixture.binding.DeploymentID, OwnerID: fixture.binding.OwnerID,
			LifecycleRestartRef: "restart-service", ExecutionBundleDigest: digest('7'),
			ExpectedInstalledManifestDigest: fixture.observer.installed, WorkerLeaseEpoch: 15,
			LeaseExpiresAt: fixture.now.Add(5 * time.Minute),
		}, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Restart(context.Background(), fixture.delivery, restart, fixture.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := client.Restart(context.Background(), fixture.delivery, restart, fixture.publicKey)
	if err != nil || fixture.runner.calls != 1 || !bytes.Equal(first.Signature, replayed.Signature) {
		t.Fatalf("socket response-loss replay: err=%v executions=%d", err, fixture.runner.calls)
	}
	recipientPrivate, _ := ecdh.X25519().GenerateKey(cryptorand.Reader)
	recipientPublic := base64.RawURLEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes())
	begin := issuePairingCapability(t, fixture, uuid.NewString(), "pairing-begin", fixture.now.Add(5*time.Minute), recipientPublic)
	firstBegin, err := client.PairingBegin(context.Background(), fixture.delivery, begin, recipientPublic, fixture.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	replayedBegin, err := client.PairingBegin(context.Background(), fixture.delivery, begin, recipientPublic, fixture.publicKey)
	if err != nil || pairingRunner.calls != 1 || !bytes.Equal(firstBegin.Signature, replayedBegin.Signature) {
		t.Fatalf("pairing begin response-loss replay: err=%v executions=%d", err, pairingRunner.calls)
	}
	resume := issuePairingCapability(t, fixture, uuid.NewString(), "pairing-resume", fixture.now.Add(5*time.Minute), "")
	firstResume, err := client.PairingResume(context.Background(), fixture.delivery, resume, fixture.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	replayedResume, err := client.PairingResume(context.Background(), fixture.delivery, resume, fixture.publicKey)
	if err != nil || fixture.runner.calls != 2 || !bytes.Equal(firstResume.Signature, replayedResume.Signature) {
		t.Fatalf("pairing resume response-loss replay: err=%v executions=%d", err, fixture.runner.calls)
	}
	if factoryCalls != 10 {
		t.Fatalf("dispatcher did not revalidate and reconstruct per request: calls=%d", factoryCalls)
	}
}

func TestLocalProtocolRejectsMalformedUnionAndMismatchedRootTrust(t *testing.T) {
	fixture := newFixture(t)
	material, _ := fixture.delivery.RootTrustMaterial(fixture.now)
	factoryCalls := 0
	server, err := NewLocalServer(material, ControlFactoryFunc(func(context.Context, installer.DeliveryV1) (LocalControl, error) {
		factoryCalls++
		return fixture.handler, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	deliveryCBOR, _ := canonical.Marshal(fixture.delivery)
	bootstrap, _ := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 1,
		fixture.now.Add(time.Minute), fixture.now,
	)
	bootstrapCBOR, _ := canonical.Marshal(bootstrap)
	malformed := LocalRequestV1{
		SchemaVersion: LocalProtocolSchemaV1, RequestID: uuid.NewString(), Action: ActionBootstrap,
		DeliveryCBOR: deliveryCBOR, BootstrapCapabilityCBOR: bootstrapCBOR,
		RestartCapabilityCBOR: []byte{0xf6},
	}
	response := dispatchRequest(t, server, malformed)
	if response.ErrorCode != ErrorInvalid || response.Status != StatusRejected || factoryCalls != 0 {
		t.Fatalf("malformed union reached control: %#v calls=%d", response, factoryCalls)
	}

	otherDelivery := fixture.delivery
	otherDelivery.Config.Binding.TaskID = uuid.NewString()
	otherCBOR, _ := canonical.Marshal(otherDelivery)
	mismatched := malformed
	mismatched.RequestID = uuid.NewString()
	mismatched.RestartCapabilityCBOR = nil
	mismatched.DeliveryCBOR = otherCBOR
	response = dispatchRequest(t, server, mismatched)
	if response.ErrorCode != ErrorUnauthorized || factoryCalls != 0 {
		t.Fatalf("mismatched delivery reached control: %#v calls=%d", response, factoryCalls)
	}
}

func TestSocketClientRejectsMalformedResponseUnion(t *testing.T) {
	client, err := newSocketClient(DefaultSocketPath, responseDialer{response: LocalResponseV1{
		SchemaVersion: LocalProtocolSchemaV1, Status: StatusSucceeded,
		PossessionProofCBOR: []byte{0xf6}, CanaryProofCBOR: []byte{0xf6},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fixture := newFixture(t)
	bootstrap, _ := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 1,
		fixture.now.Add(time.Minute), fixture.now,
	)
	if _, err := client.Bootstrap(context.Background(), fixture.delivery, bootstrap); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed response union error = %v", err)
	}
}

func dispatchRequest(t *testing.T, server *LocalServer, request LocalRequestV1) LocalResponseV1 {
	t.Helper()
	payload, _ := canonical.Marshal(request)
	var framed bytes.Buffer
	if err := writeLocalFrame(&framed, payload); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := server.Handle(context.Background(), &framed, &output); err != nil {
		t.Fatal(err)
	}
	responsePayload, err := readLocalFrame(&output, maxLocalResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	var response LocalResponseV1
	if installer.DecodeCanonical(responsePayload, &response) != nil {
		t.Fatal("decode local response")
	}
	return response
}

type pipeDialer struct{ server *LocalServer }

func (dialer pipeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if dialer.server == nil || network != "unix" || address != DefaultSocketPath {
		return nil, ErrUnavailable
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_ = dialer.server.Handle(ctx, server, server)
	}()
	return client, nil
}

type responseDialer struct{ response LocalResponseV1 }

func (dialer responseDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		requestPayload, _ := readLocalFrame(server, maxLocalRequestBytes)
		var request LocalRequestV1
		_ = installer.DecodeCanonical(requestPayload, &request)
		response := dialer.response
		response.RequestID = request.RequestID
		response.Action = request.Action
		payload, _ := canonical.Marshal(response)
		_ = writeLocalFrame(server, payload)
	}()
	return client, nil
}

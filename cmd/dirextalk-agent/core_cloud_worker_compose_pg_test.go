package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type composedCompletionDispatcher struct{}

func (composedCompletionDispatcher) RecordCompletion(context.Context, cloudworker.CompletionOutbox) error {
	return nil
}

type composedLifecycleScheduler struct{}

func (composedLifecycleScheduler) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (composedLifecycleScheduler) Wait(context.Context) error { return nil }

func writeCloudWorkerComposePinnedJSON(t *testing.T, dir, name string, value any) (string, string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err = os.WriteFile(path, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return path, hex.EncodeToString(digest[:])
}

func cloudWorkerComposeCertificateFiles(t *testing.T, dir string, names ...string) (string, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(19), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, iidPath := filepath.Join(dir, "worker-cert.pem"), filepath.Join(dir, "worker-key.pem"), filepath.Join(dir, "iid-cert.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = os.WriteFile(certPath, certificate, 0o400); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o400); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(iidPath, certificate, 0o400); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, iidPath
}

func cloudWorkerComposePGStore(t *testing.T) (*postgres.Store, func()) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for production Cloud Worker composition")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	database := "cw_compose_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{database}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config := adminConfig.Copy()
	config.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, `DROP DATABASE `+pgx.Identifier{database}.Sanitize())
		admin.Close()
		t.Fatal(err)
	}
	instanceID := uuid.NewString()
	if err = postgres.ApplyMigrations(ctx, pool, instanceID); err != nil {
		pool.Close()
		_, _ = admin.Exec(ctx, `DROP DATABASE `+pgx.Identifier{database}.Sanitize())
		admin.Close()
		t.Fatal(err)
	}
	keyring, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x43}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.New(pool, instanceID, keyring)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), `DROP DATABASE `+pgx.Identifier{database}.Sanitize())
		admin.Close()
	}
	return store, cleanup
}

func cloudWorkerComposeConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, iidFile := cloudWorkerComposeCertificateFiles(t, dir, "worker.example.test", "relay.example.test")
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	pricingFile, pricingDigest := writeCloudWorkerComposePinnedJSON(t, dir, "pricing.json", map[string]any{
		"schema": cloudworker.PricingCatalogFileSchema, "account_id": "123456789012", "region": "us-east-1",
		"instance_type": "t3.micro", "architecture": "x86_64", "volume_type": "gp3",
		"source_time": now, "expires_at": now.Add(10 * time.Minute),
		"rates": cloudworker.PricingCatalogRates{
			ComputeMicrosPerHour: 1000, EBSStorageMicrosPerGiBMonth: 1000,
			PublicIPv4MicrosPerHour: 1000, ModelMicrosPerThousandTokens: 1000,
		},
	})
	qualificationFile, qualificationDigest := writeCloudWorkerComposePinnedJSON(t, dir, "qualification.json", map[string]any{
		"schema":                  cloudworker.RuntimeQualificationFileSchema,
		"worker_protocol_version": cloudprotocol.WorkerProtocolVersion, "runtime_contract_version": cloudprotocol.RuntimeContractVersion,
		"ami_id": "ami-0123456789abcdef0", "ami_digest": digest("ami"),
		"worker_release_digest": digest("worker"), "pi_runtime_digest": digest("pi"), "architecture": "x86_64",
		"pi_version": "compose-test", "pi_executable_sha256": digest("pi-executable"),
		"result_extension_sha256": digest("result-extension"), "host_network_policy_sha256": digest("host-network"),
	})
	credentialID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("compose-cloud-worker-credential")).String()
	return config.Config{
		ListenAddress: "127.0.0.1:9443", CapabilityListenAddress: "127.0.0.1:9444",
		CoreExecutionV2Enabled: true, CoreAWSEnabled: true, CapabilityEnabled: true, ProductCapabilityEnabled: true,
		CapabilityAccountGeneration: 7, ProductCapabilityAccountGeneration: 7,
		CoreCloudWorker: config.CloudWorker{
			Enabled: true, AccountID: "123456789012", Region: "us-east-1",
			CredentialID: credentialID, CredentialRevision: 3,
			InstanceType: "t3.micro", Architecture: "x86_64", RootDeviceName: "/dev/xvda",
			VolumeGiB: 8, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125,
			AMIID: "ami-0123456789abcdef0", AMIDigest: digest("ami"), WorkerReleaseDigest: digest("worker"),
			PiRuntimeDigest: digest("pi"), HostNetworkPolicySHA256: digest("host-network"),
			VPCID: "vpc-01234567", SubnetID: "subnet-01234567",
			DNSResolverCIDRs: []string{"10.0.0.2/32"}, TLSProxyCIDRs: []string{"10.0.0.3/32"},
			AllowedFQDNs:     []string{"worker.example.test"},
			OutboundProxyURL: "https://proxy.example.test:443", OutboundProxyServerName: "proxy.example.test",
			OutboundProxyTrustSHA256: digest("proxy-ca"), ArtifactBucket: "dirextalk-compose-test",
			ArtifactBasePrefix: "executions/", ArtifactKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
			ArtifactRetention: 30 * 24 * time.Hour, WorkerControlListenAddress: "127.0.0.1:0",
			WorkerControlEndpoint: "https://worker.example.test:8443", WorkerControlServerName: "worker.example.test",
			WorkerControlTLSCertFile: certFile, WorkerControlTLSKeyFile: keyFile, WorkerControlTrustSHA256: digest("worker-ca"),
			WorkerControlMaxConcurrentRPC: 8,
			IIDCertificateFile:            iidFile, PricingCatalogFile: pricingFile, PricingCatalogSHA256: pricingDigest,
			RuntimeQualificationFile: qualificationFile, RuntimeQualificationSHA256: qualificationDigest,
			QuoteTTL: 5 * time.Minute, MaximumCatalogAge: 15 * time.Minute, AbsoluteHardLimitMicros: 20_000_000,
			MaxRuntime: time.Hour, MaxTokens: 2000, MaxOutputBytes: 1 << 20,
			ControllerPollInterval: time.Second, WorkerHeartbeatInterval: time.Second,
			ReaperInterval: time.Second, CompletionOutboxInterval: time.Second,
		},
	}
}

func TestComposeCoreCloudWorkerConstructsAndRunsProductionCleaners(t *testing.T) {
	store, cleanup := cloudWorkerComposePGStore(t)
	defer cleanup()
	cfg := cloudWorkerComposeConfig(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	credential := coreaws.RehydrateCredentialsWithTestedAt(
		cfg.CoreCloudWorker.CredentialID, "compose-test", cfg.CoreCloudWorker.Region,
		cfg.CoreCloudWorker.AccountID, "arn:aws:iam::123456789012:role/compose-test",
		[]byte("test-access-key"), []byte("test-secret-key"), nil,
		int64(cfg.CoreCloudWorker.CredentialRevision), int64(cfg.CoreCloudWorker.CredentialRevision), now, now, now,
	)
	if _, err := postgres.NewCoreAWSStore(store).CreateCredential(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	conversation, err := postgres.NewCoreConversationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := coremodel.NewService(coremodel.NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	composition, err := composeCoreCloudWorker(context.Background(), cfg, store, conversation, profiles, postgres.NewCoreTaskStore(store))
	if err != nil {
		t.Fatal(err)
	}
	completion, err := cloudworker.NewCompletionLoop(cloudworker.CompletionLoopConfig{
		Store: composition.outboxStore, Dispatcher: composedCompletionDispatcher{}, PollInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	composition.completion = completion
	if composition.reaper == nil || composition.retention == nil || composition.outputHistory == nil || len(composition.Cleaners()) != 4 {
		t.Fatalf("production cleaner graph is incomplete: %#v", composition.Cleaners())
	}
	if err = composition.StartPrivate(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	events := []string{}
	server := &lifecycleTestServer{events: &events, stop: make(chan struct{})}
	worker := &lifecycleTestWorker{events: &events}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	err = runCoreLifecycle(ctx, listener, server, composedLifecycleScheduler{}, worker, time.Second, func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		if stopErr := composition.StopPrivate(stopCtx); stopErr != nil {
			t.Errorf("stop private composition: %v", stopErr)
		}
	}, composition.Cleaners()...)
	if err != nil {
		t.Fatal(err)
	}
	if !composition.stopped {
		t.Fatal("production Cloud Worker private composition did not stop")
	}
}

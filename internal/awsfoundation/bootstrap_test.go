package awsfoundation

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
)

func TestBootstrapEstablishesFoundationWithoutPersistingAdminCredential(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := NewMemoryCredentialStore()
	vault, err := NewCredentialVault(store, bytes.Repeat([]byte{0x37}, 32), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	provider := &fakeBootstrapProvider{
		identity: awsprovider.CallerIdentity{Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012", Region: "us-east-1"},
		source:   awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("generated-source-secret-value-123456")},
		receipt:  awsprovider.FoundationStackReceipt{StackID: "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-foundation/id", Status: awsprovider.FoundationStackReadyStatus, ObservedAt: now},
	}
	factory := &fakeBootstrapFactory{provider: provider}
	template := testFoundationTemplate(t)
	bootstrapper, err := NewBootstrapper(factory, vault, template, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	result, err := bootstrapper.Establish(context.Background(), payload, EstablishRequest{
		AgentInstanceID:              "agent-01",
		Region:                       "us-east-1",
		ConfirmedAccountID:           "123456789012",
		ExpectedCredentialGeneration: 0,
		AdminAuthorization:           AdminAuthorization{SessionID: "bootstrap-session-01", AccountID: "123456789012", Region: "us-east-1", VerifiedAt: now, ExpiresAt: now.Add(10 * time.Minute)},
		ReaperImageURI:               "123456789012.dkr.ecr.us-east-1.amazonaws.com/dirextalk-agent-reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if result.Identity.AccountID != "123456789012" || result.SourceCredentialGeneration != 1 || result.Stack.StackID == "" {
		t.Fatalf("result = %#v", result)
	}
	if !allZeroBytes(payload) || !allZeroBytes(factory.seen.AccessKeyID) || !allZeroBytes(factory.seen.SecretAccessKey) {
		t.Fatal("uploaded admin credentials remained live after bootstrap")
	}
	if !allZeroBytes(provider.source.AccessKeyID) || !allZeroBytes(provider.source.SecretAccessKey) {
		t.Fatal("generated source credential remained live after envelope storage")
	}
	record, err := store.Get(context.Background(), "agent-01")
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(record.Ciphertext)
	if strings.Contains(serialized, "uploaded-root-secret") || strings.Contains(serialized, "generated-source-secret") {
		t.Fatal("credential store contains plaintext")
	}
	if provider.ensureCalls != 1 || provider.stackCalls != 1 || provider.stackRequest.FoundationRoleARN == "" || provider.stackRequest.TemplateSHA256 == "" {
		t.Fatalf("provider calls = ensure %d stack %d request %#v", provider.ensureCalls, provider.stackCalls, provider.stackRequest)
	}
}

func TestBootstrapFailsClosedBeforeMutationOnIdentityMismatch(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	vault, _ := NewCredentialVault(NewMemoryCredentialStore(), bytes.Repeat([]byte{0x48}, 32), rand.Reader, func() time.Time { return now })
	defer vault.Close()
	provider := &fakeBootstrapProvider{identity: awsprovider.CallerIdentity{Partition: "aws", AccountID: "999999999999", ARN: "arn:aws:iam::999999999999:user/admin", UserID: "admin", Region: "us-east-1"}}
	bootstrapper, err := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, testFoundationTemplate(t), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	_, err = bootstrapper.Establish(context.Background(), payload, EstablishRequest{
		AgentInstanceID: "agent-01", Region: "us-east-1", ConfirmedAccountID: "123456789012",
		AdminAuthorization: AdminAuthorization{SessionID: "bootstrap-session-01", AccountID: "123456789012", Region: "us-east-1", VerifiedAt: now, ExpiresAt: now.Add(time.Minute)},
		ReaperImageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("b", 64),
	})
	if !errors.Is(err, ErrIdentityConfirmationMismatch) {
		t.Fatalf("error = %v", err)
	}
	if provider.ensureCalls != 0 || provider.stackCalls != 0 {
		t.Fatal("AWS mutation occurred before identity confirmation")
	}
}

func TestBootstrapRedactsProviderPermissionErrors(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	vault, _ := NewCredentialVault(NewMemoryCredentialStore(), bytes.Repeat([]byte{0x59}, 32), rand.Reader, func() time.Time { return now })
	defer vault.Close()
	secret := "uploaded-root-secret-value-1234567890"
	provider := &fakeBootstrapProvider{identityErr: errors.New("AccessDenied for " + secret)}
	bootstrapper, _ := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, testFoundationTemplate(t), func() time.Time { return now })
	payload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"` + secret + `"}`)
	_, err := bootstrapper.Establish(context.Background(), payload, EstablishRequest{
		AgentInstanceID: "agent-01", Region: "us-east-1", ConfirmedAccountID: "123456789012",
		AdminAuthorization: AdminAuthorization{SessionID: "bootstrap-session-01", AccountID: "123456789012", Region: "us-east-1", VerifiedAt: now, ExpiresAt: now.Add(time.Minute)},
		ReaperImageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("c", 64),
	})
	if !errors.Is(err, ErrFoundationPermissionDenied) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestBootstrapVaultFailureRetainsCreatedSourceKeyForRemediation(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	secretCanary := "generated-source-secret-must-not-leak"
	store := &putFailingCredentialStore{
		base: NewMemoryCredentialStore(),
		err:  errors.New("vault unavailable near " + secretCanary),
	}
	vault, err := NewCredentialVault(store, bytes.Repeat([]byte{0x60}, 32), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	provider := &fakeBootstrapProvider{
		identity: awsprovider.CallerIdentity{Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012", Region: "us-east-1"},
		source:   awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte(secretCanary)},
	}
	bootstrapper, err := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, testFoundationTemplate(t), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	_, err = bootstrapper.Establish(context.Background(), payload, EstablishRequest{
		AgentInstanceID: "agent-01", Region: "us-east-1", ConfirmedAccountID: "123456789012",
		AdminAuthorization: AdminAuthorization{SessionID: "bootstrap-session-01", AccountID: "123456789012", Region: "us-east-1", VerifiedAt: now, ExpiresAt: now.Add(time.Minute)},
		ReaperImageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("9", 64),
	})
	if !errors.Is(err, ErrCredentialEnvelope) || strings.Contains(err.Error(), secretCanary) {
		t.Fatalf("vault failure error=%v", err)
	}
	if provider.ensureCalls != 1 || provider.stackCalls != 0 || len(provider.activeKeyIDs) != 1 || provider.activeKeyIDs[0] != "AKIAABCDEFGHIJKLMNOP" {
		t.Fatalf("vault failure source-key state: ensure=%d stack=%d keys=%v", provider.ensureCalls, provider.stackCalls, provider.activeKeyIDs)
	}
	if !allZeroBytes(provider.source.AccessKeyID) || !allZeroBytes(provider.source.SecretAccessKey) {
		t.Fatal("generated source credential buffer was not wiped after vault failure")
	}
	if _, err := store.base.Get(context.Background(), "agent-01"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("failed vault write unexpectedly persisted credential: %v", err)
	}
}

func TestBootstrapExistingSourceKeyRequiresFreshAdminRemediation(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	vault, _ := NewCredentialVault(NewMemoryCredentialStore(), bytes.Repeat([]byte{0x62}, 32), rand.Reader, func() time.Time { return now })
	defer vault.Close()
	provider := &fakeBootstrapProvider{
		identity:  awsprovider.CallerIdentity{Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012", Region: "us-east-1"},
		ensureErr: awsprovider.ErrSourceCredentialRemediationRequired,
	}
	bootstrapper, _ := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, testFoundationTemplate(t), func() time.Time { return now })
	payload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	_, err := bootstrapper.Establish(context.Background(), payload, EstablishRequest{
		AgentInstanceID: "agent-01", Region: "us-east-1", ConfirmedAccountID: "123456789012",
		AdminAuthorization: AdminAuthorization{SessionID: "bootstrap-session-01", AccountID: "123456789012", Region: "us-east-1", VerifiedAt: now, ExpiresAt: now.Add(time.Minute)},
		ReaperImageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("8", 64),
	})
	if !errors.Is(err, ErrAdminAuthorizationRequired) || provider.ensureCalls != 1 || provider.stackCalls != 0 {
		t.Fatalf("source remediation error=%v ensure=%d stack=%d", err, provider.ensureCalls, provider.stackCalls)
	}
}

func TestBootstrapRejectsForbiddenMutableImageTagsBeforeAWS(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	vault, _ := NewCredentialVault(NewMemoryCredentialStore(), bytes.Repeat([]byte{0x61}, 32), rand.Reader, func() time.Time { return now })
	defer vault.Close()
	provider := &fakeBootstrapProvider{}
	bootstrapper, _ := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, testFoundationTemplate(t), func() time.Time { return now })
	for _, tag := range []string{"latest", "v1.0.3", "v0.1.0"} {
		payload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
		_, err := bootstrapper.Establish(context.Background(), payload, EstablishRequest{
			AgentInstanceID: "agent-01", Region: "us-east-1", ConfirmedAccountID: "123456789012",
			ReaperImageURI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/reaper:" + tag + "@sha256:" + strings.Repeat("d", 64),
		})
		if !errors.Is(err, ErrFoundationBootstrap) || provider.ensureCalls != 0 || provider.stackCalls != 0 || !allZeroBytes(payload) {
			t.Fatalf("tag %q was not rejected before AWS: %v", tag, err)
		}
	}
}

func TestBootstrapResumesPersistedSameOperationWithoutRotatingSourceKey(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := NewMemoryCredentialStore()
	vault, _ := NewCredentialVault(store, bytes.Repeat([]byte{0x72}, 32), rand.Reader, func() time.Time { return now })
	defer vault.Close()
	provider := &fakeBootstrapProvider{
		identity: awsprovider.CallerIdentity{Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012", Region: "us-east-1"},
		source:   awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("generated-source-secret-value-123456")},
		stackErr: errors.New("response lost after CreateStack"),
	}
	bootstrapper, _ := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, testFoundationTemplate(t), func() time.Time { return now })
	authorization := AdminAuthorization{SessionID: "bootstrap-operation-01", AccountID: "123456789012", Region: "us-east-1", VerifiedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	request := EstablishRequest{
		AgentInstanceID: "agent-01", Region: "us-east-1", ConfirmedAccountID: "123456789012", ExpectedCredentialGeneration: 0,
		AdminAuthorization: authorization, ReaperImageURI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("e", 64),
	}
	firstPayload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	if _, err := bootstrapper.Establish(context.Background(), firstPayload, request); !errors.Is(err, ErrFoundationBootstrap) {
		t.Fatalf("first establish error = %v", err)
	}
	firstToken := provider.stackRequest.ClientToken
	if provider.ensureCalls != 1 || provider.stackCalls != 1 {
		t.Fatalf("first calls ensure=%d stack=%d", provider.ensureCalls, provider.stackCalls)
	}

	provider.stackErr = nil
	provider.receipt = awsprovider.FoundationStackReceipt{StackID: "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-foundation/id", Status: awsprovider.FoundationStackReadyStatus, ObservedAt: now}
	request.ResumeExistingGeneration = true
	retryPayload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	result, err := bootstrapper.Establish(context.Background(), retryPayload, request)
	if err != nil {
		t.Fatalf("resume establish: %v", err)
	}
	if result.SourceCredentialGeneration != 1 || provider.ensureCalls != 1 || provider.stackCalls != 2 {
		t.Fatalf("resume result=%#v ensure=%d stack=%d", result, provider.ensureCalls, provider.stackCalls)
	}
	if provider.stackRequest.ClientToken != firstToken {
		t.Fatalf("resume ClientToken changed: %q != %q", provider.stackRequest.ClientToken, firstToken)
	}
}

func TestBootstrapResumeCannotBypassGenerationForFirstOrDifferentOperation(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := NewMemoryCredentialStore()
	vault, _ := NewCredentialVault(store, bytes.Repeat([]byte{0x73}, 32), rand.Reader, func() time.Time { return now })
	defer vault.Close()
	provider := &fakeBootstrapProvider{
		identity: awsprovider.CallerIdentity{Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012", Region: "us-east-1"},
		source:   awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("generated-source-secret-value-123456")},
		stackErr: errors.New("response lost after CreateStack"),
	}
	bootstrapper, _ := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, testFoundationTemplate(t), func() time.Time { return now })
	base := EstablishRequest{
		AgentInstanceID: "agent-01", Region: "us-east-1", ConfirmedAccountID: "123456789012", ExpectedCredentialGeneration: 0, ResumeExistingGeneration: true,
		AdminAuthorization: AdminAuthorization{SessionID: "bootstrap-operation-01", AccountID: "123456789012", Region: "us-east-1", VerifiedAt: now, ExpiresAt: now.Add(10 * time.Minute)},
		ReaperImageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("f", 64),
	}
	payload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	if _, err := bootstrapper.Establish(context.Background(), payload, base); !errors.Is(err, ErrCredentialRevisionConflict) {
		t.Fatalf("first-operation resume error = %v", err)
	}
	if provider.ensureCalls != 0 || provider.stackCalls != 0 {
		t.Fatal("first-operation resume reached AWS mutation")
	}

	base.ResumeExistingGeneration = false
	payload = []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	if _, err := bootstrapper.Establish(context.Background(), payload, base); !errors.Is(err, ErrFoundationBootstrap) {
		t.Fatalf("initial establish error = %v", err)
	}
	base.ResumeExistingGeneration = true
	base.AdminAuthorization.SessionID = "bootstrap-operation-02"
	payload = []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	if _, err := bootstrapper.Establish(context.Background(), payload, base); !errors.Is(err, ErrCredentialRevisionConflict) {
		t.Fatalf("different-operation resume error = %v", err)
	}
	if provider.ensureCalls != 1 || provider.stackCalls != 1 {
		t.Fatalf("different operation reached mutation: ensure=%d stack=%d", provider.ensureCalls, provider.stackCalls)
	}
}

func TestBootstrapNeverAcceptsNonReadyFoundationReceipt(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	vault, _ := NewCredentialVault(NewMemoryCredentialStore(), bytes.Repeat([]byte{0x74}, 32), rand.Reader, func() time.Time { return now })
	defer vault.Close()
	provider := &fakeBootstrapProvider{
		identity: awsprovider.CallerIdentity{Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012", Region: "us-east-1"},
		source:   awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("generated-source-secret-value-123456")},
		receipt:  awsprovider.FoundationStackReceipt{StackID: "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-foundation/id", Status: "CREATE_IN_PROGRESS", ObservedAt: now},
	}
	bootstrapper, _ := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, testFoundationTemplate(t), func() time.Time { return now })
	payload := []byte(`{"AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"uploaded-root-secret-value-1234567890"}`)
	_, err := bootstrapper.Establish(context.Background(), payload, EstablishRequest{
		AgentInstanceID: "agent-01", Region: "us-east-1", ConfirmedAccountID: "123456789012",
		AdminAuthorization: AdminAuthorization{SessionID: "bootstrap-operation-01", AccountID: "123456789012", Region: "us-east-1", VerifiedAt: now, ExpiresAt: now.Add(time.Minute)},
		ReaperImageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("1", 64),
	})
	if !errors.Is(err, ErrFoundationBootstrap) {
		t.Fatalf("non-ready receipt error = %v", err)
	}
}

type fakeBootstrapFactory struct {
	provider *fakeBootstrapProvider
	seen     awsprovider.Credentials
}

type putFailingCredentialStore struct {
	base *MemoryCredentialStore
	err  error
}

func (store *putFailingCredentialStore) Get(ctx context.Context, agentInstanceID string) (EncryptedSourceCredential, error) {
	return store.base.Get(ctx, agentInstanceID)
}

func (store *putFailingCredentialStore) PutCAS(context.Context, string, uint64, EncryptedSourceCredential) error {
	return store.err
}

func (store *putFailingCredentialStore) DeleteCAS(ctx context.Context, agentInstanceID string, expectedGeneration uint64) error {
	return store.base.DeleteCAS(ctx, agentInstanceID, expectedGeneration)
}

func (factory *fakeBootstrapFactory) NewBootstrapProvider(_ context.Context, _ string, credentials *awsprovider.Credentials) (awsprovider.BootstrapProvider, error) {
	factory.seen = *credentials
	return factory.provider, nil
}

type fakeBootstrapProvider struct {
	identity     awsprovider.CallerIdentity
	identityErr  error
	source       awsprovider.SourceCredentials
	ensureErr    error
	receipt      awsprovider.FoundationStackReceipt
	stackErr     error
	ensureCalls  int
	stackCalls   int
	stackRequest awsprovider.FoundationStackRequest
	activeKeyIDs []string
}

func (provider *fakeBootstrapProvider) GetCallerIdentity(context.Context) (awsprovider.CallerIdentity, error) {
	if provider.identityErr != nil {
		return awsprovider.CallerIdentity{}, provider.identityErr
	}
	return provider.identity, nil
}

func (provider *fakeBootstrapProvider) EnsureBootstrapIdentity(_ context.Context, _ awsprovider.BootstrapIdentitySpec) (awsprovider.SourceCredentials, error) {
	provider.ensureCalls++
	if provider.ensureErr != nil {
		return awsprovider.SourceCredentials{}, provider.ensureErr
	}
	provider.activeKeyIDs = append(provider.activeKeyIDs, string(provider.source.AccessKeyID))
	return provider.source, nil
}

func (provider *fakeBootstrapProvider) CreateFoundationStack(_ context.Context, request awsprovider.FoundationStackRequest) (awsprovider.FoundationStackReceipt, error) {
	provider.stackCalls++
	provider.stackRequest = request
	if provider.stackErr != nil {
		return awsprovider.FoundationStackReceipt{}, provider.stackErr
	}
	return provider.receipt, nil
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

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

func TestLifecycleUpgradeAndFullTeardownRequireFreshAdminAndExactTemplate(t *testing.T) {
	now := time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC)
	provider := &fakeBootstrapProvider{identity: awsprovider.CallerIdentity{Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/admin", UserID: "AIDAABCDEFGHIJKLMNOP", Region: "us-east-1"}, receipt: awsprovider.FoundationStackReceipt{StackID: "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-test/id", Status: awsprovider.FoundationStackUpdatedStatus, ObservedAt: now}}
	store := NewMemoryCredentialStore()
	vault, err := NewCredentialVault(store, bytes.Repeat([]byte{0x42}, 32), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vault.Close)
	binding := SourceCredentialBinding{AgentInstanceID: "agent-test", AccountID: "123456789012", Region: "us-east-1"}
	authorization := AdminAuthorization{SessionID: "original-operation", AccountID: binding.AccountID, Region: binding.Region, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	if _, err := vault.SealAndStore(context.Background(), binding, 0, authorization, awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("secret-access-key-value")}); err != nil {
		t.Fatal(err)
	}
	template := testFoundationTemplate(t)
	bootstrapper, err := NewBootstrapper(&fakeBootstrapFactory{provider: provider}, vault, template, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := LifecycleRequest{Action: LifecycleUpgrade, OperationID: "upgrade-operation", AgentInstanceID: binding.AgentInstanceID, Region: binding.Region,
		ConfirmedAccountID: binding.AccountID, ExpectedCredentialGeneration: 1, AdminAuthorization: AdminAuthorization{SessionID: "upgrade-operation", AccountID: binding.AccountID,
			Region: binding.Region, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, TemplateDigest: bootstrapper.templateHash,
		ReaperImageURI: "registry.example/reaper:v2.0.0-rc.1@sha256:" + strings.Repeat("a", 64)}
	result, err := bootstrapper.Mutate(context.Background(), bootstrapPayload(), request)
	if err != nil {
		t.Fatalf("upgrade Mutate() error = %v", err)
	}
	if provider.policyUpdateCalls != 1 || provider.ensureCalls != 0 || provider.updateCalls != 1 || result.CredentialGeneration != 1 || result.Stack.Status != awsprovider.FoundationStackUpdatedStatus {
		t.Fatalf("upgrade provider=%#v result=%#v", provider, result)
	}

	tampered := request
	tampered.TemplateDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := bootstrapper.Mutate(context.Background(), bootstrapPayload(), tampered); !errors.Is(err, ErrFoundationBootstrap) {
		t.Fatalf("tampered template error=%v", err)
	}
	expired := request
	expired.OperationID = "teardown-operation"
	expired.Action = LifecycleTeardown
	expired.AdminAuthorization = AdminAuthorization{SessionID: expired.OperationID, AccountID: binding.AccountID, Region: binding.Region, VerifiedAt: now.Add(-11 * time.Minute), ExpiresAt: now.Add(-time.Minute)}
	if _, err := bootstrapper.Mutate(context.Background(), bootstrapPayload(), expired); !errors.Is(err, ErrAdminAuthorizationRequired) {
		t.Fatalf("expired teardown error=%v", err)
	}

	teardown := request
	teardown.OperationID = "teardown-operation"
	teardown.Action = LifecycleTeardown
	teardown.AdminAuthorization.SessionID = teardown.OperationID
	destroyed, err := bootstrapper.Mutate(context.Background(), bootstrapPayload(), teardown)
	if err != nil {
		t.Fatalf("teardown Mutate() error = %v", err)
	}
	if !destroyed.Destroyed || provider.policyUpdateCalls != 2 || provider.deleteCalls != 1 || provider.deleteIdentityCalls != 1 {
		t.Fatalf("teardown provider=%#v result=%#v", provider, destroyed)
	}
	if _, err := vault.Open(context.Background(), binding); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("vault credential after teardown = %v", err)
	}
}

func bootstrapPayload() []byte {
	return []byte("Access key ID,Secret access key\nAKIAABCDEFGHIJKLMNOP,secret-access-key-value-1234567890\n")
}

func TestFoundationLifecycleClientTokenBindsActionAndApprovedOperation(t *testing.T) {
	spec, err := BuildSpec(SpecInput{AgentInstanceID: "agent-test", Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	image := "repo/reaper:v2.0.0-rc.1@sha256:" + strings.Repeat("b", 64)
	first := foundationStackRequest(spec, image, "template", hash, string(LifecycleUpgrade), "operation-a")
	replay := foundationStackRequest(spec, image, "template", hash, string(LifecycleUpgrade), "operation-a")
	otherOperation := foundationStackRequest(spec, image, "template", hash, string(LifecycleUpgrade), "operation-b")
	otherAction := foundationStackRequest(spec, image, "template", hash, string(LifecycleTeardown), "operation-a")
	if first.ClientToken != replay.ClientToken || first.ClientToken == otherOperation.ClientToken || first.ClientToken == otherAction.ClientToken {
		t.Fatalf("tokens first=%q replay=%q operation=%q action=%q", first.ClientToken, replay.ClientToken, otherOperation.ClientToken, otherAction.ClientToken)
	}
}

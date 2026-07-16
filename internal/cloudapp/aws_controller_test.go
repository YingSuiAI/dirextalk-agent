package cloudapp

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
)

type identityRepositoryStub struct{ value AWSIdentityEvidence }

func (repository *identityRepositoryStub) PutAWSIdentityEvidence(_ context.Context, value AWSIdentityEvidence) error {
	repository.value = value
	return nil
}
func (repository *identityRepositoryStub) GetAWSIdentityEvidence(context.Context, string, uint64) (AWSIdentityEvidence, error) {
	return repository.value, nil
}

type bootstrapFactoryStub struct{ identity awsprovider.CallerIdentity }

func (factory bootstrapFactoryStub) NewBootstrapProvider(_ context.Context, region string, _ *awsprovider.Credentials) (awsprovider.BootstrapProvider, error) {
	identity := factory.identity
	identity.Region = region
	return bootstrapProviderStub{identity: identity}, nil
}

type bootstrapProviderStub struct{ identity awsprovider.CallerIdentity }

func (provider bootstrapProviderStub) GetCallerIdentity(context.Context) (awsprovider.CallerIdentity, error) {
	return provider.identity, nil
}
func (bootstrapProviderStub) EnsureBootstrapIdentity(context.Context, awsprovider.BootstrapIdentitySpec) (awsprovider.SourceCredentials, error) {
	return awsprovider.SourceCredentials{}, nil
}
func (bootstrapProviderStub) CreateFoundationStack(context.Context, awsprovider.FoundationStackRequest) (awsprovider.FoundationStackReceipt, error) {
	return awsprovider.FoundationStackReceipt{}, nil
}

func TestAWSControllerPreviewsEncryptedBootstrapAndPersistsIdentityEvidence(t *testing.T) {
	now := time.Date(2026, time.July, 16, 12, 0, 0, 0, time.UTC)
	instanceID := uuid.NewString()
	callerClientID := "message-server"
	store, keys := secretbootstrap.NewMemoryStore(), secretbootstrap.NewMemoryKeyStore()
	manager, err := secretbootstrap.NewManager(store, keys, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := manager.Create(context.Background(), callerClientID, secretbootstrap.BindingV1{
		AgentInstanceID: instanceID, OwnerID: "owner-a", Purpose: "aws_connection", TargetID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("Access key ID,Secret access key\nAKIAABCDEFGHIJKLMNOP,secret-access-key-value-1234567890\n")
	envelope, err := secretbootstrap.Seal(created.Session, payload, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := manager.Upload(context.Background(), callerClientID, created.Session.SessionID, 1, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	repository := &identityRepositoryStub{}
	controller, err := NewAWSController(instanceID, manager, bootstrapFactoryStub{identity: awsprovider.CallerIdentity{
		Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012",
	}}, repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.PreviewIdentity(context.Background(), "other-project", uploaded.SessionID, uploaded.Revision, "us-east-1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("other-client preview error=%v, want ErrForbidden", err)
	}
	identity, err := controller.PreviewIdentity(context.Background(), callerClientID, uploaded.SessionID, uploaded.Revision, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if identity.AccountID != "123456789012" || !identity.RootIdentity || repository.value.OwnerID != "owner-a" || repository.value.SessionRevision != 2 {
		t.Fatalf("identity=%#v evidence=%#v", identity, repository.value)
	}
	if repository.value.ExpiresAt.After(created.Session.ExpiresAt) || repository.value.Identity.PrincipalARN != identity.PrincipalARN {
		t.Fatal("identity evidence expiry or principal binding changed")
	}
}

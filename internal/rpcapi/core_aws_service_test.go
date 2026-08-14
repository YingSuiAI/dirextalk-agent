package rpcapi

import (
	"context"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type rpcAWSTestSTS struct{}

func (rpcAWSTestSTS) GetCallerIdentity(context.Context, coreaws.CredentialHandle) (coreaws.Identity, error) {
	return coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/test", PrincipalID: "principal"}, nil
}

func newRPCAWSFixture(t *testing.T) (*CoreCloudControlService, context.Context) {
	t.Helper()
	service := coreaws.NewService(coreaws.NewMemoryRepository(), rpcAWSTestSTS{}, nil)
	adapter, err := NewCoreCloudControlService(service)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, context.Background()
}

func TestCoreCloudControlServiceCredentials(t *testing.T) {
	s, ctx := newRPCAWSFixture(t)
	credResp, err := s.CreateCredential(ctx, &agentv1.CoreCloudControlServiceCreateCredentialRequest{IdempotencyKey: "11111111-1111-4111-8111-111111111111", Name: "prod", Region: "us-east-1", AccessKeyId: "AKIA", SecretAccessKey: "super-secret", SessionToken: "session"})
	if err != nil {
		t.Fatal(err)
	}
	if credResp.Credential.GetSecretAccessKeyConfigured() != true || credResp.Credential.GetName() != "prod" {
		t.Fatalf("unexpected credential response: %#v", credResp.Credential)
	}
	if _, ok := interface{}(credResp.Credential).(*agentv1.CoreAWSCredential); !ok {
		t.Fatal("credential response type changed")
	}
}

func TestCoreCloudControlServiceRejectsSecondActiveCredential(t *testing.T) {
	service, ctx := newRPCAWSFixture(t)
	request := func(key, name string) *agentv1.CoreCloudControlServiceCreateCredentialRequest {
		return &agentv1.CoreCloudControlServiceCreateCredentialRequest{IdempotencyKey: key, Name: name, Region: "us-east-1", AccessKeyId: "access", SecretAccessKey: "secret"}
	}
	if _, err := service.CreateCredential(ctx, request("31111111-1111-4111-8111-111111111111", "first")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateCredential(ctx, request("32222222-2222-4222-8222-222222222222", "second")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second active credential code=%s err=%v", status.Code(err), err)
	}
}

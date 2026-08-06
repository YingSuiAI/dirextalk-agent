package rpcapi

import (
	"context"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type rpcAWSTestSTS struct{}

type rpcBlockedCredentialRepository struct{ *coreaws.MemoryRepository }

func (repo *rpcBlockedCredentialRepository) CreateCredentialGuarded(context.Context, coreteam.Scope, coreaws.Credentials) (coreaws.Credentials, error) {
	return coreaws.Credentials{}, coreteam.ErrExecutionActive
}

func (repo *rpcBlockedCredentialRepository) UpdateCredentialGuarded(context.Context, coreteam.Scope, coreaws.Credentials, int64) (coreaws.Credentials, error) {
	return coreaws.Credentials{}, coreteam.ErrExecutionActive
}

func (repo *rpcBlockedCredentialRepository) DeleteCredentialGuarded(context.Context, coreteam.Scope, string, int64) error {
	return coreteam.ErrExecutionActive
}

func (rpcAWSTestSTS) GetCallerIdentity(context.Context, coreaws.CredentialHandle) (coreaws.Identity, error) {
	return coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/test", PrincipalID: "principal"}, nil
}

func newRPCAWSFixture(t *testing.T) (*CoreCloudControlService, context.Context) {
	t.Helper()
	service := coreaws.NewService(coreaws.NewMemoryRepository(), nil, nil, rpcAWSTestSTS{}, coreaws.NewFakeProvider(), nil)
	adapter, err := NewCoreCloudControlService(service)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := coreaws.WithCredentialMutationScope(context.Background(), coreteam.Scope{OwnerID: "@rpc-aws-test:example.test", AccountGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	return adapter, ctx
}

func TestCoreCloudControlServiceTrustedCredentialScope(t *testing.T) {
	service := coreaws.NewService(coreaws.NewMemoryRepository(), nil, nil, rpcAWSTestSTS{}, coreaws.NewFakeProvider(), nil)
	scope := coreteam.Scope{OwnerID: "@rpc-aws-trusted:example.test", AccountGeneration: 7}
	adapter, err := NewCoreCloudControlService(service, scope)
	if err != nil {
		t.Fatal(err)
	}
	created, err := adapter.CreateCredential(context.Background(), &agentv1.CoreCloudControlServiceCreateCredentialRequest{
		IdempotencyKey:  "10111111-1111-4111-8111-111111111111",
		Name:            "trusted",
		Region:          "ap-northeast-3",
		AccessKeyId:     "AKIA-TRUSTED",
		SecretAccessKey: "trusted-secret",
	})
	if err != nil || created.GetCredential().GetName() != "trusted" {
		t.Fatalf("trusted scope create=%#v err=%v", created, err)
	}
	if _, err = NewCoreCloudControlService(service, coreteam.Scope{}); err == nil {
		t.Fatal("constructor accepted an invalid trusted credential scope")
	}
}

func TestCoreCloudControlServiceReturnsExactTeamExecutionActive(t *testing.T) {
	repository := &rpcBlockedCredentialRepository{MemoryRepository: coreaws.NewMemoryRepository()}
	service := coreaws.NewService(repository, nil, nil, rpcAWSTestSTS{}, coreaws.NewFakeProvider(), nil)
	adapter, err := NewCoreCloudControlService(service, coreteam.Scope{OwnerID: "@rpc-aws-blocked:example.test", AccountGeneration: 2})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.CreateCredential(context.Background(), &agentv1.CoreCloudControlServiceCreateCredentialRequest{
		IdempotencyKey: "11111111-2222-4222-8222-222222222222",
		Name:           "blocked", Region: "ap-northeast-3", AccessKeyId: "AKIA-BLOCKED", SecretAccessKey: "blocked-secret",
	})
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != coreteam.ErrorCodeTeamExecutionActive {
		t.Fatalf("RPC status=%s message=%q", status.Code(err), status.Convert(err).Message())
	}
}

func TestCoreCloudControlServiceCredentialsAndPlan(t *testing.T) {
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
	planResp, err := s.CreatePlan(ctx, &agentv1.CoreCloudControlServiceCreatePlanRequest{IdempotencyKey: "22222222-2222-4222-8222-222222222222", CredentialId: credResp.Credential.GetCredentialId(), StackName: "demo", Operation: agentv1.CoreAWSOperation_CORE_AWS_OPERATION_CREATE, Template: []byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := s.Quote(ctx, &agentv1.CoreCloudControlServiceQuoteRequest{PlanId: planResp.Plan.GetPlanId()})
	if err != nil || quote.Quote.GetPlanDigest() == "" {
		t.Fatalf("quote: %#v %v", quote, err)
	}
	identity, err := s.TestCredentialIdentity(ctx, &agentv1.CoreCloudControlServiceTestCredentialIdentityRequest{CredentialId: credResp.Credential.GetCredentialId()})
	if err != nil || identity.GetAccountId() != "123456789012" {
		t.Fatalf("identity: %#v %v", identity, err)
	}
}

func TestCoreCloudControlServiceChangeReadsSurviveServiceRecreation(t *testing.T) {
	ctx, err := coreaws.WithCredentialMutationScope(context.Background(), coreteam.Scope{OwnerID: "@rpc-aws-restart:example.test", AccountGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	repo := coreaws.NewMemoryRepository()
	newService := func() *coreaws.Service {
		return coreaws.NewService(repo, nil, nil, rpcAWSTestSTS{}, coreaws.NewFakeProvider(), nil)
	}
	first, err := NewCoreCloudControlService(newService())
	if err != nil {
		t.Fatal(err)
	}
	cred, err := first.CreateCredential(ctx, &agentv1.CoreCloudControlServiceCreateCredentialRequest{IdempotencyKey: "41111111-1111-4111-8111-111111111111", Name: "prod", Region: "us-east-1", AccessKeyId: "a", SecretAccessKey: "b"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := first.CreatePlan(ctx, &agentv1.CoreCloudControlServiceCreatePlanRequest{IdempotencyKey: "42222222-2222-4222-8222-222222222222", CredentialId: cred.Credential.GetCredentialId(), StackName: "demo", Operation: agentv1.CoreAWSOperation_CORE_AWS_OPERATION_CREATE, Template: []byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	requested, err := first.RequestChange(ctx, &agentv1.CoreCloudControlServiceRequestChangeRequest{IdempotencyKey: "43333333-3333-4333-8333-333333333333", PlanId: plan.Plan.GetPlanId()})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a worker-owned durable stage transition before the RPC service
	// is recreated; the read surface must observe the persisted revision.
	stored, err := repo.GetChange(ctx, requested.Change.GetChangeId())
	if err != nil {
		t.Fatal(err)
	}
	stored.Status, stored.Stage, stored.Revision = coreaws.ChangeRunning, coreaws.StageExecuting, stored.Revision+1
	if _, err = repo.UpdateChange(ctx, stored, stored.Revision-1); err != nil {
		t.Fatal(err)
	}
	second, err := NewCoreCloudControlService(newService())
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.GetChange(ctx, &agentv1.CoreCloudControlServiceGetChangeRequest{ChangeId: requested.Change.GetChangeId()})
	if err != nil || got.Change.GetChangeId() != requested.Change.GetChangeId() || got.Change.GetStatus() != string(coreaws.ChangeRunning) {
		t.Fatalf("recreated service get: %#v %v", got, err)
	}
	listed, err := second.ListChanges(ctx, &agentv1.CoreCloudControlServiceListChangesRequest{PageSize: 10})
	if err != nil || len(listed.GetChanges()) != 1 || listed.Changes[0].GetChangeId() != requested.Change.GetChangeId() {
		t.Fatalf("recreated service list: %#v %v", listed, err)
	}
}

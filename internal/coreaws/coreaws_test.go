package coreaws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
)

func credentialTestContext() context.Context {
	ctx, err := WithCredentialMutationScope(context.Background(), coreteam.Scope{OwnerID: "@coreaws-test:example.test", AccountGeneration: 1})
	if err != nil {
		panic(err)
	}
	return ctx
}

func credentialContextFor(scope coreteam.Scope) context.Context {
	ctx, err := WithCredentialMutationScope(context.Background(), scope)
	if err != nil {
		panic(err)
	}
	return ctx
}

func TestCredentialViewRedactsSecrets(t *testing.T) {
	c := Credentials{ID: "11111111-1111-4111-8111-111111111111", Name: "prod", Region: "us-east-1", private: &credentialPayload{accessKeyID: "AKIA", secretAccessKey: "secret", sessionToken: "token"}, Revision: 1}
	v := c.View()
	if !v.HasAccessKey || !v.HasSecretKey || !v.HasSessionToken {
		t.Fatal("configured flags missing")
	}
	b, _ := json.Marshal(c)
	out := string(b) + fmt.Sprintf("%v %#+v %v", c, c, c)
	if bytes.Contains([]byte(out), []byte("secret")) || bytes.Contains([]byte(out), []byte("token")) {
		t.Fatalf("secret leaked: %s", out)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("credential", "value", c)
	if bytes.Contains(buf.Bytes(), []byte("secret")) {
		t.Fatal("slog leaked secret")
	}
	if d := canonicalDigest(c); strings.Contains(d, "secret") {
		t.Fatal("digest leaked secret")
	}
}

type teamCredentialMutationRepository struct {
	*MemoryRepository
	scopes []coreteam.Scope
}

func (repo *teamCredentialMutationRepository) CreateCredentialGuarded(ctx context.Context, scope coreteam.Scope, credential Credentials) (Credentials, error) {
	repo.scopes = append(repo.scopes, scope)
	return repo.MemoryRepository.CreateCredentialGuarded(ctx, scope, credential)
}

func (repo *teamCredentialMutationRepository) UpdateCredentialGuarded(ctx context.Context, scope coreteam.Scope, credential Credentials, expected int64) (Credentials, error) {
	repo.scopes = append(repo.scopes, scope)
	return repo.MemoryRepository.UpdateCredentialGuarded(ctx, scope, credential, expected)
}

func (repo *teamCredentialMutationRepository) DeleteCredentialGuarded(ctx context.Context, scope coreteam.Scope, id string, expected int64) error {
	repo.scopes = append(repo.scopes, scope)
	return repo.MemoryRepository.DeleteCredentialGuarded(ctx, scope, id, expected)
}

func TestTeamCredentialMutationsRequireAuthenticatedScope(t *testing.T) {
	repository := &teamCredentialMutationRepository{MemoryRepository: NewMemoryRepository()}
	service := NewService(repository, nil, nil, nil, nil, nil)
	input := CredentialInput{
		ID: "61111111-1111-4111-8111-111111111111", Name: "team", Region: "us-east-1",
		AccessKeyID: "AKIA-TEAM", SecretAccessKey: "team-secret", IdempotencyKey: "62222222-2222-4222-8222-222222222222",
	}
	if _, err := service.SaveCredential(context.Background(), input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unscoped create err=%v", err)
	}
	scope := coreteam.Scope{OwnerID: "@team-credential:example.test", AccountGeneration: 9}
	ctx, err := WithCredentialMutationScope(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.SaveCredential(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	replacement := CredentialInput{
		ID: created.ID, Name: created.Name, Region: created.Region,
		AccessKeyID: "AKIA-REPLACED", SecretAccessKey: "replaced-secret",
	}
	if _, err = service.ReplaceCredential(ctx, replacement, created.Revision, "63333333-3333-4333-8333-333333333333"); err != nil {
		t.Fatal(err)
	}
	if err = service.DeleteCredential(ctx, created.ID, created.Revision+1, "64444444-4444-4444-8444-444444444444"); err != nil {
		t.Fatal(err)
	}
	if len(repository.scopes) != 3 {
		t.Fatalf("guarded mutation calls=%d", len(repository.scopes))
	}
	for _, got := range repository.scopes {
		if got != scope {
			t.Fatalf("mutation scope=%#v want=%#v", got, scope)
		}
	}
	if _, err = WithCredentialMutationScope(context.Background(), coreteam.Scope{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid scope err=%v", err)
	}
}

func TestCoreAWSUserSurfaceRejectsForeignOwnerGeneration(t *testing.T) {
	repository := NewMemoryRepository()
	sts := &FakeSTSProvider{Identity: Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/owner"}}
	service := NewService(repository, nil, nil, sts, NewFakeProvider(), nil)
	owner := coreteam.Scope{OwnerID: "@aws-owner:example.test", AccountGeneration: 3}
	foreign := coreteam.Scope{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration + 1}
	ownerContext := credentialContextFor(owner)
	foreignContext := credentialContextFor(foreign)
	credential, err := service.SaveCredential(ownerContext, CredentialInput{
		Name: "owner", Region: "us-east-1", AccessKeyID: "AKIA-OWNER", SecretAccessKey: "owner-secret", IdempotencyKey: newUUID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.GetCredential(foreignContext, credential.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign credential read err=%v", err)
	}
	if page, listErr := service.ListCredentials(foreignContext, 20, ""); listErr != nil || len(page.Items) != 0 {
		t.Fatalf("foreign credential list=%#v err=%v", page, listErr)
	}
	if _, err = service.TestCredential(foreignContext, credential.ID); !errors.Is(err, ErrNotFound) || sts.Calls != 0 {
		t.Fatalf("foreign STS test err=%v calls=%d", err, sts.Calls)
	}
	if _, err = service.CreatePlan(foreignContext, PlanInput{CredentialID: credential.ID, StackName: "foreign", Operation: OperationCreate, Template: []byte(`{"Resources":{}}`), IdempotencyKey: newUUID()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign Plan creation err=%v", err)
	}
	if err = service.DeleteCredential(foreignContext, credential.ID, credential.Revision, newUUID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign credential delete err=%v", err)
	}
	plan, err := service.CreatePlan(ownerContext, PlanInput{CredentialID: credential.ID, StackName: "owner", Operation: OperationCreate, Template: []byte(`{"Resources":{}}`), IdempotencyKey: newUUID()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.GetPlan(foreignContext, plan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign Plan read err=%v", err)
	}
	requested, err := service.RequestChange(ownerContext, RequestChangeInput{PlanID: plan.ID, IdempotencyKey: newUUID()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.GetChange(foreignContext, requested.Change.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign Change read err=%v", err)
	}
	if _, err = service.RequestChange(foreignContext, RequestChangeInput{PlanID: plan.ID, IdempotencyKey: newUUID()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign Change request err=%v", err)
	}
}

func TestMemoryRequestChangeReplayIsOwnerGenerationScoped(t *testing.T) {
	repository := NewMemoryRepository()
	sts := &FakeSTSProvider{Identity: Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/scoped-replay"}}
	service := NewService(repository, nil, nil, sts, NewFakeProvider(), nil)
	credentialKey, replaceKey, deleteKey := newUUID(), newUUID(), newUUID()
	planKey, requestKey := newUUID(), newUUID()

	var changeIDs []string
	for index, scope := range []coreteam.Scope{
		{OwnerID: "@memory-request-a:example.test", AccountGeneration: 1},
		{OwnerID: "@memory-request-b:example.test", AccountGeneration: 8},
	} {
		ctx := credentialContextFor(scope)
		credential, err := service.SaveCredential(ctx, CredentialInput{
			Name: fmt.Sprintf("owner-%d", index), Region: "us-east-1",
			AccessKeyID: "AKIA-SCOPED", SecretAccessKey: "scoped-secret", IdempotencyKey: credentialKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		replaced, err := service.ReplaceCredential(ctx, CredentialInput{
			ID: credential.ID, Name: credential.Name, Region: credential.Region,
			AccessKeyID: "AKIA-SCOPED-REPLACED", SecretAccessKey: "scoped-replaced",
		}, credential.Revision, replaceKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = service.TestCredential(ctx, replaced.ID); err != nil {
			t.Fatal(err)
		}
		deletable, err := service.SaveCredential(ctx, CredentialInput{
			Name: fmt.Sprintf("delete-%d", index), Region: "us-east-1",
			AccessKeyID: "AKIA-DELETE", SecretAccessKey: "delete-secret", IdempotencyKey: newUUID(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = service.DeleteCredential(ctx, deletable.ID, deletable.Revision, deleteKey); err != nil {
			t.Fatal(err)
		}
		plan, err := service.CreatePlan(ctx, PlanInput{
			CredentialID: replaced.ID, StackName: fmt.Sprintf("memory-replay-%d", index),
			Operation: OperationCreate, Template: []byte(`{"Resources":{}}`), IdempotencyKey: planKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		requested, err := service.RequestChange(ctx, RequestChangeInput{PlanID: plan.ID, IdempotencyKey: requestKey})
		if err != nil {
			t.Fatalf("scope %d request: %v", index, err)
		}
		replayed, err := service.RequestChange(ctx, RequestChangeInput{PlanID: plan.ID, IdempotencyKey: requestKey})
		if err != nil || replayed.Change.ID != requested.Change.ID {
			t.Fatalf("scope %d replay=%#v err=%v", index, replayed, err)
		}
		changeIDs = append(changeIDs, requested.Change.ID)
	}
	if changeIDs[0] == changeIDs[1] {
		t.Fatalf("cross-owner requests shared one Change: %v", changeIDs)
	}
}

func TestFakeProviderTypedIdempotencyAndProgress(t *testing.T) {
	f := NewFakeProvider()
	req := ChangeSetRequest{Region: "us-east-1", StackName: "demo", ChangeSetName: "c1", ClientToken: "11111111-1111-4111-8111-111111111111", Operation: OperationCreate, Template: []byte("{}")}
	cs, e := f.CreateChangeSet(context.Background(), CredentialHandle{Region: req.Region}, req)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := f.CreateChangeSet(context.Background(), CredentialHandle{Region: req.Region}, req)
	if e != nil || replay.ID != cs.ID {
		t.Fatalf("replay: %v", e)
	}
	if e = f.ExecuteChangeSet(context.Background(), CredentialHandle{Region: req.Region}, req.Region, req.StackName, cs.ID, req.ClientToken); e != nil {
		t.Fatal(e)
	}
	s, e := f.DescribeStack(context.Background(), CredentialHandle{Region: req.Region}, req.Region, req.StackName)
	if e != nil || s.Status != "CREATE_COMPLETE" {
		t.Fatalf("stack: %#v %v", s, e)
	}
	changed := req
	changed.Template = []byte("{\"changed\":true}")
	if _, e = f.CreateChangeSet(context.Background(), CredentialHandle{Region: changed.Region}, changed); !errors.Is(e, ErrIdempotencyConflict) {
		t.Fatalf("changed token scope accepted: %v", e)
	}
}

type testConfirm struct{ c coreconfirmation.Confirmation }

func (x *testConfirm) Request(_ context.Context, cmd coreconfirmation.RequestCommand) (coreconfirmation.Confirmation, error) {
	x.c = coreconfirmation.Confirmation{ConfirmationID: "22222222-2222-4222-8222-222222222222", Binding: cmd.Binding, TaskID: cmd.TaskID, State: coreconfirmation.StatePending, Revision: 1}
	return x.c, nil
}
func (x *testConfirm) Get(_ context.Context, id string) (coreconfirmation.Confirmation, error) {
	if id != x.c.ConfirmationID {
		return coreconfirmation.Confirmation{}, ErrNotFound
	}
	return x.c, nil
}

type testTasks struct{}

func (testTasks) CreateWaitingUser(_ context.Context, r TaskCreateRequest) (Task, error) {
	return Task{ID: "33333333-3333-4333-8333-333333333333", Status: "waiting_user", Revision: 1, PlanID: r.PlanID}, nil
}
func (testTasks) Queue(context.Context, string) error                { return nil }
func (testTasks) Fail(context.Context, string, string, string) error { return nil }

func TestServiceRejectsUnconfirmedMutation(t *testing.T) {
	r := NewMemoryRepository()
	now := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	s := NewService(r, &testConfirm{}, testTasks{}, nil, NewFakeProvider(), now)
	cred, _ := s.SaveCredential(credentialTestContext(), CredentialInput{Name: "x", Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"})
	p, _ := s.CreatePlan(credentialTestContext(), PlanInput{CredentialID: cred.ID, StackName: "demo", Operation: OperationCreate, Template: []byte(`{"Resources":{"X":{"Type":"AWS::S3::Bucket"}}}`)})
	out, e := s.RequestChange(credentialTestContext(), RequestChangeInput{PlanID: p.ID, IdempotencyKey: "44444444-4444-4444-8444-444444444444"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ExecuteChange(context.Background(), out.Confirmation.ConfirmationID); !errors.Is(e, ErrUnconfirmed) {
		t.Fatalf("got %v", e)
	}
	if n := s.provider.(*FakeProvider).UnconfirmedMutationCalls(); n != 0 {
		t.Fatalf("unconfirmed calls=%d", n)
	}
}

func TestRequestChangeConcurrentReplay(t *testing.T) {
	r := NewMemoryRepository()
	now := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	conf := &testConfirm{}
	s := NewService(r, conf, testTasks{}, nil, NewFakeProvider(), now)
	cred, _ := s.SaveCredential(credentialTestContext(), CredentialInput{Name: "x", Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"})
	p, _ := s.CreatePlan(credentialTestContext(), PlanInput{CredentialID: cred.ID, StackName: "demo", Operation: OperationCreate, Template: []byte(`{"Resources":{"X":{"Type":"AWS::S3::Bucket"}}}`)})
	input := RequestChangeInput{PlanID: p.ID, IdempotencyKey: "55555555-5555-4555-8555-555555555555"}
	var wg sync.WaitGroup
	results := make([]ChangeRequestResult, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i], errs[i] = s.RequestChange(credentialTestContext(), input) }(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].Confirmation.ConfirmationID != results[1].Confirmation.ConfirmationID || results[0].Change.ID != results[1].Change.ID {
		t.Fatalf("replay mismatch: %#v %#v", errs, results)
	}
}

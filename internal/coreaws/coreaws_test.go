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
)

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
	cred, _ := s.SaveCredential(context.Background(), CredentialInput{Name: "x", Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"})
	p, _ := s.CreatePlan(context.Background(), PlanInput{CredentialID: cred.ID, StackName: "demo", Operation: OperationCreate, Template: []byte(`{"Resources":{"X":{"Type":"AWS::S3::Bucket"}}}`)})
	out, e := s.RequestChange(context.Background(), RequestChangeInput{PlanID: p.ID, IdempotencyKey: "44444444-4444-4444-8444-444444444444"})
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
	cred, _ := s.SaveCredential(context.Background(), CredentialInput{Name: "x", Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"})
	p, _ := s.CreatePlan(context.Background(), PlanInput{CredentialID: cred.ID, StackName: "demo", Operation: OperationCreate, Template: []byte(`{"Resources":{"X":{"Type":"AWS::S3::Bucket"}}}`)})
	input := RequestChangeInput{PlanID: p.ID, IdempotencyKey: "55555555-5555-4555-8555-555555555555"}
	var wg sync.WaitGroup
	results := make([]ChangeRequestResult, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i], errs[i] = s.RequestChange(context.Background(), input) }(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].Confirmation.ConfirmationID != results[1].Confirmation.ConfirmationID || results[0].Change.ID != results[1].Change.ID {
		t.Fatalf("replay mismatch: %#v %#v", errs, results)
	}
}

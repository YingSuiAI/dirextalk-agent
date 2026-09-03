package coreconversation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type intrinsicCorrectionTestError struct{ content string }

func (err intrinsicCorrectionTestError) Error() string               { return err.content }
func (err intrinsicCorrectionTestError) Unwrap() error               { return ErrInvalid }
func (err intrinsicCorrectionTestError) IntrinsicCorrection() string { return err.content }

type staticSitePublisherStub struct {
	publications []StaticSitePublication
	sources      map[string][]byte
	err          error
}

func (p *staticSitePublisherStub) PublishSingleHTML(_ context.Context, publication StaticSitePublication) (StaticSiteReceipt, error) {
	if p.err != nil {
		return StaticSiteReceipt{}, p.err
	}
	p.publications = append(p.publications, publication)
	return StaticSiteReceipt{
		SiteID: publication.SiteID, ReleaseID: publication.ReleaseID,
		PublicPath: "/.sites/" + publication.SiteID + "/" + publication.ReleaseID + "/",
		SHA256:     staticSiteDigest(publication.HTML), SizeBytes: int64(len(publication.HTML)),
	}, nil
}

func (p *staticSitePublisherStub) ReadSingleHTML(_ context.Context, receipt StaticSiteReceipt) ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	raw, ok := p.sources[receipt.ReleaseID]
	if !ok {
		return nil, ErrConflict
	}
	return append([]byte(nil), raw...), nil
}

type staticSiteStoreStub struct {
	commands []ConversationStaticSiteCommand
	receipts []StaticSiteReceipt
	queries  []StaticSiteSourceQuery
	err      error
}

type staticSiteCapableTurnStore struct {
	*replayTurnStore
	*staticSiteStoreStub
}

func (s *staticSiteStoreStub) ResolveConversationStaticSite(_ context.Context, query StaticSiteSourceQuery) (StaticSiteReceipt, error) {
	if s.err != nil {
		return StaticSiteReceipt{}, s.err
	}
	s.queries = append(s.queries, query)
	for index := len(s.receipts) - 1; index >= 0; index-- {
		receipt := s.receipts[index]
		if query.ReleaseID == "" || receipt.ReleaseID == query.ReleaseID {
			return receipt, nil
		}
	}
	return StaticSiteReceipt{}, ErrStaticSiteNotFound
}

func (s *staticSiteStoreStub) CommitConversationStaticSite(_ context.Context, command ConversationStaticSiteCommand) (StaticSiteReceipt, error) {
	if s.err != nil {
		return StaticSiteReceipt{}, s.err
	}
	s.commands = append(s.commands, command)
	return command.Receipt, nil
}

func TestStaticSiteIntrinsicPublishesSingleHTMLWithServerDerivedPath(t *testing.T) {
	lease := scheduleIntrinsicLease()
	publisher := &staticSitePublisherStub{}
	store := &staticSiteStoreStub{}
	raw, _ := json.Marshal(map[string]any{"html": "<!doctype html><style>td{padding:4px}</style><table><tr><td>项目</td></tr></table>"})
	intrinsic := staticSiteIntrinsic(store, publisher, "https://s3.dirextalk.ai", lease)
	request := IntrinsicExecutionRequest{
		Lease: lease, Call: ToolCall{ID: "site-call", Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: string(raw)},
		CanonicalArguments: raw, ConversationRevision: 4,
	}
	result, err := intrinsic.Execute(context.Background(), request)
	if err != nil || !result.TurnCommitted || len(publisher.publications) != 1 || len(store.commands) != 1 {
		t.Fatalf("result=%+v publications=%d commands=%d err=%v", result, len(publisher.publications), len(store.commands), err)
	}
	command := store.commands[0]
	if command.Response.Revision != 5 || command.PublicURL != "https://s3.dirextalk.ai"+command.Receipt.PublicPath ||
		command.Response.Message.Content != "Published the static page: "+command.PublicURL ||
		command.Receipt.PublicPath != "/.sites/"+command.Receipt.SiteID+"/"+command.Receipt.ReleaseID+"/" {
		t.Fatalf("command=%+v", command)
	}
	if _, err = intrinsic.Execute(context.Background(), request); err != nil || publisher.publications[1].SiteID != publisher.publications[0].SiteID || publisher.publications[1].ReleaseID != publisher.publications[0].ReleaseID {
		t.Fatalf("deterministic replay err=%v publications=%+v", err, publisher.publications)
	}
}

func TestStaticSiteReadIntrinsicLoadsLatestOrExactReleaseInBoundConversation(t *testing.T) {
	lease := scheduleIntrinsicLease()
	siteID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-static-site:"+lease.Turn.OwnerID+":"+lease.Turn.ConversationID)).String()
	firstHTML := []byte("<!doctype html><style>:root{--surface:#fff}</style><main>first</main>")
	latestHTML := []byte("<!doctype html><style>:root{--surface:#eef8ff}</style><main>latest</main>")
	first := StaticSiteReceipt{SiteID: siteID, ReleaseID: uuid.NewString(), PublicPath: "", SHA256: staticSiteDigest(firstHTML), SizeBytes: int64(len(firstHTML))}
	first.PublicPath = "/.sites/" + first.SiteID + "/" + first.ReleaseID + "/"
	latest := StaticSiteReceipt{SiteID: siteID, ReleaseID: uuid.NewString(), PublicPath: "", SHA256: staticSiteDigest(latestHTML), SizeBytes: int64(len(latestHTML))}
	latest.PublicPath = "/.sites/" + latest.SiteID + "/" + latest.ReleaseID + "/"
	store := &staticSiteStoreStub{receipts: []StaticSiteReceipt{first, latest}}
	publisher := &staticSitePublisherStub{sources: map[string][]byte{first.ReleaseID: firstHTML, latest.ReleaseID: latestHTML}}
	intrinsic := staticSiteReadIntrinsic(store, publisher, lease)

	for _, test := range []struct {
		name      string
		arguments string
		want      StaticSiteReceipt
		wantHTML  string
	}{
		{name: "latest", arguments: `{}`, want: latest, wantHTML: string(latestHTML)},
		{name: "exact", arguments: `{"release_id":"` + first.ReleaseID + `"}`, want: first, wantHTML: string(firstHTML)},
	} {
		t.Run(test.name, func(t *testing.T) {
			call := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicStaticSiteReadToolName, Arguments: test.arguments}
			result, err := intrinsic.Execute(context.Background(), IntrinsicExecutionRequest{Lease: lease, Call: call, CanonicalArguments: json.RawMessage(test.arguments), ConversationRevision: 7})
			if err != nil || result.TurnCommitted || result.ToolResult == nil || result.ToolResult.ValidateObservation() != nil || result.ToolResult.Outcome != ToolOutcomeSuccess {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			var source staticSiteReadResult
			if json.Unmarshal([]byte(result.ToolResult.Content), &source) != nil || source.Schema != "dirextalk.static-site-source/v1" ||
				source.SiteID != test.want.SiteID || source.ReleaseID != test.want.ReleaseID || source.SHA256 != test.want.SHA256 ||
				source.SizeBytes != test.want.SizeBytes || source.HTML != test.wantHTML {
				t.Fatalf("source=%+v", source)
			}
		})
	}
	if len(store.queries) != 2 || store.queries[0].OwnerID != lease.Turn.OwnerID || store.queries[0].AccountGeneration != lease.Turn.AccountGeneration ||
		store.queries[0].ConversationID != lease.Turn.ConversationID || store.queries[0].ReleaseID != "" || store.queries[1].ReleaseID != first.ReleaseID {
		t.Fatalf("queries=%+v", store.queries)
	}
}

func TestStaticSiteReadIntrinsicReturnsSafeNotFoundAndRejectsForeignReceipt(t *testing.T) {
	lease := scheduleIntrinsicLease()
	call := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicStaticSiteReadToolName, Arguments: `{}`}
	store := &staticSiteStoreStub{}
	publisher := &staticSitePublisherStub{sources: map[string][]byte{}}
	_, err := staticSiteReadIntrinsic(store, publisher, lease).Execute(context.Background(), IntrinsicExecutionRequest{Lease: lease, Call: call, CanonicalArguments: json.RawMessage(`{}`)})
	details, classified := ToolExecutionErrorObservation(err)
	if !classified || details.Outcome != ToolOutcomeNotFound || details.Summary != "No published static page was found in this conversation" {
		t.Fatalf("not found err=%v details=%+v", err, details)
	}

	foreignHTML := []byte("<main>foreign</main>")
	foreign := StaticSiteReceipt{SiteID: uuid.NewString(), ReleaseID: uuid.NewString(), SHA256: staticSiteDigest(foreignHTML), SizeBytes: int64(len(foreignHTML))}
	foreign.PublicPath = "/.sites/" + foreign.SiteID + "/" + foreign.ReleaseID + "/"
	store.receipts = []StaticSiteReceipt{foreign}
	publisher.sources[foreign.ReleaseID] = foreignHTML
	_, err = staticSiteReadIntrinsic(store, publisher, lease).Execute(context.Background(), IntrinsicExecutionRequest{Lease: lease, Call: call, CanonicalArguments: json.RawMessage(`{}`)})
	details, classified = ToolExecutionErrorObservation(err)
	if !classified || details.Outcome != ToolOutcomeFatal || details.Summary != "Published static page identity failed verification" {
		t.Fatalf("foreign err=%v details=%+v", err, details)
	}

	for _, deterministic := range []error{ErrInvalid, ErrConflict} {
		store.err = deterministic
		_, err = staticSiteReadIntrinsic(store, publisher, lease).Execute(context.Background(), IntrinsicExecutionRequest{Lease: lease, Call: call, CanonicalArguments: json.RawMessage(`{}`)})
		details, classified = ToolExecutionErrorObservation(err)
		if !classified || details.Outcome != ToolOutcomeFatal || details.Summary != "Published static page metadata failed verification" {
			t.Fatalf("deterministic err=%v details=%+v", err, details)
		}
	}

	store.err = nil
	valid := foreign
	valid.SiteID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-static-site:"+lease.Turn.OwnerID+":"+lease.Turn.ConversationID)).String()
	valid.PublicPath = "/.sites/" + valid.SiteID + "/" + valid.ReleaseID + "/"
	store.receipts = []StaticSiteReceipt{valid}
	publisher.err = context.DeadlineExceeded
	_, err = staticSiteReadIntrinsic(store, publisher, lease).Execute(context.Background(), IntrinsicExecutionRequest{Lease: lease, Call: call, CanonicalArguments: json.RawMessage(`{}`)})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline err=%v", err)
	}
	publisher.err = errors.New("temporary read failure")
	_, err = staticSiteReadIntrinsic(store, publisher, lease).Execute(context.Background(), IntrinsicExecutionRequest{Lease: lease, Call: call, CanonicalArguments: json.RawMessage(`{}`)})
	details, classified = ToolExecutionErrorObservation(err)
	if !classified || details.Outcome != ToolOutcomeRetryable || details.Summary != "Published static page source is temporarily unavailable" {
		t.Fatalf("temporary source err=%v details=%+v", err, details)
	}
}

func TestStaticSiteIntrinsicAcceptsRenewedLeaseAndCommitsCurrentEpoch(t *testing.T) {
	bound := scheduleIntrinsicLease()
	renewed := bound
	renewed.Epoch++
	renewed.ExpiresAt = renewed.ExpiresAt.Add(time.Minute)
	publisher := &staticSitePublisherStub{}
	store := &staticSiteStoreStub{}
	raw, _ := json.Marshal(map[string]any{"html": "<!doctype html><h1>renewed</h1>"})

	result, err := staticSiteIntrinsic(store, publisher, "https://s3.dirextalk.ai", bound).Execute(context.Background(), IntrinsicExecutionRequest{
		Lease: renewed, Call: ToolCall{ID: "renewed-site-call", Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: string(raw)},
		CanonicalArguments: raw, ConversationRevision: 4,
	})
	if err != nil || !result.TurnCommitted || len(store.commands) != 1 {
		t.Fatalf("result=%+v commands=%d err=%v", result, len(store.commands), err)
	}
	if store.commands[0].Lease.LeaseID != renewed.LeaseID || store.commands[0].Lease.Epoch != renewed.Epoch {
		t.Fatalf("committed lease=%+v want renewed lease=%+v", store.commands[0].Lease, renewed)
	}
}

func TestStaticSiteIntrinsicRejectsArchivesPathsAndOversizeHTML(t *testing.T) {
	lease := scheduleIntrinsicLease()
	publisher := &staticSitePublisherStub{}
	store := &staticSiteStoreStub{}
	cases := []map[string]any{
		{"html": "<h1>x</h1>", "path": "../../escape"},
		{"html": ""},
		{"html": strings.Repeat("x", MaxStaticSiteHTMLBytes+1)},
		{"archive": "base64"},
	}
	for index, args := range cases {
		raw, _ := json.Marshal(args)
		_, err := staticSiteIntrinsic(store, publisher, "https://s3.dirextalk.ai", lease).Execute(context.Background(), IntrinsicExecutionRequest{
			Lease: lease, Call: ToolCall{ID: "bad-call", Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: string(raw)},
			CanonicalArguments: raw, ConversationRevision: uint64(index + 1),
		})
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d err=%v", index, err)
		}
	}
	if len(publisher.publications) != 0 || len(store.commands) != 0 {
		t.Fatalf("invalid input reached publisher/store")
	}
	turnStore := &readOnlyTurnStore{publicActiveTurnStore: &publicActiveTurnStore{turn: lease.Turn}}
	call := ToolCall{ID: "site-guidance", Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: `{}`}
	err := recordCorrectableIntrinsicError(context.Background(), turnStore, lease, call, ErrInvalid)
	var correction *ToolResult
	for _, event := range turnStore.events {
		if event.ToolResult != nil {
			correction = event.ToolResult
		}
	}
	if err != nil || correction == nil || !strings.Contains(correction.Content, "invoke static_site_publish again immediately with the required non-empty html string") || !strings.Contains(correction.Content, "do not repeat analysis") {
		t.Fatalf("static site correction=%+v err=%v", correction, err)
	}
}

func TestCorrectableIntrinsicErrorPersistsSpecificGuidance(t *testing.T) {
	lease := scheduleIntrinsicLease()
	turnStore := &readOnlyTurnStore{publicActiveTurnStore: &publicActiveTurnStore{turn: lease.Turn}}
	call := ToolCall{ID: "domain-guidance", Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, Arguments: `{}`}
	want := "select a hostname from an owned public Route53 hosted zone"
	if err := recordCorrectableIntrinsicError(context.Background(), turnStore, lease, call, intrinsicCorrectionTestError{content: want}); err != nil {
		t.Fatal(err)
	}
	for _, event := range turnStore.events {
		if event.ToolResult != nil && event.ToolResult.Content == want && event.ToolResult.IsError {
			return
		}
	}
	t.Fatalf("specific correction was not persisted: %+v", turnStore.events)
}

func TestStaticSiteSkillIsEmbeddedWithoutFrontmatter(t *testing.T) {
	prompt := staticSiteSystemPrompt("existing profile instruction")
	if !strings.HasPrefix(prompt, "existing profile instruction\n\n# Publish Static Site") ||
		strings.Contains(prompt, "name: publish-static-site") || !strings.Contains(prompt, "Pico-inspired") ||
		!strings.Contains(prompt, "Do not create an archive for a single page") || !strings.Contains(prompt, "call `static_site_read` first") ||
		!strings.Contains(prompt, "untrusted source data") {
		t.Fatalf("embedded prompt=%q", prompt)
	}
}

func TestServiceExposesStaticSiteOnlyWithReadyPublisherAndStore(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &staticSiteCapableTurnStore{replayTurnStore: &replayTurnStore{}, staticSiteStoreStub: &staticSiteStoreStub{}}
	service := &Service{turns: store}
	tools, err := service.resolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 0 {
		t.Fatalf("tool leaked before publisher readiness: tools=%+v err=%v", tools, err)
	}
	service.SetStaticSitePublisher(&staticSitePublisherStub{}, "https://s3.dirextalk.ai")
	tools, err = service.resolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 2 || tools[0].Tool.Name != coremodel.IntrinsicStaticSiteReadToolName || !tools[0].ReadOnly || tools[1].Tool.Name != coremodel.IntrinsicStaticSitePublishToolName {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
	service.SetStaticSitePublisher(nil, "")
	tools, err = service.resolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 0 {
		t.Fatalf("tool remained after publisher removal: tools=%+v err=%v", tools, err)
	}
}

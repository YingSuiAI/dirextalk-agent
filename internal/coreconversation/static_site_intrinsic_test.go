package coreconversation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

type staticSitePublisherStub struct {
	publications []StaticSitePublication
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

type staticSiteStoreStub struct {
	commands []ConversationStaticSiteCommand
	err      error
}

type staticSiteCapableTurnStore struct {
	*replayTurnStore
	*staticSiteStoreStub
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
	intrinsic := staticSiteIntrinsic(store, publisher, lease)
	request := IntrinsicExecutionRequest{
		Lease: lease, Call: ToolCall{ID: "site-call", Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: string(raw)},
		CanonicalArguments: raw, ConversationRevision: 4,
	}
	result, err := intrinsic.Execute(context.Background(), request)
	if err != nil || !result.TurnCommitted || len(publisher.publications) != 1 || len(store.commands) != 1 {
		t.Fatalf("result=%+v publications=%d commands=%d err=%v", result, len(publisher.publications), len(store.commands), err)
	}
	command := store.commands[0]
	if command.Response.Revision != 5 || !strings.Contains(command.Response.Message.Content, command.Receipt.PublicPath) ||
		command.Receipt.PublicPath != "/.sites/"+command.Receipt.SiteID+"/"+command.Receipt.ReleaseID+"/" {
		t.Fatalf("command=%+v", command)
	}
	if _, err = intrinsic.Execute(context.Background(), request); err != nil || publisher.publications[1].SiteID != publisher.publications[0].SiteID || publisher.publications[1].ReleaseID != publisher.publications[0].ReleaseID {
		t.Fatalf("deterministic replay err=%v publications=%+v", err, publisher.publications)
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

	result, err := staticSiteIntrinsic(store, publisher, bound).Execute(context.Background(), IntrinsicExecutionRequest{
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
		_, err := staticSiteIntrinsic(store, publisher, lease).Execute(context.Background(), IntrinsicExecutionRequest{
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
}

func TestStaticSiteSkillIsEmbeddedWithoutFrontmatter(t *testing.T) {
	prompt := staticSiteSystemPrompt("existing profile instruction")
	if !strings.HasPrefix(prompt, "existing profile instruction\n\n# Publish Static Site") ||
		strings.Contains(prompt, "name: publish-static-site") || !strings.Contains(prompt, "Pico-inspired") ||
		!strings.Contains(prompt, "Do not create an archive for a single page") {
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
	service.SetStaticSitePublisher(&staticSitePublisherStub{})
	tools, err = service.resolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 1 || tools[0].Tool.Name != coremodel.IntrinsicStaticSitePublishToolName {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
	service.SetStaticSitePublisher(nil)
	tools, err = service.resolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 0 {
		t.Fatalf("tool remained after publisher removal: tools=%+v err=%v", tools, err)
	}
}

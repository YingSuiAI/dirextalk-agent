package agentcapability

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/corestaticsite"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

type staticSiteCapabilityRepo struct {
	authority corestaticsite.Authority
	release   corestaticsite.Release
	command   corestaticsite.DeleteCommand
}

func (r *staticSiteCapabilityRepo) ListReleases(_ context.Context, authority corestaticsite.Authority, _ corestaticsite.ListQuery, _ string) (corestaticsite.Page, error) {
	r.authority = authority
	return corestaticsite.Page{Releases: []corestaticsite.Release{r.release}}, nil
}

func (r *staticSiteCapabilityRepo) DeleteRelease(_ context.Context, authority corestaticsite.Authority, command corestaticsite.DeleteCommand, _ string, remove func(corestaticsite.Release, func() error) error) (corestaticsite.DeleteResult, error) {
	r.authority, r.command = authority, command
	if err := remove(r.release, func() error { return nil }); err != nil {
		return corestaticsite.DeleteResult{}, err
	}
	return corestaticsite.DeleteResult{ReleaseID: command.ReleaseID, Deleted: true}, nil
}

type staticSiteCapabilityFiles struct{ deleted string }

func (f *staticSiteCapabilityFiles) DeleteRelease(_ context.Context, release corestaticsite.Release, commit func() error) error {
	f.deleted = release.ReleaseID
	return commit()
}

func TestStaticSiteCapabilityUsesAuthenticatedOwnerAndCurrentOperations(t *testing.T) {
	release := corestaticsite.Release{SiteID: uuid.NewString(), ReleaseID: uuid.NewString(), ConversationID: uuid.NewString(), PublicPath: "", SizeBytes: 10, CreatedAt: time.Now().UTC()}
	release.PublicPath = "/.sites/" + release.SiteID + "/" + release.ReleaseID + "/"
	release.PublicURL = "https://s3.dirextalk.ai" + release.PublicPath
	repository, files := &staticSiteCapabilityRepo{release: release}, &staticSiteCapabilityFiles{}
	service, err := corestaticsite.NewService(repository, files, "https://s3.dirextalk.ai")
	if err != nil {
		t.Fatal(err)
	}
	capability := NewCoreStaticSiteCapability(service)
	descriptor := capability.Descriptor()
	if descriptor.GetCapabilityId() != "agent.static_sites.v1" || len(descriptor.GetOperations()) != 2 || descriptor.GetOperations()[0].GetAudience()[0] != capv1.Audience_AUDIENCE_OWNER_CLIENT {
		t.Fatalf("descriptor=%+v", descriptor)
	}
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner-1", AccountGeneration: 7})
	listRaw, err := capability.HandleOperation(ctx, "list_releases", []byte(`{}`))
	if err != nil || repository.authority.OwnerID != "owner-1" || repository.authority.AccountGeneration != 7 {
		t.Fatalf("list=%s authority=%+v err=%v", listRaw, repository.authority, err)
	}
	var list struct {
		Releases      []corestaticsite.Release `json:"releases"`
		NextPageToken string                   `json:"next_page_token"`
	}
	if json.Unmarshal(listRaw, &list) != nil || len(list.Releases) != 1 || list.Releases[0].PublicURL != release.PublicURL {
		t.Fatalf("list result=%s", listRaw)
	}
	idempotencyKey := uuid.NewString()
	deleteRaw, _ := json.Marshal(map[string]string{"release_id": release.ReleaseID, "idempotency_key": idempotencyKey})
	result, err := capability.HandleOperation(ctx, "delete_release", deleteRaw)
	if err != nil || files.deleted != release.ReleaseID || repository.command.IdempotencyKey != idempotencyKey {
		t.Fatalf("delete=%s command=%+v err=%v", result, repository.command, err)
	}
}

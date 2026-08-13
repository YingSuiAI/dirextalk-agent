package staticsite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/corestaticsite"
	"github.com/google/uuid"
)

func TestPublisherPublishesSingleHTMLWithoutArchiveAndReplaysExactly(t *testing.T) {
	root := t.TempDir()
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	publication := core.StaticSitePublication{
		SiteID: uuid.NewString(), ReleaseID: uuid.NewString(),
		HTML: []byte("<!doctype html><style>body{color:#123}</style><h1>Dirextalk</h1>"),
	}
	first, err := publisher.PublishSingleHTML(context.Background(), publication)
	if err != nil {
		t.Fatal(err)
	}
	if first.AlreadyExists || first.Validate() != nil || first.PublicPath != "/.sites/"+publication.SiteID+"/"+publication.ReleaseID+"/" {
		t.Fatalf("first receipt=%+v", first)
	}
	finalRoot := filepath.Join(root, "public", publication.SiteID, publication.ReleaseID)
	entries, err := os.ReadDir(finalRoot)
	if err != nil || len(entries) != 1 || entries[0].Name() != indexFileName {
		t.Fatalf("release entries=%v err=%v", entries, err)
	}
	raw, err := os.ReadFile(filepath.Join(finalRoot, indexFileName))
	if err != nil || string(raw) != string(publication.HTML) {
		t.Fatalf("index=%q err=%v", raw, err)
	}
	if info, statErr := os.Stat(filepath.Join(finalRoot, indexFileName)); statErr != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("index mode=%v err=%v", info.Mode().Perm(), statErr)
	}
	replayed, err := publisher.PublishSingleHTML(context.Background(), publication)
	if err != nil || !replayed.AlreadyExists || replayed.SHA256 != first.SHA256 {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	changed := publication
	changed.HTML = []byte("<h1>changed</h1>")
	if _, err = publisher.PublishSingleHTML(context.Background(), changed); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("changed content err=%v", err)
	}
	stageEntries, err := os.ReadDir(filepath.Join(root, ".staging"))
	if err != nil || len(stageEntries) != 0 {
		t.Fatalf("staging=%v err=%v", stageEntries, err)
	}
}

func TestPublisherDeleteQuarantinesAndRestoresOnCommitFailure(t *testing.T) {
	root := t.TempDir()
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	publication := core.StaticSitePublication{SiteID: uuid.NewString(), ReleaseID: uuid.NewString(), HTML: []byte("<h1>delete me</h1>")}
	receipt, err := publisher.PublishSingleHTML(context.Background(), publication)
	if err != nil {
		t.Fatal(err)
	}
	release := corestaticsite.Release{SiteID: receipt.SiteID, ReleaseID: receipt.ReleaseID, ConversationID: uuid.NewString(), PublicPath: receipt.PublicPath, PublicURL: "https://example.test" + receipt.PublicPath, SizeBytes: receipt.SizeBytes, CreatedAt: time.Now().UTC()}
	commitFailure := errors.New("commit failed")
	if err = publisher.DeleteRelease(context.Background(), release, func() error { return commitFailure }); !errors.Is(err, commitFailure) {
		t.Fatalf("delete failure=%v", err)
	}
	indexPath := filepath.Join(root, "public", publication.SiteID, publication.ReleaseID, indexFileName)
	if raw, readErr := os.ReadFile(indexPath); readErr != nil || string(raw) != string(publication.HTML) {
		t.Fatalf("release was not restored: raw=%q err=%v", raw, readErr)
	}
	if err = publisher.DeleteRelease(context.Background(), release, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(indexPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("release remains after committed delete: %v", statErr)
	}
}

func TestPublisherRejectsSymlinkRootAndInvalidPublication(t *testing.T) {
	realRoot := t.TempDir()
	linkRoot := filepath.Join(t.TempDir(), "sites")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(linkRoot); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("symlink root err=%v", err)
	}
	publisher, err := NewPublisher(realRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publisher.PublishSingleHTML(context.Background(), core.StaticSitePublication{SiteID: "../escape", ReleaseID: uuid.NewString(), HTML: []byte("x")}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("path injection err=%v", err)
	}
	if _, err = publisher.PublishSingleHTML(context.Background(), core.StaticSitePublication{SiteID: uuid.NewString(), ReleaseID: uuid.NewString(), HTML: make([]byte, core.MaxStaticSiteHTMLBytes+1)}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("oversize err=%v", err)
	}
}

func TestPublisherRepairsOwnedDirectoryModesOnRestart(t *testing.T) {
	root := t.TempDir()
	if _, err := NewPublisher(root); err != nil {
		t.Fatal(err)
	}
	publicRoot := filepath.Join(root, "public")
	stageRoot := filepath.Join(root, ".staging")
	if err := os.Chmod(publicRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stageRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(root); err != nil {
		t.Fatalf("restart with repairable owned directories: %v", err)
	}
	for path, want := range map[string]os.FileMode{publicRoot: 0o755, stageRoot: 0o700} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s mode=%v want=%v err=%v", path, info.Mode().Perm(), want, err)
		}
	}
}

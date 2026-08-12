package staticsite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

const indexFileName = "index.html"

type Publisher struct {
	root       string
	publicRoot string
	stageRoot  string
}

func NewPublisher(root string) (*Publisher, error) {
	abs, err := filepath.Abs(filepath.Clean(root))
	if err != nil || !filepath.IsAbs(abs) {
		return nil, core.ErrInvalid
	}
	if err = validateOwnedDirectory(abs, 0o022); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return nil, core.ErrInvalid
	}
	publicRoot := filepath.Join(abs, "public")
	stageRoot := filepath.Join(abs, ".staging")
	if err = ensureOwnedDirectory(publicRoot, 0o755); err != nil {
		return nil, err
	}
	if err = ensureOwnedDirectory(stageRoot, 0o700); err != nil {
		return nil, err
	}
	return &Publisher{root: abs, publicRoot: publicRoot, stageRoot: stageRoot}, nil
}

func (p *Publisher) PublishSingleHTML(ctx context.Context, publication core.StaticSitePublication) (core.StaticSiteReceipt, error) {
	if p == nil || ctx == nil || canonicalUUID(publication.SiteID) == "" || canonicalUUID(publication.ReleaseID) == "" ||
		len(publication.HTML) == 0 || len(publication.HTML) > core.MaxStaticSiteHTMLBytes {
		return core.StaticSiteReceipt{}, core.ErrInvalid
	}
	select {
	case <-ctx.Done():
		return core.StaticSiteReceipt{}, ctx.Err()
	default:
	}
	digest := digestBytes(publication.HTML)
	siteRoot := filepath.Join(p.publicRoot, publication.SiteID)
	if err := ensureOwnedDirectory(siteRoot, 0o755); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	finalRoot := filepath.Join(siteRoot, publication.ReleaseID)
	if _, err := os.Lstat(finalRoot); err == nil {
		return p.verifyExisting(publication, digest, finalRoot)
	} else if !errors.Is(err, os.ErrNotExist) {
		return core.StaticSiteReceipt{}, err
	}
	stage, err := os.MkdirTemp(p.stageRoot, publication.ReleaseID+".")
	if err != nil {
		return core.StaticSiteReceipt{}, err
	}
	defer os.RemoveAll(stage)
	if err = os.Chmod(stage, 0o700); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	indexPath := filepath.Join(stage, indexFileName)
	file, err := os.OpenFile(indexPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return core.StaticSiteReceipt{}, err
	}
	if _, err = file.Write(publication.HTML); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return core.StaticSiteReceipt{}, err
	}
	if closeErr != nil {
		return core.StaticSiteReceipt{}, closeErr
	}
	if err = os.Chmod(indexPath, 0o444); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	if err = syncDirectory(stage); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	// Keep the directory writable by its owner until every byte and directory
	// entry is durable, then seal the exact mode before the atomic rename. This
	// prevents a successful rename from exposing an inaccessible partial
	// release if a later chmod were to fail.
	if err = os.Chmod(stage, 0o755); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	if err = os.Rename(stage, finalRoot); err != nil {
		if _, statErr := os.Lstat(finalRoot); statErr == nil {
			return p.verifyExisting(publication, digest, finalRoot)
		}
		return core.StaticSiteReceipt{}, err
	}
	if err = syncDirectory(siteRoot); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	return receipt(publication, digest, false), nil
}

func (p *Publisher) verifyExisting(publication core.StaticSitePublication, digest, finalRoot string) (core.StaticSiteReceipt, error) {
	if err := validateOwnedDirectory(finalRoot, 0o022); err != nil {
		return core.StaticSiteReceipt{}, core.ErrConflict
	}
	if info, err := os.Lstat(finalRoot); err != nil || info.Mode().Perm() != 0o755 {
		return core.StaticSiteReceipt{}, core.ErrConflict
	}
	entries, err := os.ReadDir(finalRoot)
	if err != nil || len(entries) != 1 || entries[0].Name() != indexFileName || entries[0].Type()&os.ModeSymlink != 0 {
		return core.StaticSiteReceipt{}, core.ErrConflict
	}
	file, err := os.Open(filepath.Join(finalRoot, indexFileName))
	if err != nil {
		return core.StaticSiteReceipt{}, core.ErrConflict
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Size() != int64(len(publication.HTML)) {
		return core.StaticSiteReceipt{}, core.ErrConflict
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, core.MaxStaticSiteHTMLBytes+1)); err != nil || hex.EncodeToString(hash.Sum(nil)) != digest {
		return core.StaticSiteReceipt{}, core.ErrConflict
	}
	return receipt(publication, digest, true), nil
}

func receipt(publication core.StaticSitePublication, digest string, exists bool) core.StaticSiteReceipt {
	return core.StaticSiteReceipt{
		SiteID: publication.SiteID, ReleaseID: publication.ReleaseID,
		PublicPath: "/.sites/" + publication.SiteID + "/" + publication.ReleaseID + "/",
		SHA256:     digest, SizeBytes: int64(len(publication.HTML)), AlreadyExists: exists,
	}
}

func ensureOwnedDirectory(path string, mode os.FileMode) error {
	err := os.Mkdir(path, mode)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode().Perm() != mode.Perm() {
			return core.ErrInvalid
		}
		return validateOwnedDirectory(path, 0o777^mode.Perm())
	}
	if err = os.Chmod(path, mode); err != nil {
		return err
	}
	return validateOwnedDirectory(path, 0o777^mode.Perm())
}

func validateOwnedDirectory(path string, forbidden os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&forbidden != 0 {
		return core.ErrInvalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return core.ErrInvalid
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func canonicalUUID(value string) string {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return ""
	}
	return value
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

var _ core.StaticSitePublisher = (*Publisher)(nil)

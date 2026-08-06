package workerrootfs

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Publication is an identity-bound rollback token for one newly published
// rootfs. It cannot delete an arbitrary path or a file that has changed.
type Publication struct {
	mu       sync.Mutex
	manifest ManifestV1
	output   string
	info     os.FileInfo
	closed   bool
}

func newPublication(output string, manifest ManifestV1, info os.FileInfo) *Publication {
	return &Publication{manifest: manifest, output: output, info: info}
}

func (publication *Publication) Manifest() ManifestV1 {
	publication.mu.Lock()
	defer publication.mu.Unlock()
	return publication.manifest
}

// Commit consumes the rollback token after the caller has delivered the
// manifest successfully.
func (publication *Publication) Commit() {
	publication.mu.Lock()
	defer publication.mu.Unlock()
	publication.closed = true
}

// Rollback removes only the unchanged artifact represented by this token.
func (publication *Publication) Rollback() error {
	return publication.rollbackWithSync(syncDirectory)
}

func (publication *Publication) rollbackWithSync(syncParent func(string) error) error {
	if publication == nil || syncParent == nil {
		return errors.New("invalid rootfs publication rollback")
	}
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.closed {
		return errors.New("rootfs publication token is closed")
	}
	current, err := os.Lstat(publication.output)
	if err != nil || !current.Mode().IsRegular() || !sameFileState(publication.info, current) ||
		current.Size() != publication.manifest.Size {
		return errors.New("published rootfs identity changed before rollback")
	}
	parent, err := os.OpenRoot(filepath.Dir(publication.output))
	if err != nil {
		return errors.New("open rootfs publication directory")
	}
	defer parent.Close()
	name := filepath.Base(publication.output)
	content, reviewed, links, err := readRegularFile(parent, name, current, MaxArchiveBytes)
	if err != nil || links != 1 || !sameFileState(publication.info, reviewed) ||
		int64(len(content)) != publication.manifest.Size || sha256Digest(content) != publication.manifest.RootFSDigest {
		return errors.New("published rootfs content changed before rollback")
	}
	final, err := parent.Lstat(name)
	if err != nil || !sameFileState(publication.info, final) {
		return errors.New("published rootfs identity changed before rollback")
	}
	if err := parent.Remove(name); err != nil {
		return errors.New("remove rolled back rootfs publication")
	}
	publication.closed = true
	if err := syncParent(filepath.Dir(publication.output)); err != nil {
		return errors.New("sync rolled back rootfs publication directory")
	}
	return nil
}

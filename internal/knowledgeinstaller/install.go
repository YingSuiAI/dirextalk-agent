package installer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type Installer struct {
	Paths        Paths
	Runner       Runner
	Probe        RoundTripper
	Identities   IdentityResolver
	Materializer Materializer
}

func ProductionInstaller() Installer {
	return Installer{
		Paths:        ProductionPaths(),
		Runner:       FixedRunner{},
		Probe:        UnixRoundTripper{Socket: SocketPath},
		Identities:   SystemIdentityResolver{},
		Materializer: RealMaterializer{},
	}
}

func (i Installer) InstallV1(ctx context.Context) error {
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	return i.installV1Unlocked(ctx)
}

func (i Installer) installV1Unlocked(ctx context.Context) error {
	if i.Runner == nil || i.Identities == nil || i.Materializer == nil {
		return fmt.Errorf("installer dependencies are incomplete")
	}
	if err := validateFixedInstallBoundary(i.Paths); err != nil {
		return err
	}
	if err := i.Materializer.Materialize(i.Paths); err != nil {
		return err
	}
	if err := writeSecureManagedFile(i.Paths, SysusersPath, []byte(renderSysusers()), 0o644, 0, 0); err != nil {
		return err
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemd-sysusers", i.Paths.Resolve(SysusersPath)); err != nil {
		return err
	}
	qdrant, err := i.Identities.Resolve("dirextalk-qdrant")
	if err != nil {
		return err
	}
	adapter, err := i.Identities.Resolve("dirextalk-knowledge")
	if err != nil {
		return err
	}
	if err := i.preparePersistentDirectories(qdrant, adapter); err != nil {
		return err
	}
	apiKey, err := readFixedAPIKey(i.Paths.Resolve(APIKeySourcePath))
	if err != nil {
		return err
	}
	if err := writeSecureManagedFile(i.Paths, APIKeyRuntimePath, []byte(apiKey), 0o640, 0, adapter.GID); err != nil {
		return err
	}
	if err := ensureLocalTLS(i.Paths, qdrant); err != nil {
		return err
	}
	qdrantConfig, err := renderQdrantConfig(apiKey)
	if err != nil {
		return err
	}
	managed := []struct {
		path string
		data string
		mode os.FileMode
		uid  int
		gid  int
	}{
		{QdrantConfigPath, qdrantConfig, 0o640, 0, qdrant.GID},
		{TmpfilesPath, renderTmpfiles(), 0o644, 0, 0},
		{QdrantUnitPath, renderQdrantUnit(), 0o644, 0, 0},
		{AdapterUnitPath, renderAdapterUnit(), 0o644, 0, 0},
	}
	for _, file := range managed {
		if err := writeSecureManagedFile(i.Paths, file.path, []byte(file.data), file.mode, file.uid, file.gid); err != nil {
			return err
		}
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemd-tmpfiles", "--create", i.Paths.Resolve(TmpfilesPath)); err != nil {
		return err
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemctl", "enable", "--now", "dirextalk-qdrant.service"); err != nil {
		return err
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemctl", "enable", "--now", "dirextalk-knowledge-adapter.service"); err != nil {
		return err
	}
	// A repeat install may have atomically rotated the fixed API-key/config
	// while the old services remained active. The reviewed restart path makes
	// the installed state and running state identical and verifies both units.
	return i.restartV1Unlocked(ctx)
}

func (i Installer) RestartV1(ctx context.Context) error {
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	return i.restartV1Unlocked(ctx)
}

func (i Installer) restartV1Unlocked(ctx context.Context) error {
	checks := []string{
		i.Paths.Resolve(ReleaseRoot + "/.provenance-sha256"),
		i.Paths.Resolve(QdrantConfigPath),
		i.Paths.Resolve(QdrantUnitPath),
		i.Paths.Resolve(AdapterUnitPath),
	}
	for _, path := range checks {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("installed v1 boundary is incomplete")
		}
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemctl", "restart", "dirextalk-qdrant.service"); err != nil {
		return err
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemctl", "restart", "dirextalk-knowledge-adapter.service"); err != nil {
		return err
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dirextalk-qdrant.service"); err != nil {
		return err
	}
	return i.Runner.Run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dirextalk-knowledge-adapter.service")
}

func (i Installer) preparePersistentDirectories(qdrant, adapter Identity) error {
	directories := []struct {
		path string
		mode os.FileMode
		uid  int
		gid  int
	}{
		{PersistentRoot, 0o750, 0, 0},
		{PersistentRoot + "/qdrant", 0o750, qdrant.UID, qdrant.GID},
		{PersistentRoot + "/qdrant/storage", 0o750, qdrant.UID, qdrant.GID},
		{PersistentRoot + "/adapter", 0o750, adapter.UID, adapter.GID},
		{PersistentRoot + "/secrets", 0o750, 0, adapter.GID},
		{PersistentRoot + "/tls", 0o750, 0, 0},
	}
	for _, directory := range directories {
		if err := ensureSecureOwnedDirectory(i.Paths, directory.path, directory.mode, directory.uid, directory.gid); err != nil {
			return err
		}
	}
	return nil
}

func readFixedAPIKey(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("open fixed Qdrant API key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect Qdrant API key file: %w", err)
	}
	if !apiKeySourceProtected(info, 0, 0) {
		return "", fmt.Errorf("Qdrant API key file is not protected")
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", fmt.Errorf("read fixed Qdrant API key: %w", err)
	}
	value := string(data)
	if !validAPIKey(value) {
		return "", fmt.Errorf("invalid fixed Qdrant API key")
	}
	return value, nil
}

func apiKeySourceProtected(info os.FileInfo, expectedUID, expectedGID uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0o400 &&
		stat.Uid == expectedUID && stat.Gid == expectedGID
}

func writeManagedFile(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("managed path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create managed parent: %w", err)
	}
	temporary := path + ".dirextalk-new"
	if err := os.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clean managed temporary file: %w", err)
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create managed file: %w", err)
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write managed file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync managed file: %w", err)
	}
	if err := file.Chown(uid, gid); err != nil {
		return fmt.Errorf("own managed file: %w", err)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("mode managed file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close managed file: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("promote managed file: %w", err)
	}
	ok = true
	return nil
}

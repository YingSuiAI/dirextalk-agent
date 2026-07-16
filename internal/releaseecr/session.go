package releaseecr

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	dockerSessionPrefix = "dirextalk-ecr-session-"
	dockerConfigName    = "config.json"
	sessionMarkerName   = ".dirextalk-session"
	sessionClaimSuffix  = ".claim"
	maxSessionFileBytes = 64 << 10
)

var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// SessionLease owns a claimed, single-use Docker authorization directory.
// Close removes both credentials and handoff. A failed credential-directory
// removal releases the claim and may be retried through CleanupSessionFile.
type SessionLease struct {
	session    SessionV1
	descriptor string
	claim      string
	closed     bool
	removeAll  func(string) error
	remove     func(string) error
}

func (lease *SessionLease) DockerConfigDir() string { return lease.session.DockerConfigDir }
func (lease *SessionLease) RegistryHost() string    { return lease.session.RegistryHost }

func (lease *SessionLease) Close() error {
	if lease == nil || lease.closed {
		return ErrSessionCleanup
	}
	removeAll := lease.removeAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	remove := lease.remove
	if remove == nil {
		remove = os.Remove
	}
	if err := removeAll(lease.session.DockerConfigDir); err != nil {
		// Keep the de-secreted descriptor for an explicit cleanup retry, but
		// release this failed attempt's one-time claim.
		_ = remove(lease.claim)
		return ErrSessionCleanup
	}
	if _, err := os.Lstat(lease.session.DockerConfigDir); !errors.Is(err, os.ErrNotExist) {
		_ = remove(lease.claim)
		return ErrSessionCleanup
	}
	for _, name := range []string{lease.descriptor, lease.claim} {
		if err := remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ErrSessionCleanup
		}
	}
	lease.closed = true
	return nil
}

func newDockerSession() (SessionV1, error) {
	return newDockerSessionIn("")
}

func newDockerSessionIn(parent string) (SessionV1, error) {
	directory, err := os.MkdirTemp(parent, dockerSessionPrefix)
	if err != nil {
		return SessionV1{}, ErrSession
	}
	remove := true
	defer func() {
		if remove {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return SessionV1{}, ErrSession
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return SessionV1{}, ErrSession
	}
	sessionID := hex.EncodeToString(random[:])
	if err := writePrivateFile(filepath.Join(directory, sessionMarkerName), []byte(sessionID)); err != nil {
		return SessionV1{}, err
	}
	if err := writePrivateFile(filepath.Join(directory, dockerConfigName), []byte("{}\n")); err != nil {
		return SessionV1{}, err
	}
	remove = false
	return SessionV1{SchemaVersion: SessionSchemaV1, SessionID: sessionID, DockerConfigDir: directory}, nil
}

func WriteSessionFile(name string, session SessionV1) error {
	if err := validateSession(session, time.Time{}); err != nil {
		return err
	}
	absolute, err := cleanAbsolutePath(name)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return ErrSession
	}
	payload = append(payload, '\n')
	return writePrivateFile(absolute, payload)
}

func ClaimSessionFile(name string, now func() time.Time) (*SessionLease, error) {
	if now == nil {
		return nil, ErrSession
	}
	observedAt := now().UTC()
	if observedAt.IsZero() {
		return nil, ErrSession
	}
	return claimSessionFile(name, observedAt, true)
}

func CleanupSessionFile(name string) error {
	lease, err := claimSessionFile(name, time.Time{}, false)
	if err != nil {
		return err
	}
	return lease.Close()
}

func CleanupSession(session SessionV1) error {
	if err := validateSessionDirectory(session); err != nil {
		return ErrSessionCleanup
	}
	if err := os.RemoveAll(session.DockerConfigDir); err != nil {
		return ErrSessionCleanup
	}
	if _, err := os.Lstat(session.DockerConfigDir); !errors.Is(err, os.ErrNotExist) {
		return ErrSessionCleanup
	}
	return nil
}

func claimSessionFile(name string, now time.Time, requireFresh bool) (*SessionLease, error) {
	absolute, err := cleanAbsolutePath(name)
	if err != nil {
		return nil, err
	}
	claim := absolute + sessionClaimSuffix
	lock, err := os.OpenFile(claim, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, ErrSession
	}
	if closeErr := lock.Close(); closeErr != nil {
		_ = os.Remove(claim)
		return nil, ErrSession
	}
	if err := os.Chmod(claim, 0o600); err != nil {
		_ = os.Remove(claim)
		return nil, ErrSession
	}
	fail := func() (*SessionLease, error) {
		_ = os.Remove(claim)
		return nil, ErrSession
	}
	payload, err := readPrivateFile(absolute, maxSessionFileBytes)
	if err != nil {
		return fail()
	}
	var session SessionV1
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&session); err != nil {
		return fail()
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fail()
	}
	validationTime := time.Time{}
	if requireFresh {
		validationTime = now.UTC()
	}
	if err := validateSession(session, validationTime); err != nil {
		return fail()
	}
	return &SessionLease{session: session, descriptor: absolute, claim: claim}, nil
}

func validateSession(session SessionV1, now time.Time) error {
	if session.SchemaVersion != SessionSchemaV1 || !sessionIDPattern.MatchString(session.SessionID) ||
		session.RegistryHost == "" || strings.ContainsAny(session.RegistryHost, "/:@ \t\r\n") {
		return ErrSession
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, session.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC || expiresAt.Format(time.RFC3339Nano) != session.ExpiresAt ||
		(!now.IsZero() && !now.Before(expiresAt)) {
		return ErrSession
	}
	return validateSessionDirectory(session)
}

func validateSessionDirectory(session SessionV1) error {
	directory, err := cleanAbsolutePath(session.DockerConfigDir)
	tempRoot, tempErr := filepath.Abs(os.TempDir())
	if err != nil || tempErr != nil || directory != session.DockerConfigDir ||
		!sameFilesystemPath(filepath.Dir(directory), filepath.Clean(tempRoot)) ||
		!strings.HasPrefix(filepath.Base(directory), dockerSessionPrefix) {
		return ErrSession
	}
	if !privatePath(directory, true, 0o700) || !privatePath(filepath.Join(directory, dockerConfigName), false, 0o600) ||
		!privatePath(filepath.Join(directory, sessionMarkerName), false, 0o600) {
		return ErrSession
	}
	marker, err := os.ReadFile(filepath.Join(directory, sessionMarkerName))
	if err != nil || string(marker) != session.SessionID {
		return ErrSession
	}
	config, err := os.Stat(filepath.Join(directory, dockerConfigName))
	if err != nil || config.Size() < 2 || config.Size() > 1<<20 {
		return ErrSession
	}
	return nil
}

func sameFilesystemPath(first, second string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(first), filepath.Clean(second))
	}
	return filepath.Clean(first) == filepath.Clean(second)
}

func finalizeDockerConfig(session SessionV1) error {
	name := filepath.Join(session.DockerConfigDir, dockerConfigName)
	if err := os.Chmod(name, 0o600); err != nil || !privatePath(name, false, 0o600) {
		return ErrSession
	}
	return nil
}

func writePrivateFile(name string, content []byte) (err error) {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrSession
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = ErrSession
		}
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	if err = os.Chmod(name, 0o600); err != nil {
		return ErrSession
	}
	if _, err = file.Write(content); err != nil {
		return ErrSession
	}
	if err = file.Sync(); err != nil {
		return ErrSession
	}
	return nil
}

func readPrivateFile(name string, limit int64) ([]byte, error) {
	if !privatePath(name, false, 0o600) {
		return nil, ErrSession
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, ErrSession
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(content) == 0 || int64(len(content)) > limit {
		return nil, ErrSession
	}
	return content, nil
}

func privatePath(name string, directory bool, mode os.FileMode) bool {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory {
		return false
	}
	return runtime.GOOS == "windows" || info.Mode().Perm() == mode
}

func cleanAbsolutePath(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || !filepath.IsAbs(trimmed) || strings.ContainsAny(trimmed, "\x00\r\n") {
		return "", ErrSession
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil || filepath.Clean(absolute) != absolute {
		return "", ErrSession
	}
	return absolute, nil
}

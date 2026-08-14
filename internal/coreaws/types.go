// Package coreaws contains the Core v1 AWS domain boundary.  It deliberately
// exposes typed provider ports only; credentials and arbitrary AWS calls never
// cross this package's public API.
package coreaws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalid                        = errors.New("coreaws: invalid")
	ErrNotFound                       = errors.New("coreaws: not found")
	ErrConflict                       = errors.New("coreaws: conflict")
	ErrActiveCredentialExists         = errors.New("coreaws: an active credential already exists")
	ErrRevisionConflict               = errors.New("coreaws: revision conflict")
	ErrIdempotencyConflict            = errors.New("coreaws: idempotency conflict")
	ErrProvider                       = errors.New("coreaws: provider operation failed")
	ErrResponseUncertain        error = responseUncertainError{}
	ErrCredentialTestInProgress       = errors.New("coreaws: credential test in progress")
	ErrCredentialInUse                = errors.New("coreaws: credential is used by a retained Worker")
)

type responseUncertainError struct{}

func (responseUncertainError) Error() string   { return "coreaws: provider response uncertain" }
func (responseUncertainError) Uncertain() bool { return true }

// CredentialTestInProgressError carries the durable wait boundary for a
// same-key request that observes another worker's provider claim. It still
// matches ErrCredentialTestInProgress for callers that only need the class.
type CredentialTestInProgressError struct {
	LeaseExpiresAt       time.Time
	CompletionGraceUntil time.Time
}

func (e *CredentialTestInProgressError) Error() string {
	return ErrCredentialTestInProgress.Error()
}

func (e *CredentialTestInProgressError) Is(target error) bool {
	return target == ErrCredentialTestInProgress
}

type Credentials struct {
	ID               string
	Name             string
	Region           string
	private          *credentialPayload
	AccountID        string
	UserARN          string
	VerifiedRevision int64
	Revision         int64
	TestedAt         time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// RehydrateCredentials reconstructs durable credentials inside the trusted
// Agent boundary. Secret bytes must never be returned from ordinary APIs.
func RehydrateCredentials(id, name, region, accountID, userARN string, accessKeyID, secretAccessKey, sessionToken []byte, verifiedRevision, revision int64, createdAt, updatedAt time.Time) Credentials {
	return RehydrateCredentialsWithTestedAt(id, name, region, accountID, userARN, accessKeyID, secretAccessKey, sessionToken, verifiedRevision, revision, time.Time{}, createdAt, updatedAt)
}

func RehydrateCredentialsWithTestedAt(id, name, region, accountID, userARN string, accessKeyID, secretAccessKey, sessionToken []byte, verifiedRevision, revision int64, testedAt, createdAt, updatedAt time.Time) Credentials {
	return Credentials{ID: id, Name: name, Region: region, AccountID: accountID, UserARN: userARN, VerifiedRevision: verifiedRevision, Revision: revision, TestedAt: testedAt, CreatedAt: createdAt, UpdatedAt: updatedAt, private: &credentialPayload{string(accessKeyID), string(secretAccessKey), string(sessionToken)}}
}

type credentialPayload struct{ accessKeyID, secretAccessKey, sessionToken string }
type CredentialHandle struct {
	credential *credentialPayload
	Region     string
	AccountID  string
	UserARN    string
}

func (c Credentials) handle() CredentialHandle {
	if c.private == nil {
		return CredentialHandle{Region: c.Region, AccountID: c.AccountID, UserARN: c.UserARN}
	}
	return CredentialHandle{credential: &credentialPayload{c.private.accessKeyID, c.private.secretAccessKey, c.private.sessionToken}, Region: c.Region, AccountID: c.AccountID, UserARN: c.UserARN}
}
func (c Credentials) String() string   { return "[redacted-coreaws-credentials]" }
func (c Credentials) GoString() string { return "coreaws.Credentials{[redacted]}" }
func (c Credentials) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID, Name, Region, AccountID, UserARN        string
		HasAccessKey, HasSecretKey, HasSessionToken bool
		Revision                                    int64
	}{c.ID, c.Name, c.Region, c.AccountID, c.UserARN, c.private != nil && c.private.accessKeyID != "", c.private != nil && c.private.secretAccessKey != "", c.private != nil && c.private.sessionToken != "", c.Revision})
}

// CredentialView is safe for ordinary read/list responses.
type CredentialView struct {
	ID, Name, Region, AccountID, UserARN        string
	HasAccessKey, HasSecretKey, HasSessionToken bool
	Revision                                    int64
	VerifiedRevision                            int64
	TestedAt, CreatedAt, UpdatedAt              time.Time
}

func (c Credentials) View() CredentialView {
	return CredentialView{ID: c.ID, Name: c.Name, Region: c.Region, AccountID: c.AccountID, UserARN: c.UserARN, HasAccessKey: c.private != nil && c.private.accessKeyID != "", HasSecretKey: c.private != nil && c.private.secretAccessKey != "", HasSessionToken: c.private != nil && c.private.sessionToken != "", Revision: c.Revision, VerifiedRevision: c.VerifiedRevision, TestedAt: c.TestedAt, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

// StoredSecretBytes is restricted to persistence adapters inside Agent.
func (c Credentials) StoredSecretBytes() (accessKeyID, secretAccessKey, sessionToken []byte) {
	if c.private == nil {
		return nil, nil, nil
	}
	return []byte(c.private.accessKeyID), []byte(c.private.secretAccessKey), []byte(c.private.sessionToken)
}
func (c Credentials) Validate() error {
	if !validUUID(c.ID) || strings.TrimSpace(c.Name) == "" || !validRegion(c.Region) || c.private == nil || c.private.accessKeyID == "" || c.private.secretAccessKey == "" || c.Revision < 1 {
		return ErrInvalid
	}
	return nil
}

type Identity struct {
	AccountID   string
	UserARN     string
	PrincipalID string
}
type CredentialTest struct {
	CredentialID       string
	Identity           Identity
	CredentialRevision int64
	TestedAt           time.Time
}

// CredentialTestBindingDigest identifies the non-secret binding protected by
// the neutral idempotent credential-test receipt. The idempotency key itself
// is the replay-record key and is intentionally not duplicated in the digest.
func CredentialTestBindingDigest(credentialID string, expectedRevision int64) string {
	return canonicalDigest(struct {
		CredentialID     string
		ExpectedRevision int64
	}{credentialID, expectedRevision})
}

type Page[T any] struct {
	Items         []T
	NextPageToken string
}
type CredentialPage = Page[CredentialView]

type CredentialInput struct{ ID, Name, Region, AccessKeyID, SecretAccessKey, SessionToken, IdempotencyKey string }

func (in CredentialInput) String() string   { return "[redacted-coreaws-credential-input]" }
func (in CredentialInput) GoString() string { return "coreaws.CredentialInput{[redacted]}" }
func (in CredentialInput) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID, Name, Region, IdempotencyKey            string
		HasAccessKey, HasSecretKey, HasSessionToken bool
	}{in.ID, in.Name, in.Region, in.IdempotencyKey, in.AccessKeyID != "", in.SecretAccessKey != "", in.SessionToken != ""})
}
func (in CredentialInput) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", in.ID), slog.String("name", in.Name), slog.String("region", in.Region), slog.String("idempotency_key", in.IdempotencyKey), slog.Bool("has_access_key", in.AccessKeyID != ""), slog.Bool("has_secret_key", in.SecretAccessKey != ""), slog.Bool("has_session_token", in.SessionToken != ""))
}

func credentialInputDigest(in CredentialInput) string {
	return canonicalDigest(struct {
		ID, Name, Region, IdempotencyKey                               string
		AccessKeyFingerprint, SecretKeyFingerprint, SessionFingerprint string
		HasAccessKey, HasSecretKey, HasSessionToken                    bool
	}{in.ID, in.Name, in.Region, in.IdempotencyKey, secretFingerprint(in.AccessKeyID), secretFingerprint(in.SecretAccessKey), secretFingerprint(in.SessionToken), in.AccessKeyID != "", in.SecretAccessKey != "", in.SessionToken != ""})
}
func secretFingerprint(value string) string {
	if value == "" {
		return ""
	}
	buf := []byte(value)
	s := sha256.Sum256(buf)
	for i := range buf {
		buf[i] = 0
	}
	return hex.EncodeToString(s[:])
}

func validRegion(s string) bool {
	return regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d$`).MatchString(strings.TrimSpace(s))
}
func validUUID(s string) bool {
	u, e := uuid.Parse(strings.TrimSpace(s))
	return e == nil && u != uuid.Nil && u.String() == strings.TrimSpace(s)
}
func canonicalDigest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

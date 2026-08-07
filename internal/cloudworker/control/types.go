package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/identitywire"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

var (
	ErrInvalid           = errors.New("invalid cloud Worker control request")
	ErrNotFound          = errors.New("cloud Worker control record not found")
	ErrConflict          = errors.New("cloud Worker control conflict")
	ErrChallengeExpired  = errors.New("cloud Worker identity challenge expired")
	ErrChallengeConsumed = errors.New("cloud Worker identity challenge consumed")
	ErrIdentityRejected  = errors.New("cloud Worker identity rejected")
	ErrSessionRejected   = errors.New("cloud Worker session rejected")
	ErrStaleLease        = errors.New("cloud Worker lease is stale")
	ErrTerminal          = errors.New("cloud Worker session is terminal")
)

const (
	DefaultChallengeTTL = 5 * time.Minute
	MaximumClaimBytes   = int64(8 << 20)
	maximumProofBytes   = 64 << 10
)

var (
	accountPattern  = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern   = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$`)
	instancePattern = regexp.MustCompile(`^i-[0-9a-f]{8,32}$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tagKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9_.:/=+@-]{1,128}$`)
	iamIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_]{16,128}$`)
)

type TaskFence struct {
	ExecutionID       string
	TaskID            string
	AccountGeneration uint64
	Attempt           uint32
	LeaseEpoch        uint64
}

// LaunchLookup is the immutable identity a booting Worker presents before it
// may receive a challenge. It is scheduling input only: the resolver must
// bind it to the current CoreTask lease, launch expectation and AWS ledger.
type LaunchLookup struct {
	ExecutionID       string
	TaskID            string
	AccountGeneration uint64
	InstanceID        string
	LaunchIdentity    string
}

func (f TaskFence) validate() error {
	if !validUUID(f.ExecutionID) || !validUUID(f.TaskID) || f.AccountGeneration == 0 || f.Attempt == 0 || f.LeaseEpoch == 0 {
		return ErrInvalid
	}
	return nil
}

type IdentityExpectation struct {
	OwnerID           string
	AccountGeneration uint64
	AccountID         string
	Region            string
	InstanceID        string
	LaunchIdentity    string
	RoleARN           string
	RoleID            string
	InstanceProfileID string
	RequiredTags      map[string]string
}

func (e IdentityExpectation) normalize() (IdentityExpectation, error) {
	e.OwnerID = strings.TrimSpace(e.OwnerID)
	e.AccountID = strings.TrimSpace(e.AccountID)
	e.Region = strings.TrimSpace(e.Region)
	e.InstanceID = strings.TrimSpace(e.InstanceID)
	e.LaunchIdentity = strings.TrimSpace(e.LaunchIdentity)
	e.RoleARN = strings.TrimSpace(e.RoleARN)
	e.RoleID = strings.TrimSpace(e.RoleID)
	e.InstanceProfileID = strings.TrimSpace(e.InstanceProfileID)
	if e.OwnerID == "" || len(e.OwnerID) > 255 || security.ContainsLikelySecret(e.OwnerID) || e.AccountGeneration == 0 ||
		!accountPattern.MatchString(e.AccountID) || !regionPattern.MatchString(e.Region) ||
		!instancePattern.MatchString(e.InstanceID) || e.LaunchIdentity == "" || len(e.LaunchIdentity) > 256 ||
		!strings.HasPrefix(e.RoleARN, "arn:aws") || !strings.Contains(e.RoleARN, ":iam::"+e.AccountID+":role/") || len(e.RoleARN) > 2048 ||
		!iamIDPattern.MatchString(e.RoleID) || !iamIDPattern.MatchString(e.InstanceProfileID) {
		return IdentityExpectation{}, ErrInvalid
	}
	if len(e.RequiredTags) == 0 || len(e.RequiredTags) > 32 {
		return IdentityExpectation{}, ErrInvalid
	}
	tags := make(map[string]string, len(e.RequiredTags))
	for rawKey, rawValue := range e.RequiredTags {
		key, value := strings.TrimSpace(rawKey), strings.TrimSpace(rawValue)
		if !tagKeyPattern.MatchString(key) || value == "" || len(value) > 256 || security.ContainsLikelySecret(value) {
			return IdentityExpectation{}, ErrInvalid
		}
		tags[key] = value
	}
	e.RequiredTags = tags
	return e, nil
}

// Canonical validates and returns the immutable identity expectation used by
// the persistence/controller boundary. Worker requests never supply this
// value; it is derived from the centrally verified AWS resource graph.
func (e IdentityExpectation) Canonical() (IdentityExpectation, error) {
	return e.normalize()
}

type IdentityProof struct {
	Method  string
	Payload []byte
}

type IdentityClaims struct {
	AccountGeneration uint64
	AccountID         string
	Region            string
	InstanceID        string
	LaunchIdentity    string
	RoleARN           string
	RoleID            string
	InstanceProfileID string
	Tags              map[string]string
}

type IdentityVerifier interface {
	Verify(context.Context, string, IdentityProof) (IdentityClaims, error)
}

type LeaseAuthority interface {
	ValidateCloudWorkerLease(context.Context, TaskFence) error
}

type Challenge struct {
	ChallengeID string
	Nonce       string
	Fence       TaskFence
	ExpiresAt   time.Time
}

type ChallengeRecord struct {
	ChallengeID string
	NonceDigest [sha256.Size]byte
	Fence       TaskFence
	Expectation IdentityExpectation
	ExpiresAt   time.Time
	ConsumedAt  time.Time
	CreatedAt   time.Time
}

type SessionState string

const (
	SessionActive    SessionState = "active"
	SessionCompleted SessionState = "completed"
	SessionFailed    SessionState = "failed"
)

type ObjectClaim struct {
	Bucket    string
	Key       string
	VersionID string
	SHA256    string
	SizeBytes int64
	MediaType string
}

func (c ObjectClaim) normalize() (ObjectClaim, error) {
	c.Bucket = strings.TrimSpace(c.Bucket)
	c.Key = strings.TrimSpace(c.Key)
	c.VersionID = strings.TrimSpace(c.VersionID)
	c.SHA256 = strings.TrimSpace(c.SHA256)
	c.MediaType = strings.TrimSpace(c.MediaType)
	if c.Bucket == "" || len(c.Bucket) > 63 || strings.ContainsAny(c.Bucket, "/:*?#") ||
		c.Key == "" || len(c.Key) > 1024 || strings.HasPrefix(c.Key, "/") || strings.Contains(c.Key, "..") ||
		c.VersionID == "" || len(c.VersionID) > 1024 || !digestPattern.MatchString(c.SHA256) ||
		c.SizeBytes < 1 || c.SizeBytes > MaximumClaimBytes {
		return ObjectClaim{}, ErrInvalid
	}
	switch c.MediaType {
	case "application/json", "application/octet-stream", "text/plain; charset=utf-8", "application/zip":
	default:
		return ObjectClaim{}, ErrInvalid
	}
	if security.ContainsLikelySecret(c.Bucket) || security.ContainsLikelySecret(c.Key) || security.ContainsLikelySecret(c.VersionID) {
		return ObjectClaim{}, ErrInvalid
	}
	return c, nil
}

type Session struct {
	SessionID        string
	Fence            TaskFence
	Expectation      IdentityExpectation
	Identity         IdentityClaims
	State            SessionState
	ProgressSequence uint64
	Result           *ObjectClaim
	FailureCode      string
	FailureSummary   string
	Revision         uint64
	ClaimedAt        time.Time
	HeartbeatAt      time.Time
	FinishedAt       time.Time
	RuntimeTopology  *execgate.Proof
	TopologyDigest   string
}

type ClaimResult struct {
	Session      Session
	SessionToken []byte
}

func (r *ClaimResult) Destroy() {
	if r == nil {
		return
	}
	clear(r.SessionToken)
	*r = ClaimResult{}
}

type IssueChallengeRequest struct {
	Fence       TaskFence
	Expectation IdentityExpectation
	TTL         time.Duration
}

type ClaimRequest struct {
	ChallengeID string
	Nonce       string
	Fence       TaskFence
	Proof       IdentityProof
}

type HeartbeatRequest struct {
	SessionID        string
	SessionToken     []byte
	Fence            TaskFence
	ProgressSequence uint64
	IdempotencyKey   string
}

type CompleteRequest struct {
	SessionID       string
	SessionToken    []byte
	Fence           TaskFence
	Claim           ObjectClaim
	RuntimeTopology execgate.Proof
	IdempotencyKey  string
}

type FailRequest struct {
	SessionID      string
	SessionToken   []byte
	Fence          TaskFence
	Code           string
	Summary        string
	IdempotencyKey string
}

type ClaimMutation struct {
	ChallengeID string
	NonceDigest [sha256.Size]byte
	Fence       TaskFence
	Identity    IdentityClaims
	SessionID   string
	TokenDigest [sha256.Size]byte
	At          time.Time
}

type SessionMutation struct {
	SessionID        string
	TokenDigest      [sha256.Size]byte
	Fence            TaskFence
	ProgressSequence uint64
	Claim            *ObjectClaim
	RuntimeTopology  *execgate.Proof
	TopologyDigest   string
	FailureCode      string
	FailureSummary   string
	IdempotencyKey   string
	RequestDigest    string
	At               time.Time
}

type SessionFenceMutation struct {
	Fence  TaskFence
	Reason string
	At     time.Time
}

type Store interface {
	CreateChallenge(context.Context, ChallengeRecord) error
	GetChallenge(context.Context, string) (ChallengeRecord, error)
	// Claim and every session mutation must revalidate the authoritative
	// CoreTask attempt/lease epoch in the same transaction as the write.  The
	// Service pre-check is an early rejection only and is not a TOCTOU-safe
	// authorization boundary. Claim must also atomically supersede any active
	// session for the same fence before creating its replacement.
	Claim(context.Context, ClaimMutation) (Session, error)
	Heartbeat(context.Context, SessionMutation) (Session, error)
	Complete(context.Context, SessionMutation) (Session, error)
	Fail(context.Context, SessionMutation) (Session, error)
	GetSession(context.Context, string) (Session, error)
	FindSessionByFence(context.Context, TaskFence) (Session, error)
	FindLatestSessionByExecution(context.Context, string, string, uint64) (Session, error)
	// FenceSession is the token-independent controller cancellation boundary.
	// Production stores must lock/revalidate the owning CoreTask and atomically
	// make every active session for Fence terminal before cleanup can start.
	FenceSession(context.Context, SessionFenceMutation) (Session, error)
	FenceExecutionSessions(context.Context, coretask.Task, string, string) (Session, error)
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == strings.TrimSpace(value)
}

func validIdempotencyKey(value string) bool { return validUUID(value) }

func digestToken(value []byte) [sha256.Size]byte { return sha256.Sum256(value) }

func equalDigest(a, b [sha256.Size]byte) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }

func validateProof(proof IdentityProof) error {
	if proof.Method != identitywire.MethodSTSSigV4IMDSPKCS7V1 || len(proof.Payload) == 0 || len(proof.Payload) > maximumProofBytes {
		return ErrInvalid
	}
	return nil
}

func validateClaims(expectation IdentityExpectation, claims IdentityClaims) error {
	if claims.AccountGeneration != expectation.AccountGeneration || claims.AccountID != expectation.AccountID || claims.Region != expectation.Region ||
		claims.InstanceID != expectation.InstanceID || claims.LaunchIdentity != expectation.LaunchIdentity || claims.RoleARN != expectation.RoleARN ||
		claims.RoleID != expectation.RoleID || claims.InstanceProfileID != expectation.InstanceProfileID {
		return ErrIdentityRejected
	}
	for key, expected := range expectation.RequiredTags {
		if claims.Tags[key] != expected {
			return ErrIdentityRejected
		}
	}
	return nil
}

func normalizeFailure(code, summary string) (string, string, error) {
	code = strings.TrimSpace(code)
	summary = strings.TrimSpace(summary)
	if code == "" || len(code) > 64 || len(summary) > 512 || security.ContainsLikelySecret(code) || security.ContainsLikelySecret(summary) {
		return "", "", ErrInvalid
	}
	for _, r := range code {
		if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return "", "", ErrInvalid
		}
	}
	return code, summary, nil
}

func redactedVerifierError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w", ErrIdentityRejected)
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

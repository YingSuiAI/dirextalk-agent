// Package result verifies version-pinned Cloud Worker objects before any
// result is accepted by the Agent control plane.
package result

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

const MaxObjectBytes = cloudruntime.MaxArtifactBytes

var (
	ErrInvalid     = errors.New("invalid cloud Worker result")
	ErrUnavailable = errors.New("cloud Worker result object unavailable")

	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

type ObjectClaim struct {
	Name      string `json:"name"`
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
}

func (claim ObjectClaim) Validate() error {
	if !namePattern.MatchString(claim.Name) || !validBucket(claim.Bucket) ||
		!validKey(claim.Key) || !validVersionID(claim.VersionID) ||
		!validDigest(claim.SHA256) || claim.SizeBytes < 1 ||
		claim.SizeBytes > MaxObjectBytes || !validMediaType(claim.MediaType) {
		return ErrInvalid
	}
	return nil
}

type Scope struct {
	Bucket    string
	KeyPrefix string
}

func (scope Scope) Validate() error {
	if !validBucket(scope.Bucket) || scope.KeyPrefix == "" ||
		strings.HasPrefix(scope.KeyPrefix, "/") ||
		!strings.HasSuffix(scope.KeyPrefix, "/") ||
		!validKey(scope.KeyPrefix+"scope-probe") {
		return ErrInvalid
	}
	return nil
}

func (scope Scope) Contains(claim ObjectClaim) bool {
	if scope.Validate() != nil || claim.Validate() != nil ||
		claim.Bucket != scope.Bucket || !strings.HasPrefix(claim.Key, scope.KeyPrefix) {
		return false
	}
	relative := strings.TrimPrefix(claim.Key, scope.KeyPrefix)
	return relative != "" && !strings.Contains(relative, "..")
}

type ObjectRequest struct {
	Bucket       string
	Key          string
	VersionID    string
	MaximumBytes int64
}

// ObjectRead repeats immutable identity and metadata from the backing store.
// A production S3 adapter must set all fields from GetObject output and issue
// the request with VersionId, never a latest-version read.
type ObjectRead struct {
	Bucket    string
	Key       string
	VersionID string
	SizeBytes int64
	MediaType string
	Body      io.ReadCloser
}

type ObjectReader interface {
	ReadObject(context.Context, ObjectRequest) (ObjectRead, error)
}

type VerifiedObject struct {
	Claim   ObjectClaim
	Content []byte
}

func (object *VerifiedObject) Destroy() {
	if object == nil {
		return
	}
	clear(object.Content)
	*object = VerifiedObject{}
}

type Verifier struct {
	reader ObjectReader
	scope  Scope
}

func NewVerifier(reader ObjectReader, scope Scope) (*Verifier, error) {
	if reader == nil || scope.Validate() != nil {
		return nil, ErrInvalid
	}
	return &Verifier{reader: reader, scope: scope}, nil
}

func (verifier *Verifier) Verify(ctx context.Context, claim ObjectClaim) (VerifiedObject, error) {
	if verifier == nil || ctx == nil || !verifier.scope.Contains(claim) {
		return VerifiedObject{}, ErrInvalid
	}
	read, err := verifier.reader.ReadObject(ctx, ObjectRequest{
		Bucket: claim.Bucket, Key: claim.Key,
		VersionID: claim.VersionID, MaximumBytes: claim.SizeBytes,
	})
	if err != nil {
		return VerifiedObject{}, ErrUnavailable
	}
	if read.Body == nil {
		return VerifiedObject{}, ErrInvalid
	}
	defer read.Body.Close()
	if read.Bucket != claim.Bucket || read.Key != claim.Key ||
		read.VersionID != claim.VersionID || read.SizeBytes != claim.SizeBytes ||
		read.MediaType != claim.MediaType {
		return VerifiedObject{}, ErrInvalid
	}
	content, err := io.ReadAll(io.LimitReader(
		&contextReader{ctx: ctx, reader: read.Body},
		claim.SizeBytes+1,
	))
	if err != nil {
		clear(content)
		if ctx.Err() != nil {
			return VerifiedObject{}, errors.Join(ErrUnavailable, ctx.Err())
		}
		return VerifiedObject{}, ErrUnavailable
	}
	if int64(len(content)) != claim.SizeBytes {
		clear(content)
		return VerifiedObject{}, ErrInvalid
	}
	expected, err := hex.DecodeString(claim.SHA256)
	if err != nil || len(expected) != sha256.Size {
		clear(content)
		clear(expected)
		return VerifiedObject{}, ErrInvalid
	}
	actual := sha256.Sum256(content)
	valid := subtle.ConstantTimeCompare(actual[:], expected) == 1
	clear(expected)
	if !valid {
		clear(content)
		return VerifiedObject{}, ErrInvalid
	}
	return VerifiedObject{Claim: claim, Content: content}, nil
}

func (verifier *Verifier) Scope() Scope {
	if verifier == nil {
		return Scope{}
	}
	return verifier.scope
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(target []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(target)
	}
}

func validBucket(value string) bool {
	if !bucketPattern.MatchString(value) || strings.Contains(value, "..") ||
		strings.HasPrefix(value, "xn--") || strings.HasSuffix(value, "-s3alias") ||
		strings.HasSuffix(value, "--ol-s3") {
		return false
	}
	return net.ParseIP(value) == nil
}

func validKey(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") ||
		strings.Contains(value, "\\") || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validVersionID(value string) bool {
	if value == "" || value == "null" || len(value) > 1024 ||
		value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	valid := err == nil && len(decoded) == sha256.Size &&
		hex.EncodeToString(decoded) == value
	clear(decoded)
	return valid
}

func validMediaType(value string) bool {
	switch value {
	case "application/json", "text/plain; charset=utf-8", "application/gzip":
		return true
	default:
		return false
	}
}

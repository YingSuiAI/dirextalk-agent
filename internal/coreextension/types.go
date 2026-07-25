// Package coreextension defines the Core v1 MCP/Skill installation contract.
// It is intentionally independent of persistence, RPC and the extension runner.
package coreextension

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	coreconfirmation "github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/google/uuid"
)

type Task struct {
	ID                 string
	State              string
	Revision           int64
	Attempt            uint32
	LeaseEpoch         uint64
	TerminalAttempt    uint32
	TerminalLeaseEpoch uint64
	TerminalRevision   int64
	FailureCode        string
}
type TaskRequest struct {
	IdempotencyKey   string
	TaskID           string
	Goal             string
	TargetID         string
	ExpectedRevision int64
}
type LifecycleRequest struct {
	Installation Installation
	Task         TaskRequest
	Confirmation coreconfirmation.RequestCommand
	Operation    string
}

const (
	OperationInstall   = "install"
	OperationUpdate    = "update"
	OperationUninstall = "uninstall"
)

type LifecycleCoordinator interface {
	RequestLifecycle(context.Context, LifecycleRequest) (MutationResult, error)
}

type Kind string

const (
	KindMCP   Kind = "mcp"
	KindSkill Kind = "skill"
)

type Source string

const (
	SourceOfficialRegistry Source = "official_registry"
	SourceSmithery         Source = "smithery"
	SourceGlama            Source = "glama"
	SourceGitHub           Source = "github"
	SourceSkillsSh         Source = "skills_sh"
)

type Transport string

const (
	TransportStdioStatic    Transport = "stdio_static"
	TransportStreamableHTTP Transport = "streamable_http"
	TransportSkillStatic    Transport = "skill_static"
)

type State string

const (
	StateDraft        State = "draft"
	StateInstalling   State = "installing"
	StateInstalled    State = "installed"
	StateUpdating     State = "updating"
	StateUninstalling State = "uninstalling"
	StateRemoved      State = "removed"
	StateFailed       State = "failed"
)

var (
	ErrInvalid             = errors.New("invalid extension")
	ErrNotFound            = errors.New("extension not found")
	ErrConflict            = errors.New("extension conflict")
	ErrIdempotencyConflict = errors.New("extension idempotency conflict")
	ErrRevisionConflict    = errors.New("extension revision conflict")
)

var shaRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validDigest(s string) bool { return shaRE.MatchString(s) }
func validUUID(s string) bool   { _, e := uuid.Parse(strings.TrimSpace(s)); return e == nil }

// SourcePin must identify an immutable registry release or Git commit.
type SourcePin struct {
	RegistryVersion string `json:"registry_version,omitempty"`
	RegistrySHA256  string `json:"registry_sha256,omitempty"`
	GitCommit       string `json:"git_commit,omitempty"`
	GitSHA256       string `json:"git_sha256,omitempty"`
}

func (p SourcePin) Validate() error {
	reg := p.RegistryVersion != "" || p.RegistrySHA256 != ""
	git := p.GitCommit != "" || p.GitSHA256 != ""
	if reg == git {
		return ErrInvalid
	}
	if reg {
		if strings.TrimSpace(p.RegistryVersion) == "" || strings.EqualFold(p.RegistryVersion, "latest") || !validDigest(p.RegistrySHA256) {
			return ErrInvalid
		}
	}
	if git {
		if !commitRE.MatchString(p.GitCommit) || !validDigest(p.GitSHA256) {
			return ErrInvalid
		}
	}
	return nil
}

type StaticEntry struct {
	RelativePath string   `json:"relative_path"`
	Digest       string   `json:"digest"`
	Argv         []string `json:"argv"`
}
type RemoteEndpoint struct {
	URL                   string `json:"url"`
	CredentialReferenceID string `json:"credential_reference_id"`
}
type SkillEntry struct {
	RelativePath string   `json:"relative_path"`
	Digest       string   `json:"digest"`
	Executable   bool     `json:"executable,omitempty"`
	Argv         []string `json:"argv,omitempty"`
}

// ExecutionDescriptor is a closed union. Exactly one branch is allowed.
type ExecutionDescriptor struct {
	Stdio  *StaticEntry    `json:"stdio,omitempty"`
	Remote *RemoteEndpoint `json:"remote,omitempty"`
	Skill  *SkillEntry     `json:"skill,omitempty"`
}

func (e ExecutionDescriptor) Validate(kind Kind, transport Transport) error {
	n := 0
	if e.Stdio != nil {
		n++
	}
	if e.Remote != nil {
		n++
	}
	if e.Skill != nil {
		n++
	}
	if n != 1 {
		return ErrInvalid
	}
	switch transport {
	case TransportStdioStatic:
		if kind != KindMCP || e.Stdio == nil || !validStatic(*e.Stdio) {
			return ErrInvalid
		}
	case TransportStreamableHTTP:
		if kind != KindMCP || e.Remote == nil || !validRemote(*e.Remote) {
			return ErrInvalid
		}
	case TransportSkillStatic:
		if kind != KindSkill || e.Skill == nil || !validSkill(*e.Skill) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func validPath(p string) bool {
	return p != "" && !strings.HasPrefix(p, "/") && !strings.Contains(p, "..") && !strings.ContainsAny(p, "\\\x00\r\n")
}
func validStatic(s StaticEntry) bool {
	if !validPath(s.RelativePath) || !validDigest(s.Digest) || len(s.Argv) == 0 {
		return false
	}
	for _, a := range s.Argv {
		if a == "" || strings.ContainsAny(a, "\r\n") {
			return false
		}
	}
	return true
}
func validSkill(s SkillEntry) bool {
	if !validPath(s.RelativePath) || !validDigest(s.Digest) {
		return false
	}
	if !s.Executable {
		return len(s.Argv) == 0
	}
	if s.RelativePath != "entry" || len(s.Argv) == 0 || len(s.Argv) > 128 {
		return false
	}
	for _, arg := range s.Argv {
		if strings.IndexByte(arg, 0) >= 0 || len(arg) > 16<<10 {
			return false
		}
	}
	return true
}
func validRemote(r RemoteEndpoint) bool {
	u, e := url.Parse(r.URL)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.Host == strings.ToLower(u.Host) && validUUID(r.CredentialReferenceID) && u.User == nil && u.Fragment == "" && u.RawQuery == "" && !strings.Contains(u.Path, "..")
}

type NetworkGrant struct {
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Port       uint32 `json:"port"`
	PathPrefix string `json:"path_prefix"`
	Digest     string `json:"digest"`
}

func (g NetworkGrant) Validate() error {
	if g.Scheme != "https" && g.Scheme != "http" {
		return ErrInvalid
	}
	if g.Host == "" || len(g.Host) > 253 || g.Host != strings.TrimSpace(g.Host) || !isASCII(g.Host) {
		return ErrInvalid
	}
	if net.ParseIP(g.Host) == nil && strings.ContainsAny(g.Host, " /\\") {
		return ErrInvalid
	}
	if g.Port == 0 || g.Port > 65535 || !strings.HasPrefix(g.PathPrefix, "/") || !validDigest(g.Digest) {
		return ErrInvalid
	}
	return nil
}
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

type SecretPurpose string

const (
	SecretPurposeMCPCredential SecretPurpose = "mcp_credential"
	SecretPurposeSkillSecret   SecretPurpose = "skill_secret"
)

type SecretInput struct {
	ReferenceID string        `json:"reference_id"`
	Purpose     SecretPurpose `json:"purpose"`
	Value       string        `json:"-"`
}

func (s SecretInput) Validate() error {
	if !validUUID(s.ReferenceID) || (s.Purpose != SecretPurposeMCPCredential && s.Purpose != SecretPurposeSkillSecret) || s.Value == "" {
		return ErrInvalid
	}
	return nil
}
func (s SecretInput) Fingerprint() string {
	h := sha256.Sum256([]byte(s.Value))
	return hex.EncodeToString(h[:])
}
func (s SecretInput) String() string {
	return fmt.Sprintf("SecretInput{reference_id:%s purpose:%s value:<redacted>}", s.ReferenceID, s.Purpose)
}
func (s SecretInput) GoString() string { return s.String() }

type SecretGrantDescriptor struct {
	ReferenceID   string        `json:"reference_id"`
	Purpose       SecretPurpose `json:"purpose"`
	BindingDigest string        `json:"binding_digest"`
	Configured    bool          `json:"configured"`
}

func (s SecretGrantDescriptor) Validate() error {
	if !validUUID(s.ReferenceID) || (s.Purpose != SecretPurposeMCPCredential && s.Purpose != SecretPurposeSkillSecret) || !validDigest(s.BindingDigest) {
		return ErrInvalid
	}
	return nil
}

type Candidate struct {
	ID          string    `json:"id"`
	Kind        Kind      `json:"kind"`
	Source      Source    `json:"source"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Pin         SourcePin `json:"pin"`
	Transport   Transport `json:"transport"`
}

func equalCandidate(a, b Candidate) bool {
	return a.ID == b.ID && a.Kind == b.Kind && a.Source == b.Source && a.Name == b.Name && a.Description == b.Description && a.Transport == b.Transport && a.Pin == b.Pin
}

func (c Candidate) Validate() error {
	if c.ID == "" || c.Name == "" || !validKindSource(c.Kind, c.Source) || c.Pin.Validate() != nil || !validTransport(c.Kind, c.Transport) {
		return ErrInvalid
	}
	if c.Source == SourceGitHub {
		if c.Pin.GitCommit == "" {
			return ErrInvalid
		}
	} else if c.Pin.RegistryVersion == "" {
		return ErrInvalid
	}
	return nil
}

type Inspection struct {
	Candidate           Candidate               `json:"candidate"`
	ContentDigest       string                  `json:"content_digest"`
	ManifestDigest      string                  `json:"manifest_digest"`
	ExecutionDigest     string                  `json:"execution_digest"`
	NetworkSchemaDigest string                  `json:"network_schema_digest"`
	SecretSchemaDigest  string                  `json:"secret_schema_digest"`
	Execution           ExecutionDescriptor     `json:"execution"`
	NetworkGrants       []NetworkGrant          `json:"network_grants"`
	SecretGrants        []SecretGrantDescriptor `json:"secret_grants"`
}

func (i Inspection) Validate() error {
	if i.Candidate.Validate() != nil || !validDigest(i.ContentDigest) || !validDigest(i.ManifestDigest) || !validDigest(i.ExecutionDigest) || !validDigest(i.NetworkSchemaDigest) || !validDigest(i.SecretSchemaDigest) || i.Execution.Validate(i.Candidate.Kind, i.Candidate.Transport) != nil {
		return ErrInvalid
	}
	for _, g := range i.NetworkGrants {
		if g.Validate() != nil {
			return ErrInvalid
		}
	}
	if i.Candidate.Transport != TransportStreamableHTTP && len(i.NetworkGrants) > 0 {
		return ErrInvalid
	}
	for _, g := range i.SecretGrants {
		if g.Validate() != nil {
			return ErrInvalid
		}
	}
	for _, g := range i.NetworkGrants {
		if g.Validate() != nil {
			return ErrInvalid
		}
	}
	if i.Candidate.Transport == TransportStreamableHTTP && i.Execution.Remote != nil {
		u, _ := url.Parse(i.Execution.Remote.URL)
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		port := uint32(443)
		if u.Port() != "" {
			port = 0
			for _, c := range u.Port() {
				port = port*10 + uint32(c-'0')
			}
		}
		matched := false
		for _, g := range i.NetworkGrants {
			if g.Scheme == u.Scheme && g.Host == u.Hostname() && g.Port == port && g.PathPrefix == path {
				matched = true
			}
		}
		if !matched {
			return ErrInvalid
		}
		secretMatched := false
		for _, g := range i.SecretGrants {
			if g.ReferenceID == i.Execution.Remote.CredentialReferenceID {
				secretMatched = true
			}
		}
		if !secretMatched {
			return ErrInvalid
		}
	}
	return nil
}

type FetchArtifact struct {
	Candidate      Candidate  `json:"candidate"`
	Content        []byte     `json:"-"`
	ContentDigest  string     `json:"content_digest"`
	ManifestDigest string     `json:"manifest_digest"`
	Inspection     Inspection `json:"inspection"`
}

func (f FetchArtifact) Validate() error {
	if f.Inspection.Validate() != nil || f.Candidate.ID != f.Inspection.Candidate.ID || !validDigest(f.ContentDigest) || f.ContentDigest != digestBytes(f.Content) {
		return ErrInvalid
	}
	return nil
}
func digestBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type VersionRecord struct {
	VersionID           string                  `json:"version_id"`
	Pin                 SourcePin               `json:"pin"`
	ContentDigest       string                  `json:"content_digest"`
	ManifestDigest      string                  `json:"manifest_digest"`
	ExecutionDigest     string                  `json:"execution_digest"`
	NetworkSchemaDigest string                  `json:"network_schema_digest"`
	SecretSchemaDigest  string                  `json:"secret_schema_digest"`
	Execution           ExecutionDescriptor     `json:"execution"`
	Tools               []Tool                  `json:"tools,omitempty"`
	NetworkGrants       []NetworkGrant          `json:"network_grants,omitempty"`
	SecretGrants        []SecretGrantDescriptor `json:"secret_grants,omitempty"`
	ArtifactPath        string                  `json:"artifact_path,omitempty"`
	ArtifactDigest      string                  `json:"artifact_digest,omitempty"`
	CreatedAt           time.Time               `json:"created_at"`
}
type Installation struct {
	ID                string                  `json:"id"`
	Candidate         Candidate               `json:"candidate"`
	Kind              Kind                    `json:"kind"`
	Source            Source                  `json:"source"`
	CandidateID       string                  `json:"candidate_id"`
	Name              string                  `json:"name"`
	Description       string                  `json:"description,omitempty"`
	Transport         Transport               `json:"transport"`
	Revision          int64                   `json:"revision"`
	State             State                   `json:"state"`
	ActiveVersionID   string                  `json:"active_version_id,omitempty"`
	ProposedVersionID string                  `json:"proposed_version_id,omitempty"`
	Versions          []VersionRecord         `json:"versions,omitempty"`
	NetworkGrants     []NetworkGrant          `json:"network_grants,omitempty"`
	SecretGrants      []SecretGrantDescriptor `json:"secret_grants,omitempty"`
	CreatedAt         time.Time               `json:"created_at"`
	UpdatedAt         time.Time               `json:"updated_at"`
}

// LifecycleRecord is the durable proposal/fence snapshot used to complete a
// confirmation-bound install, update, or uninstall exactly once.
type LifecycleRecord struct {
	InstallationID       string
	Operation            string
	ConfirmationID       string
	TaskID               string
	Binding              coreconfirmation.Binding
	AcquiredAttempt      uint32
	AcquiredLeaseEpoch   uint64
	AcquiredTaskRevision int64
	TerminalAttempt      uint32
	TerminalLeaseEpoch   uint64
	TerminalTaskRevision int64
	State                string
	RequestDigest        string
	CompletionDigest     string
	ExpectedRevision     int64
}

func (i Installation) Validate() error {
	if !validUUID(i.ID) || i.Candidate.Validate() != nil || i.Candidate.ID != i.CandidateID || i.Candidate.Kind != i.Kind || i.Candidate.Source != i.Source || i.Candidate.Name != i.Name || i.Candidate.Description != i.Description || i.Candidate.Transport != i.Transport || !validKindSource(i.Kind, i.Source) || i.CandidateID == "" || i.Name == "" || i.Revision < 1 || !validState(i.State) || !validTransport(i.Kind, i.Transport) {
		return ErrInvalid
	}
	for _, v := range i.Versions {
		if v.Pin.Validate() != nil || !validDigest(v.ContentDigest) || !validDigest(v.ManifestDigest) || !validDigest(v.ExecutionDigest) || !validDigest(v.NetworkSchemaDigest) || !validDigest(v.SecretSchemaDigest) || v.Execution.Validate(i.Kind, transportFor(i.Kind, v.Execution)) != nil {
			return ErrInvalid
		}
		for _, g := range v.NetworkGrants {
			if g.Validate() != nil {
				return ErrInvalid
			}
		}
		for _, g := range v.SecretGrants {
			if g.Validate() != nil || !g.Configured {
				return ErrInvalid
			}
		}
		if (v.ArtifactPath == "") != (v.ArtifactDigest == "") || v.ArtifactDigest != "" && !validDigest(v.ArtifactDigest) {
			return ErrInvalid
		}
	}
	for _, g := range i.SecretGrants {
		if g.Validate() != nil {
			return ErrInvalid
		}
	}
	if (i.State == StateInstalling || i.State == StateUpdating) && i.ProposedVersionID == "" {
		return ErrInvalid
	}
	if i.State == StateInstalled && i.ActiveVersionID == "" {
		return ErrInvalid
	}
	return nil
}
func transportFor(k Kind, e ExecutionDescriptor) Transport {
	if k == KindSkill {
		return TransportSkillStatic
	}
	if e.Remote != nil {
		return TransportStreamableHTTP
	}
	return TransportStdioStatic
}
func validKindSource(k Kind, s Source) bool {
	switch k {
	case KindMCP:
		return s == SourceOfficialRegistry || s == SourceSmithery || s == SourceGlama || s == SourceGitHub
	case KindSkill:
		return s == SourceSkillsSh || s == SourceGitHub
	}
	return false
}
func validTransport(k Kind, t Transport) bool {
	return (k == KindMCP && (t == TransportStdioStatic || t == TransportStreamableHTTP)) || (k == KindSkill && t == TransportSkillStatic)
}
func validState(s State) bool {
	switch s {
	case StateDraft, StateInstalling, StateInstalled, StateUpdating, StateUninstalling, StateRemoved, StateFailed:
		return true
	}
	return false
}
func (i Installation) Redacted() Installation {
	x := i
	x.SecretGrants = append([]SecretGrantDescriptor(nil), i.SecretGrants...)
	return x
}
func (i Installation) String() string   { b, _ := json.Marshal(i.Redacted()); return string(b) }
func (i Installation) GoString() string { return i.String() }

type SearchQuery struct {
	Kind      Kind
	Source    Source
	Text      string
	PageSize  int
	PageToken string
}
type Page struct {
	Candidates    []Candidate
	NextPageToken string
}
type InspectRequest struct {
	Kind   Kind
	Source Source
	ID     string
	Pin    SourcePin
}
type Mutation struct {
	IdempotencyKey   string
	InstallationID   string
	ExpectedRevision int64
	Candidate        Candidate
	Inspection       Inspection
	SecretInputs     []SecretInput
	ArtifactPath     string
	ArtifactDigest   string
}
type MutationResult struct {
	Installation   Installation
	ConfirmationID string
	TaskID         string
}
type ExecuteRequest struct {
	InstallationID   string
	ExpectedRevision int64
	ToolName         string
	Input            json.RawMessage
	IdempotencyKey   string
}
type ExecuteResult struct{ TaskID string }

type SourceAdapter interface {
	Search(context.Context, SearchQuery) (Page, error)
	Inspect(context.Context, InspectRequest) (Inspection, error)
	Fetch(context.Context, Candidate) (FetchArtifact, error)
}

type ArtifactReceipt struct {
	RelativePath string
	Digest       string
}
type ArtifactStore interface {
	Materialize(context.Context, FetchArtifact) (ArtifactReceipt, error)
	Remove(context.Context, ArtifactReceipt) error
}

// LifecycleArtifactPromoter is the post-confirmation publication boundary.
// Implementations must make Promote/Remove idempotent and bind both operations
// to the immutable version's staged artifact digest.
type LifecycleArtifactPromoter interface {
	Promote(context.Context, VersionRecord) error
	Remove(context.Context, VersionRecord) error
}
type SecretReceipt struct {
	ReferenceID string
	Purpose     SecretPurpose
	Fingerprint string
}
type SecretStore interface {
	Bind(context.Context, []SecretInput) ([]SecretReceipt, error)
}

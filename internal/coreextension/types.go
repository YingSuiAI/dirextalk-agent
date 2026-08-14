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
	SourceBuiltin          Source = "builtin"
	SourceNPM              Source = "npm"
)

type Transport string

const (
	TransportStdioStatic    Transport = "stdio_static"
	TransportStreamableHTTP Transport = "streamable_http"
	TransportSkillStatic    Transport = "skill_static"
	TransportStdioNode      Transport = "stdio_node"
)

const (
	MaxInstallations          = 32
	MaxNodeSourceBytes        = uint64(64 << 20)
	MaxNodeArtifactBytes      = uint64(64 << 20)
	MaxNodeStorageBytes       = uint64(512 << 20)
	MaxNodeArtifactFiles      = uint32(8192)
	MaxNodeInstallConcurrency = 1
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
	ErrInstallBusy         = errors.New("extension install busy")
	ErrInstallationLimit   = errors.New("extension installation limit")
	ErrNodeStorageQuota    = errors.New("extension node storage quota")
)

const (
	BuiltinLocalSandboxCandidateID = "dirextalk-local-sandbox"
	BuiltinLocalSandboxToolName    = "local_sandbox_run"
)

func BuiltinMCPInstallationID(candidateID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:builtin-mcp:installation:"+candidateID)).String()
}

var shaRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
var exactSemverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var npmNamePartRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func validDigest(s string) bool { return shaRE.MatchString(s) }
func validUUID(s string) bool   { _, e := uuid.Parse(strings.TrimSpace(s)); return e == nil }

func validExactSemver(value string) bool {
	match := exactSemverRE.FindStringSubmatch(value)
	if match == nil {
		return false
	}
	if match[4] == "" {
		return true
	}
	for _, identifier := range strings.Split(match[4], ".") {
		if len(identifier) > 1 && identifier[0] == '0' {
			numeric := true
			for _, char := range identifier {
				if char < '0' || char > '9' {
					numeric = false
					break
				}
			}
			if numeric {
				return false
			}
		}
	}
	return true
}

func validNPMPackageName(value string) bool {
	if value == "" || len(value) > 214 || value != strings.ToLower(value) || strings.Contains(value, "..") {
		return false
	}
	if strings.HasPrefix(value, "@") {
		parts := strings.Split(value[1:], "/")
		return len(parts) == 2 && npmNamePartRE.MatchString(parts[0]) && npmNamePartRE.MatchString(parts[1])
	}
	return !strings.Contains(value, "/") && npmNamePartRE.MatchString(value)
}

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
	Runtime      string   `json:"runtime,omitempty"`
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
		if kind != KindMCP || e.Stdio == nil || !validStatic(*e.Stdio) || e.Stdio.Runtime != "" {
			return ErrInvalid
		}
	case TransportStdioNode:
		if kind != KindMCP || e.Stdio == nil || !validNodeStatic(*e.Stdio) {
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
func validNodeStatic(s StaticEntry) bool {
	if !validPath(s.RelativePath) || !validDigest(s.Digest) || s.Runtime != "node" || len(s.Argv) > 128 {
		return false
	}
	for _, a := range s.Argv {
		if a == "" || strings.ContainsAny(a, "\x00\r\n") || len(a) > 16<<10 {
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
	return e == nil && u.Scheme == "https" && u.Host != "" && u.Host == strings.ToLower(u.Host) && (r.CredentialReferenceID == "" || validUUID(r.CredentialReferenceID)) && u.User == nil && u.Fragment == "" && u.RawQuery == "" && !strings.Contains(u.Path, "..")
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
	if c.Transport == TransportStdioNode {
		if c.Kind != KindMCP || c.Source != SourceGitHub && c.Source != SourceNPM {
			return ErrInvalid
		}
		if c.Source == SourceNPM && (!validNPMPackageName(c.ID) || !validExactSemver(c.Pin.RegistryVersion)) {
			return ErrInvalid
		}
	} else if c.Source == SourceNPM {
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
		credentialRef := i.Execution.Remote.CredentialReferenceID
		if credentialRef == "" {
			for _, g := range i.SecretGrants {
				if g.Purpose == SecretPurposeMCPCredential {
					return ErrInvalid
				}
			}
		} else {
			secretMatched := false
			for _, g := range i.SecretGrants {
				if g.ReferenceID == credentialRef && g.Purpose == SecretPurposeMCPCredential {
					secretMatched = true
				}
			}
			if !secretMatched {
				return ErrInvalid
			}
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
	VersionID            string                  `json:"version_id"`
	Pin                  SourcePin               `json:"pin"`
	ContentDigest        string                  `json:"content_digest"`
	ManifestDigest       string                  `json:"manifest_digest"`
	ExecutionDigest      string                  `json:"execution_digest"`
	NetworkSchemaDigest  string                  `json:"network_schema_digest"`
	SecretSchemaDigest   string                  `json:"secret_schema_digest"`
	Execution            ExecutionDescriptor     `json:"execution"`
	Tools                []Tool                  `json:"tools,omitempty"`
	NetworkGrants        []NetworkGrant          `json:"network_grants,omitempty"`
	SecretGrants         []SecretGrantDescriptor `json:"secret_grants,omitempty"`
	ArtifactPath         string                  `json:"artifact_path,omitempty"`
	ArtifactDigest       string                  `json:"artifact_digest,omitempty"`
	ArtifactCleanupToken string                  `json:"artifact_cleanup_token,omitempty"`
	NodeArtifact         *NodeArtifactReceipt    `json:"node_artifact,omitempty"`
	PublishedAt          time.Time               `json:"published_at,omitempty"`
	CreatedAt            time.Time               `json:"created_at"`
}
type Installation struct {
	ID          string    `json:"id"`
	Candidate   Candidate `json:"candidate"`
	Kind        Kind      `json:"kind"`
	Source      Source    `json:"source"`
	CandidateID string    `json:"candidate_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Transport   Transport `json:"transport"`
	Revision    int64     `json:"revision"`
	State       State     `json:"state"`
	// Enabled is the durable execution gate for an installed extension. A
	// successful first install enables the extension by default; disabling is
	// a revision-bound mutation and never removes the immutable version.
	Enabled           bool                    `json:"enabled"`
	ActiveVersionID   string                  `json:"active_version_id,omitempty"`
	ProposedVersionID string                  `json:"proposed_version_id,omitempty"`
	Versions          []VersionRecord         `json:"versions,omitempty"`
	NetworkGrants     []NetworkGrant          `json:"network_grants,omitempty"`
	SecretGrants      []SecretGrantDescriptor `json:"secret_grants,omitempty"`
	CreatedAt         time.Time               `json:"created_at"`
	UpdatedAt         time.Time               `json:"updated_at"`
}

type PublicNodeArtifactReceipt struct {
	PackageName              string `json:"package_name"`
	PackageVersion           string `json:"package_version"`
	ArtifactBytes            uint64 `json:"artifact_bytes"`
	FileCount                uint32 `json:"file_count"`
	NodeVersion              string `json:"node_version"`
	NPMVersion               string `json:"npm_version"`
	LifecycleScriptsDisabled bool   `json:"lifecycle_scripts_disabled"`
	NativeAddonsAbsent       bool   `json:"native_addons_absent"`
}

type PublicVersionRecord struct {
	VersionID           string                     `json:"version_id"`
	Pin                 SourcePin                  `json:"pin"`
	ContentDigest       string                     `json:"content_digest"`
	ManifestDigest      string                     `json:"manifest_digest"`
	ExecutionDigest     string                     `json:"execution_digest"`
	NetworkSchemaDigest string                     `json:"network_schema_digest"`
	SecretSchemaDigest  string                     `json:"secret_schema_digest"`
	Execution           ExecutionDescriptor        `json:"execution"`
	NetworkGrants       []NetworkGrant             `json:"network_grants"`
	SecretGrants        []SecretGrantDescriptor    `json:"secret_grants"`
	NodeArtifact        *PublicNodeArtifactReceipt `json:"node_artifact,omitempty"`
	CreatedAt           time.Time                  `json:"created_at"`
}

type PublicInstallation struct {
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
	Enabled           bool                    `json:"enabled"`
	ActiveVersionID   string                  `json:"active_version_id,omitempty"`
	ProposedVersionID string                  `json:"proposed_version_id,omitempty"`
	Versions          []PublicVersionRecord   `json:"versions,omitempty"`
	NetworkGrants     []NetworkGrant          `json:"network_grants"`
	SecretGrants      []SecretGrantDescriptor `json:"secret_grants"`
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
		if v.Pin.Validate() != nil || !validDigest(v.ContentDigest) || !validDigest(v.ManifestDigest) || !validDigest(v.ExecutionDigest) || !validDigest(v.NetworkSchemaDigest) || !validDigest(v.SecretSchemaDigest) || v.Execution.Validate(i.Kind, i.Transport) != nil {
			return ErrInvalid
		}
		if i.Transport == TransportStdioNode {
			if v.NodeArtifact == nil || !validUUID(v.ArtifactCleanupToken) || v.NodeArtifact.Validate(i.Candidate, v.Execution, v.ArtifactDigest) != nil {
				return ErrInvalid
			}
		} else if v.NodeArtifact != nil {
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
func validKindSource(k Kind, s Source) bool {
	switch k {
	case KindMCP:
		return s == SourceOfficialRegistry || s == SourceSmithery || s == SourceGlama || s == SourceGitHub || s == SourceNPM || s == SourceBuiltin
	case KindSkill:
		return s == SourceSkillsSh || s == SourceGitHub || s == SourceBuiltin
	}
	return false
}
func validTransport(k Kind, t Transport) bool {
	return (k == KindMCP && (t == TransportStdioStatic || t == TransportStreamableHTTP || t == TransportStdioNode)) || (k == KindSkill && t == TransportSkillStatic)
}
func validState(s State) bool {
	switch s {
	case StateDraft, StateInstalling, StateInstalled, StateUpdating, StateUninstalling, StateRemoved, StateFailed:
		return true
	}
	return false
}
func (i Installation) Redacted() Installation {
	x := cloneInstallation(i)
	for index := range x.Versions {
		x.Versions[index].ArtifactPath = ""
		x.Versions[index].ArtifactCleanupToken = ""
		x.Versions[index].NodeArtifact = nil
	}
	return x
}
func (i Installation) Public() PublicInstallation {
	x := cloneInstallation(i)
	out := PublicInstallation{ID: x.ID, Candidate: x.Candidate, Kind: x.Kind, Source: x.Source, CandidateID: x.CandidateID, Name: x.Name, Description: x.Description, Transport: x.Transport, Revision: x.Revision, State: x.State, Enabled: x.Enabled, ActiveVersionID: x.ActiveVersionID, ProposedVersionID: x.ProposedVersionID, NetworkGrants: append([]NetworkGrant{}, x.NetworkGrants...), SecretGrants: append([]SecretGrantDescriptor{}, x.SecretGrants...), CreatedAt: x.CreatedAt, UpdatedAt: x.UpdatedAt}
	for _, version := range x.Versions {
		execution := cloneExecution(version.Execution)
		if execution.Stdio != nil && execution.Stdio.Argv == nil {
			execution.Stdio.Argv = []string{}
		}
		publicVersion := PublicVersionRecord{VersionID: version.VersionID, Pin: version.Pin, ContentDigest: version.ContentDigest, ManifestDigest: version.ManifestDigest, ExecutionDigest: version.ExecutionDigest, NetworkSchemaDigest: version.NetworkSchemaDigest, SecretSchemaDigest: version.SecretSchemaDigest, Execution: execution, NetworkGrants: append([]NetworkGrant{}, version.NetworkGrants...), SecretGrants: append([]SecretGrantDescriptor{}, version.SecretGrants...), CreatedAt: version.CreatedAt}
		if version.NodeArtifact != nil && !version.PublishedAt.IsZero() {
			receipt := version.NodeArtifact
			publicVersion.NodeArtifact = &PublicNodeArtifactReceipt{PackageName: receipt.PackageName, PackageVersion: receipt.PackageVersion, ArtifactBytes: receipt.ArtifactBytes, FileCount: receipt.FileCount, NodeVersion: receipt.NodeVersion, NPMVersion: receipt.NPMVersion, LifecycleScriptsDisabled: receipt.LifecycleScriptsDisabled, NativeAddonsAbsent: receipt.NativeAddonsAbsent}
		}
		out.Versions = append(out.Versions, publicVersion)
	}
	return out
}

type PublicInstallationPage struct {
	Installations []PublicInstallation `json:"installations"`
	NextPageToken string               `json:"next_page_token"`
}

func (p InstallationPage) Public() PublicInstallationPage {
	out := PublicInstallationPage{NextPageToken: p.NextPageToken, Installations: make([]PublicInstallation, len(p.Installations))}
	for index := range p.Installations {
		out.Installations[index] = p.Installations[index].Public()
	}
	return out
}

type PublicMutationResult struct {
	Installation   PublicInstallation `json:"installation"`
	ConfirmationID string             `json:"confirmation_id,omitempty"`
	TaskID         string             `json:"task_id,omitempty"`
}

func (m MutationResult) Public() PublicMutationResult {
	return PublicMutationResult{Installation: m.Installation.Public(), ConfirmationID: m.ConfirmationID, TaskID: m.TaskID}
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
	IdempotencyKey       string
	InstallationID       string
	ExpectedRevision     int64
	Candidate            Candidate
	Inspection           Inspection
	SecretInputs         []SecretInput
	ArtifactPath         string
	ArtifactDigest       string
	ArtifactCleanupToken string
	NodeArtifact         *NodeArtifactReceipt
}

// ValidateUninstallRequest accepts only the public uninstall identity tuple.
// Candidate, inspection, secret, and artifact facts are always reconstructed
// from the authoritative active VersionRecord inside the repository.
func (m Mutation) ValidateUninstallRequest() error {
	if !validUUID(m.IdempotencyKey) || !validUUID(m.InstallationID) || m.ExpectedRevision < 1 ||
		m.Candidate != (Candidate{}) || m.Inspection.Candidate != (Candidate{}) ||
		m.Inspection.ContentDigest != "" || m.Inspection.ManifestDigest != "" || m.Inspection.ExecutionDigest != "" ||
		m.Inspection.NetworkSchemaDigest != "" || m.Inspection.SecretSchemaDigest != "" ||
		m.Inspection.Execution.Stdio != nil || m.Inspection.Execution.Remote != nil || m.Inspection.Execution.Skill != nil ||
		len(m.Inspection.NetworkGrants) != 0 || len(m.Inspection.SecretGrants) != 0 || len(m.SecretInputs) != 0 ||
		m.ArtifactPath != "" || m.ArtifactDigest != "" || m.ArtifactCleanupToken != "" || m.NodeArtifact != nil {
		return ErrInvalid
	}
	return nil
}

func (m Mutation) ValidateArtifactReceipt() error {
	if m.Candidate.Transport != TransportStdioNode {
		if m.NodeArtifact != nil {
			return ErrInvalid
		}
		return nil
	}
	if m.NodeArtifact == nil || !validUUID(m.ArtifactCleanupToken) || m.NodeArtifact.InputDigest != m.Inspection.ContentDigest || m.NodeArtifact.Validate(m.Candidate, m.Inspection.Execution, m.ArtifactDigest) != nil {
		return ErrInvalid
	}
	return nil
}

type MutationResult struct {
	Installation   Installation `json:"installation"`
	ConfirmationID string       `json:"confirmation_id,omitempty"`
	TaskID         string       `json:"task_id,omitempty"`
}

// ToggleCommand changes only the execution gate of an installed extension.
// It intentionally does not reuse Mutation: no source inspection, artifact,
// or secret material is involved in enable/disable.
type ToggleCommand struct {
	IdempotencyKey   string
	InstallationID   string
	ExpectedRevision int64
	Enabled          bool
}
type ExecuteRequest struct {
	OwnerID           string
	AccountGeneration uint64
	InstallationID    string
	ExpectedRevision  int64
	ToolName          string
	Input             json.RawMessage
	IdempotencyKey    string
}
type ExecuteResult struct {
	TaskID         string `json:"task_id"`
	ConfirmationID string `json:"confirmation_id"`
}

type SourceAdapter interface {
	Search(context.Context, SearchQuery) (Page, error)
	Inspect(context.Context, InspectRequest) (Inspection, error)
	Fetch(context.Context, Candidate) (FetchArtifact, error)
}

type ArtifactReceipt struct {
	RelativePath string
	// ContentDigest authenticates the canonical bytes returned by SourceAdapter.Fetch.
	ContentDigest string
	// ArtifactDigest identifies the immutable materialized install consumed by the runner.
	ArtifactDigest string
	// CleanupToken fences removal of this materialization generation.
	CleanupToken string
	// NodeArtifact is an authoritative receipt from the network-disabled,
	// scripts-disabled offline Node build. Source inspection never supplies it.
	NodeArtifact *NodeArtifactReceipt
}

const (
	ManagedNodeVersion = "v24.18.1"
	ManagedNPMVersion  = "11.16.0"
)

// NodeArtifactReceipt binds an exact source input to the expanded immutable
// tree produced by the managed offline Node builder.
type NodeArtifactReceipt struct {
	InputDigest              string `json:"input_digest"`
	ArtifactDigest           string `json:"artifact_digest"`
	ArtifactBytes            uint64 `json:"artifact_bytes"`
	FileCount                uint32 `json:"file_count"`
	EntryPath                string `json:"entry_path"`
	EntrySHA256              string `json:"entry_sha256"`
	PackageName              string `json:"package_name"`
	PackageVersion           string `json:"package_version"`
	LockSHA256               string `json:"lock_sha256"`
	NodeVersion              string `json:"node_version"`
	NPMVersion               string `json:"npm_version"`
	LifecycleScriptsDisabled bool   `json:"lifecycle_scripts_disabled"`
	NativeAddonsAbsent       bool   `json:"native_addons_absent"`
}

func (r NodeArtifactReceipt) Validate(candidate Candidate, execution ExecutionDescriptor, artifactDigest string) error {
	if candidate.Transport != TransportStdioNode || execution.Stdio == nil || execution.Stdio.Runtime != "node" || !validDigest(r.InputDigest) || !validDigest(r.ArtifactDigest) || r.ArtifactDigest != artifactDigest || r.ArtifactBytes == 0 || r.ArtifactBytes > MaxNodeArtifactBytes || r.FileCount == 0 || r.FileCount > MaxNodeArtifactFiles || !validPath(r.EntryPath) || !validDigest(r.EntrySHA256) || r.EntryPath != execution.Stdio.RelativePath || r.EntrySHA256 != execution.Stdio.Digest || r.PackageName == "" || !validExactSemver(r.PackageVersion) || !validDigest(r.LockSHA256) || r.NodeVersion != ManagedNodeVersion || r.NPMVersion != ManagedNPMVersion || !r.LifecycleScriptsDisabled || !r.NativeAddonsAbsent {
		return ErrInvalid
	}
	if !validNPMPackageName(r.PackageName) {
		return ErrInvalid
	}
	if candidate.Source == SourceNPM && (r.PackageName != candidate.ID || r.PackageVersion != candidate.Pin.RegistryVersion) {
		return ErrInvalid
	}
	return nil
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
	// Bind MUST be pure and side-effect-free: it validates inputs and returns
	// receipts only. Implementations must not persist plaintext, fingerprints,
	// staged secrets, or perform external mutation. Durable secret staging and
	// promotion are owned exclusively by the lifecycle repository transaction.
	Bind(context.Context, []SecretInput) ([]SecretReceipt, error)
}

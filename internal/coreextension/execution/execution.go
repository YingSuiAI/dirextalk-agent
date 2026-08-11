package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"github.com/google/uuid"
)

var (
	ErrStaleFence    = errors.New("extension execution fence is stale")
	ErrNotConfirmed  = errors.New("extension execution is not confirmed")
	ErrSecretBinding = errors.New("secret reference or binding mismatch")
)

// PurposeBoundSecretResolver is the only execution-time secret seam. Every
// lookup binds installation, version, reference, purpose, and digest.
type PurposeBoundSecretResolver interface {
	ResolveExactBound(context.Context, string, string, string, string, string) ([]byte, error)
}

type LocalInvocation struct {
	TaskID, TaskFence, InstallationID, VersionID, InstallDigest string
	ContentDigest, ArtifactDigest                               string
	EntryPath                                                   string
	Argv                                                        []string
	Tool                                                        string
	Input                                                       json.RawMessage
	Workspace                                                   string
	Timeout                                                     time.Duration
	Limits                                                      extensionrunner.LimitsV2
	Secrets                                                     []SecretBinding
	ResultFiles                                                 []string
	Stdin                                                       []byte
}

// LocalSandboxLimitsV2 is the single production budget for local MCP and
// executable Skill processes. Callers must bind it explicitly to each
// invocation; LocalExecutor intentionally does not repair zero limits.
func LocalSandboxLimitsV2() extensionrunner.LimitsV2 {
	return extensionrunner.LimitsV2{
		CPUSeconds:  30,
		MemoryBytes: 256 << 20,
		Processes:   32,
		FileBytes:   16 << 20,
		OpenFiles:   64,
	}
}

type LocalRunner interface {
	RunV2(context.Context, extensionrunner.RequestV2, []*os.File) (extensionrunner.StatusV1, error)
}

type SecretBinding struct {
	Name, InstallationID, VersionID, ReferenceID, Purpose, BindingDigest string
}

type LocalExecutor struct {
	Runner  LocalRunner
	Secrets PurposeBoundSecretResolver
}

// ListTools performs the MCP initialize handshake and tools/list request over
// the isolated runner. The runner is the only process boundary used for local
// extensions; this helper never starts a process or opens a network socket.
func (e *LocalExecutor) ListTools(ctx context.Context, in LocalInvocation) ([]core.Tool, error) {
	status, err := e.executeMCP(ctx, in, mcpRequest{Method: "tools/list", ID: 2})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Result struct {
			Tools []struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := decodeMCPResponse(status.Stdout, 2, &envelope); err != nil {
		return nil, err
	}
	out := make([]core.Tool, 0, len(envelope.Result.Tools))
	for _, tool := range envelope.Result.Tools {
		var schema map[string]any
		if strings.TrimSpace(tool.Name) == "" || json.Unmarshal(tool.InputSchema, &schema) != nil || schema == nil {
			return nil, core.ErrInvalid
		}
		canonical, err := json.Marshal(schema)
		if err != nil {
			return nil, core.ErrInvalid
		}
		out = append(out, core.Tool{Name: tool.Name, Description: tool.Description, InputSchemaDigest: digestBytes(canonical), InputSchema: canonical})
	}
	return out, nil
}

// CallTool performs an exact MCP tools/call over the isolated runner and
// returns the provider's bounded JSON result. A tool-declared error is surfaced
// as a normal task result with a stable summary, never retried in-process.
func (e *LocalExecutor) CallTool(ctx context.Context, in LocalInvocation, name string, input json.RawMessage) (coretask.Result, error) {
	if strings.TrimSpace(name) == "" {
		return coretask.Result{}, core.ErrInvalid
	}
	canonical, err := canonicalJSON(input, coretask.MaxCanonicalInputBytes)
	if err != nil {
		return coretask.Result{}, err
	}
	status, err := e.executeMCP(ctx, in, mcpRequest{Method: "tools/call", ID: 2, Params: map[string]any{"name": name, "arguments": json.RawMessage(canonical)}})
	if err != nil {
		return coretask.Result{}, err
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := decodeMCPResponse(status.Stdout, 2, &envelope); err != nil {
		return coretask.Result{}, err
	}
	var callResult struct {
		Content []json.RawMessage `json:"content"`
		IsError bool              `json:"isError"`
	}
	if len(envelope.Result) == 0 || json.Unmarshal(envelope.Result, &callResult) != nil || callResult.Content == nil {
		return coretask.Result{}, core.ErrInvalid
	}
	summary := "local MCP tool result"
	if callResult.IsError {
		summary = "local MCP tool returned an error"
	}
	result := coretask.Result{JSON: append([]byte(nil), envelope.Result...), Summary: summary}
	return result, result.Validate()
}

type mcpRequest struct {
	Method string
	ID     int
	Params any
}

func (e *LocalExecutor) executeMCP(ctx context.Context, in LocalInvocation, request mcpRequest) (extensionrunner.StatusV1, error) {
	params := map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "dirextalk-agent", "version": "core-v1"}}
	initialize := mcpWire{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: params}
	initialized := mcpWire{JSONRPC: "2.0", Method: "notifications/initialized", Params: map[string]any{}}
	call := mcpWire{JSONRPC: "2.0", ID: request.ID, Method: request.Method, Params: request.Params}
	data := make([]byte, 0, 512)
	for _, message := range []mcpWire{initialize, initialized, call} {
		line, err := json.Marshal(message)
		if err != nil {
			return extensionrunner.StatusV1{}, core.ErrInvalid
		}
		data = append(data, line...)
		data = append(data, '\n')
	}
	in.Stdin = data
	status, err := e.Execute(ctx, in)
	if err != nil {
		return extensionrunner.StatusV1{}, err
	}
	if status.Phase != extensionrunner.PhaseTombstone || status.Error != extensionrunner.ErrorNone {
		return extensionrunner.StatusV1{}, core.ErrConflict
	}
	return status, nil
}

type mcpWire struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

func decodeMCPResponse(stdout []byte, id int, out any) error {
	lines := strings.Split(string(stdout), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var envelope struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   json.RawMessage `json:"error"`
		}
		if json.Unmarshal([]byte(line), &envelope) != nil || envelope.JSONRPC != "2.0" {
			continue
		}
		var got int
		if json.Unmarshal(envelope.ID, &got) != nil || got != id {
			continue
		}
		if len(envelope.Error) > 0 {
			return core.ErrConflict
		}
		if json.Unmarshal([]byte(line), out) != nil {
			return core.ErrInvalid
		}
		return nil
	}
	return core.ErrInvalid
}

func (e *LocalExecutor) Execute(ctx context.Context, in LocalInvocation) (extensionrunner.StatusV1, error) {
	if e == nil || e.Runner == nil || !coretask.ValidUUID(in.TaskID) || !coretask.ValidUUID(in.InstallationID) || !coretask.ValidUUID(in.VersionID) || in.TaskFence == "" || len(in.ContentDigest) != 64 || len(in.ArtifactDigest) != 64 || in.InstallDigest != in.ArtifactDigest || in.EntryPath == "" || in.Workspace == "" || !filepath.IsAbs(in.Workspace) || in.Timeout <= 0 {
		return extensionrunner.StatusV1{}, extensionrunner.ErrInvalid
	}
	if filepath.IsAbs(in.EntryPath) || strings.Contains(in.EntryPath, "..") || strings.ContainsAny(in.EntryPath, "\\\x00\r\n") {
		return extensionrunner.StatusV1{}, extensionrunner.ErrInvalid
	}
	// The task workspace is runner-owned. The Agent may validate the opaque
	// capability path, but must never create or mutate the directory that the
	// isolated runner resolves by task/fence.
	files := make([]*os.File, 0, len(in.Secrets)+1)
	secrets := make([]extensionrunner.SecretFD, 0, len(in.Secrets))
	var stdinRef *extensionrunner.FDRef
	if len(in.Stdin) > extensionrunner.MaxStdinBytes {
		return extensionrunner.StatusV1{}, extensionrunner.ErrInvalid
	}
	if len(in.Stdin) > 0 {
		f, err := sealSecret(in.Stdin)
		if err != nil {
			return extensionrunner.StatusV1{}, err
		}
		files = append(files, f)
		stdinRef = &extensionrunner.FDRef{Index: 0, Size: int64(len(in.Stdin)), SHA256: fileDigest(f)}
	}
	for _, b := range in.Secrets {
		if b.Name == "" || e.Secrets == nil {
			return extensionrunner.StatusV1{}, ErrSecretBinding
		}
		data, err := e.Secrets.ResolveExactBound(ctx, b.InstallationID, b.VersionID, b.ReferenceID, b.Purpose, b.BindingDigest)
		if err != nil {
			return extensionrunner.StatusV1{}, ErrSecretBinding
		}
		f, err := sealSecret(data)
		zero(data)
		if err != nil {
			return extensionrunner.StatusV1{}, err
		}
		files = append(files, f)
		secrets = append(secrets, extensionrunner.SecretFD{Name: b.Name, Index: len(files) - 1, Size: fSize(f), SHA256: fileDigest(f)})
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	fence := in.TaskFence
	if !coretask.ValidUUID(fence) {
		fence = StableRunID(in.TaskID, fence)
	}
	runID := StableRunID(in.TaskID, fence, in.InstallationID, in.VersionID, in.ContentDigest, in.ArtifactDigest, strings.Join(in.Argv, "\x00"))
	request := extensionrunner.RequestV2{RunID: runID, TaskID: in.TaskID, TaskFence: fence, InstallDigest: in.InstallDigest, Entry: "entry", Argv: append([]string(nil), in.Argv...), Stdin: stdinRef, Secrets: secrets, ResultFiles: append([]string(nil), in.ResultFiles...), TimeoutMS: in.Timeout.Milliseconds(), Limits: in.Limits}
	if err := extensionrunner.ValidateRequestV2(request); err != nil {
		return extensionrunner.StatusV1{}, err
	}
	if err := extensionrunner.ValidateFDSet(request, len(files)); err != nil {
		return extensionrunner.StatusV1{}, err
	}
	status, err := e.Runner.RunV2(ctx, request, files)
	if err != nil {
		// Once the descriptor request reaches the runner transport, an error
		// without a verified terminal receipt cannot prove whether the isolated
		// process ran. Preserve the underlying diagnostic for operators while
		// giving durable callers a stable reconciliation classification.
		return status, errors.Join(ErrLocalOutcomeUncertain, err)
	}
	if err = localRunnerResourceFailure(status); err != nil {
		return status, err
	}
	return status, nil
}

func StableRunID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, h.Sum(nil)).String()
}

type RemoteExecutor struct {
	Secrets PurposeBoundSecretResolver
	Options []mcphttp.Option
}

type remoteSecrets struct {
	owner   *RemoteExecutor
	install string
	version string
	purpose string
	ref     string
	binding string
}

func (s remoteSecrets) ResolveSecret(ctx context.Context, ref string) ([]byte, error) {
	if ref != s.ref || s.owner == nil || s.owner.Secrets == nil {
		return nil, ErrSecretBinding
	}
	return s.owner.Secrets.ResolveExactBound(ctx, s.install, s.version, ref, s.purpose, s.binding)
}

// ListToolsBoundExact resolves the credential only for the pinned installation
// version and binding before making the remote MCP request.
func (e *RemoteExecutor) ListToolsBoundExact(ctx context.Context, endpoint core.RemoteEndpoint, installationID, versionID, purpose, bindingDigest string) ([]core.Tool, error) {
	return e.listToolsBound(ctx, endpoint, installationID, versionID, purpose, bindingDigest)
}

func (e *RemoteExecutor) listToolsBound(ctx context.Context, endpoint core.RemoteEndpoint, installationID, versionID, purpose, bindingDigest string) ([]core.Tool, error) {
	provider, err := e.providerBoundExact(endpoint, installationID, versionID, purpose, bindingDigest)
	if err != nil {
		return nil, err
	}
	tools, err := provider.Tools(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.Tool, 0, len(tools))
	for _, t := range tools {
		schema, _ := json.Marshal(t.Definition.InputSchema)
		out = append(out, core.Tool{Name: t.Definition.Name, Description: t.Definition.Description, InputSchemaDigest: digestJSON(t.Definition.InputSchema), InputSchema: schema})
	}
	return out, nil
}

func (e *RemoteExecutor) ExecuteBoundExact(ctx context.Context, endpoint core.RemoteEndpoint, installationID, versionID, purpose, bindingDigest, tool string, input json.RawMessage) (coretask.Result, error) {
	canonical, err := canonicalJSON(input, coretask.MaxCanonicalInputBytes)
	if err != nil {
		return coretask.Result{}, err
	}
	provider, err := e.providerBoundExact(endpoint, installationID, versionID, purpose, bindingDigest)
	if err != nil {
		return coretask.Result{}, err
	}
	tools, err := provider.Tools(ctx)
	if err != nil {
		return coretask.Result{}, err
	}
	for _, t := range tools {
		if t.Definition.Name == tool {
			r, runErr := t.Run(ctx, mcphttp.ToolInvocation{Name: t.Definition.Name, Arguments: canonical})
			if runErr != nil {
				return coretask.Result{}, runErr
			}
			result := coretask.Result{Text: r.Content, Summary: boundSummary(r.Content)}
			if r.IsError {
				result.Summary = "remote tool reported an error"
			}
			return result, result.Validate()
		}
	}
	return coretask.Result{}, errors.New("tool not found")
}

func (e *RemoteExecutor) providerBoundExact(endpoint core.RemoteEndpoint, installationID, versionID, purpose, bindingDigest string) (*mcphttp.Provider, error) {
	if endpoint.URL == "" {
		return nil, core.ErrInvalid
	}
	if endpoint.CredentialReferenceID == "" {
		return mcphttp.New([]mcphttp.ServerConfig{{ID: "mcp", Endpoint: endpoint.URL}}, nil, e.Options...)
	}
	resolver := remoteSecrets{owner: e, install: installationID, version: versionID, purpose: purpose, ref: endpoint.CredentialReferenceID, binding: bindingDigest}
	return mcphttp.New([]mcphttp.ServerConfig{{ID: "mcp", Endpoint: endpoint.URL, SecretRef: endpoint.CredentialReferenceID}}, resolver, e.Options...)
}

type SkillReader interface {
	ReadSkill(context.Context, string, string) ([]byte, error)
}
type SkillExecutor struct {
	Root   string
	Reader SkillReader
	Digest string
}

func (e SkillExecutor) Execute(ctx context.Context, entry core.SkillEntry) (coretask.Result, error) {
	if (e.Reader == nil && (e.Root == "" || !filepath.IsAbs(e.Root))) || !validRel(entry.RelativePath) {
		return coretask.Result{}, core.ErrInvalid
	}
	var b []byte
	var err error
	if e.Reader != nil {
		b, err = e.Reader.ReadSkill(ctx, e.Digest, entry.RelativePath)
	} else {
		b, err = os.ReadFile(filepath.Join(e.Root, filepath.FromSlash(entry.RelativePath)))
	}
	if err != nil {
		return coretask.Result{}, err
	}
	if len(b) > coretask.MaxResultTextBytes || digestBytes(b) != entry.Digest {
		return coretask.Result{}, core.ErrInvalid
	}
	r := coretask.Result{Text: string(b), Summary: boundSummary(string(b))}
	return r, r.Validate()
}

// Coordinator is the durable seam owned by the composition root. Resolve must
// return an exact active-version/lease fence; Complete/Fail are atomic domain
// transitions and must be idempotent on replay.
type Coordinator interface {
	Resolve(context.Context, coretask.Task) (Invocation, error)
	Complete(context.Context, coretask.Task, coretask.Result) (bool, error)
	Fail(context.Context, coretask.Task, string, string) (bool, error)
}
type Invocation struct {
	Kind   core.Kind
	Local  *LocalInvocation
	Remote *RemoteInvocation
	Skill  *SkillInvocation
}
type RemoteInvocation struct {
	Endpoint       core.RemoteEndpoint
	InstallationID string
	VersionID      string
	Purpose        string
	BindingDigest  string
	Tool           string
	Input          json.RawMessage
}
type SkillInvocation struct {
	Entry          core.SkillEntry
	Root           string
	InstallDigest  string
	Input          json.RawMessage
	Workspace      string
	TaskID         string
	TaskFence      string
	InstallationID string
	VersionID      string
	ContentDigest  string
	ArtifactDigest string
	Limits         extensionrunner.LimitsV2
	Secrets        []SecretBinding
}

type Handler struct {
	Coordinator Coordinator
	Local       *LocalExecutor
	Remote      *RemoteExecutor
	SkillReader SkillReader
}

func (h *Handler) Handle(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
	if h == nil || h.Coordinator == nil {
		return coreruntime.ManagedOutcome{Err: errors.New("extension coordinator unavailable"), TerminalOwned: true}
	}
	in, err := h.Coordinator.Resolve(ctx, task)
	if err != nil {
		return coreruntime.ManagedOutcome{Err: err, TerminalOwned: true}
	}
	var result coretask.Result
	switch {
	case in.Local != nil:
		if h.Local == nil {
			err = errors.New("local executor unavailable")
			break
		}
		result, err = h.Local.CallTool(ctx, *in.Local, in.Local.Tool, in.Local.Input)
	case in.Remote != nil:
		if h.Remote == nil {
			err = errors.New("remote executor unavailable")
			break
		}
		result, err = h.Remote.ExecuteBoundExact(ctx, in.Remote.Endpoint, in.Remote.InstallationID, in.Remote.VersionID, in.Remote.Purpose, in.Remote.BindingDigest, in.Remote.Tool, in.Remote.Input)
	case in.Skill != nil:
		if in.Skill.Entry.Executable {
			if h.Local == nil {
				err = errors.New("local executor unavailable")
				break
			}
			status, runErr := h.Local.Execute(ctx, LocalInvocation{TaskID: in.Skill.TaskID, TaskFence: in.Skill.TaskFence, InstallationID: in.Skill.InstallationID, VersionID: in.Skill.VersionID, InstallDigest: in.Skill.InstallDigest, ContentDigest: in.Skill.ContentDigest, ArtifactDigest: in.Skill.ArtifactDigest, EntryPath: in.Skill.Entry.RelativePath, Argv: append([]string(nil), in.Skill.Entry.Argv...), Workspace: in.Skill.Workspace, Timeout: 10 * time.Minute, Limits: in.Skill.Limits, Secrets: in.Skill.Secrets, Stdin: append([]byte(nil), in.Skill.Input...)})
			if runErr == nil && status.Error != extensionrunner.ErrorNone {
				runErr = errors.New("isolated skill runner failed")
			}
			if runErr != nil {
				err = runErr
			} else {
				result = coretask.Result{Text: string(status.Stdout), Summary: "isolated skill execution"}
				err = result.Validate()
			}
		} else {
			result, err = (SkillExecutor{Root: in.Skill.Root, Reader: h.SkillReader, Digest: in.Skill.InstallDigest}).Execute(ctx, in.Skill.Entry)
		}
	default:
		err = core.ErrInvalid
	}
	if err != nil {
		code, summary := "extension_execution_failed", "extension execution failed"
		if resourceCode, resourceSummary, ok := LocalResourceFailure(err); ok {
			code, summary = resourceCode, resourceSummary
		} else if errors.Is(err, ErrLocalOutcomeUncertain) {
			code, summary = "extension_execution_uncertain", "execution outcome is uncertain; reconciliation required"
		}
		committed, failErr := h.Coordinator.Fail(ctx, task, code, summary)
		if failErr != nil {
			return coreruntime.ManagedOutcome{Err: errors.Join(err, failErr), TerminalOwned: committed}
		}
		return coreruntime.ManagedOutcome{Err: err, TerminalOwned: committed}
	}
	committed, completeErr := h.Coordinator.Complete(ctx, task, result)
	if completeErr != nil {
		return coreruntime.ManagedOutcome{Err: completeErr, TerminalOwned: committed}
	}
	return coreruntime.ManagedOutcome{Result: result, TerminalOwned: committed}
}

func canonicalJSON(raw json.RawMessage, max int) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > max || !json.Valid(raw) {
		return nil, core.ErrInvalid
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, core.ErrInvalid
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > max || string(b) != string(raw) {
		return nil, core.ErrInvalid
	}
	return b, nil
}
func digestJSON(v any) string     { b, _ := json.Marshal(v); return digestBytes(b) }
func digestBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func boundSummary(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > coretask.MaxSummaryBytes {
		s = s[:coretask.MaxSummaryBytes]
	}
	return s
}
func validRel(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.Clean(filepath.FromSlash(p)) == filepath.FromSlash(p) && !strings.Contains(p, "..")
}
func fSize(f *os.File) int64 {
	st, e := f.Stat()
	if e != nil {
		return 0
	}
	return st.Size()
}
func fileDigest(f *os.File) string {
	if _, e := f.Seek(0, 0); e != nil {
		return ""
	}
	h := sha256.New()
	_, _ = io.Copy(h, f)
	_, _ = f.Seek(0, 0)
	return hex.EncodeToString(h.Sum(nil))
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

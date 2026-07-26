package rpcapi

import (
	"context"
	"encoding/json"
	"errors"
	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
	"time"
)

type MCPService struct {
	agentv1.UnimplementedMCPServiceServer
	svc coreextension.Service
}
type SkillService struct {
	agentv1.UnimplementedSkillServiceServer
	svc coreextension.Service
}

func NewMCPService(s coreextension.Service) *MCPService     { return &MCPService{svc: s} }
func NewSkillService(s coreextension.Service) *SkillService { return &SkillService{svc: s} }

func extErr(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, coreextension.ErrInvalid):
		return status.Error(codes.InvalidArgument, e.Error())
	case errors.Is(e, coreextension.ErrNotFound):
		return status.Error(codes.NotFound, e.Error())
	case errors.Is(e, coreextension.ErrRevisionConflict), errors.Is(e, coreextension.ErrConflict):
		return status.Error(codes.Aborted, e.Error())
	case errors.Is(e, coreextension.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, e.Error())
	default:
		return status.Error(codes.Internal, e.Error())
	}
}
func candFrom(p *agentv1.CoreExtensionCandidate) coreextension.Candidate {
	if p == nil {
		return coreextension.Candidate{}
	}
	c := coreextension.Candidate{ID: p.Id, Name: p.Name, Description: p.Description, Kind: coreextension.Kind(strings.ToLower(p.Kind.String()[len("CORE_EXTENSION_KIND_"):]))}
	_ = c
	return candidateProto(p)
}
func secretPurpose(v agentv1.CoreSecretPurpose) coreextension.SecretPurpose {
	switch v {
	case agentv1.CoreSecretPurpose_CORE_SECRET_PURPOSE_MCP_CREDENTIAL:
		return coreextension.SecretPurposeMCPCredential
	case agentv1.CoreSecretPurpose_CORE_SECRET_PURPOSE_SKILL_SECRET:
		return coreextension.SecretPurposeSkillSecret
	}
	return ""
}
func purposeProto(v coreextension.SecretPurpose) agentv1.CoreSecretPurpose {
	switch v {
	case coreextension.SecretPurposeMCPCredential:
		return agentv1.CoreSecretPurpose_CORE_SECRET_PURPOSE_MCP_CREDENTIAL
	case coreextension.SecretPurposeSkillSecret:
		return agentv1.CoreSecretPurpose_CORE_SECRET_PURPOSE_SKILL_SECRET
	}
	return agentv1.CoreSecretPurpose_CORE_SECRET_PURPOSE_UNSPECIFIED
}
func executionFrom(p *agentv1.CoreExecution) coreextension.ExecutionDescriptor {
	if p == nil {
		return coreextension.ExecutionDescriptor{}
	}
	if x := p.GetStdio(); x != nil {
		return coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{RelativePath: x.RelativePath, Digest: x.Digest, Argv: append([]string(nil), x.Argv...)}}
	}
	if x := p.GetRemote(); x != nil {
		return coreextension.ExecutionDescriptor{Remote: &coreextension.RemoteEndpoint{URL: x.Url, CredentialReferenceID: x.CredentialReferenceId}}
	}
	if x := p.GetSkill(); x != nil {
		return coreextension.ExecutionDescriptor{Skill: &coreextension.SkillEntry{RelativePath: x.RelativePath, Digest: x.Digest, Executable: x.Executable, Argv: append([]string(nil), x.Argv...)}}
	}
	return coreextension.ExecutionDescriptor{}
}
func inspectionFrom(p *agentv1.CoreExtensionInspection, c coreextension.Candidate) coreextension.Inspection {
	i := coreextension.Inspection{Candidate: c}
	if p == nil {
		return i
	}
	i.ContentDigest = p.ContentDigest
	i.ManifestDigest = p.ManifestDigest
	i.ExecutionDigest = p.ExecutionDigest
	i.NetworkSchemaDigest = p.NetworkSchemaDigest
	i.SecretSchemaDigest = p.SecretSchemaDigest
	i.Execution = executionFrom(p.Execution)
	for _, g := range p.NetworkGrants {
		if g != nil {
			i.NetworkGrants = append(i.NetworkGrants, coreextension.NetworkGrant{Scheme: g.Scheme, Host: g.Host, Port: g.Port, PathPrefix: g.PathPrefix, Digest: g.Digest})
		}
	}
	for _, g := range p.SecretGrants {
		if g != nil {
			i.SecretGrants = append(i.SecretGrants, coreextension.SecretGrantDescriptor{ReferenceID: g.ReferenceId, Purpose: secretPurpose(g.Purpose), BindingDigest: g.BindingDigest, Configured: g.Configured})
		}
	}
	return i
}
func candidateProto(p *agentv1.CoreExtensionCandidate) coreextension.Candidate {
	c := coreextension.Candidate{ID: p.Id, Name: p.Name, Description: p.Description, Kind: kindProto(p.Kind), Source: sourceProto(p.Source), Transport: transportProto(p.Transport)}
	if p.Pin != nil {
		c.Pin = coreextension.SourcePin{RegistryVersion: p.Pin.RegistryVersion, RegistrySHA256: p.Pin.RegistrySha256, GitCommit: p.Pin.GitCommit, GitSHA256: p.Pin.GitSha256}
	}
	return c
}
func kindProto(v agentv1.CoreExtensionKind) coreextension.Kind {
	if v == agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_SKILL {
		return coreextension.KindSkill
	}
	return coreextension.KindMCP
}
func sourceProto(v agentv1.CoreExtensionSource) coreextension.Source {
	switch v {
	case agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_SMITHERY:
		return coreextension.SourceSmithery
	case agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_GLAMA:
		return coreextension.SourceGlama
	case agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_GITHUB:
		return coreextension.SourceGitHub
	case agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_SKILLS_SH:
		return coreextension.SourceSkillsSh
	}
	return coreextension.SourceOfficialRegistry
}
func transportProto(v agentv1.CoreExtensionTransport) coreextension.Transport {
	switch v {
	case agentv1.CoreExtensionTransport_CORE_EXTENSION_TRANSPORT_STREAMABLE_HTTP:
		return coreextension.TransportStreamableHTTP
	case agentv1.CoreExtensionTransport_CORE_EXTENSION_TRANSPORT_SKILL_STATIC:
		return coreextension.TransportSkillStatic
	}
	return coreextension.TransportStdioStatic
}
func stateProto(v agentv1.CoreExtensionState) coreextension.State {
	switch v {
	case agentv1.CoreExtensionState_CORE_EXTENSION_STATE_INSTALLING:
		return coreextension.StateInstalling
	case agentv1.CoreExtensionState_CORE_EXTENSION_STATE_INSTALLED:
		return coreextension.StateInstalled
	case agentv1.CoreExtensionState_CORE_EXTENSION_STATE_UPDATING:
		return coreextension.StateUpdating
	case agentv1.CoreExtensionState_CORE_EXTENSION_STATE_UNINSTALLING:
		return coreextension.StateUninstalling
	case agentv1.CoreExtensionState_CORE_EXTENSION_STATE_REMOVED:
		return coreextension.StateRemoved
	case agentv1.CoreExtensionState_CORE_EXTENSION_STATE_FAILED:
		return coreextension.StateFailed
	}
	return ""
}
func candTo(c coreextension.Candidate) *agentv1.CoreExtensionCandidate {
	p := &agentv1.CoreExtensionCandidate{Id: c.ID, Name: c.Name, Description: c.Description, Kind: agentv1.CoreExtensionKind(agentv1.CoreExtensionKind_value["CORE_EXTENSION_KIND_"+strings.ToUpper(string(c.Kind))]), Source: agentv1.CoreExtensionSource(agentv1.CoreExtensionSource_value["CORE_EXTENSION_SOURCE_"+strings.ToUpper(string(c.Source))]), Transport: agentv1.CoreExtensionTransport(agentv1.CoreExtensionTransport_value["CORE_EXTENSION_TRANSPORT_"+strings.ToUpper(string(c.Transport))]), Pin: &agentv1.CoreSourcePin{RegistryVersion: c.Pin.RegistryVersion, RegistrySha256: c.Pin.RegistrySHA256, GitCommit: c.Pin.GitCommit, GitSha256: c.Pin.GitSHA256}}
	return p
}
func installTo(i coreextension.Installation) *agentv1.CoreInstallation {
	p := &agentv1.CoreInstallation{InstallationId: i.ID, Kind: agentv1.CoreExtensionKind(agentv1.CoreExtensionKind_value["CORE_EXTENSION_KIND_"+strings.ToUpper(string(i.Kind))]), Source: agentv1.CoreExtensionSource(agentv1.CoreExtensionSource_value["CORE_EXTENSION_SOURCE_"+strings.ToUpper(string(i.Source))]), Name: i.Name, Description: i.Description, CandidateId: i.CandidateID, Transport: agentv1.CoreExtensionTransport(agentv1.CoreExtensionTransport_value["CORE_EXTENSION_TRANSPORT_"+strings.ToUpper(string(i.Transport))]), Revision: i.Revision, State: agentv1.CoreExtensionState(agentv1.CoreExtensionState_value["CORE_EXTENSION_STATE_"+strings.ToUpper(string(i.State))]), ActiveVersionId: i.ActiveVersionID, ProposedVersionId: i.ProposedVersionID, CreatedAt: timestamppb.New(i.CreatedAt), UpdatedAt: timestamppb.New(i.UpdatedAt)}
	for _, g := range i.NetworkGrants {
		p.NetworkGrants = append(p.NetworkGrants, &agentv1.CoreNetworkGrant{Scheme: g.Scheme, Host: g.Host, Port: g.Port, PathPrefix: g.PathPrefix, Digest: g.Digest})
	}
	for _, g := range i.SecretGrants {
		p.SecretGrants = append(p.SecretGrants, &agentv1.CoreExtensionSecretGrantDescriptor{ReferenceId: g.ReferenceID, Purpose: purposeProto(g.Purpose), BindingDigest: g.BindingDigest, Configured: g.Configured})
	}
	for _, v := range i.Versions {
		p.Versions = append(p.Versions, &agentv1.CoreExtensionVersion{VersionId: v.VersionID, ContentDigest: v.ContentDigest, ManifestDigest: v.ManifestDigest, ExecutionDigest: v.ExecutionDigest, NetworkSchemaDigest: v.NetworkSchemaDigest, SecretSchemaDigest: v.SecretSchemaDigest, Pin: &agentv1.CoreSourcePin{RegistryVersion: v.Pin.RegistryVersion, RegistrySha256: v.Pin.RegistrySHA256, GitCommit: v.Pin.GitCommit, GitSha256: v.Pin.GitSHA256}, CreatedAt: timestamppb.New(v.CreatedAt), Execution: executionTo(v.Execution)})
	}
	return p
}
func executionTo(e coreextension.ExecutionDescriptor) *agentv1.CoreExecution {
	switch {
	case e.Stdio != nil:
		return &agentv1.CoreExecution{Descriptor_: &agentv1.CoreExecution_Stdio{Stdio: &agentv1.CoreStaticEntry{RelativePath: e.Stdio.RelativePath, Digest: e.Stdio.Digest, Argv: append([]string(nil), e.Stdio.Argv...)}}}
	case e.Remote != nil:
		return &agentv1.CoreExecution{Descriptor_: &agentv1.CoreExecution_Remote{Remote: &agentv1.CoreRemoteEndpoint{Url: e.Remote.URL, CredentialReferenceId: e.Remote.CredentialReferenceID}}}
	case e.Skill != nil:
		return &agentv1.CoreExecution{Descriptor_: &agentv1.CoreExecution_Skill{Skill: &agentv1.CoreSkillEntry{RelativePath: e.Skill.RelativePath, Digest: e.Skill.Digest, Executable: e.Skill.Executable, Argv: append([]string(nil), e.Skill.Argv...)}}}
	}
	return nil
}
func inspectionTo(i coreextension.Inspection) *agentv1.CoreExtensionInspection {
	p := &agentv1.CoreExtensionInspection{Candidate: candTo(i.Candidate), ContentDigest: i.ContentDigest, ManifestDigest: i.ManifestDigest, ExecutionDigest: i.ExecutionDigest, NetworkSchemaDigest: i.NetworkSchemaDigest, SecretSchemaDigest: i.SecretSchemaDigest, Execution: executionTo(i.Execution)}
	for _, g := range i.NetworkGrants {
		p.NetworkGrants = append(p.NetworkGrants, &agentv1.CoreNetworkGrant{Scheme: g.Scheme, Host: g.Host, Port: g.Port, PathPrefix: g.PathPrefix, Digest: g.Digest})
	}
	for _, g := range i.SecretGrants {
		p.SecretGrants = append(p.SecretGrants, &agentv1.CoreExtensionSecretGrantDescriptor{ReferenceId: g.ReferenceID, Purpose: purposeProto(g.Purpose), BindingDigest: g.BindingDigest, Configured: g.Configured})
	}
	return p
}
func mutFrom(k string, id string, rev int64, c *agentv1.CoreExtensionCandidate, in *agentv1.CoreExtensionInspection, inputs []*agentv1.CoreExtensionSecretInput) coreextension.Mutation {
	m := coreextension.Mutation{IdempotencyKey: k, InstallationID: id, ExpectedRevision: rev, Candidate: candidateProto(c)}
	m.Inspection = inspectionFrom(in, m.Candidate)
	for _, x := range inputs {
		if x != nil {
			m.SecretInputs = append(m.SecretInputs, coreextension.SecretInput{ReferenceID: x.ReferenceId, Purpose: secretPurpose(x.Purpose), Value: x.SecretValue})
		}
	}
	return m
}
func (s *MCPService) Search(ctx context.Context, r *agentv1.MCPServiceSearchRequest) (*agentv1.MCPServiceSearchResponse, error) {
	if r == nil || r.Kind != agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_MCP || r.Source == agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	p, e := s.svc.Search(ctx, coreextension.SearchQuery{Kind: kindProto(r.Kind), Source: sourceProto(r.Source), Text: r.Text, PageSize: int(r.PageSize), PageToken: r.PageToken})
	if e != nil {
		return nil, extErr(e)
	}
	o := &agentv1.MCPServiceSearchResponse{NextPageToken: p.NextPageToken}
	for _, c := range p.Candidates {
		o.Candidates = append(o.Candidates, candTo(c))
	}
	return o, nil
}
func (s *MCPService) Inspect(ctx context.Context, r *agentv1.MCPServiceInspectRequest) (*agentv1.MCPServiceInspectResponse, error) {
	if r == nil || r.Kind != agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_MCP || r.Source == agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_UNSPECIFIED || r.Pin == nil {
		return nil, status.Error(codes.InvalidArgument, "request and immutable pin are required")
	}
	i, e := s.svc.Inspect(ctx, coreextension.InspectRequest{Kind: kindProto(r.Kind), Source: sourceProto(r.Source), ID: r.Id, Pin: coreextension.SourcePin{RegistryVersion: r.Pin.RegistryVersion, RegistrySHA256: r.Pin.RegistrySha256, GitCommit: r.Pin.GitCommit, GitSHA256: r.Pin.GitSha256}})
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.MCPServiceInspectResponse{Inspection: inspectionTo(i)}, nil
}
func (s *MCPService) RequestInstall(ctx context.Context, r *agentv1.MCPServiceRequestInstallRequest) (*agentv1.MCPServiceRequestInstallResponse, error) {
	if r == nil || r.Candidate == nil || r.Inspection == nil || r.Candidate.Kind != agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_MCP {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	x, e := s.svc.RequestInstall(ctx, mutFrom(r.IdempotencyKey, r.InstallationId, r.ExpectedRevision, r.Candidate, r.Inspection, r.SecretInputs))
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.MCPServiceRequestInstallResponse{Installation: installTo(x.Installation), ConfirmationId: x.ConfirmationID, TaskId: x.TaskID}, nil
}
func (s *MCPService) RequestUpdate(ctx context.Context, r *agentv1.MCPServiceRequestUpdateRequest) (*agentv1.MCPServiceRequestUpdateResponse, error) {
	if r == nil || r.Mutation == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	x, e := s.svc.RequestUpdate(ctx, mutFrom(r.Mutation.IdempotencyKey, r.Mutation.InstallationId, r.Mutation.ExpectedRevision, r.Mutation.Candidate, r.Mutation.Inspection, r.Mutation.SecretInputs))
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.MCPServiceRequestUpdateResponse{Installation: installTo(x.Installation), ConfirmationId: x.ConfirmationID, TaskId: x.TaskID}, nil
}
func (s *MCPService) RequestUninstall(ctx context.Context, r *agentv1.MCPServiceRequestUninstallRequest) (*agentv1.MCPServiceRequestUninstallResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	x, e := s.svc.RequestUninstall(ctx, coreextension.Mutation{IdempotencyKey: r.IdempotencyKey, InstallationID: r.InstallationId, ExpectedRevision: r.ExpectedRevision})
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.MCPServiceRequestUninstallResponse{Installation: installTo(x.Installation), ConfirmationId: x.ConfirmationID, TaskId: x.TaskID}, nil
}
func (s *MCPService) List(ctx context.Context, r *agentv1.MCPServiceListRequest) (*agentv1.MCPServiceListResponse, error) {
	p, e := s.svc.List(ctx, coreextension.ListQuery{Kind: kindProto(r.Kind), Source: sourceProto(r.Source), State: stateProto(r.State), PageSize: int(r.PageSize), PageToken: r.PageToken})
	if e != nil {
		return nil, extErr(e)
	}
	o := &agentv1.MCPServiceListResponse{NextPageToken: p.NextPageToken}
	for _, i := range p.Installations {
		o.Installations = append(o.Installations, installTo(i))
	}
	return o, nil
}
func (s *MCPService) Get(ctx context.Context, r *agentv1.MCPServiceGetRequest) (*agentv1.MCPServiceGetResponse, error) {
	i, e := s.svc.Get(ctx, r.InstallationId)
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.MCPServiceGetResponse{Installation: installTo(i)}, nil
}
func (s *MCPService) ListTools(ctx context.Context, r *agentv1.MCPServiceListToolsRequest) (*agentv1.MCPServiceListToolsResponse, error) {
	t, e := s.svc.ListTools(ctx, r.InstallationId, r.ExpectedRevision)
	if e != nil {
		return nil, extErr(e)
	}
	o := &agentv1.MCPServiceListToolsResponse{}
	for _, x := range t {
		o.Tools = append(o.Tools, &agentv1.CoreTool{Name: x.Name, Description: x.Description, InputSchemaDigest: x.InputSchemaDigest})
	}
	return o, nil
}
func (s *MCPService) ExecuteTool(ctx context.Context, r *agentv1.MCPServiceExecuteToolRequest) (*agentv1.MCPServiceExecuteToolResponse, error) {
	var in json.RawMessage
	if r.Input != nil {
		in, _ = json.Marshal(r.Input.AsMap())
	}
	x, e := s.svc.Execute(ctx, coreextension.ExecuteRequest{IdempotencyKey: r.IdempotencyKey, InstallationID: r.InstallationId, ExpectedRevision: r.ExpectedRevision, ToolName: r.ToolName, Input: in})
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.MCPServiceExecuteToolResponse{TaskId: x.TaskID, ConfirmationId: x.ConfirmationID}, nil
}

// SkillService delegates to the same narrow implementation while preserving
// the generated service-specific protobuf contract.
func (s *SkillService) Search(ctx context.Context, r *agentv1.SkillServiceSearchRequest) (*agentv1.SkillServiceSearchResponse, error) {
	if r == nil || r.Kind != agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_SKILL || r.Source == agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "skill kind/source required")
	}
	p, e := s.svc.Search(ctx, coreextension.SearchQuery{Kind: coreextension.KindSkill, Source: sourceProto(r.Source), Text: r.Text, PageSize: int(r.PageSize), PageToken: r.PageToken})
	if e != nil {
		return nil, extErr(e)
	}
	o := &agentv1.SkillServiceSearchResponse{NextPageToken: p.NextPageToken}
	for _, c := range p.Candidates {
		o.Candidates = append(o.Candidates, candTo(c))
	}
	return o, nil
}
func (s *SkillService) Inspect(ctx context.Context, r *agentv1.SkillServiceInspectRequest) (*agentv1.SkillServiceInspectResponse, error) {
	if r == nil || r.Kind != agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_SKILL || r.Source == agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_UNSPECIFIED || r.Pin == nil {
		return nil, status.Error(codes.InvalidArgument, "request and immutable pin are required")
	}
	i, e := s.svc.Inspect(ctx, coreextension.InspectRequest{Kind: coreextension.KindSkill, Source: sourceProto(r.Source), ID: r.Id, Pin: coreextension.SourcePin{RegistryVersion: r.Pin.RegistryVersion, RegistrySHA256: r.Pin.RegistrySha256, GitCommit: r.Pin.GitCommit, GitSHA256: r.Pin.GitSha256}})
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.SkillServiceInspectResponse{Inspection: inspectionTo(i)}, nil
}
func (s *SkillService) RequestInstall(ctx context.Context, r *agentv1.SkillServiceRequestInstallRequest) (*agentv1.SkillServiceRequestInstallResponse, error) {
	if r == nil || r.Candidate == nil || r.Inspection == nil || r.Candidate.Kind != agentv1.CoreExtensionKind_CORE_EXTENSION_KIND_SKILL {
		return nil, status.Error(codes.InvalidArgument, "skill candidate/inspection required")
	}
	x, e := s.svc.RequestInstall(ctx, mutFrom(r.IdempotencyKey, r.InstallationId, r.ExpectedRevision, r.Candidate, r.Inspection, r.SecretInputs))
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.SkillServiceRequestInstallResponse{Installation: installTo(x.Installation), ConfirmationId: x.ConfirmationID, TaskId: x.TaskID}, nil
}
func (s *SkillService) RequestUpdate(ctx context.Context, r *agentv1.SkillServiceRequestUpdateRequest) (*agentv1.SkillServiceRequestUpdateResponse, error) {
	if r == nil || r.Mutation == nil || r.Mutation.Candidate == nil || r.Mutation.Inspection == nil {
		return nil, status.Error(codes.InvalidArgument, "skill update mutation required")
	}
	x, e := s.svc.RequestUpdate(ctx, mutFrom(r.Mutation.IdempotencyKey, r.Mutation.InstallationId, r.Mutation.ExpectedRevision, r.Mutation.Candidate, r.Mutation.Inspection, r.Mutation.SecretInputs))
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.SkillServiceRequestUpdateResponse{Installation: installTo(x.Installation), ConfirmationId: x.ConfirmationID, TaskId: x.TaskID}, nil
}
func (s *SkillService) RequestUninstall(ctx context.Context, r *agentv1.SkillServiceRequestUninstallRequest) (*agentv1.SkillServiceRequestUninstallResponse, error) {
	x, e := s.svc.RequestUninstall(ctx, coreextension.Mutation{IdempotencyKey: r.IdempotencyKey, InstallationID: r.InstallationId, ExpectedRevision: r.ExpectedRevision})
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.SkillServiceRequestUninstallResponse{Installation: installTo(x.Installation), ConfirmationId: x.ConfirmationID, TaskId: x.TaskID}, nil
}
func (s *SkillService) List(ctx context.Context, r *agentv1.SkillServiceListRequest) (*agentv1.SkillServiceListResponse, error) {
	p, e := s.svc.List(ctx, coreextension.ListQuery{Kind: coreextension.KindSkill, Source: sourceProto(r.Source), State: stateProto(r.State), PageSize: int(r.PageSize), PageToken: r.PageToken})
	if e != nil {
		return nil, extErr(e)
	}
	o := &agentv1.SkillServiceListResponse{NextPageToken: p.NextPageToken}
	for _, i := range p.Installations {
		o.Installations = append(o.Installations, installTo(i))
	}
	return o, nil
}
func (s *SkillService) Get(ctx context.Context, r *agentv1.SkillServiceGetRequest) (*agentv1.SkillServiceGetResponse, error) {
	i, e := s.svc.Get(ctx, r.InstallationId)
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.SkillServiceGetResponse{Installation: installTo(i)}, nil
}
func (s *SkillService) Execute(ctx context.Context, r *agentv1.SkillServiceExecuteRequest) (*agentv1.SkillServiceExecuteResponse, error) {
	var in json.RawMessage
	if r.Input != nil {
		in, _ = json.Marshal(r.Input.AsMap())
	}
	x, e := s.svc.Execute(ctx, coreextension.ExecuteRequest{IdempotencyKey: r.IdempotencyKey, InstallationID: r.InstallationId, ExpectedRevision: r.ExpectedRevision, Input: in})
	if e != nil {
		return nil, extErr(e)
	}
	return &agentv1.SkillServiceExecuteResponse{TaskId: x.TaskID, ConfirmationId: x.ConfirmationID}, nil
}

var _ = time.Time{}
var _ = structpb.NewStruct

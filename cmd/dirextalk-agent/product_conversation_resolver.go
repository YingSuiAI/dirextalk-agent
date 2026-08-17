package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// productConversationResolver adds the message-server Product catalog to the
// model-facing tool list only for an authenticated Agent Capability call. It
// keeps ordinary Core gRPC callers out of the callback path and routes every
// tool invocation through the same CallContext and PermissionContext.
type productConversationResolver struct {
	base    coreconversation.ExtensionResolver
	product *capabilityclient.Client
}

type productConversationTool struct {
	capabilityID    string
	capabilityVer   string
	protocolVersion int32
	operation       string
	schemaDigest    []byte
}

func (r *productConversationResolver) ResolveExtensions(ctx context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	var resolved []coreconversation.ResolvedExtension
	if r != nil && r.base != nil {
		base, err := r.base.ResolveExtensions(ctx, selections)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, base...)
	}
	if r == nil || r.product == nil {
		return resolved, nil
	}
	callCtx, ok := capabilityclient.CallContextFromContext(ctx)
	permission, permissionOK := capabilityclient.PermissionFromContext(ctx)
	if !ok || !permissionOK || callCtx == nil || permission == nil {
		return resolved, nil
	}
	catalog, err := r.product.DescribeCapabilities(ctx, callCtx)
	if err != nil {
		return nil, err
	}
	digest, err := validateProductCatalogDigest(catalog)
	if err != nil {
		return nil, err
	}
	tools := make([]coremodel.Tool, 0)
	bindings := make(map[string]productConversationTool)
	allowedNames := make([]string, 0)
	orderedCatalog := cloneProductCatalog(catalog)
	for _, capability := range orderedCatalog.GetCapabilities() {
		if capability == nil || !capability.GetReadiness() {
			continue
		}
		for _, operation := range capability.GetOperations() {
			if !productOperationAllowed(operation, permission) {
				continue
			}
			schemaDigest, schema, ok := productToolSchema(operation)
			if !ok {
				continue
			}
			name := productToolName(capability.GetCapabilityId(), operation.GetOperationId())
			if name == "" {
				continue
			}
			if _, exists := bindings[name]; exists {
				continue
			}
			tools = append(tools, coremodel.Tool{Name: name, Description: operation.GetDescription(), InputSchema: schema})
			allowedNames = append(allowedNames, name)
			bindings[name] = productConversationTool{capabilityID: capability.GetCapabilityId(), capabilityVer: capability.GetSemanticVersion(), protocolVersion: capability.GetProtocolVersion(), operation: operation.GetOperationId(), schemaDigest: schemaDigest}
		}
	}
	if len(tools) == 0 {
		return resolved, nil
	}
	selectionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("product-capability-tools:"+digest)).String()
	selection := coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: selectionID, Version: "1.0.0", Digest: digest, AllowedTools: allowedNames}
	schemaDigest := productToolsSchemaDigest(tools)
	artifactDigest := digestBytes([]byte("product-capability-artifact:" + digest))
	resolved = append(resolved, coreconversation.ResolvedExtension{
		Selection: selection,
		Snapshot:  productConversationSnapshot(selection, digest, artifactDigest, schemaDigest, allowedNames),
		Tools:     tools,
		Execute: func(toolCtx context.Context, request coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
			binding, exists := bindings[request.Call.Name]
			if !exists {
				return coreconversation.ToolResult{}, fmt.Errorf("product tool %q is not in the described catalog", request.Call.Name)
			}
			parent, parentOK := capabilityclient.CallContextFromContext(toolCtx)
			grant, grantOK := capabilityclient.PermissionFromContext(toolCtx)
			if !parentOK || !grantOK || parent == nil || grant == nil {
				return coreconversation.ToolResult{}, fmt.Errorf("product capability context is missing")
			}
			requestJSON := []byte(request.Call.Arguments)
			if len(requestJSON) == 0 {
				requestJSON = []byte(`{}`)
			}
			canonicalRequest, err := capv1.CanonicalizeJSON(requestJSON)
			if err != nil {
				return coreconversation.ToolResult{}, fmt.Errorf("product tool arguments must be canonical JSON: %w", err)
			}
			businessInput, err := capv1.ParseBusinessInput(canonicalRequest)
			if err != nil {
				return coreconversation.ToolResult{}, err
			}
			rootDigest, err := capv1.ComputeRootRequestDigest(binding.protocolVersion, binding.capabilityID, binding.capabilityVer, binding.schemaDigest, binding.operation, 0, businessInput, nil)
			if err != nil {
				return coreconversation.ToolResult{}, err
			}
			delegation, err := r.product.ExchangeProductDelegation(toolCtx, parent, capv1.ExchangeProductTargetKind_EXCHANGE_PRODUCT_TARGET_KIND_QUERY, "", binding.capabilityID, binding.operation, canonicalRequest, 0, grant)
			if err != nil {
				return coreconversation.ToolResult{}, err
			}
			if !bytes.Equal(rootDigest, delegation.RootRequestDigest) {
				return coreconversation.ToolResult{}, fmt.Errorf("product delegation root digest mismatch")
			}
			result, callErr := r.product.QueryWithPermission(toolCtx, parent, binding.capabilityID, binding.operation, canonicalRequest, delegation.Permission)
			if callErr != nil {
				return coreconversation.ToolResult{}, callErr
			}
			return coreconversation.ToolResult{CallID: request.Call.ID, ToolName: request.Call.Name, Content: string(result)}, nil
		},
	})
	return resolved, nil
}

func productConversationSnapshot(selection coreconversation.ExtensionSelection, contentDigest, artifactDigest, schemaDigest string, toolNames []string) coreconversation.ExtensionExecutionSnapshot {
	return coreconversation.ExtensionExecutionSnapshot{
		Selection: selection, InstallationID: selection.ID, VersionID: selection.Version,
		Source: "product-capability", ContentDigest: contentDigest, ArtifactDigest: artifactDigest,
		ToolSchemaDigest: schemaDigest, ToolNames: append([]string(nil), toolNames...), ReadOnly: true,
	}
}

func productToolName(capabilityID, operation string) string {
	capabilityID = strings.TrimSpace(capabilityID)
	operation = strings.TrimSpace(operation)
	if capabilityID == "" || operation == "" {
		return ""
	}
	raw := "product_" + capabilityID + "_" + operation
	var normalized strings.Builder
	normalized.Grow(len(raw))
	for _, current := range raw {
		if (current >= 'a' && current <= 'z') || (current >= 'A' && current <= 'Z') ||
			(current >= '0' && current <= '9') || current == '_' {
			normalized.WriteRune(current)
		} else {
			normalized.WriteByte('_')
		}
	}
	name := normalized.String()
	if len(name) > 128 {
		h := sha256.Sum256([]byte(raw))
		name = name[:95] + "_" + hex.EncodeToString(h[:])[:32]
	}
	return name
}

func productCatalogDigest(catalog *capv1.DescribeCapabilitiesResponse) string {
	if catalog == nil {
		return ""
	}
	if len(catalog.GetCatalogDigest()) == sha256.Size {
		return hex.EncodeToString(catalog.GetCatalogDigest())
	}
	b, _ := deterministicProductCatalogBytes(catalog)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func cloneProductCatalog(catalog *capv1.DescribeCapabilitiesResponse) *capv1.DescribeCapabilitiesResponse {
	if catalog == nil {
		return &capv1.DescribeCapabilitiesResponse{}
	}
	clone, ok := proto.Clone(catalog).(*capv1.DescribeCapabilitiesResponse)
	if !ok {
		return &capv1.DescribeCapabilitiesResponse{}
	}
	sort.Slice(clone.Capabilities, func(i, j int) bool {
		return clone.Capabilities[i].GetCapabilityId() < clone.Capabilities[j].GetCapabilityId()
	})
	for _, capability := range clone.Capabilities {
		if capability == nil {
			continue
		}
		sort.Slice(capability.Operations, func(i, j int) bool {
			return capability.Operations[i].GetOperationId() < capability.Operations[j].GetOperationId()
		})
	}
	return clone
}

func deterministicProductCatalogBytes(catalog *capv1.DescribeCapabilitiesResponse) ([]byte, error) {
	return (proto.MarshalOptions{Deterministic: true}).Marshal(cloneProductCatalog(catalog))
}

func productOperationAllowed(operation *capv1.OperationDescriptor, permission *capv1.PermissionContext) bool {
	if operation == nil || operation.GetOperationId() == "" || operation.GetOperationType() != capv1.OperationType_OPERATION_TYPE_READ || permission == nil || len(operation.GetRequiredScopes()) == 0 || len(permission.GetGrantedScopes()) == 0 {
		return false
	}
	if !containsProductAudience(operation.GetAudience(), capv1.Audience_AUDIENCE_NATIVE_AGENT) {
		return false
	}
	granted := make(map[string]struct{}, len(permission.GetGrantedScopes()))
	for _, scope := range permission.GetGrantedScopes() {
		granted[scope] = struct{}{}
	}
	for _, required := range operation.GetRequiredScopes() {
		if _, ok := granted[required]; !ok {
			return false
		}
	}
	if operation.GetRiskLevel() >= capv1.RiskLevel_RISK_LEVEL_HIGH || len(operation.GetRequiredGrants()) > 0 {
		return false
	}
	return true
}

func containsProductAudience(audiences []capv1.Audience, want capv1.Audience) bool {
	for _, audience := range audiences {
		if audience == want {
			return true
		}
	}
	return false
}

func productToolSchema(operation *capv1.OperationDescriptor) ([]byte, map[string]any, bool) {
	if operation == nil {
		return nil, nil, false
	}
	raw := operation.GetInputSchemaJson()
	if strings.TrimSpace(raw) == "" {
		return nil, nil, false
	}
	var schema map[string]any
	if json.Unmarshal([]byte(raw), &schema) != nil || schema == nil {
		return nil, nil, false
	}
	sum := sha256.Sum256([]byte(raw))
	if len(operation.GetInputSchemaDigest()) != sha256.Size || !bytes.Equal(operation.GetInputSchemaDigest(), sum[:]) {
		return nil, nil, false
	}
	digest := append([]byte(nil), sum[:]...)
	return digest, schema, true
}

func productToolsSchemaDigest(tools []coremodel.Tool) string {
	ordered := append([]coremodel.Tool(nil), tools...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	b, _ := json.Marshal(ordered)
	return digestBytes(b)
}

func validateProductCatalogDigest(catalog *capv1.DescribeCapabilitiesResponse) (string, error) {
	if catalog == nil || len(catalog.GetCatalogDigest()) != sha256.Size {
		return "", fmt.Errorf("product catalog digest is missing or invalid")
	}
	encoded, err := productCatalogWireBytes(catalog)
	if err != nil {
		return "", fmt.Errorf("encode product catalog: %w", err)
	}
	sum := sha256.Sum256(encoded)
	if !bytes.Equal(catalog.GetCatalogDigest(), sum[:]) {
		return "", fmt.Errorf("product catalog digest mismatch")
	}
	return hex.EncodeToString(sum[:]), nil
}

// productCatalogWireBytes mirrors the Product server's deterministic digest:
// capability descriptors are ordered by ID while each descriptor's advertised
// operation order remains part of the signed catalog bytes.
func productCatalogWireBytes(catalog *capv1.DescribeCapabilitiesResponse) ([]byte, error) {
	if catalog == nil {
		return nil, fmt.Errorf("catalog is required")
	}
	clone, ok := proto.Clone(catalog).(*capv1.DescribeCapabilitiesResponse)
	if !ok {
		return nil, fmt.Errorf("catalog clone failed")
	}
	sort.Slice(clone.Capabilities, func(i, j int) bool {
		return clone.Capabilities[i].GetCapabilityId() < clone.Capabilities[j].GetCapabilityId()
	})
	var out bytes.Buffer
	for _, descriptor := range clone.Capabilities {
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(descriptor)
		if err != nil {
			return nil, err
		}
		_, _ = out.Write(encoded)
	}
	return out.Bytes(), nil
}

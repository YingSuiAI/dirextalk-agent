package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestProductOperationAllowedUsesReadinessAudienceScopesAndRisk(t *testing.T) {
	permission := &capv1.PermissionContext{GrantedScopes: []string{"contacts:read", "contacts:write"}}
	base := &capv1.OperationDescriptor{OperationId: "list", OperationType: capv1.OperationType_OPERATION_TYPE_READ, Audience: []capv1.Audience{capv1.Audience_AUDIENCE_NATIVE_AGENT}, RequiredScopes: []string{"contacts:read"}}
	if !productOperationAllowed(base, permission) {
		t.Fatal("native read operation was filtered")
	}
	for name, mutate := range map[string]func(*capv1.OperationDescriptor){
		"missing audience": func(op *capv1.OperationDescriptor) {
			op.Audience = []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT}
		},
		"missing scope": func(op *capv1.OperationDescriptor) { op.RequiredScopes = []string{"contacts:delete"} },
		"mutation": func(op *capv1.OperationDescriptor) {
			op.OperationType = capv1.OperationType_OPERATION_TYPE_MUTATION
		},
		"required grant": func(op *capv1.OperationDescriptor) {
			op.OperationType = capv1.OperationType_OPERATION_TYPE_MUTATION
			op.RequiredGrants = []string{"aws:deploy"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			op := proto.Clone(base).(*capv1.OperationDescriptor)
			mutate(op)
			if productOperationAllowed(op, permission) {
				t.Fatal("unsafe/unscoped operation was allowed")
			}
		})
	}
	if productOperationAllowed(&capv1.OperationDescriptor{OperationId: "x", OperationType: capv1.OperationType_OPERATION_TYPE_READ, Audience: []capv1.Audience{capv1.Audience_AUDIENCE_NATIVE_AGENT}, RequiredScopes: []string{"contacts:read", "contacts:write"}}, &capv1.PermissionContext{GrantedScopes: []string{"contacts:read"}}) {
		t.Fatal("partial scope grant was accepted")
	}
}

func TestProductConversationSnapshotIsReadOnlySyntheticTool(t *testing.T) {
	selection := coreconversation.ExtensionSelection{
		Kind: coreconversation.ExtensionMCP, ID: uuid.NewString(), Version: "1.0.0",
		Digest: strings.Repeat("a", 64), AllowedTools: []string{"product_product_rooms_v1_list"},
	}
	snapshot := productConversationSnapshot(selection, selection.Digest, strings.Repeat("b", 64), strings.Repeat("c", 64), selection.AllowedTools)
	if !snapshot.ReadOnly || snapshot.Source != "product-capability" || snapshot.VersionID != selection.Version {
		t.Fatalf("product snapshot is not a read-only synthetic tool: %+v", snapshot)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("product snapshot is invalid: %v", err)
	}
}

func TestProductCatalogDigestUsesServerDigestOrDeterministicFallback(t *testing.T) {
	descriptor := &capv1.CapabilityDescriptor{CapabilityId: "z", Operations: []*capv1.OperationDescriptor{{OperationId: "b"}, {OperationId: "a"}}}
	catalog := &capv1.DescribeCapabilitiesResponse{Capabilities: []*capv1.CapabilityDescriptor{descriptor}}
	first := productCatalogDigest(catalog)
	if len(first) != sha256.Size*2 {
		t.Fatalf("fallback catalog digest=%q", first)
	}
	clone := cloneProductCatalog(catalog)
	if clone.GetCapabilities()[0].GetOperations()[0].GetOperationId() != "a" {
		t.Fatalf("operations were not sorted in deterministic clone")
	}
	serverDigest := bytes.Repeat([]byte{0x5a}, sha256.Size)
	catalog.CatalogDigest = serverDigest
	if got := productCatalogDigest(catalog); got != hex.EncodeToString(serverDigest) {
		t.Fatalf("server catalog digest=%q", got)
	}
	encoded, err := productCatalogWireBytes(catalog)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	catalog.CatalogDigest = sum[:]
	if got, err := validateProductCatalogDigest(catalog); err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("validated catalog digest=%q err=%v", got, err)
	}
	catalog.CatalogDigest[0] ^= 0xff
	if _, err := validateProductCatalogDigest(catalog); err == nil {
		t.Fatal("accepted mismatched advertised catalog digest")
	}
}

func TestProductToolSchemaRequiresAdvertisedDigestAndNonEmptySchema(t *testing.T) {
	raw := `{"type":"object","properties":{"q":{"type":"string"}}}`
	sum := sha256.Sum256([]byte(raw))
	op := &capv1.OperationDescriptor{InputSchemaJson: raw, InputSchemaDigest: sum[:]}
	if _, _, ok := productToolSchema(op); !ok {
		t.Fatal("valid advertised schema was rejected")
	}
	op.InputSchemaDigest[0] ^= 0xff
	if _, _, ok := productToolSchema(op); ok {
		t.Fatal("mismatched advertised schema digest was accepted")
	}
	if _, _, ok := productToolSchema(&capv1.OperationDescriptor{InputSchemaJson: `{}`}); ok {
		t.Fatal("schema without advertised digest was accepted")
	}
	if _, _, ok := productToolSchema(&capv1.OperationDescriptor{}); ok {
		t.Fatal("empty schema was accepted")
	}
}

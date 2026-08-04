package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type grantTestCapability struct{ descriptor *capv1.CapabilityDescriptor }

func (c grantTestCapability) Descriptor() *capv1.CapabilityDescriptor { return c.descriptor }
func (grantTestCapability) HandleOperation(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return []byte(`{"ok":true}`), nil
}

type grantTestRegistry struct{ capability grantTestCapability }

func (r grantTestRegistry) Get(id string) (Capability, bool) {
	if r.capability.descriptor.GetCapabilityId() != id {
		return nil, false
	}
	return r.capability, true
}
func (r grantTestRegistry) List() []*capv1.CapabilityDescriptor {
	return []*capv1.CapabilityDescriptor{r.capability.descriptor}
}

func TestVerifyGrantBindsAgentCatalogSchemaAndOperation(t *testing.T) {
	operation := &capv1.OperationDescriptor{
		OperationId:     "read",
		OperationType:   capv1.OperationType_OPERATION_TYPE_READ,
		InputSchemaJson: `{"type":"object"}`,
		RequiredScopes:  []string{"agent:read"},
	}
	descriptor := &capv1.CapabilityDescriptor{
		CapabilityId:    "agent.test.v1",
		SemanticVersion: "1.0.0",
		ProtocolVersion: 1,
		Operations:      []*capv1.OperationDescriptor{operation},
		Readiness:       true,
	}
	registry := grantTestRegistry{capability: grantTestCapability{descriptor: descriptor}}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	key := privateKey.Public().(ed25519.PublicKey)
	rootOperation := uuid.NewString()
	owner := uuid.NewString()
	call := &capv1.CallContext{ChainId: uuid.NewString(), RootOperationId: rootOperation, Hop: 2, Route: "ms→agent", DeadlineUnixMs: time.Now().Add(time.Minute).UnixMilli()}
	schema := sha256.Sum256([]byte(operation.GetInputSchemaJson()))
	catalog := computeCatalogDigest(registry.List())
	grant, err := (capv1.GrantCodec{}).Sign(capv1.GrantClaims{
		ChainID: uuid.MustParse(call.GetChainId()).String(), RootOperationID: rootOperation, EntryRoute: capv1.NodeMessage, EntryHop: 1, OwnerID: owner, AccountGeneration: 7,
		Scopes: []string{"agent:read"}, RootCapabilityID: descriptor.GetCapabilityId(), RootOperation: operation.GetOperationId(),
		RootRequestDigest: bytes.Repeat([]byte{0x33}, sha256.Size),
		CatalogDigest:     catalog, SchemaDigest: schema[:],
		MaxHop: capv1.MaxCallHop,
	}, privateKey)
	if err != nil {
		t.Fatalf("sign grant: %v", err)
	}
	permission := &capv1.PermissionContext{AuthenticatedOwnerId: owner, AccountGeneration: 7, CapabilityGrant: grant, GrantedScopes: []string{"agent:read"}}
	s := &Server{registry: registry, grantKey: key}
	if err := s.verifyAgentGrant(call, permission, descriptor, "read", bytes.Repeat([]byte{0x33}, sha256.Size), false); err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}

	mutate := func(name string, change func(*capv1.GrantClaims)) {
		t.Helper()
		claims := capv1.GrantClaims{ChainID: call.GetChainId(), RootOperationID: rootOperation, EntryRoute: capv1.NodeMessage, EntryHop: 1, OwnerID: owner, AccountGeneration: 7, Scopes: []string{"agent:read"}, RootCapabilityID: descriptor.GetCapabilityId(), RootOperation: operation.GetOperationId(), RootRequestDigest: bytes.Repeat([]byte{0x33}, sha256.Size), CatalogDigest: catalog, SchemaDigest: schema[:], MaxHop: capv1.MaxCallHop}
		change(&claims)
		forged, signErr := (capv1.GrantCodec{}).Sign(claims, privateKey)
		if signErr != nil {
			t.Fatalf("sign %s grant: %v", name, signErr)
		}
		permission.CapabilityGrant = forged
		if verifyErr := s.verifyAgentGrant(call, permission, descriptor, "read", bytes.Repeat([]byte{0x33}, sha256.Size), false); !errors.Is(verifyErr, capv1.ErrGrantBinding) {
			t.Fatalf("%s mutation accepted: %v", name, verifyErr)
		}
		permission.CapabilityGrant = grant
	}
	mutate("catalog", func(claims *capv1.GrantClaims) { claims.CatalogDigest[0] ^= 0xff })
	mutate("schema", func(claims *capv1.GrantClaims) { claims.SchemaDigest[0] ^= 0xff })
	mutate("root operation", func(claims *capv1.GrantClaims) { claims.RootOperation = "write" })
}

func TestRootAndFinalRequestDigestsAreDistinctBindings(t *testing.T) {
	operation := &capv1.OperationDescriptor{OperationId: "write", OperationType: capv1.OperationType_OPERATION_TYPE_MUTATION, InputSchemaJson: `{"type":"object"}`, RequiredScopes: []string{"agent:write"}}
	descriptor := &capv1.CapabilityDescriptor{CapabilityId: "agent.test.v1", SemanticVersion: "1.0.0", ProtocolVersion: 1, Operations: []*capv1.OperationDescriptor{operation}}
	grant := bytes.Repeat([]byte{0x41}, 64)
	req := &capv1.StartOperationRequest{OperationId: uuid.NewString(), CapabilityId: descriptor.GetCapabilityId(), Operation: operation.GetOperationId(), RequestJson: []byte(`{"value":1}`), Permission: &capv1.PermissionContext{CapabilityGrant: grant}, ExpectedRevision: 0}
	rootDigest, err := canonicalRootRequestDigest(descriptor, operation, req)
	if err != nil {
		t.Fatal(err)
	}
	finalDigest, err := canonicalRequestDigest(descriptor, operation, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := capv1.VerifyRequestDigest(finalDigest, finalDigest); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rootDigest, finalDigest) {
		t.Fatal("root request digest unexpectedly includes permission grant")
	}
	second := append([]byte(nil), grant...)
	second[0] ^= 0xff
	req.Permission.CapabilityGrant = second
	changedFinal, err := canonicalRequestDigest(descriptor, operation, req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootDigest, mustRootDigest(t, descriptor, operation, req)) || bytes.Equal(finalDigest, changedFinal) {
		t.Fatal("grant mutation did not preserve root / change final digest")
	}
}

func mustRootDigest(t *testing.T, descriptor *capv1.CapabilityDescriptor, operation *capv1.OperationDescriptor, req *capv1.StartOperationRequest) []byte {
	t.Helper()
	digest, err := canonicalRootRequestDigest(descriptor, operation, req)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestOperationControlGrantIsDomainSeparatedAndTargetBound(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6b}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	call := &capv1.CallContext{ChainId: uuid.NewString(), RootOperationId: uuid.NewString(), Hop: 2, Route: "ms→agent", DeadlineUnixMs: time.Now().Add(time.Minute).UnixMilli()}
	op := &operation.Operation{ID: uuid.NewString(), OwnerID: "owner", AccountGeneration: 3}
	control, err := (capv1.GrantCodec{}).SignOperationControlGrant(capv1.OperationControlGrant{ChainID: call.GetChainId(), OwnerID: op.OwnerID, AccountGeneration: op.AccountGeneration, OperationID: op.ID, ControlAction: "get", ControlScope: "operation:control:get", EntryRoute: "ms", EntryHop: 1, DeadlineUnixMs: call.GetDeadlineUnixMs()}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{config: &Config{AccountGeneration: op.AccountGeneration}, grantKey: publicKey}
	permission := &capv1.PermissionContext{AuthenticatedOwnerId: op.OwnerID, AccountGeneration: op.AccountGeneration, CapabilityGrant: control}
	if err := s.authorizeOperation(call, permission, op, "get"); err != nil {
		t.Fatalf("valid control grant rejected: %v", err)
	}
	if err := s.authorizeOperation(call, permission, op, "cancel"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("control action replay accepted: %v", err)
	}
	root := bytes.Repeat([]byte{0x4a}, 32)
	rootGrant, err := (capv1.GrantCodec{}).Sign(capv1.GrantClaims{ChainID: call.GetChainId(), RootOperationID: call.GetRootOperationId(), OwnerID: op.OwnerID, AccountGeneration: op.AccountGeneration, Scopes: []string{"agent:read"}, RootCapabilityID: "agent.test.v1", RootOperation: "read", RootRequestDigest: root, CatalogDigest: root, SchemaDigest: root, EntryRoute: "ms", EntryHop: 1, MaxHop: capv1.MaxCallHop}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	permission.CapabilityGrant = rootGrant
	if err := s.authorizeOperation(call, permission, op, "get"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("root grant crossed into control verifier: %v", err)
	}
}

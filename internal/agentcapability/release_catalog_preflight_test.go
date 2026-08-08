package agentcapability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfig"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// TestMessageServerBaselineCatalogPreflight is a release-time cross-repository
// contract check, not a runtime dependency. It reads the sibling Message Server
// Go sources as data and compares every readiness-baseline action against the
// real Agent descriptor constructors. All differences are reported together so
// a release cannot expose catalog drift one action at a time.
func TestMessageServerBaselineCatalogPreflight(t *testing.T) {
	messageServerRoot := strings.TrimSpace(os.Getenv("DIREXTALK_MESSAGE_SERVER_ROOT"))
	explicitRoot := messageServerRoot != ""
	if messageServerRoot == "" {
		candidate, err := filepath.Abs(filepath.Join("..", "..", "..", "dirextalk-message-server"))
		if err != nil {
			t.Fatal(err)
		}
		messageServerRoot = candidate
	}
	requiredFiles := []string{
		filepath.Join(messageServerRoot, "p2p", "native_agent_catalog.go"),
		filepath.Join(messageServerRoot, "internal", "agentgateway", "runner.go"),
		filepath.Join(messageServerRoot, "internal", "agentgateway", "catalog_requirements.go"),
	}
	for _, path := range requiredFiles {
		if _, err := os.Stat(path); err != nil {
			if explicitRoot {
				t.Fatalf("Message Server release-preflight input is unavailable: %v", err)
			}
			t.Skipf("Message Server checkout is unavailable for release preflight: %v", err)
		}
	}

	baseline, err := parseBaselineActions(requiredFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := parseActionBindings(requiredFiles[1])
	if err != nil {
		t.Fatal(err)
	}
	pins, err := parseCatalogPins(requiredFiles[2])
	if err != nil {
		t.Fatal(err)
	}
	descriptors := releaseBaselineDescriptors()

	var mismatches []string
	for _, action := range baseline {
		binding, ok := bindings[action]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("%s: Message Server baseline action has no runner binding", action))
			continue
		}
		pin, ok := pins[action]
		if !ok || len(pin.input) != sha256.Size || len(pin.result) != sha256.Size {
			mismatches = append(mismatches, fmt.Sprintf("%s: Message Server baseline action has no complete schema pin", action))
			continue
		}
		descriptor := descriptors[binding.capability]
		if descriptor == nil {
			mismatches = append(mismatches, fmt.Sprintf("%s: Agent capability %s is missing", action, binding.capability))
			continue
		}
		if !descriptor.GetReadiness() || descriptor.GetProtocolVersion() != 1 {
			mismatches = append(mismatches, fmt.Sprintf("%s: Agent capability %s is not ready on protocol 1", action, binding.capability))
			continue
		}
		operation := operationByID(descriptor, binding.operation)
		if operation == nil {
			mismatches = append(mismatches, fmt.Sprintf("%s: Agent operation %s/%s is missing", action, binding.capability, binding.operation))
			continue
		}
		mismatches = append(mismatches, comparePinnedSchema(action, "input", operation.GetInputSchemaJson(), operation.GetInputSchemaDigest(), pin.input)...)
		mismatches = append(mismatches, comparePinnedSchema(action, "result", operation.GetResultSchemaJson(), operation.GetResultSchemaDigest(), pin.result)...)
		if len(pin.event) > 0 || operation.GetEventSchemaJson() != "" || len(operation.GetEventSchemaDigest()) > 0 {
			mismatches = append(mismatches, comparePinnedSchema(action, "event", operation.GetEventSchemaJson(), operation.GetEventSchemaDigest(), pin.event)...)
		}
	}
	if len(mismatches) != 0 {
		sort.Strings(mismatches)
		t.Fatalf("Message Server baseline catalog mismatches (%d):\n- %s", len(mismatches), strings.Join(mismatches, "\n- "))
	}
	t.Logf("verified %d Message Server baseline actions against %d Agent capability descriptors", len(baseline), len(descriptors))
}

type releaseCatalogBinding struct{ capability, operation string }

type releaseCatalogPin struct{ input, result, event []byte }

type releaseConfigStore struct{}

func (releaseConfigStore) Get(context.Context, string) (coreconfig.Config, error) {
	return coreconfig.Config{}, nil
}

func (releaseConfigStore) Update(context.Context, string, coreconfig.Update) (coreconfig.Config, error) {
	return coreconfig.Config{}, nil
}

func releaseBaselineDescriptors() map[string]*capv1.CapabilityDescriptor {
	values := []*capv1.CapabilityDescriptor{
		(&coreAccountCapability{}).Descriptor(),
		NewInfoCapability(InfoProviderFunc{}).Descriptor(),
		NewConfigCapability(nil, releaseConfigStore{}).Descriptor(),
		(&coreChatCapability{}).Descriptor(),
		NewCoreWebSearchCapability(nil).Descriptor(),
		NewCoreTextToolCapability(nil).Descriptor(),
		NewCoreImageToolCapability(nil).Descriptor(),
		(&coreModelCapability{}).Descriptor(),
		(&coreKnowledgeCapability{}).Descriptor(),
		(&coreTaskCapability{}).Descriptor(),
		(&coreScheduleCapability{}).Descriptor(),
		(&coreConfirmationCapability{}).Descriptor(),
	}
	result := make(map[string]*capv1.CapabilityDescriptor, len(values))
	for _, descriptor := range values {
		if descriptor != nil {
			result[descriptor.GetCapabilityId()] = descriptor
		}
	}
	return result
}

func operationByID(descriptor *capv1.CapabilityDescriptor, operationID string) *capv1.OperationDescriptor {
	for _, operation := range descriptor.GetOperations() {
		if operation.GetOperationId() == operationID {
			return operation
		}
	}
	return nil
}

func comparePinnedSchema(action, kind, schema string, advertised, expected []byte) []string {
	var mismatches []string
	if strings.TrimSpace(schema) == "" {
		return []string{fmt.Sprintf("%s: Agent %s schema is missing", action, kind)}
	}
	digest := sha256.Sum256([]byte(schema))
	if len(advertised) != sha256.Size || !equalBytes(advertised, digest[:]) {
		mismatches = append(mismatches, fmt.Sprintf("%s: Agent %s schema digest is not self-consistent", action, kind))
	}
	if len(expected) != sha256.Size || !equalBytes(expected, digest[:]) {
		mismatches = append(mismatches, fmt.Sprintf("%s: Agent %s schema digest=%s, Message Server pin=%s", action, kind, hex.EncodeToString(digest[:]), hex.EncodeToString(expected)))
	}
	return mismatches
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func parseBaselineActions(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	var actions []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "nativeAgentCatalogRequirements" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			literal, literalOK := assignment.Rhs[0].(*ast.CompositeLit)
			if !ok || !literalOK || name.Name != "base" {
				return true
			}
			for _, element := range literal.Elts {
				if value, ok := stringLiteral(element); ok {
					actions = append(actions, value)
				}
			}
			return false
		})
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("parse Message Server baseline: no actions found in %s", path)
	}
	return actions, nil
}

func parseActionBindings(path string) (map[string]releaseCatalogBinding, error) {
	literal, err := parsePackageVariable(path, "actionBindings")
	if err != nil {
		return nil, err
	}
	result := make(map[string]releaseCatalogBinding, len(literal.Elts))
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		action, ok := stringLiteral(pair.Key)
		value, valueOK := pair.Value.(*ast.CompositeLit)
		if !ok || !valueOK || len(value.Elts) != 2 {
			continue
		}
		capability, capabilityOK := stringLiteral(value.Elts[0])
		operation, operationOK := stringLiteral(value.Elts[1])
		if capabilityOK && operationOK {
			result[action] = releaseCatalogBinding{capability: capability, operation: operation}
		}
	}
	return result, nil
}

func parseCatalogPins(path string) (map[string]releaseCatalogPin, error) {
	literal, err := parsePackageVariable(path, "expectedCatalogSchemaDigests")
	if err != nil {
		return nil, err
	}
	result := make(map[string]releaseCatalogPin, len(literal.Elts))
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		action, ok := stringLiteral(pair.Key)
		value, valueOK := pair.Value.(*ast.CompositeLit)
		if !ok || !valueOK {
			continue
		}
		encoded := make(map[string]string)
		for _, field := range value.Elts {
			item, itemOK := field.(*ast.KeyValueExpr)
			if !itemOK {
				continue
			}
			name, nameOK := item.Key.(*ast.Ident)
			text, textOK := stringLiteral(item.Value)
			if nameOK && textOK {
				encoded[name.Name] = text
			}
		}
		input, inputErr := hex.DecodeString(encoded["inputHex"])
		resultDigest, resultErr := hex.DecodeString(encoded["resultHex"])
		event, eventErr := hex.DecodeString(encoded["eventHex"])
		if inputErr != nil || resultErr != nil || eventErr != nil {
			return nil, fmt.Errorf("parse Message Server schema pins for %s", action)
		}
		result[action] = releaseCatalogPin{input: input, result: resultDigest, event: event}
	}
	return result, nil
}

func parsePackageVariable(path, variable string) (*ast.CompositeLit, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range value.Names {
				if name.Name == variable && index < len(value.Values) {
					if literal, ok := value.Values[index].(*ast.CompositeLit); ok {
						return literal, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("parse %s: variable %s was not found", path, variable)
}

func stringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

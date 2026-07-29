package teamplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const maximumProposalBytes = 256 << 10

type proposalInputV1 struct {
	Roles      []roleProposalInputV1 `json:"roles"`
	Confidence uint32                `json:"confidence"`
	Rationale  string                `json:"rationale"`
}

type roleProposalInputV1 struct {
	RoleID               string              `json:"role_id"`
	Title                string              `json:"title"`
	Objective            string              `json:"objective"`
	WorkClass            WorkClass           `json:"work_class"`
	RequiredCapabilities []Capability        `json:"required_capabilities"`
	PreferredFamilies    []RuntimeFamily     `json:"preferred_families,omitempty"`
	Workspace            WorkspaceMode       `json:"workspace"`
	DependsOnRoleIDs     []string            `json:"depends_on_role_ids,omitempty"`
	Duration             durationInputV1     `json:"duration"`
	Tokens               TokenEstimate       `json:"tokens"`
	ModelNeed            ModelNeed           `json:"model_need"`
	MinimumResources     resourceNeedInputV1 `json:"minimum_resources"`
}

type durationInputV1 struct {
	MinimumSeconds  uint64 `json:"minimum_seconds"`
	ExpectedSeconds uint64 `json:"expected_seconds"`
	MaximumSeconds  uint64 `json:"maximum_seconds"`
}

type resourceNeedInputV1 struct {
	VCPU      uint32 `json:"vcpu"`
	MemoryMiB uint64 `json:"memory_mib"`
	DiskGiB   uint64 `json:"disk_gib"`
}

// DecodeProposalJSON is the only model-output decoder for TeamProposal. The
// wire shape deliberately has no runtime release, image, model profile,
// credential, provider, Region, instance type, price, or approval field.
func DecodeProposalJSON(raw []byte, policy Policy) (TeamProposal, error) {
	if len(raw) == 0 || len(raw) > maximumProposalBytes ||
		security.ContainsLikelySecret(string(raw)) ||
		validatePolicy(policy) != nil {
		return TeamProposal{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input proposalInputV1
	if err := decoder.Decode(&input); err != nil {
		return TeamProposal{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return TeamProposal{}, ErrInvalid
	}
	proposal := TeamProposal{
		Roles:      make([]RoleProposal, 0, len(input.Roles)),
		Confidence: input.Confidence,
		Rationale:  input.Rationale,
	}
	for _, role := range input.Roles {
		duration, err := decodeDuration(role.Duration)
		if err != nil {
			return TeamProposal{}, err
		}
		proposal.Roles = append(proposal.Roles, RoleProposal{
			RoleID:               role.RoleID,
			Title:                role.Title,
			Objective:            role.Objective,
			WorkClass:            role.WorkClass,
			RequiredCapabilities: append([]Capability(nil), role.RequiredCapabilities...),
			PreferredFamilies:    append([]RuntimeFamily(nil), role.PreferredFamilies...),
			Workspace:            role.Workspace,
			DependsOnRoleIDs:     append([]string(nil), role.DependsOnRoleIDs...),
			Duration:             duration,
			Tokens:               role.Tokens,
			ModelNeed:            role.ModelNeed,
			MinimumResources: ResourceEnvelope{
				VCPU:      role.MinimumResources.VCPU,
				MemoryMiB: role.MinimumResources.MemoryMiB,
				DiskGiB:   role.MinimumResources.DiskGiB,
			},
		})
	}
	if err := validateTeamProposal(proposal, policy); err != nil {
		return TeamProposal{}, err
	}
	return canonicalProposal(proposal), nil
}

// ProposalInputSchema returns the exact closed schema supplied to the capture
// tool. Limits are derived from the trusted policy, not from model output.
func ProposalInputSchema(policy Policy) (map[string]any, error) {
	if err := validatePolicy(policy); err != nil {
		return nil, err
	}
	schema := proposalSchemaForType(reflect.TypeOf(proposalInputV1{}))
	constrainIntegerSchema(proposalProperty(schema, "confidence"), 1, 100)
	constrainStringSchema(proposalProperty(schema, "rationale"), 1, 4096)

	roles := proposalProperty(schema, "roles")
	roles["minItems"] = 1
	roles["maxItems"] = policy.MaxWorkers
	role := proposalSchemaItems(roles)
	roleID := proposalProperty(role, "role_id")
	roleID["pattern"] = roleIDPattern.String()
	constrainStringSchema(proposalProperty(role, "title"), 1, 160)
	constrainStringSchema(proposalProperty(role, "objective"), 1, 8192)
	proposalProperty(role, "work_class")["enum"] = stringValues(validWorkClasses())
	proposalProperty(role, "workspace")["enum"] = stringValues([]WorkspaceMode{
		WorkspaceReadOnly,
		WorkspaceIsolated,
		WorkspaceExclusive,
	})

	capabilities := proposalProperty(role, "required_capabilities")
	capabilities["minItems"] = 1
	capabilities["maxItems"] = 24
	capabilities["uniqueItems"] = true
	proposalSchemaItems(capabilities)["enum"] = stringValues(validCapabilities())

	families := proposalProperty(role, "preferred_families")
	families["maxItems"] = len(validRuntimeFamilies())
	families["uniqueItems"] = true
	proposalSchemaItems(families)["enum"] = stringValues(validRuntimeFamilies())

	dependencies := proposalProperty(role, "depends_on_role_ids")
	dependencies["maxItems"] = policy.MaxWorkers - 1
	dependencies["uniqueItems"] = true
	proposalSchemaItems(dependencies)["pattern"] = roleIDPattern.String()

	duration := proposalProperty(role, "duration")
	maximumSeconds := uint64(policy.MaxRoleDuration / time.Second)
	for _, name := range []string{
		"minimum_seconds",
		"expected_seconds",
		"maximum_seconds",
	} {
		constrainIntegerSchema(proposalProperty(duration, name), 1, maximumSeconds)
	}

	tokens := proposalProperty(role, "tokens")
	for _, name := range []string{
		"input_minimum",
		"input_expected",
		"input_maximum",
		"output_minimum",
		"output_expected",
		"output_maximum",
	} {
		constrainIntegerSchema(proposalProperty(tokens, name), 1, absoluteMaxTokens)
	}

	modelNeed := proposalProperty(role, "model_need")
	proposalProperty(modelNeed, "minimum_quality")["enum"] = stringValues([]QualityTier{
		QualityEconomy,
		QualityBalanced,
		QualityPremium,
	})
	constrainIntegerSchema(
		proposalProperty(modelNeed, "minimum_context_tokens"),
		1,
		absoluteMaxContextTokens,
	)

	resources := proposalProperty(role, "minimum_resources")
	constrainIntegerSchema(
		proposalProperty(resources, "vcpu"),
		1,
		policy.MaxVCPUPerWorker,
	)
	constrainIntegerSchema(
		proposalProperty(resources, "memory_mib"),
		1,
		policy.MaxMemoryMiBPerWorker,
	)
	constrainIntegerSchema(
		proposalProperty(resources, "disk_gib"),
		1,
		policy.MaxDiskGiBPerWorker,
	)
	return schema, nil
}

func decodeDuration(value durationInputV1) (DurationEstimate, error) {
	minimum, err := durationFromSeconds(value.MinimumSeconds)
	if err != nil {
		return DurationEstimate{}, err
	}
	expected, err := durationFromSeconds(value.ExpectedSeconds)
	if err != nil {
		return DurationEstimate{}, err
	}
	maximum, err := durationFromSeconds(value.MaximumSeconds)
	if err != nil {
		return DurationEstimate{}, err
	}
	return DurationEstimate{
		Minimum: minimum, Expected: expected, Maximum: maximum,
	}, nil
}

func durationFromSeconds(value uint64) (time.Duration, error) {
	if value == 0 || value > uint64(math.MaxInt64/int64(time.Second)) {
		return 0, ErrInvalid
	}
	return time.Duration(value) * time.Second, nil
}

func proposalSchemaForType(value reflect.Type) map[string]any {
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Struct:
		properties := make(map[string]any)
		required := make([]string, 0, value.NumField())
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			if !field.IsExported() {
				continue
			}
			name, optional := proposalJSONFieldName(field)
			if name == "" {
				continue
			}
			properties[name] = proposalSchemaForType(field.Type)
			if !optional {
				required = append(required, name)
			}
		}
		result := map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties":           properties,
		}
		if len(required) > 0 {
			result["required"] = required
		}
		return result
	case reflect.Slice, reflect.Array:
		return map[string]any{
			"type":  "array",
			"items": proposalSchemaForType(value.Elem()),
		}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	default:
		return map[string]any{"type": "string"}
	}
}

func proposalJSONFieldName(field reflect.StructField) (string, bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	if name == "" {
		name = field.Name
	}
	optional := false
	for _, option := range parts[1:] {
		optional = optional || option == "omitempty"
	}
	return name, optional
}

func proposalProperty(schema map[string]any, name string) map[string]any {
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		panic("Team Proposal schema object is missing properties")
	}
	property, ok := properties[name].(map[string]any)
	if !ok {
		panic("Team Proposal schema is missing property " + name)
	}
	return property
}

func proposalSchemaItems(schema map[string]any) map[string]any {
	items, ok := schema["items"].(map[string]any)
	if !ok {
		panic("Team Proposal array schema is missing items")
	}
	return items
}

func constrainStringSchema(schema map[string]any, minimum, maximum int) {
	schema["minLength"] = minimum
	schema["maxLength"] = maximum
}

func constrainIntegerSchema[T ~int | ~uint32 | ~uint64](
	schema map[string]any,
	minimum T,
	maximum T,
) {
	schema["minimum"] = minimum
	schema["maximum"] = maximum
}

func stringValues[T ~string](values []T) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return result
}

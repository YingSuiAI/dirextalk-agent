package coreteaminput

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

var (
	digestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	rolePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	providerPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	modelPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	mediaPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$`)
)

func Compile(request CompileRequest) (CompiledInput, error) {
	assignment := cloneAssignment(request.Assignment)
	if assignment.RuntimeContextDigest != "" {
		return CompiledInput{}, ErrInvalid
	}
	validationAssignment := cloneAssignment(assignment)
	if validationAssignment.WorkerID == "" {
		validationAssignment.WorkerID = "11111111-1111-4111-8111-111111111111"
	}
	validationAssignment.RuntimeContextDigest = strings.Repeat("0", 64)
	if validationAssignment.Validate() != nil || validateModel(request.Model) != nil || request.CredentialRevision == 0 ||
		!digestPattern.MatchString(request.WorkspaceDigest) || validateCredential(request.Credential) != nil {
		return CompiledInput{}, ErrInvalid
	}
	contextDocument, err := compileContext(validationAssignment, request.Context, request.DependencyRoles)
	if err != nil {
		return CompiledInput{}, err
	}
	contextJSON, err := json.Marshal(contextDocument)
	if err != nil || len(contextJSON) == 0 || len(contextJSON) > MaxContextBytes || security.ContainsLikelySecret(string(contextJSON)) {
		clear(contextJSON)
		return CompiledInput{}, ErrInvalid
	}
	contextDigest := digestBytes(contextJSON)
	capabilities := append([]coreteam.Capability(nil), validationAssignment.Capabilities...)
	slices.Sort(capabilities)
	manifest := ManifestV1{
		SchemaVersion: ManifestSchemaV1, ExecutionID: validationAssignment.ExecutionID, PlanID: validationAssignment.PlanID,
		RoleID: validationAssignment.RoleID, Attempt: validationAssignment.Attempt, PlanDigest: validationAssignment.PlanDigest,
		GoalDigest: digestBytes([]byte(validationAssignment.Goal)), Capabilities: capabilities,
		RuntimeID: validationAssignment.RuntimeID, OutputTokens: validationAssignment.OutputTokens,
		ResultSchemaVersion: validationAssignment.ResultSchemaVersion, Model: request.Model,
		CredentialRevision: request.CredentialRevision, ContextDigest: contextDigest,
		WorkspaceDigest: request.WorkspaceDigest,
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil || len(manifestJSON) == 0 || len(manifestJSON) > MaxManifestBytes || security.ContainsLikelySecret(string(manifestJSON)) {
		clear(contextJSON)
		clear(manifestJSON)
		return CompiledInput{}, ErrInvalid
	}
	runtimeDigest, err := runtimeContextDigest(manifestJSON, request.Credential)
	if err != nil {
		clear(contextJSON)
		clear(manifestJSON)
		return CompiledInput{}, err
	}
	assignment.RuntimeContextDigest = runtimeDigest
	assignment.Capabilities = capabilities
	return CompiledInput{
		Assignment: assignment, Manifest: manifest, ContextJSON: contextJSON,
		ManifestJSON: manifestJSON, RuntimeContextDigest: runtimeDigest,
	}, nil
}

func VerifyMaterialized(input MaterializedInput) error {
	if input.Assignment.Validate() != nil || validateModel(input.Model) != nil || input.CredentialRevision == 0 ||
		!digestPattern.MatchString(input.WorkspaceDigest) || validateCredential(input.Credential) != nil {
		return ErrInvalid
	}
	var manifest ManifestV1
	if decodeCanonical(input.ManifestJSON, MaxManifestBytes, &manifest) != nil || validateManifest(manifest) != nil {
		return ErrInvalid
	}
	var contextDocument ContextDocumentV1
	if decodeCanonical(input.ContextJSON, MaxContextBytes, &contextDocument) != nil || validateContextDocument(contextDocument, nil) != nil ||
		security.ContainsLikelySecret(string(input.ContextJSON)) {
		return ErrInvalid
	}
	capabilities := append([]coreteam.Capability(nil), input.Assignment.Capabilities...)
	slices.Sort(capabilities)
	if manifest.ExecutionID != input.Assignment.ExecutionID || manifest.PlanID != input.Assignment.PlanID ||
		manifest.RoleID != input.Assignment.RoleID || manifest.Attempt != input.Assignment.Attempt ||
		manifest.PlanDigest != input.Assignment.PlanDigest || manifest.GoalDigest != digestBytes([]byte(input.Assignment.Goal)) ||
		!slices.Equal(manifest.Capabilities, capabilities) || manifest.RuntimeID != input.Assignment.RuntimeID ||
		manifest.OutputTokens != input.Assignment.OutputTokens || manifest.ResultSchemaVersion != input.Assignment.ResultSchemaVersion ||
		manifest.Model != input.Model || manifest.CredentialRevision != input.CredentialRevision ||
		manifest.ContextDigest != digestBytes(input.ContextJSON) || manifest.WorkspaceDigest != input.WorkspaceDigest ||
		contextDocument.ExecutionID != input.Assignment.ExecutionID || contextDocument.PlanID != input.Assignment.PlanID ||
		contextDocument.PlanDigest != input.Assignment.PlanDigest || contextDocument.RoleID != input.Assignment.RoleID {
		return ErrInvalid
	}
	actual, err := runtimeContextDigest(input.ManifestJSON, input.Credential)
	if err != nil || subtle.ConstantTimeCompare([]byte(actual), []byte(input.Assignment.RuntimeContextDigest)) != 1 {
		return ErrInvalid
	}
	return nil
}

func compileContext(assignment coreteamworker.Assignment, input ContextInput, dependencyRoles []string) (ContextDocumentV1, error) {
	allowed := make(map[string]struct{}, len(dependencyRoles))
	for _, roleID := range dependencyRoles {
		if !rolePattern.MatchString(roleID) || roleID == assignment.RoleID {
			return ContextDocumentV1{}, ErrInvalid
		}
		if _, duplicate := allowed[roleID]; duplicate {
			return ContextDocumentV1{}, ErrInvalid
		}
		allowed[roleID] = struct{}{}
	}
	document := ContextDocumentV1{
		SchemaVersion: ContextSchemaV1, ExecutionID: assignment.ExecutionID, PlanID: assignment.PlanID,
		PlanDigest: assignment.PlanDigest, RoleID: assignment.RoleID, GoalSummary: input.GoalSummary,
		Constraints:  append([]string{}, input.Constraints...),
		Dependencies: append([]DependencyResultV1{}, input.Dependencies...),
		Artifacts:    append([]ArtifactRefV1{}, input.Artifacts...),
	}
	slices.Sort(document.Constraints)
	slices.SortFunc(document.Dependencies, func(left, right DependencyResultV1) int { return strings.Compare(left.RoleID, right.RoleID) })
	slices.SortFunc(document.Artifacts, func(left, right ArtifactRefV1) int { return strings.Compare(left.ArtifactID, right.ArtifactID) })
	if validateContextDocument(document, allowed) != nil {
		return ContextDocumentV1{}, ErrInvalid
	}
	return document, nil
}

func validateContextDocument(document ContextDocumentV1, allowed map[string]struct{}) error {
	if document.SchemaVersion != ContextSchemaV1 || !canonicalUUID(document.ExecutionID) || !canonicalUUID(document.PlanID) ||
		!digestPattern.MatchString(document.PlanDigest) || !rolePattern.MatchString(document.RoleID) ||
		!validText(document.GoalSummary, MaxGoalSummaryBytes) || len(document.Constraints) > MaxConstraints ||
		len(document.Dependencies) > MaxDependencies || len(document.Artifacts) > MaxArtifacts ||
		document.Constraints == nil || document.Dependencies == nil || document.Artifacts == nil {
		return ErrInvalid
	}
	seenText := make(map[string]struct{}, len(document.Constraints))
	for _, constraint := range document.Constraints {
		if !validText(constraint, MaxConstraintBytes) {
			return ErrInvalid
		}
		if _, duplicate := seenText[constraint]; duplicate {
			return ErrInvalid
		}
		seenText[constraint] = struct{}{}
	}
	seenRoles := make(map[string]struct{}, len(document.Dependencies))
	for _, dependency := range document.Dependencies {
		if !rolePattern.MatchString(dependency.RoleID) || dependency.RoleID == document.RoleID ||
			!digestPattern.MatchString(dependency.ResultDigest) || !validText(dependency.Summary, MaxDependencySummaryBytes) {
			return ErrInvalid
		}
		if allowed != nil {
			if _, ok := allowed[dependency.RoleID]; !ok {
				return ErrInvalid
			}
		}
		if _, duplicate := seenRoles[dependency.RoleID]; duplicate {
			return ErrInvalid
		}
		seenRoles[dependency.RoleID] = struct{}{}
	}
	seenArtifacts := make(map[string]struct{}, len(document.Artifacts))
	for _, artifact := range document.Artifacts {
		if !canonicalUUID(artifact.ArtifactID) || !digestPattern.MatchString(artifact.Digest) ||
			!mediaPattern.MatchString(artifact.MediaType) || !validText(artifact.Purpose, MaxConstraintBytes) {
			return ErrInvalid
		}
		if _, duplicate := seenArtifacts[artifact.ArtifactID]; duplicate {
			return ErrInvalid
		}
		seenArtifacts[artifact.ArtifactID] = struct{}{}
	}
	return nil
}

func validateManifest(manifest ManifestV1) error {
	assignment := coreteamworker.Assignment{
		WorkerID: "11111111-1111-4111-8111-111111111111", ExecutionID: manifest.ExecutionID, PlanID: manifest.PlanID,
		RoleID: manifest.RoleID, Attempt: manifest.Attempt, PlanDigest: manifest.PlanDigest,
		RuntimeContextDigest: strings.Repeat("0", 64), Goal: "bound-by-goal-digest",
		Capabilities: manifest.Capabilities, RuntimeID: manifest.RuntimeID, OutputTokens: manifest.OutputTokens,
		ResultSchemaVersion: manifest.ResultSchemaVersion,
	}
	if manifest.SchemaVersion != ManifestSchemaV1 || assignment.Validate() != nil || !digestPattern.MatchString(manifest.GoalDigest) ||
		validateModel(manifest.Model) != nil || manifest.CredentialRevision == 0 ||
		!digestPattern.MatchString(manifest.ContextDigest) || !digestPattern.MatchString(manifest.WorkspaceDigest) {
		return ErrInvalid
	}
	capabilities := append([]coreteam.Capability(nil), manifest.Capabilities...)
	slices.Sort(capabilities)
	if !slices.Equal(capabilities, manifest.Capabilities) {
		return ErrInvalid
	}
	return nil
}

func runtimeContextDigest(manifestJSON, credential []byte) (string, error) {
	if len(manifestJSON) == 0 || len(manifestJSON) > MaxManifestBytes || validateCredential(credential) != nil {
		return "", ErrInvalid
	}
	runtimeContext := runtimeContextV1{
		SchemaVersion: RuntimeContextSchemaV1, ManifestDigest: digestBytes(manifestJSON),
		CredentialHash: digestBytes(credential),
	}
	canonical, err := json.Marshal(runtimeContext)
	if err != nil {
		return "", ErrInvalid
	}
	digest := digestBytes(canonical)
	clear(canonical)
	return digest, nil
}

func decodeCanonical(raw []byte, maximum int, target any) error {
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return ErrInvalid
	}
	clear(canonical)
	return nil
}

func validateModel(model ModelBindingV1) error {
	if !providerPattern.MatchString(model.Provider) || !modelPattern.MatchString(model.Name) ||
		model.Interface != "openai_compatible" || model.Revision == 0 {
		return ErrInvalid
	}
	return nil
}

func validateCredential(credential []byte) error {
	if len(credential) < 16 || len(credential) > MaxCredentialBytes || bytes.IndexByte(credential, 0) >= 0 {
		return ErrInvalid
	}
	return nil
}

func validText(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) && len(value) <= maximum &&
		!security.ContainsLikelySecret(value)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func cloneAssignment(assignment coreteamworker.Assignment) coreteamworker.Assignment {
	assignment.Capabilities = append([]coreteam.Capability(nil), assignment.Capabilities...)
	return assignment
}

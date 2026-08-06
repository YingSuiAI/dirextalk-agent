package coreteaminput

import (
	"bytes"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
)

func TestCompileBuildsDeterministicSecretFreeRuntimeContext(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	first, err := Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()

	request.Context.Constraints[0], request.Context.Constraints[1] = request.Context.Constraints[1], request.Context.Constraints[0]
	request.Context.Artifacts[0], request.Context.Artifacts[1] = request.Context.Artifacts[1], request.Context.Artifacts[0]
	second, err := Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()

	if !bytes.Equal(first.ContextJSON, second.ContextJSON) || !bytes.Equal(first.ManifestJSON, second.ManifestJSON) ||
		first.RuntimeContextDigest != second.RuntimeContextDigest || first.Assignment.RuntimeContextDigest != first.RuntimeContextDigest {
		t.Fatal("semantically identical input changed canonical runtime context")
	}
	all := string(first.ContextJSON) + string(first.ManifestJSON)
	if strings.Contains(all, string(request.Credential)) || strings.Contains(all, "credential_digest") || strings.Contains(all, "api_key") {
		t.Fatalf("compiled input leaked credential material: %s", all)
	}
	if first.Manifest.ExecutionID != request.Assignment.ExecutionID || first.Manifest.RoleID != request.Assignment.RoleID ||
		first.Manifest.Model.Revision != request.Model.Revision || first.Manifest.CredentialRevision != request.CredentialRevision ||
		first.Manifest.WorkspaceDigest != request.WorkspaceDigest {
		t.Fatalf("manifest=%+v", first.Manifest)
	}
}

func TestCompileBindsRoleBeforeWorkerIdentityExists(t *testing.T) {
	t.Parallel()
	withoutWorker := validCompileRequest()
	withoutWorker.Assignment.WorkerID = ""
	compiledBeforeChallenge, err := Compile(withoutWorker)
	if err != nil {
		t.Fatalf("pre-challenge compile failed: %v", err)
	}
	defer compiledBeforeChallenge.Destroy()

	withWorker := validCompileRequest()
	compiledAfterChallenge, err := Compile(withWorker)
	if err != nil {
		t.Fatalf("post-challenge compile failed: %v", err)
	}
	defer compiledAfterChallenge.Destroy()

	if compiledBeforeChallenge.RuntimeContextDigest != compiledAfterChallenge.RuntimeContextDigest ||
		!bytes.Equal(compiledBeforeChallenge.ManifestJSON, compiledAfterChallenge.ManifestJSON) {
		t.Fatal("ephemeral Worker identity changed the role runtime context")
	}
}

func TestVerifyMaterializedRuntimeContextRejectsEverySubstitution(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	compiled, err := Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Destroy()

	valid := MaterializedInput{
		Assignment: compiled.Assignment, Model: request.Model, CredentialRevision: request.CredentialRevision,
		ContextJSON: compiled.ContextJSON, ManifestJSON: compiled.ManifestJSON,
		WorkspaceDigest: request.WorkspaceDigest, Credential: request.Credential,
	}
	if err := VerifyMaterialized(valid); err != nil {
		t.Fatalf("valid materialized input rejected: %v", err)
	}

	for name, mutate := range map[string]func(*MaterializedInput){
		"assignment digest": func(input *MaterializedInput) { input.Assignment.RuntimeContextDigest = strings.Repeat("0", 64) },
		"plan digest":       func(input *MaterializedInput) { input.Assignment.PlanDigest = strings.Repeat("1", 64) },
		"model":             func(input *MaterializedInput) { input.Model.Name = "substituted-model" },
		"model revision":    func(input *MaterializedInput) { input.Model.Revision++ },
		"credential revision": func(input *MaterializedInput) {
			input.CredentialRevision++
		},
		"context":   func(input *MaterializedInput) { input.ContextJSON = append(bytes.Clone(input.ContextJSON), ' ') },
		"manifest":  func(input *MaterializedInput) { input.ManifestJSON = append(bytes.Clone(input.ManifestJSON), ' ') },
		"workspace": func(input *MaterializedInput) { input.WorkspaceDigest = strings.Repeat("2", 64) },
		"credential": func(input *MaterializedInput) {
			input.Credential = []byte("different-scoped-credential-123456")
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := valid.Clone()
			mutate(&input)
			if err := VerifyMaterialized(input); err == nil {
				t.Fatal("substituted materialized input was accepted")
			}
		})
	}
}

func TestCompileRejectsUnsafeOrUnboundInput(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*CompileRequest){
		"prebound assignment": func(request *CompileRequest) { request.Assignment.RuntimeContextDigest = strings.Repeat("a", 64) },
		"secret context":      func(request *CompileRequest) { request.Context.GoalSummary = "api_key=super-secret-value" },
		"unknown dependency":  func(request *CompileRequest) { request.Context.Dependencies[0].RoleID = "unknown" },
		"workspace digest":    func(request *CompileRequest) { request.WorkspaceDigest = "latest" },
		"model revision":      func(request *CompileRequest) { request.Model.Revision = 0 },
		"credential revision": func(request *CompileRequest) { request.CredentialRevision = 0 },
		"short credential":    func(request *CompileRequest) { request.Credential = []byte("short") },
	} {
		t.Run(name, func(t *testing.T) {
			request := validCompileRequest()
			mutate(&request)
			compiled, err := Compile(request)
			compiled.Destroy()
			if err == nil {
				t.Fatal("unsafe or unbound input was accepted")
			}
		})
	}
}

func validCompileRequest() CompileRequest {
	return CompileRequest{
		Assignment: coreteamworker.Assignment{
			WorkerID: "11111111-1111-4111-8111-111111111111", ExecutionID: "22222222-2222-4222-8222-222222222222",
			PlanID: "33333333-3333-4333-8333-333333333333", RoleID: "implementer", Attempt: 1,
			PlanDigest: strings.Repeat("a", 64), Goal: "Implement the approved change.",
			Capabilities: []coreteam.Capability{coreteam.CapabilityTest, coreteam.CapabilityRepositoryWrite, coreteam.CapabilityStructuredResult},
			RuntimeID:    coreteam.OfficialRuntimeID, OutputTokens: 4096, ResultSchemaVersion: coreteamworker.ResultSchemaVersion,
		},
		Model:              ModelBindingV1{Provider: "deepseek", Name: "deepseek-v4-pro", Interface: "openai_compatible", Revision: 7},
		CredentialRevision: 11,
		Context: ContextInput{
			GoalSummary:  "Implement and verify the approved change.",
			Constraints:  []string{"Run focused tests.", "Do not change unrelated files."},
			Dependencies: []DependencyResultV1{{RoleID: "researcher", ResultDigest: strings.Repeat("b", 64), Summary: "Relevant source facts."}},
			Artifacts: []ArtifactRefV1{
				{ArtifactID: "44444444-4444-4444-8444-444444444444", Digest: strings.Repeat("c", 64), MediaType: "application/json", Purpose: "input facts"},
				{ArtifactID: "55555555-5555-4555-8555-555555555555", Digest: strings.Repeat("d", 64), MediaType: "text/plain", Purpose: "requirements"},
			},
		},
		DependencyRoles: []string{"researcher"},
		WorkspaceDigest: strings.Repeat("e", 64),
		Credential:      []byte("scoped-test-credential-1234567890"),
	}
}

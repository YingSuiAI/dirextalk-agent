package workerprotocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWorkerProtocolV1ContractsValidateAndDigest(t *testing.T) {
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	manifest := validWorkerManifest()
	manifestDigest := mustContractDigest(t, manifest)
	input := validInputBundle()
	inputDigest := mustContractDigest(t, input)
	grant := validCredentialGrant(now)
	grantDigest := mustContractDigest(t, grant)
	envelope := validExecutionEnvelope(now, inputDigest, grantDigest)
	envelopeDigest := mustContractDigest(t, envelope)
	checkpoint := validCheckpoint(now)
	checkpointDigest := mustContractDigest(t, checkpoint)
	result := validResultManifest(now, checkpointDigest)
	resultDigest := mustContractDigest(t, result)
	cleanup := validCleanupReceipt(now, resultDigest)
	cleanupDigest := mustContractDigest(t, cleanup)
	control := ControlFrameV1{
		SchemaVersion:   ControlFrameSchemaV1,
		ProtocolVersion: ProtocolVersion,
		StreamID:        uuid.NewString(),
		Sequence:        1,
		Direction:       DirectionCentralToWorker,
		Kind:            ControlAssignment,
		ExecutionID:     envelope.ExecutionID,
		WorkerID:        envelope.WorkerID,
		Attempt:         envelope.Attempt,
		LeaseEpoch:      envelope.LeaseEpoch,
		SentAt:          now,
		Reference: &ControlReferenceV1{
			ReferenceID: envelope.OperationID,
			Digest:      envelopeDigest,
		},
	}
	controlDigest := mustContractDigest(t, control)

	for name, digest := range map[string]string{
		"manifest":   manifestDigest,
		"input":      inputDigest,
		"grant":      grantDigest,
		"envelope":   envelopeDigest,
		"control":    controlDigest,
		"checkpoint": checkpointDigest,
		"result":     resultDigest,
		"cleanup":    cleanupDigest,
	} {
		if !validDigest(digest) {
			t.Fatalf("%s digest=%q", name, digest)
		}
	}
	first, err := manifest.Digest()
	if err != nil || first != manifestDigest {
		t.Fatalf("manifest digest replay=%q error=%v", first, err)
	}
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"api_key",
		"access_token",
		"secret_access_key",
		"ghp_",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("credential grant leaked %q: %s", forbidden, raw)
		}
	}
}

func TestWorkerProtocolV1FailsClosedOnSubstitution(t *testing.T) {
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	input := validInputBundle()
	inputDigest := mustContractDigest(t, input)
	grant := validCredentialGrant(now)
	grantDigest := mustContractDigest(t, grant)
	envelope := validExecutionEnvelope(now, inputDigest, grantDigest)
	checkpoint := validCheckpoint(now)
	checkpointDigest := mustContractDigest(t, checkpoint)
	result := validResultManifest(now, checkpointDigest)
	resultDigest := mustContractDigest(t, result)

	tests := map[string]func() error{
		"arbitrary entrypoint": func() error {
			value := validWorkerManifest()
			value.Entrypoint = "/bin/sh"
			return value.Validate()
		},
		"unknown network service": func() error {
			value := validWorkerManifest()
			value.RequestedPermissions.NetworkServices =
				append(
					value.RequestedPermissions.NetworkServices,
					NetworkService("aws_admin"),
				)
			return value.Validate()
		},
		"workspace traversal": func() error {
			value := input
			value.Context.LocalPath =
				FixedInputRoot + "/../secrets/key"
			return value.Validate()
		},
		"unsorted dependencies": func() error {
			value := input
			value.Dependencies[0], value.Dependencies[1] =
				value.Dependencies[1], value.Dependencies[0]
			return value.Validate()
		},
		"image substitution": func() error {
			value := envelope
			value.ImageDigest = "latest"
			return value.Validate()
		},
		"lease beyond approved duration": func() error {
			value := envelope
			value.LeaseExpiresAt =
				value.IssuedAt.Add(2 * time.Hour)
			return value.Validate()
		},
		"credential broker substitution": func() error {
			value := grant
			value.BrokerSocket = "/tmp/model.sock"
			return value.Validate()
		},
		"control direction mismatch": func() error {
			value := validHeartbeat(now, envelope)
			value.Direction = DirectionCentralToWorker
			return value.Validate()
		},
		"control payload smuggling": func() error {
			value := validHeartbeat(now, envelope)
			value.Reference = &ControlReferenceV1{
				ReferenceID: uuid.NewString(),
				Digest:      checkpointDigest,
			}
			return value.Validate()
		},
		"successful empty result": func() error {
			value := result
			value.Artifacts = nil
			value.ChangeSet = nil
			return value.Validate()
		},
		"duplicate output path": func() error {
			value := result
			duplicate := value.Artifacts[0]
			duplicate.ArtifactID = uuid.NewString()
			value.Artifacts = append(value.Artifacts, duplicate)
			return value.Validate()
		},
		"incomplete cleanup": func() error {
			value := validCleanupReceipt(now, resultDigest)
			value.CredentialGrantRevoked = false
			return value.Validate()
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v want ErrInvalid", err)
			}
		})
	}
}

func validWorkerManifest() WorkerManifestV1 {
	return WorkerManifestV1{
		SchemaVersion:   WorkerManifestSchemaV1,
		ProtocolVersion: ProtocolVersion,
		WorkerTypeID:    "11111111-1111-4111-8111-111111111111",
		Name:            "Reference Code Worker",
		Description: "Implements and reviews repository changes through " +
			"the Dirextalk Worker Host Harness.",
		Entrypoint:       FixedEntrypoint,
		ControlTransport: FixedControlTransport,
		Capabilities: []string{
			"code.review",
			"repository.read",
			"repository.write",
		},
		ModelInterfaces: []string{"openai.responses"},
		WorkspaceModes: []WorkspaceMode{
			WorkspaceIsolated,
			WorkspaceReadOnly,
		},
		RequestedPermissions: validPermissionSet(),
		MinimumResources: ResourceEnvelopeV1{
			VCPU:         2,
			MemoryMiB:    2048,
			DiskGiB:      20,
			Architecture: ArchitectureAMD64,
		},
		RecommendedResources: ResourceEnvelopeV1{
			VCPU:         4,
			MemoryMiB:    8192,
			DiskGiB:      40,
			Architecture: ArchitectureAMD64,
		},
		MaxTaskSeconds:  3600,
		TaskConcurrency: 1,
	}
}

func validPermissionSet() PermissionSetV1 {
	return PermissionSetV1{
		Workspace: WorkspaceIsolated,
		NetworkServices: []NetworkService{
			NetworkArtifactStore,
			NetworkControlPlane,
			NetworkModelGateway,
		},
		ToolScopes: []string{
			"git.read",
			"git.write_patch",
			"shell.sandboxed",
		},
		MaxTempDiskMiB: 4096,
	}
}

func validInputBundle() InputBundleV1 {
	return InputBundleV1{
		SchemaVersion: InputBundleSchemaV1,
		ExecutionID:   "22222222-2222-4222-8222-222222222222",
		RoleID:        "implementation",
		Context: ArtifactRefV1{
			ArtifactID: "30000000-0000-4000-8000-000000000001",
			Digest:     contractDigest("1"),
			SizeBytes:  1024,
			MediaType:  "application/json",
			LocalPath:  FixedInputRoot + "/context.json",
		},
		Workspace: &WorkspaceMountV1{
			Mode: WorkspaceIsolated,
			Artifact: ArtifactRefV1{
				ArtifactID: "30000000-0000-4000-8000-000000000002",
				Digest:     contractDigest("2"),
				SizeBytes:  2048,
				MediaType:  "application/x-tar",
				LocalPath:  FixedInputRoot + "/workspace",
			},
		},
		Dependencies: []ArtifactRefV1{
			{
				ArtifactID: "30000000-0000-4000-8000-000000000003",
				Digest:     contractDigest("3"),
				SizeBytes:  512,
				MediaType:  "application/json",
				LocalPath:  FixedInputRoot + "/dependencies/requirements.json",
			},
			{
				ArtifactID: "30000000-0000-4000-8000-000000000004",
				Digest:     contractDigest("4"),
				SizeBytes:  768,
				MediaType:  "text/plain",
				LocalPath:  FixedInputRoot + "/dependencies/notes.txt",
			},
		},
	}
}

func validCredentialGrant(now time.Time) CredentialGrantV1 {
	return CredentialGrantV1{
		SchemaVersion:       CredentialGrantSchemaV1,
		GrantID:             "44444444-4444-4444-8444-444444444444",
		ExecutionID:         "22222222-2222-4222-8222-222222222222",
		WorkerID:            "55555555-5555-4555-8555-555555555555",
		WorkerReleaseID:     "66666666-6666-4666-8666-666666666666",
		Audience:            "dirextalk-model-gateway",
		BrokerSocket:        FixedCredentialBroker,
		ModelProfileID:      "openai.code.premium",
		ModelInterface:      "openai.responses",
		MaximumInputTokens:  100_000,
		MaximumOutputTokens: 20_000,
		MaximumRequests:     128,
		Permissions:         validPermissionSet(),
		IssuedAt:            now,
		ExpiresAt:           now.Add(time.Hour),
	}
}

func validExecutionEnvelope(
	now time.Time,
	inputDigest,
	grantDigest string,
) ExecutionEnvelopeV1 {
	return ExecutionEnvelopeV1{
		SchemaVersion:          ExecutionEnvelopeSchemaV1,
		ProtocolVersion:        ProtocolVersion,
		ExecutionID:            "22222222-2222-4222-8222-222222222222",
		OperationID:            "77777777-7777-4777-8777-777777777777",
		DeploymentID:           "88888888-8888-4888-8888-888888888888",
		WorkerID:               "55555555-5555-4555-8555-555555555555",
		WorkerTypeID:           "11111111-1111-4111-8111-111111111111",
		WorkerReleaseID:        "66666666-6666-4666-8666-666666666666",
		ImageDigest:            contractDigest("5"),
		RegistryRevision:       contractDigest("6"),
		PlanDigest:             contractDigest("7"),
		ApprovalID:             "99999999-9999-4999-8999-999999999999",
		RoleID:                 "implementation",
		Attempt:                1,
		LeaseEpoch:             1,
		IssuedAt:               now,
		LeaseExpiresAt:         now.Add(15 * time.Minute),
		InputBundleDigest:      inputDigest,
		CredentialGrantDigest:  grantDigest,
		MaximumDurationSeconds: 3600,
		MaximumCostMicros:      500_000,
	}
}

func validHeartbeat(
	now time.Time,
	envelope ExecutionEnvelopeV1,
) ControlFrameV1 {
	return ControlFrameV1{
		SchemaVersion:   ControlFrameSchemaV1,
		ProtocolVersion: ProtocolVersion,
		StreamID:        uuid.NewString(),
		Sequence:        2,
		Direction:       DirectionWorkerToCentral,
		Kind:            ControlHeartbeat,
		ExecutionID:     envelope.ExecutionID,
		WorkerID:        envelope.WorkerID,
		Attempt:         envelope.Attempt,
		LeaseEpoch:      envelope.LeaseEpoch,
		SentAt:          now,
	}
}

func validCheckpoint(now time.Time) CheckpointV1 {
	return CheckpointV1{
		SchemaVersion:   CheckpointSchemaV1,
		CheckpointID:    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ExecutionID:     "22222222-2222-4222-8222-222222222222",
		WorkerID:        "55555555-5555-4555-8555-555555555555",
		WorkerReleaseID: "66666666-6666-4666-8666-666666666666",
		Attempt:         1,
		LeaseEpoch:      1,
		Sequence:        1,
		State: ArtifactRefV1{
			ArtifactID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			Digest:     contractDigest("8"),
			SizeBytes:  4096,
			MediaType:  "application/json",
			LocalPath:  FixedOutputRoot + "/checkpoint/state.json",
		},
		CompletedStages: []string{"analysis", "implementation"},
		CreatedAt:       now.Add(10 * time.Minute),
	}
}

func validResultManifest(
	now time.Time,
	checkpointDigest string,
) ResultManifestV1 {
	return ResultManifestV1{
		SchemaVersion:   ResultManifestSchemaV1,
		ResultID:        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		ExecutionID:     "22222222-2222-4222-8222-222222222222",
		OperationID:     "77777777-7777-4777-8777-777777777777",
		WorkerID:        "55555555-5555-4555-8555-555555555555",
		WorkerReleaseID: "66666666-6666-4666-8666-666666666666",
		ImageDigest:     contractDigest("5"),
		Attempt:         1,
		LeaseEpoch:      1,
		Outcome:         ResultSucceeded,
		Summary:         "Implemented the approved change and ran focused tests.",
		Artifacts: []ArtifactRefV1{{
			ArtifactID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
			Digest:     contractDigest("9"),
			SizeBytes:  1024,
			MediaType:  "application/json",
			LocalPath:  FixedOutputRoot + "/result/summary.json",
		}},
		ChangeSet: &ChangeSetV1{
			Format: "git_patch_v1",
			Patch: ArtifactRefV1{
				ArtifactID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
				Digest:     contractDigest("a"),
				SizeBytes:  2048,
				MediaType:  "text/x-diff",
				LocalPath:  FixedOutputRoot + "/result/change.patch",
			},
		},
		Tests: []TestEvidenceV1{{
			Name:   "go test ./...",
			Status: "passed",
			Evidence: ArtifactRefV1{
				ArtifactID: "ffffffff-ffff-4fff-8fff-ffffffffffff",
				Digest:     contractDigest("b"),
				SizeBytes:  512,
				MediaType:  "text/plain",
				LocalPath:  FixedOutputRoot + "/tests/go-test.txt",
			},
		}},
		Usage: TokenUsageV1{
			InputTokens:  10_000,
			CachedTokens: 2_000,
			OutputTokens: 3_000,
		},
		LatestCheckpointDigest: checkpointDigest,
		StartedAt:              now,
		CompletedAt:            now.Add(20 * time.Minute),
	}
}

func validCleanupReceipt(
	now time.Time,
	resultDigest string,
) CleanupReceiptV1 {
	return CleanupReceiptV1{
		SchemaVersion:          CleanupReceiptSchemaV1,
		ReceiptID:              uuid.NewString(),
		ExecutionID:            "22222222-2222-4222-8222-222222222222",
		WorkerID:               "55555555-5555-4555-8555-555555555555",
		WorkerReleaseID:        "66666666-6666-4666-8666-666666666666",
		HarnessInstanceID:      uuid.NewString(),
		Attempt:                1,
		LeaseEpoch:             1,
		WorkerProcessExited:    true,
		WorkspaceRemoved:       true,
		CredentialGrantRevoked: true,
		NetworkLeaseRevoked:    true,
		OutputManifestDigest:   resultDigest,
		CompletedAt:            now.Add(21 * time.Minute),
	}
}

type contractDigester interface {
	Digest() (string, error)
}

func mustContractDigest(t *testing.T, value contractDigester) string {
	t.Helper()
	digest, err := value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func contractDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

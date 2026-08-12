package cloudworker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

func TestValidateCollectedLimitsRequiresInputBoundWorkspaceDelta(t *testing.T) {
	t.Parallel()
	inputDigest := digestValue("runtime-input-manifest")
	plan := Plan{
		WorkspaceMode: WorkspaceWrite,
		Limits: Limits{
			MaxTokens:      100,
			MaxOutputBytes: 64 << 10,
		},
	}
	material := RuntimeTaskMaterial{InputManifestSHA256: inputDigest}
	workspace := t.TempDir()
	collector := cloudruntime.FilesystemOutputCollector{}
	baseline, err := collector.Snapshot(
		t.Context(), workspace, inputDigest, plan.Limits.MaxOutputBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Destroy()
	if err := os.WriteFile(
		filepath.Join(workspace, "result.txt"), []byte("validated output\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	workspaceArtifacts, err := collector.Collect(
		t.Context(), workspace, baseline, plan.Limits.MaxOutputBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	collected := cloudresult.Collected{
		Manifest: cloudresult.Manifest{
			Usage: cloudruntime.Usage{OutputTokens: 1},
		},
		Artifacts: []cloudresult.CollectedArtifact{{
			Claim: cloudresult.ObjectClaim{
				Name: "final.json", SizeBytes: 2, MediaType: "application/json",
			},
			Content: []byte("{}"),
		}},
	}
	for _, artifact := range workspaceArtifacts {
		collected.Artifacts = append(collected.Artifacts, cloudresult.CollectedArtifact{
			Claim: cloudresult.ObjectClaim{
				Name: artifact.Name, SizeBytes: int64(len(artifact.Content)),
				MediaType: artifact.MediaType,
			},
			Content: artifact.Content,
		})
	}
	if err := validateCollectedLimits(plan, material, collected); err != nil {
		t.Fatalf("valid input-bound delta rejected: %v", err)
	}

	wrongMaterial := material
	wrongMaterial.InputManifestSHA256 = digestValue("different-runtime-input-manifest")
	if err := validateCollectedLimits(plan, wrongMaterial, collected); err == nil {
		t.Fatal("delta bound to a different input manifest was accepted")
	}

	withoutDelta := collected
	withoutDelta.Artifacts = withoutDelta.Artifacts[:1]
	if err := validateCollectedLimits(plan, material, withoutDelta); err == nil {
		t.Fatal("write result without an authoritative delta archive was accepted")
	}
}

func TestBuildDeliverableContextExposesFilesAndScreensSecrets(t *testing.T) {
	t.Parallel()
	inputDigest := digestValue("deliverable-context-input")
	workspace := t.TempDir()
	collector := cloudruntime.FilesystemOutputCollector{}
	baseline, err := collector.Snapshot(t.Context(), workspace, inputDigest, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Destroy()
	files := map[string][]byte{
		"README.md":                        []byte("# LogScope\n\nThe command groups errors by time window.\n"),
		"report.csv":                       []byte("category,count\ntimeout,7\n"),
		"preview.png":                      {0x89, 'P', 'N', 'G', 0, 1, 2},
		"secret.txt":                       []byte("api_key=sk-abcdefghijklmnopqrstuvwxyz123456"),
		"__pycache__/logscope.cpython.pyc": {0, 1, 2},
	}
	for name, content := range files {
		if err = os.MkdirAll(filepath.Dir(filepath.Join(workspace, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(workspace, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	artifacts, err := collector.Collect(t.Context(), workspace, baseline, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	collected := cloudresult.Collected{}
	for _, artifact := range artifacts {
		collected.Artifacts = append(collected.Artifacts, cloudresult.CollectedArtifact{
			Claim: cloudresult.ObjectClaim{
				Name: artifact.Name, MediaType: artifact.MediaType,
				SizeBytes: int64(len(artifact.Content)),
			},
			Content: artifact.Content,
		})
	}
	collected.Artifacts = append(collected.Artifacts, cloudresult.CollectedArtifact{
		Claim: cloudresult.ObjectClaim{
			Name: "changes.patch", MediaType: "text/plain; charset=utf-8", SizeBytes: 22,
		},
		Content: []byte("diff --git a/a b/a\n+ok\n"),
	})
	contextItems, omitted, err := buildDeliverableContext(collected, inputDigest, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if omitted != 0 {
		t.Fatalf("unexpected omitted deliverables: %d", omitted)
	}
	byPath := make(map[string]DeliverableContext, len(contextItems))
	for _, item := range contextItems {
		byPath[item.Path] = item
	}
	if len(byPath) != 5 || byPath["README.md"].TextPreview != string(files["README.md"]) ||
		byPath["report.csv"].MediaType != "text/csv; charset=utf-8" ||
		byPath["preview.png"].MediaType != "image/png" || byPath["preview.png"].TextPreview != "" ||
		byPath["secret.txt"].TextPreview != "" || byPath["changes.patch"].TextPreview == "" {
		t.Fatalf("unexpected Central deliverable context: %+v", contextItems)
	}
	for _, item := range contextItems {
		if strings.Contains(item.Path, "meta/") || strings.Contains(item.Path, "files/") {
			t.Fatalf("internal archive path leaked into deliverables: %+v", item)
		}
	}
}

func TestValidateCollectedLimitsTreatsReasoningAsOutputSubset(t *testing.T) {
	t.Parallel()
	plan := Plan{
		WorkspaceMode: WorkspaceNone,
		Limits: Limits{
			MaxTokens:      4096,
			MaxOutputBytes: 64 << 10,
		},
	}
	material := RuntimeTaskMaterial{InputManifestSHA256: digestValue("runtime-input-manifest")}
	collected := cloudresult.Collected{
		Manifest: cloudresult.Manifest{
			Usage: cloudruntime.Usage{
				OutputTokens:          4096,
				ReasoningOutputTokens: 3072,
			},
		},
		Artifacts: []cloudresult.CollectedArtifact{{
			Claim: cloudresult.ObjectClaim{
				Name: "final.json", SizeBytes: 2, MediaType: "application/json",
			},
			Content: []byte("{}"),
		}},
	}
	if err := validateCollectedLimits(plan, material, collected); err != nil {
		t.Fatalf("reasoning included in output tokens was double-counted: %v", err)
	}

	collected.Manifest.Usage.ReasoningOutputTokens = 4097
	if err := validateCollectedLimits(plan, material, collected); err == nil {
		t.Fatal("reasoning tokens greater than total output tokens were accepted")
	}
}

func TestResultCollectionUsesCurrentSessionFenceAfterLeaseReclaim(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, execution, prerequisite, sourceRead := stagingFixture(t, now)
	defer sourceRead.Body.Close()
	var err error
	execution, err = execution.Transition(StateQueued, now)
	if err != nil {
		t.Fatal(err)
	}
	execution, err = execution.Transition(StateProvisioning, now)
	if err != nil {
		t.Fatal(err)
	}
	prerequisite.ConfirmedAt = now
	source := plan.InputManifest.Items[0]
	staged := StagedInputManifest{Schema: StagedInputManifestSchemaV1, ExecutionID: plan.ExecutionID, SourceManifestDigest: plan.InputManifestDigest,
		Items: []StagedInputManifestItem{{InputID: source.InputID, MountPath: source.MountPath, MediaType: source.MediaType,
			SizeBytes: source.SizeBytes, SHA256: source.SHA256, S3Bucket: plan.ArtifactGrant.Bucket,
			S3Key: plan.ArtifactGrant.KeyPrefix + "inputs/" + source.InputID, S3VersionID: "version-1"}}}
	if _, err = staged.Seal(plan.InputManifest); err != nil {
		t.Fatal(err)
	}
	initialFence, err := prerequisite.RuntimeFence(plan)
	if err != nil {
		t.Fatal(err)
	}
	material, err := BuildRuntimeTask(plan, execution, staged, initialFence, RuntimeQualification{
		WorkerProtocolVersion: cloudprotocol.WorkerProtocolVersion, RuntimeContractVersion: cloudprotocol.RuntimeContractVersion,
		PiRuntimeDigest: plan.Compute.PiRuntimeDigest, PiVersion: "0.83.0",
		PiExecutableSHA256: digestValue("pi-executable"), ResultExtensionSHA256: digestValue("result-extension"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	authorization := LaunchAuthorization{LaunchPrerequisite: prerequisite,
		RuntimeTaskSHA256: material.RuntimeTaskSHA256, InputManifestSHA256: material.InputManifestSHA256,
		StagedManifestSHA256: material.StagedManifestSHA256, AuthorizedAt: now.Add(time.Second)}

	currentFence := initialFence
	currentFence.Attempt++
	currentFence.LeaseEpoch++
	currentMaterial, err := material.CloneForFence(currentFence)
	if err != nil {
		t.Fatal(err)
	}
	defer currentMaterial.Destroy()
	session := control.Session{
		SessionID: "11111111-1111-4111-8111-111111111111",
		Fence: control.TaskFence{ExecutionID: currentFence.ExecutionID, TaskID: currentFence.TaskID,
			AccountGeneration: currentFence.AccountGeneration, Attempt: currentFence.Attempt, LeaseEpoch: currentFence.LeaseEpoch},
		State: control.SessionCompleted,
		Result: &control.ObjectClaim{Bucket: plan.ArtifactGrant.Bucket, Key: plan.ArtifactGrant.KeyPrefix + "result.json",
			VersionID: "version-1", SHA256: digestValue("result"), SizeBytes: 1, MediaType: "application/json"},
	}
	if err := validateResultCollectionAuthority(plan, execution, authorization, currentMaterial, session); err != nil {
		t.Fatalf("current reclaimed fence rejected: %v", err)
	}
	if err := validateResultCollectionAuthority(plan, execution, authorization, material, session); err == nil {
		t.Fatal("initial material fence accepted for a reclaimed session")
	}
	if currentMaterial.RuntimeTaskSHA256 != material.RuntimeTaskSHA256 || currentMaterial.InputManifestSHA256 != material.InputManifestSHA256 {
		t.Fatal("lease reclaim changed immutable material digests")
	}
}

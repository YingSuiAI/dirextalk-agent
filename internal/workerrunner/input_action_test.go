package workerrunner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

func TestInputMaterializeActionStreamsDigestBoundInputsAtomically(
	t *testing.T,
) {
	t.Parallel()
	contextBytes := []byte(`{"goal":"implement approved change"}`)
	workspaceBytes := workspaceArchive(
		t,
		[]tar.Header{
			{Name: "src/", Typeflag: tar.TypeDir, Mode: 0o755},
			{
				Name: "src/main.go", Typeflag: tar.TypeReg,
				Mode: 0o644, Size: int64(len("package main\n")),
			},
			{
				Name: "run.sh", Typeflag: tar.TypeReg,
				Mode: 0o755, Size: int64(len("#!/bin/sh\n")),
			},
			{
				Name: "current.go", Typeflag: tar.TypeSymlink,
				Linkname: "src/main.go",
			},
		},
		[][]byte{
			nil,
			[]byte("package main\n"),
			[]byte("#!/bin/sh\n"),
			nil,
		},
	)
	contextDigest := inputTestDigest(contextBytes)
	workspaceDigest := inputTestDigest(workspaceBytes)
	store := &inputMemoryStore{objects: map[string][]byte{
		"s3://bucket/deployments/deployment/artifacts/context.json":  contextBytes,
		"s3://bucket/deployments/deployment/artifacts/workspace.tar": workspaceBytes,
	}}
	root := t.TempDir()
	contextRoot := filepath.Join(root, "contexts")
	workspaceRoot := filepath.Join(root, "workspaces")
	for _, directory := range []string{contextRoot, workspaceRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := NewInputMaterializeAction(
		store,
		contextRoot,
		workspaceRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	action := inputMaterializeTestAction(
		contextBytes,
		contextDigest,
		workspaceBytes,
		workspaceDigest,
	)
	result, err := handler.Execute(context.Background(), action)
	if err != nil || result.Status != "materialized" {
		t.Fatalf("execute result=%+v error=%v", result, err)
	}
	contextTarget := filepath.Join(
		contextRoot,
		contextDigest[len("sha256:"):]+".json",
	)
	gotContext, err := os.ReadFile(contextTarget)
	if err != nil || !bytes.Equal(gotContext, contextBytes) {
		t.Fatalf("context=%q error=%v", gotContext, err)
	}
	workspaceTarget := filepath.Join(
		workspaceRoot,
		workspaceDigest[len("sha256:"):],
	)
	gotSource, err := os.ReadFile(
		filepath.Join(workspaceTarget, "src", "main.go"),
	)
	if err != nil || string(gotSource) != "package main\n" {
		t.Fatalf("workspace source=%q error=%v", gotSource, err)
	}
	scriptInfo, err := os.Stat(filepath.Join(workspaceTarget, "run.sh"))
	if err != nil || scriptInfo.Mode().Perm() != 0o700 {
		t.Fatalf("script mode=%v error=%v", scriptInfo, err)
	}
	linkInfo, err := os.Lstat(
		filepath.Join(workspaceTarget, "current.go"),
	)
	if err != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("workspace symlink=%v error=%v", linkInfo, err)
	}
	linkedSource, err := os.ReadFile(
		filepath.Join(workspaceTarget, "current.go"),
	)
	if err != nil || string(linkedSource) != "package main\n" {
		t.Fatalf("linked source=%q error=%v", linkedSource, err)
	}
	marker, err := os.ReadFile(
		filepath.Join(
			workspaceTarget,
			workerruntime.WorkspaceDigestMarker,
		),
	)
	if err != nil || string(marker) != workspaceDigest+"\n" {
		t.Fatalf("workspace marker=%q error=%v", marker, err)
	}
	if store.opens != 2 {
		t.Fatalf("object opens=%d", store.opens)
	}
	if _, err := handler.Execute(context.Background(), action); err != nil {
		t.Fatal(err)
	}
	if store.opens != 2 {
		t.Fatalf("idempotent replay reopened objects: %d", store.opens)
	}
}

func TestInputMaterializeActionRejectsUnsafeWorkspaceArchives(
	t *testing.T,
) {
	t.Parallel()
	tests := []struct {
		name    string
		headers []tar.Header
		bodies  [][]byte
	}{
		{
			name: "path traversal",
			headers: []tar.Header{{
				Name: "../escape", Typeflag: tar.TypeReg,
				Mode: 0o600, Size: 1,
			}},
			bodies: [][]byte{[]byte("x")},
		},
		{
			name: "absolute path",
			headers: []tar.Header{{
				Name: "/escape", Typeflag: tar.TypeReg,
				Mode: 0o600, Size: 1,
			}},
			bodies: [][]byte{[]byte("x")},
		},
		{
			name: "absolute symbolic link",
			headers: []tar.Header{{
				Name: "link", Typeflag: tar.TypeSymlink,
				Linkname: "/etc/passwd",
			}},
			bodies: [][]byte{nil},
		},
		{
			name: "escaping symbolic link",
			headers: []tar.Header{{
				Name: "nested/link", Typeflag: tar.TypeSymlink,
				Linkname: "../../outside",
			}},
			bodies: [][]byte{nil},
		},
		{
			name: "reserved digest marker",
			headers: []tar.Header{{
				Name:     workerruntime.WorkspaceDigestMarker,
				Typeflag: tar.TypeReg,
				Mode:     0o600,
				Size:     1,
			}},
			bodies: [][]byte{[]byte("x")},
		},
		{
			name: "hard link",
			headers: []tar.Header{{
				Name: "link", Typeflag: tar.TypeLink,
				Linkname: "target",
			}},
			bodies: [][]byte{nil},
		},
		{
			name: "device",
			headers: []tar.Header{{
				Name: "device", Typeflag: tar.TypeChar,
			}},
			bodies: [][]byte{nil},
		},
		{
			name: "duplicate",
			headers: []tar.Header{
				{
					Name: "same", Typeflag: tar.TypeReg,
					Mode: 0o600, Size: 1,
				},
				{
					Name: "same", Typeflag: tar.TypeReg,
					Mode: 0o600, Size: 1,
				},
			},
			bodies: [][]byte{[]byte("a"), []byte("b")},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			contextBytes := []byte(`{"goal":"safe"}`)
			workspaceBytes := workspaceArchive(
				t,
				testCase.headers,
				testCase.bodies,
			)
			contextDigest := inputTestDigest(contextBytes)
			workspaceDigest := inputTestDigest(workspaceBytes)
			store := &inputMemoryStore{objects: map[string][]byte{
				"s3://bucket/deployments/deployment/artifacts/context.json":  contextBytes,
				"s3://bucket/deployments/deployment/artifacts/workspace.tar": workspaceBytes,
			}}
			root := t.TempDir()
			contextRoot := filepath.Join(root, "contexts")
			workspaceRoot := filepath.Join(root, "workspaces")
			for _, directory := range []string{
				contextRoot,
				workspaceRoot,
			} {
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			handler, err := NewInputMaterializeAction(
				store,
				contextRoot,
				workspaceRoot,
			)
			if err != nil {
				t.Fatal(err)
			}
			action := inputMaterializeTestAction(
				contextBytes,
				contextDigest,
				workspaceBytes,
				workspaceDigest,
			)
			if _, err := handler.Execute(
				context.Background(),
				action,
			); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("unsafe archive error=%v", err)
			}
			entries, err := os.ReadDir(workspaceRoot)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("unsafe archive left entries: %+v", entries)
			}
		})
	}
}

func TestInputMaterializeActionRejectsObjectDigestMismatch(
	t *testing.T,
) {
	t.Parallel()
	contextBytes := []byte(`{"goal":"safe"}`)
	store := &inputMemoryStore{objects: map[string][]byte{
		"s3://bucket/deployments/deployment/artifacts/context.json": contextBytes,
	}}
	root := t.TempDir()
	contextRoot := filepath.Join(root, "contexts")
	workspaceRoot := filepath.Join(root, "workspaces")
	for _, directory := range []string{contextRoot, workspaceRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := NewInputMaterializeAction(
		store,
		contextRoot,
		workspaceRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	action := ActionV1{
		ID: "materialize-input", Kind: InputMaterializeActionKind,
		TimeoutSeconds: 30,
		Input: &InputMaterializeInputV1{
			Context: MaterializeObjectV1{
				ObjectName:  "context.json",
				S3Ref:       "s3://bucket/deployments/deployment/artifacts/context.json",
				SHA256:      inputTestDigest([]byte("different")),
				SizeBytes:   int64(len(contextBytes)),
				ContentType: "application/json",
			},
		},
	}
	if _, err := handler.Execute(
		context.Background(),
		action,
	); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("digest mismatch error=%v", err)
	}
	entries, err := os.ReadDir(contextRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("digest mismatch left entries: %+v", entries)
	}
}

func TestInputAssignmentBindsDeploymentBucketOrderAndRuntimeDigests(
	t *testing.T,
) {
	t.Parallel()
	const deploymentID = "11111111-1111-4111-8111-111111111111"
	task := validRuntimeTask()
	contextBytes := []byte(`{"goal":"safe"}`)
	workspaceBytes := workspaceArchive(
		t,
		[]tar.Header{{
			Name: "README.md", Typeflag: tar.TypeReg,
			Mode: 0o600, Size: 5,
		}},
		[][]byte{[]byte("ready")},
	)
	task.ContextDigest = inputTestDigest(contextBytes)
	task.WorkspaceDigest = inputTestDigest(workspaceBytes)
	inputAction := inputMaterializeTestAction(
		contextBytes,
		task.ContextDigest,
		workspaceBytes,
		task.WorkspaceDigest,
	)
	runtimeAction := ActionV1{
		ID: "execute-role", Kind: RuntimeExecuteActionKind,
		TimeoutSeconds: 60,
		Runtime:        &RuntimeExecuteInputV1{Task: task},
	}
	assignment := &agentv1.WorkerAssignment{
		DeploymentId: deploymentID,
		Access: &agentv1.WorkerAccessScope{
			ArtifactBucket: "bucket",
			ArtifactPrefix: "workers/principal/" +
				deploymentID + "/artifacts/",
		},
		RecipeBundle: &agentv1.WorkerBundleReference{
			S3Ref: "s3://bucket/workers/principal/" +
				deploymentID + "/bundles/recipe.cbor",
		},
	}
	valid := ExecutionBundleV1{
		Actions: []ActionV1{inputAction, runtimeAction},
	}
	bound, err := bindInputAssignment(valid, assignment)
	if err != nil {
		t.Fatalf("valid input assignment error=%v", err)
	}
	if bound.Actions[0].Input.Context.S3Ref !=
		"s3://bucket/workers/principal/"+deploymentID+
			"/artifacts/context.json" ||
		bound.Actions[0].Input.Workspace.S3Ref !=
			"s3://bucket/workers/principal/"+deploymentID+
				"/artifacts/workspace.tar" {
		t.Fatalf("bound input refs=%+v", bound.Actions[0].Input)
	}
	tests := []struct {
		name   string
		mutate func(*ExecutionBundleV1)
	}{
		{
			name: "nested object name",
			mutate: func(bundle *ExecutionBundleV1) {
				bundle.Actions[0].Input.Context.ObjectName =
					"nested/context.json"
			},
		},
		{
			name: "traversal object name",
			mutate: func(bundle *ExecutionBundleV1) {
				bundle.Actions[0].Input.Context.ObjectName =
					"..context.json"
			},
		},
		{
			name: "duplicate object name",
			mutate: func(bundle *ExecutionBundleV1) {
				bundle.Actions[0].Input.Workspace.ObjectName =
					bundle.Actions[0].Input.Context.ObjectName
			},
		},
		{
			name: "runtime before materializer",
			mutate: func(bundle *ExecutionBundleV1) {
				bundle.Actions[0], bundle.Actions[1] =
					bundle.Actions[1], bundle.Actions[0]
			},
		},
		{
			name: "context digest substitution",
			mutate: func(bundle *ExecutionBundleV1) {
				bundle.Actions[0].Input.Context.SHA256 =
					inputTestDigest([]byte("other"))
			},
		},
		{
			name: "workspace digest substitution",
			mutate: func(bundle *ExecutionBundleV1) {
				bundle.Actions[0].Input.Workspace.SHA256 =
					inputTestDigest([]byte("other"))
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			bundle := ExecutionBundleV1{
				Actions: []ActionV1{inputAction, runtimeAction},
			}
			inputCopy := *inputAction.Input
			contextCopy := inputCopy.Context
			workspaceCopy := *inputCopy.Workspace
			inputCopy.Context = contextCopy
			inputCopy.Workspace = &workspaceCopy
			bundle.Actions[0].Input = &inputCopy
			testCase.mutate(&bundle)
			if _, err := bindInputAssignment(
				bundle,
				assignment,
			); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("substitution error=%v", err)
			}
		})
	}
}

func inputMaterializeTestAction(
	contextBytes []byte,
	contextDigest string,
	workspaceBytes []byte,
	workspaceDigest string,
) ActionV1 {
	return ActionV1{
		ID: "materialize-input", Kind: InputMaterializeActionKind,
		TimeoutSeconds: 30,
		Input: &InputMaterializeInputV1{
			Context: MaterializeObjectV1{
				ObjectName:  "context.json",
				S3Ref:       "s3://bucket/deployments/deployment/artifacts/context.json",
				SHA256:      contextDigest,
				SizeBytes:   int64(len(contextBytes)),
				ContentType: "application/json",
			},
			Workspace: &MaterializeObjectV1{
				ObjectName:  "workspace.tar",
				S3Ref:       "s3://bucket/deployments/deployment/artifacts/workspace.tar",
				SHA256:      workspaceDigest,
				SizeBytes:   int64(len(workspaceBytes)),
				ContentType: "application/x-tar",
			},
		},
	}
}

func workspaceArchive(
	t *testing.T,
	headers []tar.Header,
	bodies [][]byte,
) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for index := range headers {
		header := headers[index]
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if len(bodies[index]) != 0 {
			if _, err := writer.Write(bodies[index]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func inputTestDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

type inputMemoryStore struct {
	objects map[string][]byte
	opens   int
}

func (store *inputMemoryStore) OpenInput(
	_ context.Context,
	reference string,
	maximum int64,
) (io.ReadCloser, int64, error) {
	content, ok := store.objects[reference]
	if !ok || int64(len(content)) > maximum {
		return nil, 0, ErrWorkerObjectUnavailable
	}
	store.opens++
	return io.NopCloser(bytes.NewReader(content)), int64(len(content)), nil
}

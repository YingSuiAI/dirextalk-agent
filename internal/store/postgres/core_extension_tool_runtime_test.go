package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	coreexecution "github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/google/uuid"
)

type toolCatalogLocalRunner struct {
	request extensionrunner.RequestV2
	calls   int
}

func (r *toolCatalogLocalRunner) RunV2(_ context.Context, request extensionrunner.RequestV2, _ []*os.File) (extensionrunner.StatusV1, error) {
	r.calls++
	r.request = request
	return extensionrunner.StatusV1{
		RunID:  request.RunID,
		Phase:  extensionrunner.PhaseTombstone,
		Status: "succeeded",
		Stdout: []byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"local_task","description":"bounded","inputSchema":{"z":{"type":"string"},"a":{"type":"integer"}}}]}}`),
	}, nil
}

func TestPostgresExtensionToolRuntimeDiscoversCanonicalLocalCatalog(t *testing.T) {
	runner := &toolCatalogLocalRunner{}
	digest := strings.Repeat("a", 64)
	installationID, versionID := uuid.NewString(), uuid.NewString()
	runtime := &PostgresExtensionToolRuntime{
		coord: &PostgresExtensionExecutionCoordinator{WorkspaceRoot: t.TempDir()},
		local: &coreexecution.LocalExecutor{Runner: runner},
	}
	tools, err := runtime.discoverTools(context.Background(), coreextension.Installation{
		ID: installationID, Revision: 1,
	}, coreextension.VersionRecord{
		VersionID: versionID, ContentDigest: digest, ArtifactDigest: digest,
		Execution: coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{RelativePath: "entry", Argv: []string{"entry"}}},
	})
	if err != nil || len(tools) != 1 {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
	if runner.calls != 1 || runner.request.TimeoutMS != (30*time.Second).Milliseconds() || runner.request.Limits != coreexecution.LocalSandboxLimitsV2() {
		t.Fatalf("calls=%d timeout_ms=%d limits=%+v", runner.calls, runner.request.TimeoutMS, runner.request.Limits)
	}
	wantSchema := `{"a":{"type":"integer"},"z":{"type":"string"}}`
	wantDigest := sha256.Sum256([]byte(wantSchema))
	if string(tools[0].InputSchema) != wantSchema || tools[0].InputSchemaDigest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("tool=%+v", tools[0])
	}
	if err := validateDiscoveredTools(tools); err != nil {
		t.Fatalf("validate discovered tools: %v", err)
	}
}

package extensionrunner

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type denialInstallResolver struct {
	install *AdmittedInstall
	err     error
}

func (r denialInstallResolver) ResolveInstall(string) (*AdmittedInstall, error) {
	return r.install, r.err
}

type denialWorkspaceResolver struct {
	fd  int
	err error
}

func (r denialWorkspaceResolver) ResolveWorkspace(string, string) (int, error) {
	return r.fd, r.err
}

type denialBackend struct{}

func (denialBackend) Probe(context.Context) error { return nil }
func (denialBackend) StartV2(context.Context, SandboxInvocationV2) (Process, error) {
	return nil, ErrUnavailable
}

func TestRunnerLogsOnlyStableAdmissionFailureStage(t *testing.T) {
	const rawSentinel = "secret-value at /private/install/path"
	for _, tc := range []struct {
		name      string
		stage     string
		install   InstallResolver
		workspace WorkspaceResolver
	}{
		{name: "install", stage: "install_resolve", install: denialInstallResolver{err: errors.New(rawSentinel)}, workspace: denialWorkspaceResolver{}},
		{name: "workspace", stage: "workspace_resolve", install: denialInstallResolver{install: &AdmittedInstall{}}, workspace: denialWorkspaceResolver{err: errors.New(rawSentinel)}},
		{name: "snapshot", stage: "workspace_snapshot", install: denialInstallResolver{install: &AdmittedInstall{}}, workspace: denialWorkspaceResolver{fd: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			runner := Runner{
				InstallResolver: tc.install, WorkspaceResolver: tc.workspace, V2Backend: denialBackend{},
				Logger: slog.New(slog.NewTextHandler(&logs, nil)),
			}
			request := clientProtocolRequest()
			status, err := runner.RunV2(context.Background(), request, nil, NewRunRegistry())
			if !errors.Is(err, ErrDenied) || status.Phase != PhaseFailed || status.Error != ErrorDeniedRequest {
				t.Fatalf("status=%+v err=%v", status, err)
			}
			line := logs.String()
			for _, want := range []string{"extension runner request denied", "run_id=" + request.RunID, "stage=" + tc.stage, "error_code=" + string(ErrorDeniedRequest)} {
				if !strings.Contains(line, want) {
					t.Fatalf("log %q missing %q", line, want)
				}
			}
			for _, forbidden := range []string{rawSentinel, request.InstallDigest, request.TaskID, request.TaskFence} {
				if strings.Contains(line, forbidden) {
					t.Fatalf("log exposed protected admission detail %q: %q", forbidden, line)
				}
			}
		})
	}
}

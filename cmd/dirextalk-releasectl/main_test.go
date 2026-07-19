package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/releasepublish"
)

func TestRunPublishEmitsOnlySafeResult(t *testing.T) {
	originalPublish, originalClaim := publishRelease, claimECRSession
	t.Cleanup(func() { publishRelease, claimECRSession = originalPublish, originalClaim })
	lease := &fakeReleaseSession{dockerConfigDir: "C:/private/docker-session", registryHost: "ghcr.io"}
	claimECRSession = func(path string) (releaseSession, error) {
		if path != "C:/protected/ecr-session.json" {
			t.Fatalf("session path = %q", path)
		}
		return lease, nil
	}
	wantRequest := releasepublish.Request{
		ReleaseTag:           "v0.1.0-alpha-0123456789ab",
		Architecture:         "amd64",
		AgentRepository:      "ghcr.io/yingsuiai/dirextalk-agent",
		WorkerRepository:     "ghcr.io/yingsuiai/dirextalk-cloud-worker",
		ReaperRepository:     "ghcr.io/yingsuiai/dirextalk-aws-reaper",
		ManifestOutput:       "C:/outside/release.json",
		RootFSOutput:         "C:/outside/worker.tar",
		DockerConfigDir:      lease.dockerConfigDir,
		RegistryHost:         lease.registryHost,
		BuildSourcesVerified: true,
	}
	wantResult := releasepublish.Result{
		SchemaVersion:      "dirextalk.agent.release-manifest/v1",
		ReleaseTag:         wantRequest.ReleaseTag,
		ManifestDigest:     digest('a'),
		AgentDigest:        digest('b'),
		WorkerDigest:       digest('c'),
		ReaperDigest:       digest('d'),
		WorkerRootFSDigest: digest('e'),
		WorkerBinaryDigest: digest('f'),
	}
	publishRelease = func(_ context.Context, request releasepublish.Request) (releasepublish.Result, error) {
		if !reflect.DeepEqual(request, wantRequest) {
			t.Fatalf("request = %#v", request)
		}
		return wantResult, nil
	}
	arguments := []string{
		"publish",
		"--release-tag", wantRequest.ReleaseTag,
		"--architecture", wantRequest.Architecture,
		"--agent-repository", wantRequest.AgentRepository,
		"--worker-repository", wantRequest.WorkerRepository,
		"--reaper-repository", wantRequest.ReaperRepository,
		"--manifest-output", wantRequest.ManifestOutput,
		"--rootfs-output", wantRequest.RootFSOutput,
		"--ecr-session", "C:/protected/ecr-session.json",
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), arguments, &stdout, &stderr); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if lease.closeCalls != 1 {
		t.Fatalf("session cleanup calls = %d", lease.closeCalls)
	}
	for _, forbidden := range []string{"ghcr.io", "C:/outside"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("stdout exposed %q: %s", forbidden, stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), `"manifest_digest":"`+wantResult.ManifestDigest+`"`) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunUsesFixedMessagesAndNeverEchoesArgumentsOrErrors(t *testing.T) {
	originalPublish, originalClaim := publishRelease, claimECRSession
	t.Cleanup(func() { publishRelease, claimECRSession = originalPublish, originalClaim })
	claimECRSession = func(string) (releaseSession, error) {
		return &fakeReleaseSession{dockerConfigDir: "C:/private/docker-session", registryHost: "ghcr.io"}, nil
	}
	publishRelease = func(context.Context, releasepublish.Request) (releasepublish.Result, error) {
		return releasepublish.Result{}, errors.New("registry rejected super-sensitive-token")
	}

	tests := []struct {
		name      string
		arguments []string
		wantCode  int
		wantError string
	}{
		{name: "missing command", arguments: []string{"super-sensitive-token"}, wantCode: 2, wantError: usageMessage},
		{name: "unknown flag", arguments: []string{"publish", "--password", "super-sensitive-token"}, wantCode: 2, wantError: usageMessage},
		{name: "publish failure", arguments: validArguments(), wantCode: 1, wantError: publishMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), test.arguments, &stdout, &stderr)
			if code != test.wantCode || stderr.String() != test.wantError || stdout.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "super-sensitive-token") {
				t.Fatal("stderr exposed argument or wrapped error")
			}
		})
	}
}

func TestRunReportsOutputFailureWithFixedMessage(t *testing.T) {
	originalPublish, originalClaim := publishRelease, claimECRSession
	t.Cleanup(func() { publishRelease, claimECRSession = originalPublish, originalClaim })
	lease := &fakeReleaseSession{dockerConfigDir: "C:/private/docker-session", registryHost: "ghcr.io"}
	claimECRSession = func(string) (releaseSession, error) { return lease, nil }
	publishRelease = func(context.Context, releasepublish.Request) (releasepublish.Result, error) {
		return releasepublish.Result{SchemaVersion: "v1"}, nil
	}
	var stderr bytes.Buffer
	code := run(context.Background(), validArguments(), failingWriter{}, &stderr)
	if code != 1 || stderr.String() != outputMessage {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if lease.closeCalls != 1 {
		t.Fatalf("session cleanup calls = %d", lease.closeCalls)
	}
}

func TestRunCleansSessionOnPublishFailureAndFailsClosedOnCleanupError(t *testing.T) {
	originalPublish, originalClaim := publishRelease, claimECRSession
	t.Cleanup(func() { publishRelease, claimECRSession = originalPublish, originalClaim })
	publishRelease = func(context.Context, releasepublish.Request) (releasepublish.Result, error) {
		return releasepublish.Result{}, errors.New("publish failed")
	}
	lease := &fakeReleaseSession{dockerConfigDir: "C:/private/docker-session", registryHost: "ghcr.io"}
	claimECRSession = func(string) (releaseSession, error) { return lease, nil }
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), validArguments(), &stdout, &stderr); code != 1 || stderr.String() != publishMessage || lease.closeCalls != 1 {
		t.Fatalf("publish failure: code=%d close=%d stderr=%q", code, lease.closeCalls, stderr.String())
	}

	publishRelease = func(context.Context, releasepublish.Request) (releasepublish.Result, error) {
		return releasepublish.Result{SchemaVersion: "v1"}, nil
	}
	lease = &fakeReleaseSession{dockerConfigDir: "C:/private/docker-session", registryHost: "ghcr.io", closeErr: errors.New("cleanup failed")}
	var cleanupStdout, cleanupStderr bytes.Buffer
	if code := run(context.Background(), validArguments(), &cleanupStdout, &cleanupStderr); code != 1 || cleanupStdout.Len() != 0 || cleanupStderr.String() != sessionMessage || lease.closeCalls != 1 {
		t.Fatalf("cleanup failure: code=%d close=%d stdout=%q stderr=%q", code, lease.closeCalls, cleanupStdout.String(), cleanupStderr.String())
	}
}

func validArguments() []string {
	return []string{
		"publish",
		"--release-tag", "v0.1.0-alpha-0123456789ab",
		"--architecture", "amd64",
		"--agent-repository", "ghcr.io/yingsuiai/dirextalk-agent",
		"--worker-repository", "ghcr.io/yingsuiai/dirextalk-cloud-worker",
		"--reaper-repository", "ghcr.io/yingsuiai/dirextalk-aws-reaper",
		"--manifest-output", "C:/outside/release.json",
		"--rootfs-output", "C:/outside/worker.tar",
		"--ecr-session", "C:/protected/ecr-session.json",
	}
}

func digest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type fakeReleaseSession struct {
	dockerConfigDir string
	registryHost    string
	closeCalls      int
	closeErr        error
}

func (session *fakeReleaseSession) DockerConfigDir() string    { return session.dockerConfigDir }
func (session *fakeReleaseSession) RegistryHost() string       { return session.registryHost }
func (session *fakeReleaseSession) BuilderName() string        { return "" }
func (session *fakeReleaseSession) BuildSourcesVerified() bool { return true }
func (session *fakeReleaseSession) Close() error {
	session.closeCalls++
	return session.closeErr
}

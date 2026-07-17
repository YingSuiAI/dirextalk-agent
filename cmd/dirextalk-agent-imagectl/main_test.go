package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseecr"
	"github.com/YingSuiAI/dirextalk-agent/internal/releasepublish"
)

func TestRunPrepareUsesAgentOnlyPreparerAndKeepsSessionOutOfReceipt(t *testing.T) {
	originalPrepare, originalWrite, originalCleanup := prepareAgentECR, writeECRSession, cleanupECRSession
	t.Cleanup(func() {
		prepareAgentECR, writeECRSession, cleanupECRSession = originalPrepare, originalWrite, originalCleanup
	})
	called := false
	prepared := releaseecr.PreparedV1{
		Result: releaseecr.ResultV1{
			SchemaVersion: releaseecr.AgentResultSchemaV1,
			AccountID:     "123456789012",
			Region:        "eu-west-2",
			Repositories: []releaseecr.RepositoryResultV1{{
				Component: "agent", Name: releaseecr.RepositoryAgent, URI: "123456789012.dkr.ecr.eu-west-2.amazonaws.com/dirextalk-agent",
			}},
		},
		Session: releaseecr.SessionV1{SessionID: strings.Repeat("a", 32), DockerConfigDir: "C:/private/session"},
	}
	prepareAgentECR = func(_ context.Context, options releaseecr.Options) (releaseecr.PreparedV1, error) {
		called = true
		if options.Region != "eu-west-2" || options.ExpectedAccountID != "123456789012" {
			t.Fatalf("prepare options = %#v", options)
		}
		return prepared, nil
	}
	writeECRSession = func(path string, session releaseecr.SessionV1) error {
		if path != "C:/protected/session.json" || session != prepared.Session {
			t.Fatalf("session handoff = path %q session %#v", path, session)
		}
		return nil
	}
	cleanupECRSession = func(releaseecr.SessionV1) error { t.Fatal("unexpected session cleanup"); return nil }

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"prepare", "--region", "eu-west-2", "--account-id", "123456789012", "--session-output", "C:/protected/session.json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run prepare code = %d, stderr = %q", code, stderr.String())
	}
	if !called || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"schema_version":"`+releaseecr.AgentResultSchemaV1+`"`) ||
		strings.Contains(stdout.String(), prepared.Session.DockerConfigDir) || strings.Contains(stdout.String(), "dirextalk-cloud-worker") || strings.Contains(stdout.String(), "dirextalk-aws-reaper") {
		t.Fatalf("prepare output = %q", stdout.String())
	}
}

func TestRunPublishDerivesFixedAgentRepositoryAndCleansSession(t *testing.T) {
	originalClaim, originalPublish := claimECRSession, publishAgent
	t.Cleanup(func() { claimECRSession, publishAgent = originalClaim, originalPublish })
	session := &fakeImageSession{dockerConfigDir: "C:/private/session", registryHost: "123456789012.dkr.ecr.eu-west-2.amazonaws.com"}
	claimECRSession = func(path string) (imageReleaseSession, error) {
		if path != "C:/protected/session.json" {
			t.Fatalf("session path = %q", path)
		}
		return session, nil
	}
	publishAgent = func(_ context.Context, request releasepublish.AgentRequest) (releasepublish.AgentResult, error) {
		if request.AgentRepository != session.registryHost+"/"+releaseecr.RepositoryAgent || request.RegistryHost != session.registryHost ||
			request.DockerConfigDir != session.dockerConfigDir || request.ReleaseTag != "v0.1.0-alpha-0123456789ab" || request.Architecture != "amd64" {
			t.Fatalf("publish request = %#v", request)
		}
		return releasepublish.AgentResult{SchemaVersion: releasepublish.AgentResultSchemaV1, AgentImage: request.AgentRepository + ":" + request.ReleaseTag + "@sha256:" + strings.Repeat("a", 64)}, nil
	}

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"publish", "--release-tag", "v0.1.0-alpha-0123456789ab", "--architecture", "amd64", "--ecr-session", "C:/protected/session.json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run publish code = %d, stderr = %q", code, stderr.String())
	}
	if session.closeCalls != 1 || stderr.Len() != 0 || strings.Contains(stdout.String(), "worker") || strings.Contains(stdout.String(), "reaper") {
		t.Fatalf("publish output/session = output %q close_calls %d stderr %q", stdout.String(), session.closeCalls, stderr.String())
	}
}

func TestRunPublishRejectsRepositoryOverrideBeforeClaimingSession(t *testing.T) {
	originalClaim := claimECRSession
	t.Cleanup(func() { claimECRSession = originalClaim })
	claimECRSession = func(string) (imageReleaseSession, error) {
		t.Fatal("repository override reached session claim")
		return nil, nil
	}

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"publish", "--release-tag", "v0.1.0-alpha-0123456789ab", "--architecture", "amd64", "--ecr-session", "C:/protected/session.json", "--agent-repository", "example/dirextalk-agent"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != usageMessage {
		t.Fatalf("repository override result = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestRunPublishFailsClosedWhenSessionCleanupFails(t *testing.T) {
	originalClaim, originalPublish := claimECRSession, publishAgent
	t.Cleanup(func() { claimECRSession, publishAgent = originalClaim, originalPublish })
	session := &fakeImageSession{dockerConfigDir: "C:/private/session", registryHost: "123456789012.dkr.ecr.eu-west-2.amazonaws.com", closeErr: errors.New("cleanup failed")}
	claimECRSession = func(string) (imageReleaseSession, error) { return session, nil }
	publishAgent = func(context.Context, releasepublish.AgentRequest) (releasepublish.AgentResult, error) {
		return releasepublish.AgentResult{SchemaVersion: releasepublish.AgentResultSchemaV1}, nil
	}

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"publish", "--release-tag", "v0.1.0-alpha-0123456789ab", "--architecture", "amd64", "--ecr-session", "C:/protected/session.json"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != sessionMessage || session.closeCalls != 1 {
		t.Fatalf("cleanup failure result = code %d stdout %q stderr %q closes %d", code, stdout.String(), stderr.String(), session.closeCalls)
	}
}

type fakeImageSession struct {
	dockerConfigDir string
	registryHost    string
	closeErr        error
	closeCalls      int
}

func (session *fakeImageSession) DockerConfigDir() string { return session.dockerConfigDir }
func (session *fakeImageSession) RegistryHost() string    { return session.registryHost }
func (session *fakeImageSession) Close() error {
	session.closeCalls++
	return session.closeErr
}

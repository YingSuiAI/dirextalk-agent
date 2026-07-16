package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseecr"
)

func TestRunPreparesExplicitAccountAndRegionAndWritesPublicJSON(t *testing.T) {
	originalPrepare, originalWrite, originalCleanup := prepareECR, writeECRSession, cleanupECRSession
	t.Cleanup(func() {
		prepareECR, writeECRSession, cleanupECRSession = originalPrepare, originalWrite, originalCleanup
	})
	want := releaseecr.ResultV1{
		SchemaVersion: releaseecr.ResultSchemaV1, AccountID: "123456789012", Region: "us-east-1",
		RegistryHost: "123456789012.dkr.ecr.us-east-1.amazonaws.com", LoginExpiresAt: "2026-07-18T00:00:00Z",
		Repositories: []releaseecr.RepositoryResultV1{{Component: "agent", Name: releaseecr.RepositoryAgent, URI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/dirextalk-agent"}},
	}
	wantSession := releaseecr.SessionV1{SchemaVersion: releaseecr.SessionSchemaV1, SessionID: strings.Repeat("a", 32), RegistryHost: want.RegistryHost, DockerConfigDir: "C:/private/docker", ExpiresAt: want.LoginExpiresAt}
	prepareECR = func(_ context.Context, options releaseecr.Options) (releaseecr.PreparedV1, error) {
		if options.Region != want.Region || options.ExpectedAccountID != want.AccountID {
			t.Fatalf("unexpected options: %#v", options)
		}
		return releaseecr.PreparedV1{Result: want, Session: wantSession}, nil
	}
	sessionOutput := "C:/protected/ecr-session.json"
	writeECRSession = func(path string, session releaseecr.SessionV1) error {
		if path != sessionOutput || !reflect.DeepEqual(session, wantSession) {
			t.Fatalf("unexpected session handoff: path=%q session=%#v", path, session)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	arguments := []string{"prepare", "--region", want.Region, "--account-id", want.AccountID, "--session-output", sessionOutput}
	if code := run(context.Background(), arguments, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got releaseecr.ResultV1
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.AccountID != want.AccountID || got.RegistryHost != want.RegistryHost || len(got.Repositories) != 1 || strings.Contains(stdout.String(), wantSession.DockerConfigDir) {
		t.Fatalf("unexpected public JSON: %#v", got)
	}
}

func TestRunRejectsCredentialFlagsWithoutCallingAWS(t *testing.T) {
	original := prepareECR
	t.Cleanup(func() { prepareECR = original })
	called := false
	prepareECR = func(context.Context, releaseecr.Options) (releaseecr.PreparedV1, error) {
		called = true
		return releaseecr.PreparedV1{}, nil
	}
	for _, forbidden := range []string{"--access-key-id", "--secret-access-key", "--session-token", "--rootkey"} {
		var stdout, stderr bytes.Buffer
		arguments := []string{"prepare", "--region", "us-east-1", "--account-id", "123456789012", "--session-output", "session.json", forbidden, "sensitive-value"}
		if code := run(context.Background(), arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != usageMessage {
			t.Fatalf("flag %s: code=%d stdout=%q stderr=%q", forbidden, code, stdout.String(), stderr.String())
		}
	}
	if called {
		t.Fatal("credential flag reached ECR preparation")
	}
}

func TestRunRedactsPreparationError(t *testing.T) {
	original := prepareECR
	t.Cleanup(func() { prepareECR = original })
	secret := "provider secret in failure"
	prepareECR = func(context.Context, releaseecr.Options) (releaseecr.PreparedV1, error) {
		return releaseecr.PreparedV1{}, errors.New(secret)
	}
	var stdout, stderr bytes.Buffer
	arguments := []string{"prepare", "--region", "us-east-1", "--account-id", "123456789012", "--session-output", "session.json"}
	code := run(context.Background(), arguments, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || stderr.String() != prepareMessage || strings.Contains(stderr.String(), secret) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunCleansPreparedSessionWhenHandoffOrOutputFails(t *testing.T) {
	originalPrepare, originalWrite, originalCleanup, originalCleanupFile := prepareECR, writeECRSession, cleanupECRSession, cleanupECRSessionFile
	t.Cleanup(func() {
		prepareECR, writeECRSession, cleanupECRSession, cleanupECRSessionFile = originalPrepare, originalWrite, originalCleanup, originalCleanupFile
	})
	session := releaseecr.SessionV1{SessionID: strings.Repeat("b", 32), DockerConfigDir: "C:/private/session"}
	prepareECR = func(context.Context, releaseecr.Options) (releaseecr.PreparedV1, error) {
		return releaseecr.PreparedV1{Result: releaseecr.ResultV1{SchemaVersion: releaseecr.ResultSchemaV1}, Session: session}, nil
	}
	arguments := []string{"prepare", "--region", "us-east-1", "--account-id", "123456789012", "--session-output", "C:/protected/session.json"}

	t.Run("handoff failure", func(t *testing.T) {
		writeECRSession = func(string, releaseecr.SessionV1) error { return errors.New("write failed") }
		cleaned := false
		cleanupECRSession = func(got releaseecr.SessionV1) error { cleaned = reflect.DeepEqual(got, session); return nil }
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), arguments, &stdout, &stderr); code != 1 || !cleaned || stdout.Len() != 0 || stderr.String() != prepareMessage {
			t.Fatalf("code=%d cleaned=%t stdout=%q stderr=%q", code, cleaned, stdout.String(), stderr.String())
		}
	})

	t.Run("stdout failure", func(t *testing.T) {
		writeECRSession = func(string, releaseecr.SessionV1) error { return nil }
		cleaned := false
		cleanupECRSessionFile = func(path string) error { cleaned = path == "C:/protected/session.json"; return nil }
		var stderr bytes.Buffer
		if code := run(context.Background(), arguments, failingWriter{}, &stderr); code != 1 || !cleaned || stderr.String() != outputMessage {
			t.Fatalf("code=%d cleaned=%t stderr=%q", code, cleaned, stderr.String())
		}
	})
}

func TestRunCleanupExplicitlyConsumesUnpublishedSession(t *testing.T) {
	original := cleanupECRSessionFile
	t.Cleanup(func() { cleanupECRSessionFile = original })
	called := ""
	cleanupECRSessionFile = func(path string) error { called = path; return nil }
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"cleanup", "--session", "C:/protected/session.json"}, &stdout, &stderr); code != 0 || called == "" || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d called=%q stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

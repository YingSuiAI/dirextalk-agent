package awsreaper

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

type unusedProvider struct{ resource.Provider }

type failingMirror struct {
	resource.ManifestMirror
	err error
}

func (mirror failingMirror) ListExpired(context.Context, time.Time) ([]resource.Manifest, error) {
	return nil, mirror.err
}

func TestHandlerLogsOnlyStructuredRedactedFailure(t *testing.T) {
	canary := "sk-abcdefghijklmnopqrstuvwxyz012345"
	reaper, err := resource.NewReaper(&unusedProvider{}, failingMirror{err: errors.New("provider failed " + canary)})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	handler, err := NewHandler(reaper, slog.New(slog.NewJSONHandler(&output, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.Handle(context.Background()); !errors.Is(err, ErrSweepFailed) {
		t.Fatalf("Handle error = %v", err)
	}
	logs := output.String()
	if strings.Contains(logs, canary) || !strings.Contains(logs, `"error_code":"sweep_failed"`) {
		t.Fatalf("unsafe or unstructured logs: %s", logs)
	}
}

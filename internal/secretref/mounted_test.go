package secretref

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

func TestMountedResolverReturnsCallerOwnedSecret(t *testing.T) {
	directory := t.TempDir()
	writeProtected(t, filepath.Join(directory, "deepseek-token"), "token-value\n")
	resolver, err := NewMountedResolver(directory)
	if err != nil {
		t.Fatalf("NewMountedResolver() error = %v", err)
	}

	first, err := resolver.ResolveSecret(context.Background(), "mounted:deepseek-token")
	if err != nil || string(first) != "token-value" {
		t.Fatalf("ResolveSecret() = %q, %v", first, err)
	}
	clear(first)
	second, err := resolver.ResolveSecret(context.Background(), "mounted:deepseek-token")
	if err != nil || string(second) != "token-value" {
		t.Fatalf("second ResolveSecret() = %q, %v", second, err)
	}
}

func TestMountedResolverRejectsUntrustedReferencesWithoutDetail(t *testing.T) {
	directory := t.TempDir()
	resolver, err := NewMountedResolver(directory)
	if err != nil {
		t.Fatalf("NewMountedResolver() error = %v", err)
	}
	for _, reference := range []string{"file:token", "mounted:../token", `mounted:C:\\token`, "mounted:", "mounted:name/child"} {
		_, resolveErr := resolver.ResolveSecret(context.Background(), reference)
		if !errors.Is(resolveErr, modelapi.ErrSecretUnavailable) {
			t.Fatalf("ResolveSecret(%q) error = %v", reference, resolveErr)
		}
		if strings.Contains(resolveErr.Error(), reference) || strings.Contains(resolveErr.Error(), directory) {
			t.Fatalf("error exposed reference or path: %v", resolveErr)
		}
	}
}

func TestMountedResolverRejectsEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires optional Windows privileges")
	}
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	writeProtected(t, outside, "must-not-read")
	if err := os.Symlink(outside, filepath.Join(directory, "linked")); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewMountedResolver(directory)
	if err != nil {
		t.Fatalf("NewMountedResolver() error = %v", err)
	}
	if _, err := resolver.ResolveSecret(context.Background(), "mounted:linked"); !errors.Is(err, modelapi.ErrSecretUnavailable) {
		t.Fatalf("ResolveSecret() error = %v", err)
	}
}

func TestMountedResolverHonorsCancellation(t *testing.T) {
	directory := t.TempDir()
	resolver, err := NewMountedResolver(directory)
	if err != nil {
		t.Fatalf("NewMountedResolver() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveSecret(ctx, "mounted:any"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveSecret() error = %v", err)
	}
}

func writeProtected(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

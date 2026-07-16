// Package secretref resolves opaque secret references without exposing secret
// material to runtime configuration, model prompts, or ordinary application
// state.
package secretref

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

const (
	mountedPrefix = "mounted:"
	maxSecretSize = 16 << 10
)

var mountedNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// MountedResolver maps mounted:<name> references to protected files beneath a
// single configured directory. References never contain filesystem paths.
type MountedResolver struct {
	directory string
}

func NewMountedResolver(directory string) (*MountedResolver, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil, modelapi.ErrSecretUnavailable
	}
	realDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, modelapi.ErrSecretUnavailable
	}
	realDirectory, err = filepath.Abs(realDirectory)
	if err != nil {
		return nil, modelapi.ErrSecretUnavailable
	}
	info, err := os.Stat(realDirectory)
	if err != nil || !info.IsDir() {
		return nil, modelapi.ErrSecretUnavailable
	}
	return &MountedResolver{directory: realDirectory}, nil
}

func (resolver *MountedResolver) ResolveSecret(ctx context.Context, reference string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if resolver == nil {
		return nil, modelapi.ErrSecretUnavailable
	}
	name, ok := strings.CutPrefix(strings.TrimSpace(reference), mountedPrefix)
	if !ok || !mountedNamePattern.MatchString(name) {
		return nil, modelapi.ErrSecretUnavailable
	}

	path, err := filepath.EvalSymlinks(filepath.Join(resolver.directory, name))
	if err != nil {
		return nil, modelapi.ErrSecretUnavailable
	}
	path, err = filepath.Abs(path)
	if err != nil || !containedBy(resolver.directory, path) {
		return nil, modelapi.ErrSecretUnavailable
	}
	if err := config.ValidateMountedSecretFile(path); err != nil {
		return nil, modelapi.ErrSecretUnavailable
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, modelapi.ErrSecretUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxSecretSize+1))
	if err != nil {
		clear(raw)
		return nil, modelapi.ErrSecretUnavailable
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxSecretSize || bytes.ContainsAny(trimmed, "\r\n\x00") {
		clear(raw)
		return nil, modelapi.ErrSecretUnavailable
	}
	secret := append([]byte(nil), trimmed...)
	clear(raw)
	return secret, nil
}

func containedBy(directory, path string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

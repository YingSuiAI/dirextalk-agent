package workerruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxPiArtifactPathBytes = 512

func collectPiArtifacts(
	ctx context.Context,
	task TaskV1,
	workspace string,
	paths []string,
) ([]Artifact, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if ctx == nil ||
		(task.WorkspaceMode != WorkspaceIsolated &&
			task.WorkspaceMode != WorkspaceExclusive) ||
		!cleanAbsolute(workspace) {
		return nil, ErrInvalid
	}
	root, err := os.Lstat(workspace)
	if err != nil || root.Mode()&os.ModeSymlink != 0 || !root.IsDir() {
		return nil, ErrInvalid
	}
	maximum := MaxArtifactsPerResult - 1
	if task.IncludePatch {
		maximum--
	}
	if len(paths) > maximum {
		return nil, ErrInvalid
	}

	artifacts := make([]Artifact, 0, len(paths))
	seenNames := make(map[string]struct{}, len(paths))
	for _, relative := range paths {
		name, mediaType, err := validatePiArtifactPath(workspace, relative)
		if err != nil {
			destroyArtifacts(artifacts)
			return nil, ErrInvalid
		}
		if _, duplicate := seenNames[name]; duplicate {
			destroyArtifacts(artifacts)
			return nil, ErrInvalid
		}
		seenNames[name] = struct{}{}
		content, err := readStableFile(
			ctx,
			filepath.Join(workspace, filepath.FromSlash(relative)),
			MaxArtifactBytes,
		)
		if err != nil {
			destroyArtifacts(artifacts)
			return nil, ErrInvalid
		}
		artifact := Artifact{Name: name, MediaType: mediaType, Content: content}
		if artifact.Validate() != nil {
			clear(content)
			destroyArtifacts(artifacts)
			return nil, ErrInvalid
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, nil
}

func validatePiArtifactPath(workspace, relative string) (string, string, error) {
	if relative == "" ||
		len(relative) > maxPiArtifactPathBytes ||
		!utf8.ValidString(relative) ||
		strings.TrimSpace(relative) != relative ||
		strings.Contains(relative, "\\") ||
		strings.IndexFunc(relative, unicode.IsControl) >= 0 ||
		filepath.IsAbs(relative) ||
		filepath.Clean(relative) != filepath.FromSlash(relative) ||
		relative == "." ||
		strings.HasPrefix(relative, "../") {
		return "", "", ErrInvalid
	}
	parts := strings.Split(relative, "/")
	current := workspace
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", "", ErrInvalid
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", "", ErrInvalid
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", "", ErrInvalid
		}
	}
	name := parts[len(parts)-1]
	if !artifactNamePattern.MatchString(name) ||
		name == "final.json" || name == "changes.patch" {
		return "", "", ErrInvalid
	}
	mediaType := ""
	switch filepath.Ext(name) {
	case ".json":
		mediaType = "application/json"
	case ".md", ".txt":
		mediaType = "text/plain; charset=utf-8"
	default:
		return "", "", ErrInvalid
	}
	return name, mediaType, nil
}

func destroyArtifacts(artifacts []Artifact) {
	for _, artifact := range artifacts {
		clear(artifact.Content)
	}
}

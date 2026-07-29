package workerruntime

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const maxUntrackedFiles = 256

type GitPatchCollector struct {
	executable string
	processes  ProcessRunner
}

func NewGitPatchCollector(
	executable string,
	processes ProcessRunner,
) (*GitPatchCollector, error) {
	if !cleanAbsolute(executable) || processes == nil {
		return nil, ErrInvalid
	}
	return &GitPatchCollector{
		executable: executable,
		processes:  processes,
	}, nil
}

func (collector *GitPatchCollector) Collect(
	ctx context.Context,
	workspace string,
) ([]byte, error) {
	if collector == nil || ctx == nil || !cleanAbsolute(workspace) {
		return nil, ErrInvalid
	}
	inside, err := collector.run(
		ctx, workspace, 64,
		[]string{"-C", workspace, "rev-parse", "--is-inside-work-tree"},
		nil,
	)
	if err != nil || string(bytes.TrimSpace(inside)) != "true" {
		clear(inside)
		return nil, ErrExecution
	}
	clear(inside)

	tracked, err := collector.run(
		ctx, workspace, MaxPatchBytes,
		[]string{
			"-C", workspace, "diff", "--binary", "--no-ext-diff",
			"--no-textconv", "--no-color", "HEAD", "--",
		},
		nil,
	)
	if err != nil {
		return nil, err
	}
	untrackedRaw, err := collector.run(
		ctx, workspace, MaxContextBytes,
		[]string{
			"-C", workspace, "ls-files", "--others",
			"--exclude-standard", "-z",
		},
		nil,
	)
	if err != nil {
		clear(tracked)
		return nil, err
	}
	defer clear(untrackedRaw)
	untracked, err := parseUntrackedPaths(untrackedRaw)
	if err != nil {
		clear(tracked)
		return nil, err
	}
	patch := bytes.Clone(tracked)
	clear(tracked)
	for _, relative := range untracked {
		remaining := MaxPatchBytes - len(patch)
		if remaining <= 0 {
			clear(patch)
			return nil, ErrExecution
		}
		addition, runErr := collector.run(
			ctx, workspace, remaining,
			[]string{
				"-C", workspace, "diff", "--binary", "--no-ext-diff",
				"--no-textconv", "--no-color", "--no-index", "--",
				"/dev/null", relative,
			},
			[]int{1},
		)
		if runErr != nil {
			clear(patch)
			return nil, runErr
		}
		patch = append(patch, addition...)
		clear(addition)
		if len(patch) > MaxPatchBytes {
			clear(patch)
			return nil, ErrExecution
		}
	}
	if len(patch) != 0 &&
		(!utf8Valid(patch) || security.ContainsLikelySecret(string(patch))) {
		clear(patch)
		return nil, ErrExecution
	}
	return patch, nil
}

func (collector *GitPatchCollector) run(
	ctx context.Context,
	workspace string,
	maximum int,
	arguments []string,
	allowedExitCodes []int,
) ([]byte, error) {
	output, err := collector.processes.Run(ctx, ProcessSpec{
		Executable: collector.executable,
		Arguments:  arguments,
		Directory:  workspace,
		Environment: map[string]string{
			"PATH":                "/usr/bin:/bin",
			"HOME":                "/nonexistent",
			"LANG":                "C.UTF-8",
			"LC_ALL":              "C.UTF-8",
			"GIT_CONFIG_NOSYSTEM": "1",
			"GIT_CONFIG_GLOBAL":   "/dev/null",
			"GIT_OPTIONAL_LOCKS":  "0",
			"GIT_TERMINAL_PROMPT": "0",
		},
		AllowedExitCodes: allowedExitCodes,
		MaxStdoutBytes:   maximum,
		MaxStderrBytes:   MaxFinalResponseBytes,
	})
	if err != nil {
		return nil, errors.Join(ErrExecution, err)
	}
	return output.Stdout, nil
}

func parseUntrackedPaths(input []byte) ([]string, error) {
	if len(input) == 0 {
		return nil, nil
	}
	if input[len(input)-1] != 0 {
		return nil, ErrExecution
	}
	rawPaths := bytes.Split(input[:len(input)-1], []byte{0})
	if len(rawPaths) > maxUntrackedFiles {
		return nil, ErrExecution
	}
	paths := make([]string, 0, len(rawPaths))
	seen := make(map[string]struct{}, len(rawPaths))
	for _, raw := range rawPaths {
		value := string(raw)
		if value == "" || strings.IndexByte(value, 0) >= 0 ||
			filepath.IsAbs(value) || filepath.Clean(value) != value ||
			value == "." || value == ".." ||
			strings.HasPrefix(value, ".."+string(filepath.Separator)) ||
			security.ContainsLikelySecret(value) {
			return nil, ErrExecution
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrExecution
		}
		seen[value] = struct{}{}
		paths = append(paths, value)
	}
	return paths, nil
}

func utf8Valid(value []byte) bool {
	return bytes.Equal(bytes.ToValidUTF8(value, nil), value)
}

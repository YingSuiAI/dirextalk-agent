package main

import (
	"log/slog"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

func main() {
	if err := run(); err != nil {
		// Never render the underlying error: startup errors may contain a local
		// trust-file or artifact path. The systemd journal receives only a stable
		// de-secreted code.
		slog.Error("worker installer unavailable", "code", installer.ErrorCodeOf(err))
		os.Exit(1)
	}
}

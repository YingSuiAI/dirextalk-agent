// dirextalk-cloud-worker-exec-gate is the only Cloud Worker image process
// granted CAP_SYS_ADMIN. It owns fanotify execution permission decisions and
// exposes a closed, local Unix protocol to the unprivileged Worker.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

func main() {
	if len(os.Args) != 1 || os.Geteuid() != 0 {
		slog.Error("[cloud-worker-exec-gate] outcome=invalid_startup")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server, err := execgate.NewServer(execgate.DefaultConfig())
	if err != nil {
		slog.Error("[cloud-worker-exec-gate] outcome=qualification_failed")
		os.Exit(1)
	}
	defer server.Close()
	if err = server.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("[cloud-worker-exec-gate] outcome=failed")
		os.Exit(1)
	}
	slog.Info("[cloud-worker-exec-gate] outcome=stopped")
}

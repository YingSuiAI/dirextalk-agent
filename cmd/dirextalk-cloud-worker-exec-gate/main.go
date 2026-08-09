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
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

func main() {
	if os.Geteuid() != 0 {
		slog.Error("[cloud-worker-exec-gate] outcome=invalid_startup")
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "--qualify-fanotify" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := execgate.QualifyFanotifyExecPermission(ctx, "/bin/true"); err != nil {
			slog.Error("[cloud-worker-exec-gate] fanotify_qualification=failed")
			os.Exit(1)
		}
		slog.Info("[cloud-worker-exec-gate] fanotify_qualification=pass")
		return
	}
	if len(os.Args) != 1 {
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

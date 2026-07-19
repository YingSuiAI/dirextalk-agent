package releaseprocess

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestSIGTERMReachesReleaseCleanupContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not deliver POSIX SIGTERM")
	}
	if os.Getenv("DIREXTALK_RELEASE_SIGNAL_HELPER") == "1" {
		ctx, stop := Context()
		ready, cleaned := os.Getenv("DIREXTALK_RELEASE_READY"), os.Getenv("DIREXTALK_RELEASE_CLEANED")
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
			os.Exit(2)
		}
		<-ctx.Done()
		if err := os.WriteFile(cleaned, []byte("cleaned"), 0o600); err != nil {
			os.Exit(3)
		}
		stop()
		os.Exit(0)
	}
	root := t.TempDir()
	ready, cleaned := filepath.Join(root, "ready"), filepath.Join(root, "cleaned")
	command := exec.Command(os.Args[0], "-test.run=^TestSIGTERMReachesReleaseCleanupContext$")
	command.Env = append(os.Environ(),
		"DIREXTALK_RELEASE_SIGNAL_HELPER=1",
		"DIREXTALK_RELEASE_READY="+ready,
		"DIREXTALK_RELEASE_CLEANED="+cleaned,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			t.Fatal("signal helper did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cleaned); err != nil {
		t.Fatalf("SIGTERM skipped cleanup context: %v", err)
	}
}

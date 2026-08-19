package coretask

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNamedScheduleTimezoneDoesNotDependOnHostZoneinfo(t *testing.T) {
	if os.Getenv("DIREXTALK_TZDATA_HELPER") == "1" {
		location, err := time.LoadLocation("Asia/Shanghai")
		if err != nil {
			t.Fatalf("load embedded timezone: %v", err)
		}
		if got := time.Date(2026, 8, 19, 9, 0, 0, 0, location).UTC(); !got.Equal(time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)) {
			t.Fatalf("Shanghai 09:00 converted to %v", got)
		}
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("filesystem-isolated tzdata regression is Linux-only")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bubblewrap is unavailable for filesystem-isolated tzdata regression")
	}
	if probe := exec.Command(bwrap, "--ro-bind", "/", "/", "/bin/true"); probe.Run() != nil {
		t.Skip("bubblewrap user namespaces are unavailable for filesystem-isolated tzdata regression")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	goRootOutput, err := exec.Command("go", "env", "GOROOT").CombinedOutput()
	if err != nil {
		t.Fatalf("resolve GOROOT through go env: %v\n%s", err, goRootOutput)
	}
	goRoot := strings.TrimSpace(string(goRootOutput))
	if goRoot == "" {
		t.Fatal("resolve GOROOT through go env: empty output")
	}
	args := []string{"--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"}
	for _, source := range []string{"/usr/share/zoneinfo", "/usr/share/lib/zoneinfo", "/usr/lib/locale/TZ", "/etc/zoneinfo", filepath.Join(goRoot, "lib/time")} {
		info, statErr := os.Stat(source)
		switch {
		case statErr == nil && info.IsDir():
			args = append(args, "--tmpfs", source)
		case os.IsNotExist(statErr):
			continue
		case statErr != nil:
			t.Fatalf("inspect zoneinfo source %q: %v", source, statErr)
		default:
			t.Fatalf("zoneinfo source %q is not a directory", source)
		}
	}
	args = append(args, executable, "-test.run=^TestNamedScheduleTimezoneDoesNotDependOnHostZoneinfo$", "-test.count=1")
	command := exec.Command(bwrap, args...)
	command.Env = append(os.Environ(), "DIREXTALK_TZDATA_HELPER=1", "ZONEINFO=/missing-zoneinfo.zip")
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("run without host zoneinfo: %v\n%s", runErr, output)
	}
}

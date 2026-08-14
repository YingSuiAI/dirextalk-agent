//go:build unix

package runtime

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestConfigureProcessCancellationPinsIdentityDeathAndCapabilities(t *testing.T) {
	t.Parallel()
	command := exec.Command("/bin/true")
	if err := configureProcessCancellation(command, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	attributes := command.SysProcAttr
	if attributes == nil || !attributes.Setpgid || attributes.Pdeathsig != syscall.SIGKILL ||
		attributes.Credential == nil || attributes.Credential.Uid != 65532 ||
		attributes.Credential.Gid != 65532 || attributes.Credential.NoSetGroups ||
		len(attributes.Credential.Groups) != 0 ||
		len(attributes.AmbientCaps) != 0 || command.Cancel == nil || command.WaitDelay != 0 {
		t.Fatalf("process attributes = %+v wait=%s cancel=%t", attributes, command.WaitDelay, command.Cancel != nil)
	}
}

func TestOSProcessRunnerExecutesAsPinnedPiIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only AMI qualification gate for actual setuid/setgid child")
	}
	directory, err := os.MkdirTemp("", "dirextalk-pi-identity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chown(directory, 0, 65532); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	runner, err := NewOSProcessRunner(65532, 65532)
	if err != nil {
		t.Fatal(err)
	}
	const script = `printf '%s\n' "$(id -u)" "$(id -g)" "$(id -G)" "$(umask)"; awk '/^Cap(Inh|Prm|Eff|Amb):/ { print $1 $2 }' /proc/self/status`
	output, err := runner.Run(t.Context(), ProcessSpec{
		Executable: "/bin/sh",
		Arguments:  []string{"-c", script},
		Directory:  directory,
		Environment: map[string]string{
			"PATH": "/usr/bin:/bin",
		},
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(output.Stdout)
	lines := strings.Split(strings.TrimSpace(string(output.Stdout)), "\n")
	if len(lines) != 8 || lines[0] != "65532" || lines[1] != "65532" ||
		lines[2] != "65532" || lines[3] != "0007" {
		t.Fatalf("identity output = %q", output.Stdout)
	}
	capabilities := make(map[string]string, 4)
	for _, line := range lines[4:] {
		field, value, found := strings.Cut(line, ":")
		if !found {
			t.Fatalf("capability line = %q", line)
		}
		capabilities[field] = value
	}
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if capabilities[field] != "0000000000000000" {
			t.Fatalf("%s = %q", field, capabilities[field])
		}
	}
}

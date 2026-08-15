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
	directory := piIdentityTempDir(t)
	sha, err := digestPath("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	binding := ProcessBinding{
		ExecutionID: "11111111-1111-4111-8111-111111111111",
		TaskID:      "22222222-2222-4222-8222-222222222222",
		Attempt:     1, LeaseEpoch: 2, RuntimeTaskSHA256: strings.Repeat("1", 64),
	}
	runner := OSProcessRunner{
		uid: 65532, gid: 65532,
		gate: &fakeProcessExecGate{}, state: &processRunnerState{},
	}
	bound, err := runner.BindProcess(binding)
	if err != nil {
		t.Fatal(err)
	}
	const script = `printf '%s\n' "$(id -u)" "$(id -g)" "$(id -G)" "$(umask)"; awk '/^Cap(Inh|Prm|Eff|Amb):/ { print $1 $2 }' /proc/self/status`
	output, err := bound.Run(t.Context(), ProcessSpec{
		Executable:               "/bin/sh",
		ExpectedExecutableSHA256: sha,
		Arguments:                []string{"-c", script},
		Directory:                directory,
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

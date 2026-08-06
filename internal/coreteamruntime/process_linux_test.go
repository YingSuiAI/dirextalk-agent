//go:build linux

package coreteamruntime

import (
	"os/exec"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
)

func TestConfigureSandboxIdentityAssignsOnlyOfficialPiIdentity(t *testing.T) {
	command := exec.Command("/bin/true")
	configureProcessCancellation(command)
	configureSandboxIdentity(command, true)

	credential := command.SysProcAttr.Credential
	if credential == nil || credential.Uid != pisandbox.OfficialPiUID || credential.Gid != pisandbox.OfficialPiGID ||
		credential.NoSetGroups || len(credential.Groups) != 0 {
		t.Fatalf("credential = %+v", credential)
	}
}

func TestConfigureSandboxIdentityLeavesControlProcessesUnchanged(t *testing.T) {
	command := exec.Command("/bin/true")
	configureProcessCancellation(command)
	configureSandboxIdentity(command, false)

	if command.SysProcAttr.Credential != nil {
		t.Fatalf("credential = %+v", command.SysProcAttr.Credential)
	}
}

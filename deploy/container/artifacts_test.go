package container_test

import (
	"os"
	"strings"
	"testing"
)

func TestWorkerArtifactPreservesExclusiveVMRuntimeBoundary(t *testing.T) {
	containerfile := readArtifact(t, "worker.Containerfile")
	for _, required := range []string{
		"FROM scratch",
		"USER 65532:65532",
		"DIREXTALK_WORKER_BINARY_SHA256_FILE=/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256",
		"sha256sum /out/dirextalk-cloud-worker",
		"sha256sum /out/dirextalk-worker-installer",
		"COPY --from=build --chmod=0555 /out/dirextalk-worker-installer /usr/local/bin/dirextalk-worker-installer",
		"dirextalk-worker-installer.socket /usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.socket",
		"dirextalk-installer.tmpfiles /usr/local/share/dirextalk-worker/ami/dirextalk-installer.tmpfiles",
		"ENTRYPOINT [\"/usr/local/bin/dirextalk-cloud-worker\"]",
		"grep -Eq '^v[0-9]+\\.[0-9]+\\.[0-9]+-(alpha|beta|rc)",
	} {
		if !strings.Contains(containerfile, required) {
			t.Fatalf("worker.Containerfile is missing %q", required)
		}
	}
	for _, forbidden := range []string{"USER 0:0", "aws-cli", "awscli", "nodejs", "npm ", "docker.sock", "dockerd"} {
		if strings.Contains(strings.ToLower(containerfile), strings.ToLower(forbidden)) {
			t.Fatalf("worker.Containerfile contains forbidden runtime surface %q", forbidden)
		}
	}
}

func TestAllRuntimeArtifactsRequireImmutablePrereleaseMetadata(t *testing.T) {
	for _, name := range []string{"agent.Containerfile", "worker.Containerfile", "reaper.Containerfile"} {
		artifact := readArtifact(t, name)
		for _, required := range []string{
			"ARG VERSION",
			"ARG REVISION",
			"org.opencontainers.image.version=\"$VERSION\"",
			"org.opencontainers.image.revision=\"$REVISION\"",
			"grep -Eq '^v[0-9]+\\.[0-9]+\\.[0-9]+-(alpha|beta|rc)",
			"grep -Eq '^[0-9a-f]{40}$'",
			"test \"$VERSION\" != 'v1.0.3'",
		} {
			if !strings.Contains(artifact, required) {
				t.Fatalf("%s is missing immutable release metadata boundary %q", name, required)
			}
		}
	}
}

func TestWorkerAMIRootfsRunsSupervisorWithoutPrivilegeOrInboundSocket(t *testing.T) {
	service := readArtifact(t, "worker-ami/dirextalk-cloud-worker.service")
	for _, required := range []string{
		"User=dirextalk-worker",
		"Group=dirextalk-worker",
		"ExecStart=/usr/local/bin/dirextalk-cloud-worker",
		"NoNewPrivileges=yes",
		"CapabilityBoundingSet=\n",
		"ProtectSystem=strict",
		"SocketBindDeny=any",
	} {
		if !strings.Contains(service, required) {
			t.Fatalf("Worker AMI service is missing %q", required)
		}
	}
	for _, forbidden := range []string{"User=root", "Group=root", "ExecStart=/bin/", "ExecStart=/usr/bin/aws", "docker.sock"} {
		if strings.Contains(service, forbidden) {
			t.Fatalf("Worker AMI service contains forbidden runtime surface %q", forbidden)
		}
	}
	if user := readArtifact(t, "worker-ami/dirextalk-worker.sysusers"); !strings.Contains(user, "dirextalk-worker 65532") {
		t.Fatal("Worker AMI user is not pinned to uid 65532")
	}
}

func TestWorkerAMIInstallerUsesOnlyApprovalBoundUnixSocket(t *testing.T) {
	service := readArtifact(t, "worker-ami/dirextalk-worker-installer.service")
	for _, required := range []string{
		"User=root", "ExecStart=/usr/local/bin/dirextalk-worker-installer", "PrivateNetwork=yes",
		"RestrictAddressFamilies=AF_UNIX", "ProtectSystem=strict", "CapabilityBoundingSet=\n",
		"ConditionPathExists=/etc/dirextalk-installer/approval-public-key",
		"ConditionPathExists=/etc/dirextalk-installer/binding.cbor",
	} {
		if !strings.Contains(service, required) {
			t.Fatalf("Worker installer service is missing %q", required)
		}
	}
	for _, forbidden := range []string{"ExecStart=/bin/", "ExecStart=/usr/bin/aws", "docker.sock", "Environment=AWS_", "Environment=SECRET"} {
		if strings.Contains(service, forbidden) {
			t.Fatalf("Worker installer service contains forbidden surface %q", forbidden)
		}
	}
	socket := readArtifact(t, "worker-ami/dirextalk-worker-installer.socket")
	for _, required := range []string{
		"ListenStream=/run/dirextalk-installer/installer.sock", "SocketUser=root",
		"SocketGroup=dirextalk-worker", "SocketMode=0620", "DirectoryMode=0710", "Accept=no",
	} {
		if !strings.Contains(socket, required) {
			t.Fatalf("Worker installer socket is missing %q", required)
		}
	}
}

func readArtifact(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

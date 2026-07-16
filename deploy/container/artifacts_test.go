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

func readArtifact(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

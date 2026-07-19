package container_test

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAllContainerBasesRequireClosedPrivateBuildArguments(t *testing.T) {
	const goBuilder = "FROM --platform=linux/amd64 ${GO_BUILD_BASE} AS build"
	const lambdaRuntime = "FROM --platform=linux/amd64 ${REAPER_RUNTIME_BASE}"

	tests := map[string][]string{
		"agent.Containerfile":  {goBuilder, "FROM scratch"},
		"worker.Containerfile": {goBuilder, "FROM scratch"},
		"reaper.Containerfile": {goBuilder, lambdaRuntime},
	}
	for name, expected := range tests {
		var bases []string
		for _, line := range strings.Split(readArtifact(t, name), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "FROM ") {
				bases = append(bases, line)
			}
		}
		if !reflect.DeepEqual(bases, expected) {
			t.Fatalf("%s base images = %q, want required private build arguments %q", name, bases, expected)
		}
		artifact := readArtifact(t, name)
		if strings.Contains(artifact, "# syntax=") || strings.Contains(artifact, "docker.io/") ||
			strings.Contains(artifact, "public.ecr.aws/") || !strings.Contains(artifact, "ARG GO_BUILD_BASE") {
			t.Fatalf("%s contains an external/default source or lacks GO_BUILD_BASE", name)
		}
		if name == "reaper.Containerfile" && !strings.Contains(artifact, "ARG REAPER_RUNTIME_BASE") {
			t.Fatalf("%s lacks REAPER_RUNTIME_BASE", name)
		}
		assertExactNoDefaultARG(t, name, artifact, "GO_BUILD_BASE")
		if name == "reaper.Containerfile" {
			assertExactNoDefaultARG(t, name, artifact, "REAPER_RUNTIME_BASE")
		}
	}
}

func assertExactNoDefaultARG(t *testing.T, name, artifact, argument string) {
	t.Helper()
	want := "ARG " + argument
	count := 0
	for _, raw := range strings.Split(artifact, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, want) {
			if line != want {
				t.Fatalf("%s source argument %s has a default or suffix: %q", name, argument, line)
			}
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%s exact %q declarations = %d", name, want, count)
	}
}

func TestWorkerArtifactPreservesExclusiveVMRuntimeBoundary(t *testing.T) {
	containerfile := readArtifact(t, "worker.Containerfile")
	for _, required := range []string{
		"FROM scratch",
		"USER 65532:65532",
		"DIREXTALK_WORKER_BINARY_SHA256_FILE=/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256",
		"sha256sum /out/dirextalk-cloud-worker",
		"sha256sum /out/dirextalk-worker-installer",
		"COPY --from=build --chmod=0555 /out/dirextalk-worker-installer /usr/local/bin/dirextalk-worker-installer",
		"dirextalk-worker-installer-bootstrap.service /usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer-bootstrap.service",
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

func TestWorkerArtifactBootstrapsTraversableRootfsDirectories(t *testing.T) {
	containerfile := readArtifact(t, "worker.Containerfile")
	for _, required := range []string{
		"mkdir -p /out/worker-rootfs-dirs/etc/ssl/certs",
		"/out/worker-rootfs-dirs/usr/local/share/dirextalk-worker/ami",
		"/out/worker-rootfs-dirs/var/lib/dirextalk-worker",
		"COPY --from=build --chmod=0755 /out/worker-rootfs-dirs/ /",
	} {
		if !strings.Contains(containerfile, required) {
			t.Fatalf("worker.Containerfile is missing traversable rootfs directory bootstrap %q", required)
		}
	}
	if strings.Index(containerfile, "COPY --from=build --chmod=0755 /out/worker-rootfs-dirs/ /") >
		strings.Index(containerfile, "COPY --from=build --chmod=0444 /etc/ssl/certs/ca-certificates.crt") {
		t.Fatal("worker rootfs directory bootstrap follows the restrictive certificate copy")
	}
}

func TestAgentArtifactProvidesNonRootTLSGrpcHealthcheck(t *testing.T) {
	containerfile := readArtifact(t, "agent.Containerfile")
	for _, required := range []string{
		"FROM scratch",
		"USER 65532:65532",
		"ENTRYPOINT [\"/usr/local/bin/dirextalk-agent\"]",
		"CMD [\"serve\"]",
		"HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD [\"/usr/local/bin/dirextalk-agent\", \"healthcheck\"]",
	} {
		if !strings.Contains(containerfile, required) {
			t.Fatalf("agent.Containerfile is missing %q", required)
		}
	}
	for _, forbidden := range []string{"USER 0:0", "aws-cli", "awscli", "nodejs", "npm ", "docker.sock", "dockerd"} {
		if strings.Contains(strings.ToLower(containerfile), strings.ToLower(forbidden)) {
			t.Fatalf("agent.Containerfile contains forbidden runtime surface %q", forbidden)
		}
	}
	compose := readArtifact(t, "compose.yaml")
	if !strings.Contains(compose, "AGENT_GRPC_HEALTHCHECK_SERVER_NAME: ${AGENT_GRPC_HEALTHCHECK_SERVER_NAME:?") {
		t.Fatal("compose.yaml does not require the TLS server name for the image healthcheck")
	}
}

func TestAgentComposeExposesStagedAWSControlGates(t *testing.T) {
	compose := readArtifact(t, "compose.yaml")
	for _, required := range []string{
		"AGENT_ENABLE_AWS_CONTROL: ${AGENT_ENABLE_AWS_CONTROL:-false}",
		"AGENT_ENABLE_MANAGED_PREPARATION_AWS: ${AGENT_ENABLE_MANAGED_PREPARATION_AWS:-false}",
		"AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME: ${AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME:-}",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("compose.yaml is missing staged AWS control boundary %q", required)
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
		"User=root", "ExecStart=/usr/local/bin/dirextalk-worker-installer serve", "NoNewPrivileges=yes",
		"StateDirectory=dirextalk-installer", "StateDirectoryMode=0700",
		"ConditionPathExists=/etc/dirextalk-installer/trust.cbor",
	} {
		if !strings.Contains(service, required) {
			t.Fatalf("Worker installer service is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateDevices=yes", "PrivateNetwork=yes",
		"ProtectSystem=", "ProtectHome=", "ProtectProc=", "ReadWritePaths=", "RestrictAddressFamilies=",
		"RestrictNamespaces=", "RestrictSUIDSGID=", "SocketBindDeny=", "SystemCallFilter=", "IPAddressDeny=",
	} {
		if strings.Contains(service, forbidden) {
			t.Fatalf("exclusive-VM root installer is accidentally sandboxed by %q", forbidden)
		}
	}
	bootstrap := readArtifact(t, "worker-ami/dirextalk-worker-installer-bootstrap.service")
	for _, required := range []string{
		"Type=oneshot", "User=root", "ExecStart=/usr/local/bin/dirextalk-worker-installer bootstrap",
		"Before=dirextalk-cloud-worker.service dirextalk-worker-installer.socket",
		"CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE", "AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_OVERRIDE",
		"Restart=on-failure", "RestartSec=5s",
	} {
		if !strings.Contains(bootstrap, required) {
			t.Fatalf("Worker installer bootstrap service is missing %q", required)
		}
	}
	for _, forbidden := range []string{"PrivateDevices=yes", "PrivateTmp=yes", "ProtectSystem=", "ReadWritePaths="} {
		if strings.Contains(bootstrap, forbidden) {
			t.Fatalf("Worker installer bootstrap would hide host EBS mounts through %q", forbidden)
		}
	}
	for _, forbidden := range []string{"ExecStart=/bin/", "ExecStart=/usr/bin/aws", "AWS_ACCESS_KEY", "docker.sock", "node", "npm", "IPAddressDeny=any"} {
		if strings.Contains(strings.ToLower(bootstrap), strings.ToLower(forbidden)) {
			t.Fatalf("Worker installer bootstrap contains forbidden surface %q", forbidden)
		}
	}
	if tmpfiles := readArtifact(t, "worker-ami/dirextalk-installer.tmpfiles"); !strings.Contains(tmpfiles, "d /etc/dirextalk-installer 0700 root root -") ||
		!strings.Contains(tmpfiles, "d /usr/local/share/dirextalk-worker/artifacts 0755 root root -") {
		t.Fatal("installer trust/artifact directories are not root-owned")
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

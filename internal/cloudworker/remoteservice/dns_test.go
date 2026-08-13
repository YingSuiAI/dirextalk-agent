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
}

func (client *fakeRoute53) VerifyAccount(context.Context, string) error {
	client.verifies++
	return nil
}

func (client *fakeRoute53) UpsertA(_ context.Context, mutation DNSMutation) error {
	client.upserts++
	client.record, client.exists = mutation.Record, true
	return nil
}

func (client *fakeRoute53) DeleteA(_ context.Context, _ DNSMutation) error {
	client.deletes++
	client.exists = false
	return nil
}

func (client *fakeRoute53) ReadA(context.Context, string, string) (ARecord, bool, error) {
	record := client.record
	if client.readMismatch {
		record.IPv4 = "203.0.113.99"
	}
	return record, client.exists, nil
}

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

package remoteservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

type DNSAction string

const (
	DNSUpsertA DNSAction = "upsert_a"
	DNSDeleteA DNSAction = "delete_a"
)

type ARecord struct {
	ZoneID   string
	Hostname string
	IPv4     string
	TTL      uint32
}

type DNSMutation struct {
	Action     DNSAction
	AccountID  string
	WorkerID   string
	WorkloadID string
	Record     ARecord
}

type ConfirmedDNSMutation struct {
	Mutation     DNSMutation
	Confirmation ExactConfirmation
}

// ReconcileLiteral applies an owner-authorized Worker domain operation and
// verifies the resulting Route53 record. Capability operations already bind
// the exact Worker/workload/record arguments and accept only the literal
// bind_domain or unbind_domain confirmation.
func ReconcileLiteral(ctx context.Context, client Route53, mutation DNSMutation, confirmation string) error {
	if ctx == nil || client == nil || mutation.validate() != nil ||
		(mutation.Action == DNSUpsertA && confirmation != "bind_domain") ||
		(mutation.Action == DNSDeleteA && confirmation != "unbind_domain" && confirmation != "destroy_worker") {
		return ErrNotConfirmed
	}
	if err := client.VerifyAccount(ctx, mutation.AccountID); err != nil {
		return err
	}
	if mutation.Action == DNSDeleteA {
		current, exists, err := client.ReadA(ctx, mutation.Record.ZoneID, canonicalHostname(mutation.Record.Hostname))
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if !sameRecord(current, mutation.Record) {
			return ErrReadback
		}
		if err = client.DeleteA(ctx, mutation); err != nil {
			return err
		}
	} else if err := client.UpsertA(ctx, mutation); err != nil {
		return err
	}
	record, exists, err := client.ReadA(ctx, mutation.Record.ZoneID, canonicalHostname(mutation.Record.Hostname))
	if err != nil {
		return err
	}
	if mutation.Action == DNSDeleteA {
		if exists {
			return ErrReadback
		}
		return nil
	}
	if !exists || !sameRecord(record, mutation.Record) {
		return ErrReadback
	}
	return nil
}

// Route53 is expected to be constructed from credentials for Mutation.AccountID.
// ReconcileRoute53 verifies the exact confirmed record after every mutation.
type Route53 interface {
	VerifyAccount(context.Context, string) error
	UpsertA(context.Context, DNSMutation) error
	// DeleteA must issue an exact Route53 DELETE using all Record fields.
	DeleteA(context.Context, DNSMutation) error
	ReadA(context.Context, string, string) (ARecord, bool, error)
}

type ExternalDNSInstructions struct {
	Hostname string
	Type     string
	Value    string
	TTL      uint32
	Summary  string
}

func (binding DomainBinding) validate(exposureHostname string) error {
	if binding.Mode != DomainRoute53SameAccount && binding.Mode != DomainExternal {
		return ErrInvalid
	}
	if !validHostname(binding.Hostname) || canonicalHostname(binding.Hostname) != canonicalHostname(exposureHostname) || binding.TTL < 60 || binding.TTL > 86400 {
		return ErrInvalid
	}
	if binding.Mode == DomainRoute53SameAccount && !safeToken(binding.ZoneID, 128) {
		return ErrInvalid
	}
	if binding.Mode == DomainExternal && binding.ZoneID != "" {
		return ErrInvalid
	}
	return nil
}

func (mutation DNSMutation) Digest() (string, error) {
	if mutation.validate() != nil {
		return "", ErrInvalid
	}
	canonical := strings.Join([]string{
		"route53-a-v1", string(mutation.Action), mutation.AccountID, mutation.WorkerID, mutation.WorkloadID,
		mutation.Record.ZoneID, canonicalHostname(mutation.Record.Hostname), mutation.Record.IPv4, fmt.Sprint(mutation.Record.TTL),
	}, "\x00")
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

func (mutation DNSMutation) validate() error {
	address, err := netip.ParseAddr(mutation.Record.IPv4)
	if (mutation.Action != DNSUpsertA && mutation.Action != DNSDeleteA) || !validAccountID(mutation.AccountID) || !idPattern.MatchString(mutation.WorkerID) ||
		!idPattern.MatchString(mutation.WorkloadID) || !safeToken(mutation.Record.ZoneID, 128) || !validHostname(mutation.Record.Hostname) ||
		err != nil || !address.Is4() || mutation.Record.TTL < 60 || mutation.Record.TTL > 86400 {
		return ErrInvalid
	}
	return nil
}

func (confirmed ConfirmedDNSMutation) Validate() error {
	digest, err := confirmed.Mutation.Digest()
	if err != nil {
		return err
	}
	return requireExact(confirmed.Confirmation, digest)
}

func ReconcileRoute53(ctx context.Context, client Route53, confirmed ConfirmedDNSMutation) error {
	if ctx == nil || client == nil {
		return ErrInvalid
	}
	if err := confirmed.Validate(); err != nil {
		return err
	}
	mutation := confirmed.Mutation
	if err := client.VerifyAccount(ctx, mutation.AccountID); err != nil {
		return err
	}
	if mutation.Action == DNSDeleteA {
		current, exists, readErr := client.ReadA(ctx, mutation.Record.ZoneID, canonicalHostname(mutation.Record.Hostname))
		if readErr != nil {
			return readErr
		}
		if !exists || !sameRecord(current, mutation.Record) {
			return ErrReadback
		}
		if err := client.VerifyAccount(ctx, mutation.AccountID); err != nil {
			return err
		}
	}
	var err error
	if mutation.Action == DNSUpsertA {
		err = client.UpsertA(ctx, mutation)
	} else {
		err = client.DeleteA(ctx, mutation)
	}
	if err != nil {
		return err
	}
	if err := client.VerifyAccount(ctx, mutation.AccountID); err != nil {
		return err
	}
	record, exists, err := client.ReadA(ctx, mutation.Record.ZoneID, canonicalHostname(mutation.Record.Hostname))
	if err != nil {
		return err
	}
	if mutation.Action == DNSDeleteA {
		if exists {
			return ErrReadback
		}
		return nil
	}
	if !exists || !sameRecord(record, mutation.Record) {
		return ErrReadback
	}
	return nil
}

// Route53MutationForWorker binds a same-account domain mutation to the
// worker's currently observed ordinary public IPv4. Calling it again after a
// stop/start or replacement produces a new digest and therefore requires an
// exact confirmation for the new address.
func Route53MutationForWorker(worker Worker, workload Workload, action DNSAction) (DNSMutation, error) {
	if worker.Validate() != nil || workload.validate() != nil || workload.Exposure == nil || !workload.Exposure.Enabled || workload.Exposure.Domain == nil ||
		workload.Exposure.Domain.Mode != DomainRoute53SameAccount || workload.Exposure.Domain.validate(workload.Exposure.Hostname) != nil {
		return DNSMutation{}, ErrInvalid
	}
	found := false
	for _, candidate := range worker.Workloads {
		if candidate.ID == workload.ID {
			found = true
			break
		}
	}
	if !found {
		return DNSMutation{}, ErrInvalid
	}
	binding := workload.Exposure.Domain
	mutation := DNSMutation{
		Action: action, AccountID: worker.AccountID, WorkerID: worker.ID, WorkloadID: workload.ID,
		Record: ARecord{ZoneID: binding.ZoneID, Hostname: binding.Hostname, IPv4: worker.PublicIPv4, TTL: binding.TTL},
	}
	if mutation.validate() != nil {
		return DNSMutation{}, ErrInvalid
	}
	return mutation, nil
}

func CompileExternalDNS(binding DomainBinding, targetIPv4 string) (ExternalDNSInstructions, error) {
	if binding.Mode != DomainExternal || binding.validate(binding.Hostname) != nil {
		return ExternalDNSInstructions{}, ErrInvalid
	}
	address, err := netip.ParseAddr(targetIPv4)
	if err != nil || !address.Is4() {
		return ExternalDNSInstructions{}, ErrInvalid
	}
	hostname := canonicalHostname(binding.Hostname)
	return ExternalDNSInstructions{
		Hostname: hostname,
		Type:     "A",
		Value:    address.String(),
		TTL:      binding.TTL,
		Summary:  fmt.Sprintf("Create an A record for %s pointing to %s with TTL %d; Dirextalk will not modify this external DNS provider.", hostname, address, binding.TTL),
	}, nil
}

func sameRecord(left, right ARecord) bool {
	return left.ZoneID == right.ZoneID && canonicalHostname(left.Hostname) == canonicalHostname(right.Hostname) && left.IPv4 == right.IPv4 && left.TTL == right.TTL
}

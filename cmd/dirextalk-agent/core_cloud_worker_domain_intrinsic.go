package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

func cloudWorkerDomainIntentDigest(payload cloudworker.RetainedWorkerDomainIntent) string {
	payload.IntentDigest = ""
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (executor *sshWorkerExecutor) ResolveRetainedWorkerDomain(ctx context.Context, ownerID string, accountGeneration uint64, operation, workerID, workloadID, hostname string) (cloudworker.RetainedWorkerDomainIntent, error) {
	if executor != nil && executor.resolveDomain != nil {
		return executor.resolveDomain(ctx, ownerID, accountGeneration, operation, workerID, workloadID, hostname)
	}
	if executor == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || accountGeneration == 0 ||
		(operation != "bind" && operation != "unbind") || !coretask.ValidUUID(workerID) || strings.TrimSpace(workloadID) == "" ||
		(operation == "bind" && !remoteservice.ValidHostname(hostname)) || (operation == "unbind" && strings.TrimSpace(hostname) != "") {
		return cloudworker.RetainedWorkerDomainIntent{}, cloudworker.ErrInvalid
	}
	worker, found, err := executor.state.LoadWorker(ctx, workerID)
	if err != nil || !found || worker.OwnerID != ownerID || worker.AccountGeneration != accountGeneration || worker.Phase == sshworker.WorkerDestroyed {
		return cloudworker.RetainedWorkerDomainIntent{}, errors.Join(sshworker.ErrIdentity, err)
	}
	identity := sshworker.WorkerIdentity{OwnerID: ownerID, AccountGeneration: accountGeneration, WorkerID: worker.WorkerID,
		Credential: worker.Credential, InstanceID: worker.Instance.ID, KeyPairID: worker.KeyPair.ID, SecurityGroupID: worker.SecurityGroup.ID}
	if !completeWorkerResourceIdentity(identity) {
		return cloudworker.RetainedWorkerDomainIntent{}, sshworker.ErrIdentity
	}
	var status sshworker.WorkerStatus
	if operation == "bind" {
		status, err = executor.ObserveWorker(ctx, sshworker.OwnerAuthority{OwnerID: ownerID, AccountGeneration: accountGeneration}, identity)
		if err != nil || status.Availability != sshworker.WorkerAvailable {
			return cloudworker.RetainedWorkerDomainIntent{}, errors.Join(sshworker.ErrIdentity, err)
		}
	} else if _, err = executor.currentBindingForCredential(ctx, identity.Credential); err != nil {
		// Exact DNS cleanup does not depend on EC2 or SSH availability, but it
		// still requires the same current credential identity as the persisted
		// Worker before freezing or reusing the cleanup authority.
		return cloudworker.RetainedWorkerDomainIntent{}, errors.Join(sshworker.ErrIdentity, err)
	}
	service, err := executor.workloads.Get(ctx, identity, workloadID)
	if err != nil {
		return cloudworker.RetainedWorkerDomainIntent{}, errors.Join(sshworker.ErrIdentity, err)
	}
	var domain *sshworkload.Domain
	if operation == "bind" {
		canonical := remoteservice.CanonicalHostname(hostname)
		if status.PublicIP == "" || (service.Hostname != "" && remoteservice.CanonicalHostname(service.Hostname) != canonical) {
			return cloudworker.RetainedWorkerDomainIntent{}, sshworker.ErrIdentity
		}
		dns := executor.route53For(ctx, identity.Credential)
		if dns == nil {
			return cloudworker.RetainedWorkerDomainIntent{}, remoteservice.ErrInvalid
		}
		if err = dns.VerifyAccount(ctx, identity.Credential.AccountID); err != nil {
			return cloudworker.RetainedWorkerDomainIntent{}, err
		}
		zoneID, found, resolveErr := dns.ResolveHostedZone(ctx, canonical)
		if resolveErr != nil {
			return cloudworker.RetainedWorkerDomainIntent{}, resolveErr
		}
		if !found {
			return cloudworker.RetainedWorkerDomainIntent{}, cloudworker.ErrRetainedWorkerPublicRoute53Required
		}
		domain = &sshworkload.Domain{ZoneID: zoneID, Hostname: canonical, TTL: workerDomainTTL, BoundIPv4: status.PublicIP}
		if service.Domain != nil && !reflect.DeepEqual(*service.Domain, *domain) {
			return cloudworker.RetainedWorkerDomainIntent{}, sshworker.ErrIdentity
		}
		if service.PendingDomain != nil && !reflect.DeepEqual(*service.PendingDomain, *domain) {
			return cloudworker.RetainedWorkerDomainIntent{}, sshworker.ErrIdentity
		}
	} else {
		if service.PendingDomain != nil {
			return cloudworker.RetainedWorkerDomainIntent{}, sshworker.ErrIdentity
		}
		persisted := service.Domain
		if persisted == nil {
			persisted = service.RemovedDomain
		}
		if persisted == nil {
			return cloudworker.RetainedWorkerDomainIntent{}, sshworker.ErrIdentity
		}
		copy := *persisted
		domain = &copy
	}
	payload := cloudworker.RetainedWorkerDomainIntent{Operation: operation, OwnerID: ownerID, AccountGeneration: accountGeneration,
		CredentialID: identity.Credential.CredentialID, CredentialRevision: identity.Credential.CredentialRevision,
		AWSAccountID: identity.Credential.AccountID, Region: identity.Credential.Region, WorkerID: identity.WorkerID,
		InstanceID: identity.InstanceID, KeyPairID: identity.KeyPairID, SecurityGroupID: identity.SecurityGroupID,
		WorkloadID: service.WorkloadID, Hostname: domain.Hostname, ZoneID: domain.ZoneID, TargetIPv4: domain.BoundIPv4, TTL: domain.TTL}
	payload.IntentDigest = cloudWorkerDomainIntentDigest(payload)
	return payload, nil
}

func (executor *sshWorkerExecutor) ApplyRetainedWorkerDomain(ctx context.Context, expected cloudworker.RetainedWorkerDomainIntent) (cloudworker.RetainedWorkerDomainResult, error) {
	if executor == nil || ctx == nil || expected.IntentDigest == "" || cloudWorkerDomainIntentDigest(expected) != expected.IntentDigest {
		return cloudworker.RetainedWorkerDomainResult{}, cloudworker.ErrInvalid
	}
	hostname := ""
	if expected.Operation == "bind" {
		hostname = expected.Hostname
	}
	current, err := executor.ResolveRetainedWorkerDomain(ctx, expected.OwnerID, expected.AccountGeneration, expected.Operation, expected.WorkerID, expected.WorkloadID, hostname)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return cloudworker.RetainedWorkerDomainResult{}, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	identity := sshworker.WorkerIdentity{OwnerID: expected.OwnerID, AccountGeneration: expected.AccountGeneration, WorkerID: expected.WorkerID,
		Credential: sshworker.CredentialIdentity{CredentialID: expected.CredentialID, CredentialRevision: expected.CredentialRevision, AccountID: expected.AWSAccountID, Region: expected.Region},
		InstanceID: expected.InstanceID, KeyPairID: expected.KeyPairID, SecurityGroupID: expected.SecurityGroupID}
	domain := &sshworkload.Domain{ZoneID: expected.ZoneID, Hostname: expected.Hostname, TTL: expected.TTL, BoundIPv4: expected.TargetIPv4}
	dns := executor.route53For(ctx, identity.Credential)
	if dns == nil {
		return cloudworker.RetainedWorkerDomainResult{}, remoteservice.ErrInvalid
	}
	fenced := &domainIntentRoute53{executor: executor, expected: expected, client: dns}
	action := remoteservice.DNSUpsertA
	if expected.Operation == "unbind" {
		action = remoteservice.DNSDeleteA
	}
	mutation := domainMutation(expected.AWSAccountID, expected.WorkerID, expected.WorkloadID, action, domain)
	if expected.Operation == "bind" {
		if err = executor.workloads.StageDomain(ctx, identity, expected.WorkloadID, domain); err == nil {
			err = remoteservice.ReconcilePlannedUpsert(ctx, fenced, mutation)
		}
		if err == nil {
			err = executor.workloads.CommitDomain(ctx, identity, expected.WorkloadID)
		}
	} else {
		err = remoteservice.ReconcilePlannedDelete(ctx, fenced, mutation)
		if err == nil {
			err = executor.workloads.SetDomain(ctx, identity, expected.WorkloadID, nil)
		}
	}
	if err != nil {
		return cloudworker.RetainedWorkerDomainResult{}, err
	}
	stored, err := executor.workloads.Get(ctx, identity, expected.WorkloadID)
	if err != nil {
		return cloudworker.RetainedWorkerDomainResult{}, err
	}
	publication := servicePublication{PublicIPv4: expected.TargetIPv4, Port: stored.Port, HealthPath: stored.HealthPath}
	if expected.Operation == "bind" {
		publication.Hostname, publication.ZoneID = expected.Hostname, expected.ZoneID
	}
	if err = executor.upsertServiceArtifact(ctx, sshworker.OwnerAuthority{OwnerID: expected.OwnerID, AccountGeneration: expected.AccountGeneration}, expected.WorkerID,
		cloudworker.ServiceSpec{WorkloadID: stored.WorkloadID, Port: stored.Port, HealthPath: stored.HealthPath, Hostname: publication.Hostname}, publication, "healthy"); err != nil {
		return cloudworker.RetainedWorkerDomainResult{}, err
	}
	state := "current"
	if expected.Operation == "unbind" {
		state = "absent"
	}
	return cloudworker.RetainedWorkerDomainResult{WorkerID: expected.WorkerID, WorkloadID: expected.WorkloadID, Hostname: expected.Hostname,
		TargetIPv4: expected.TargetIPv4, ZoneID: expected.ZoneID, RecordState: state}, nil
}

type domainIntentRoute53 struct {
	executor *sshWorkerExecutor
	expected cloudworker.RetainedWorkerDomainIntent
	client   remoteservice.HostedZoneRoute53
}

func (f *domainIntentRoute53) revalidate(ctx context.Context) error {
	if f == nil || f.executor == nil || f.client == nil {
		return cloudworker.ErrStaleAuthorization
	}
	hostname := ""
	if f.expected.Operation == "bind" {
		hostname = f.expected.Hostname
	}
	current, err := f.executor.ResolveRetainedWorkerDomain(ctx, f.expected.OwnerID, f.expected.AccountGeneration, f.expected.Operation, f.expected.WorkerID, f.expected.WorkloadID, hostname)
	if err != nil || !reflect.DeepEqual(current, f.expected) {
		return errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	return nil
}

func (f *domainIntentRoute53) VerifyAccount(ctx context.Context, account string) error {
	if err := f.revalidate(ctx); err != nil {
		return err
	}
	return f.client.VerifyAccount(ctx, account)
}
func (f *domainIntentRoute53) UpsertA(ctx context.Context, mutation remoteservice.DNSMutation) error {
	if err := f.revalidate(ctx); err != nil {
		return err
	}
	return f.client.UpsertA(ctx, mutation)
}
func (f *domainIntentRoute53) DeleteA(ctx context.Context, mutation remoteservice.DNSMutation) error {
	if err := f.revalidate(ctx); err != nil {
		return err
	}
	return f.client.DeleteA(ctx, mutation)
}
func (f *domainIntentRoute53) ReadA(ctx context.Context, zoneID, hostname string) (remoteservice.ARecord, bool, error) {
	if err := f.revalidate(ctx); err != nil {
		return remoteservice.ARecord{}, false, err
	}
	return f.client.ReadA(ctx, zoneID, hostname)
}

package control

import (
	"context"
	"log/slog"
	"strconv"
	"time"
)

const maximumIdentityEvidenceAge = 2 * time.Minute

type AttestedInstance struct {
	AccountID   string
	Region      string
	InstanceID  string
	RoleARN     string
	RoleID      string
	PendingTime time.Time
}

type DispatchIdentityRecord struct {
	OwnerID           string
	AccountGeneration uint64
	AccountID         string
	Region            string
	ProviderID        string
	InstanceID        string
	LaunchIdentity    string
	RoleARN           string
	RoleID            string
	InstanceProfileID string
	RequiredTags      map[string]string
}

type ProviderInstanceIdentity struct {
	Exists            bool
	AccountID         string
	Region            string
	InstanceID        string
	LaunchIdentity    string
	RoleARN           string
	RoleID            string
	InstanceProfileID string
	LaunchTime        time.Time
	Tags              map[string]string
	ObservedAt        time.Time
}

type DispatchIdentityLedger interface {
	LookupWorkerIdentity(context.Context, string, string, string) (DispatchIdentityRecord, error)
}

type ProviderIdentityReader interface {
	ReadWorkerIdentity(context.Context, string, string, string, string) (ProviderInstanceIdentity, error)
}

type IdentityEvidenceReader interface {
	ReadIdentityEvidence(context.Context, AttestedInstance) (IdentityClaims, error)
}

// RevalidatingIdentityEvidenceReader joins the durable dispatch owner record
// with a fresh provider readback. Mutable instance names are never an identity
// boundary; account, Region, provider ID, launch identity, role and tags all
// have to agree on every proof verification.
type RevalidatingIdentityEvidenceReader struct {
	ledger   DispatchIdentityLedger
	provider ProviderIdentityReader
	now      func() time.Time
}

func NewRevalidatingIdentityEvidenceReader(
	ledger DispatchIdentityLedger,
	provider ProviderIdentityReader,
	now func() time.Time,
) (*RevalidatingIdentityEvidenceReader, error) {
	if ledger == nil || provider == nil || now == nil {
		return nil, ErrInvalid
	}
	return &RevalidatingIdentityEvidenceReader{
		ledger: ledger, provider: provider, now: now,
	}, nil
}

func (reader *RevalidatingIdentityEvidenceReader) ReadIdentityEvidence(
	ctx context.Context,
	attested AttestedInstance,
) (IdentityClaims, error) {
	if reader == nil || ctx == nil || !accountPattern.MatchString(attested.AccountID) ||
		!regionPattern.MatchString(attested.Region) ||
		!instancePattern.MatchString(attested.InstanceID) || attested.RoleARN == "" ||
		!iamIDPattern.MatchString(attested.RoleID) || attested.PendingTime.IsZero() {
		logIdentityEvidenceRejected("input")
		return IdentityClaims{}, ErrIdentityRejected
	}
	record, err := reader.ledger.LookupWorkerIdentity(
		ctx, attested.AccountID, attested.Region, attested.InstanceID,
	)
	if err != nil {
		logIdentityEvidenceRejected("ledger_lookup")
		return IdentityClaims{}, ErrIdentityRejected
	}
	provider, err := reader.provider.ReadWorkerIdentity(
		ctx, attested.AccountID, attested.Region, record.ProviderID, attested.InstanceID,
	)
	if err != nil {
		logIdentityEvidenceRejected("provider_readback")
		return IdentityClaims{}, ErrIdentityRejected
	}
	now := reader.now().UTC()
	if record.OwnerID == "" || record.AccountGeneration == 0 ||
		record.AccountID != attested.AccountID || record.Region != attested.Region || record.ProviderID == "" ||
		record.InstanceID != attested.InstanceID || record.LaunchIdentity == "" ||
		record.RoleARN != attested.RoleARN || record.RoleID != attested.RoleID ||
		!iamIDPattern.MatchString(record.RoleID) || !iamIDPattern.MatchString(record.InstanceProfileID) || len(record.RequiredTags) == 0 {
		logIdentityEvidenceRejected("ledger_binding")
		return IdentityClaims{}, ErrIdentityRejected
	}
	if !provider.Exists || provider.AccountID != record.AccountID ||
		provider.Region != record.Region || provider.InstanceID != record.InstanceID ||
		provider.LaunchIdentity != record.LaunchIdentity || provider.RoleARN != record.RoleARN ||
		provider.RoleID != record.RoleID || provider.InstanceProfileID != record.InstanceProfileID ||
		provider.LaunchTime.IsZero() || !provider.LaunchTime.Equal(attested.PendingTime) {
		logIdentityEvidenceRejected("provider_binding")
		return IdentityClaims{}, ErrIdentityRejected
	}
	if provider.ObservedAt.IsZero() || provider.ObservedAt.After(now.Add(30*time.Second)) ||
		now.Sub(provider.ObservedAt) > maximumIdentityEvidenceAge {
		logIdentityEvidenceRejected("provider_freshness")
		return IdentityClaims{}, ErrIdentityRejected
	}
	if provider.Tags["dirextalk:account_generation"] != strconv.FormatUint(record.AccountGeneration, 10) {
		logIdentityEvidenceRejected("account_generation_tag")
		return IdentityClaims{}, ErrIdentityRejected
	}
	for key, value := range record.RequiredTags {
		if provider.Tags[key] != value {
			logIdentityEvidenceRejected("required_tags")
			return IdentityClaims{}, ErrIdentityRejected
		}
	}
	tags := make(map[string]string, len(provider.Tags))
	for key, value := range provider.Tags {
		tags[key] = value
	}
	return IdentityClaims{
		AccountGeneration: record.AccountGeneration,
		AccountID:         record.AccountID, Region: record.Region,
		InstanceID: record.InstanceID, LaunchIdentity: record.LaunchIdentity,
		RoleARN: record.RoleARN, RoleID: record.RoleID, InstanceProfileID: record.InstanceProfileID, Tags: tags,
	}, nil
}

func logIdentityEvidenceRejected(stage string) {
	slog.Warn("[cloud-worker.identity] evidence_rejected", "stage", stage)
}

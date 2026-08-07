package control

import (
	"context"
	"errors"
	"testing"
	"time"
)

type identityEvidenceLedgerFake struct {
	record DispatchIdentityRecord
	err    error
}

func (fake identityEvidenceLedgerFake) LookupWorkerIdentity(context.Context, string, string, string) (DispatchIdentityRecord, error) {
	return fake.record, fake.err
}

type identityEvidenceProviderFake struct {
	record ProviderInstanceIdentity
	err    error
}

func (fake identityEvidenceProviderFake) ReadWorkerIdentity(context.Context, string, string, string, string) (ProviderInstanceIdentity, error) {
	return fake.record, fake.err
}

func TestIdentityEvidenceBindsSTSRolePrefixAndInstanceProfileID(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	tags := map[string]string{"dirextalk:account_generation": "7", "dirextalk:execution_id": "execution-1"}
	record := DispatchIdentityRecord{
		OwnerID: "owner-1", AccountGeneration: 7, AccountID: "123456789012", Region: "us-east-1", ProviderID: "credential:11111111-1111-4111-8111-111111111111:revision:3",
		InstanceID: "i-0123456789abcdef0", LaunchIdentity: "launch-identity-1",
		RoleARN: "arn:aws:iam::123456789012:role/dirextalk-worker", RoleID: "AROA1234567890ABCDEFG",
		InstanceProfileID: "AIPA1234567890ABCDEFG", RequiredTags: tags,
	}
	provider := ProviderInstanceIdentity{
		Exists: true, AccountID: record.AccountID, Region: record.Region, InstanceID: record.InstanceID,
		LaunchIdentity: record.LaunchIdentity, RoleARN: record.RoleARN, RoleID: record.RoleID,
		InstanceProfileID: record.InstanceProfileID, LaunchTime: now.Add(-time.Minute), Tags: tags, ObservedAt: now,
	}
	reader, err := NewRevalidatingIdentityEvidenceReader(identityEvidenceLedgerFake{record: record}, identityEvidenceProviderFake{record: provider}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	attested := AttestedInstance{AccountID: record.AccountID, Region: record.Region, InstanceID: record.InstanceID,
		RoleARN: record.RoleARN, RoleID: record.RoleID, PendingTime: provider.LaunchTime}
	claims, err := reader.ReadIdentityEvidence(context.Background(), attested)
	if err != nil || claims.RoleID != record.RoleID || claims.InstanceProfileID != record.InstanceProfileID {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}

	t.Run("STS UserId role prefix differs from ledger RoleId", func(t *testing.T) {
		drifted := attested
		drifted.RoleID = "AROAQRSTUVWXYZ1234567"
		if _, err := reader.ReadIdentityEvidence(context.Background(), drifted); !errors.Is(err, ErrIdentityRejected) {
			t.Fatalf("role prefix drift accepted: %v", err)
		}
	})
	t.Run("same-name instance profile replacement", func(t *testing.T) {
		drifted := provider
		drifted.InstanceProfileID = "AIPAQRSTUVWXYZ1234567"
		replacementReader, _ := NewRevalidatingIdentityEvidenceReader(identityEvidenceLedgerFake{record: record}, identityEvidenceProviderFake{record: drifted}, func() time.Time { return now })
		if _, err := replacementReader.ReadIdentityEvidence(context.Background(), attested); !errors.Is(err, ErrIdentityRejected) {
			t.Fatalf("profile replacement accepted: %v", err)
		}
	})
}

func TestParseSTSRoleReturnsImmutableRolePrefix(t *testing.T) {
	document := instanceIdentityDocument{AccountID: "123456789012", Region: "us-east-1", InstanceID: "i-0123456789abcdef0"}
	roleARN, roleID, err := parseSTSRole(stsIdentityResponse{
		Account: document.AccountID,
		ARN:     "arn:aws:sts::123456789012:assumed-role/dirextalk-worker/" + document.InstanceID,
		UserID:  "AROA1234567890ABCDEFG:" + document.InstanceID,
	}, document)
	if err != nil || roleARN != "arn:aws:iam::123456789012:role/dirextalk-worker" || roleID != "AROA1234567890ABCDEFG" {
		t.Fatalf("role ARN=%q role ID=%q err=%v", roleARN, roleID, err)
	}
}

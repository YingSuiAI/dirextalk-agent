package aws

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
)

var workerInstanceIDPattern = regexp.MustCompile(`^i-[0-9a-f]{8,32}$`)

const lookupWorkerIdentitySQL = `SELECT record_json
    FROM core_cloud_worker_aws_ledger
    WHERE account_id=$1 AND region=$2 AND state='active'
      AND record_json #>> '{resources,ec2,provider_id}' = $3
    ORDER BY identity_key
    LIMIT 2`

// LookupWorkerIdentity resolves an instance only through the immutable active
// dispatch ledger. An EC2 name/tag search is not an owner authorization
// boundary and cannot manufacture a WorkerControl expectation.
func (ledger *PostgresLedger) LookupWorkerIdentity(ctx context.Context, accountID, region, instanceID string) (control.DispatchIdentityRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || !accountPattern.MatchString(accountID) ||
		!regionPattern.MatchString(region) || !workerInstanceIDPattern.MatchString(instanceID) {
		return control.DispatchIdentityRecord{}, ErrInvalid
	}
	rows, err := ledger.db.Query(ctx, lookupWorkerIdentitySQL, accountID, region, instanceID)
	if err != nil {
		return control.DispatchIdentityRecord{}, errors.Join(ErrCloudReadback, err)
	}
	defer rows.Close()
	var records []LedgerRecord
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return control.DispatchIdentityRecord{}, errors.Join(ErrCloudReadback, err)
		}
		record, err := decodeLedgerRecord(encoded)
		if err != nil {
			return control.DispatchIdentityRecord{}, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return control.DispatchIdentityRecord{}, errors.Join(ErrCloudReadback, err)
	}
	if len(records) == 0 {
		return control.DispatchIdentityRecord{}, ErrNotFound
	}
	if len(records) != 1 {
		return control.DispatchIdentityRecord{}, ErrConflict
	}
	return workerIdentityFromRecord(records[0], accountID, region, instanceID)
}

func (ledger *MemoryLedger) LookupWorkerIdentity(_ context.Context, accountID, region, instanceID string) (control.DispatchIdentityRecord, error) {
	if ledger == nil || !accountPattern.MatchString(accountID) || !regionPattern.MatchString(region) || !workerInstanceIDPattern.MatchString(instanceID) {
		return control.DispatchIdentityRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	var matched *LedgerRecord
	for _, value := range ledger.records {
		record := value.clone()
		instance := record.Resources[ResourceEC2]
		if record.Identity.AccountID != accountID || record.Identity.Region != region || record.State != LifecycleActive || instance.ProviderID != instanceID {
			continue
		}
		if matched != nil {
			return control.DispatchIdentityRecord{}, ErrConflict
		}
		matched = &record
	}
	if matched == nil {
		return control.DispatchIdentityRecord{}, ErrNotFound
	}
	return workerIdentityFromRecord(*matched, accountID, region, instanceID)
}

func workerIdentityFromRecord(record LedgerRecord, accountID, region, instanceID string) (control.DispatchIdentityRecord, error) {
	instance := record.Resources[ResourceEC2]
	role := record.Resources[ResourceIAMRole]
	profile := record.Resources[ResourceInstanceProfile]
	requiredTags := RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest)
	if record.Validate() != nil || record.State != LifecycleActive || record.Identity.AccountID != accountID || record.Identity.Region != region ||
		instance.ProviderID != instanceID || instance.State != ResourceActive || !instance.Observation.Exists ||
		instance.Observation.ProviderID != instanceID || instance.Observation.LaunchIdentity != record.Identity.LaunchIdentity ||
		instance.Observation.Generation != record.Identity.Generation ||
		role.State != ResourceActive || !validIAMImmutableID(role.ProviderID) || !role.Observation.Exists ||
		role.Observation.ProviderID != role.ProviderID || role.Observation.LaunchIdentity != record.Identity.LaunchIdentity ||
		role.Observation.Generation != record.Identity.Generation || !containsTags(instance.Observation.Tags, requiredTags) ||
		!containsTags(role.Observation.Tags, requiredTags) || profile.State != ResourceActive ||
		profile.IdentityState != ResourceIdentityVerified || !validIAMImmutableID(profile.ProviderID) ||
		!profile.Observation.Exists || profile.Observation.ProviderID != profile.ProviderID ||
		profile.Observation.LaunchIdentity != record.Identity.LaunchIdentity || profile.Observation.Generation != record.Identity.Generation ||
		!containsTags(profile.Observation.Tags, requiredTags) {
		return control.DispatchIdentityRecord{}, ErrIdentityMismatch
	}
	return control.DispatchIdentityRecord{
		OwnerID: record.Identity.OwnerID, AccountGeneration: record.Identity.AccountGeneration,
		AccountID: accountID, Region: region, ProviderID: record.Identity.ProviderID, InstanceID: instanceID,
		LaunchIdentity: record.Identity.LaunchIdentity, RoleARN: workerRoleARN(record.Plan),
		RoleID: role.ProviderID, InstanceProfileID: profile.ProviderID,
		RequiredTags: cloneMap(requiredTags),
	}, nil
}

func workerRoleARN(plan Plan) string {
	partition := "aws"
	if strings.HasPrefix(plan.Identity.Region, "cn-") {
		partition = "aws-cn"
	} else if strings.HasPrefix(plan.Identity.Region, "us-gov-") {
		partition = "aws-us-gov"
	}
	return "arn:" + partition + ":iam::" + plan.Identity.AccountID + ":role/" + plan.IAMRoleName
}

var _ control.DispatchIdentityLedger = (*PostgresLedger)(nil)
var _ control.DispatchIdentityLedger = (*MemoryLedger)(nil)

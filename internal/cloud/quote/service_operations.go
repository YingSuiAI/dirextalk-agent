package quote

import (
	"fmt"
	"sort"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

// PrivateEndpointServiceV1 is deliberately a closed server-owned allowlist.
// The runtime derives the regional AWS service name; callers never submit it.
type PrivateEndpointServiceV1 string

const (
	PrivateEndpointServiceS3 PrivateEndpointServiceV1 = "s3"
)

type EndpointSecurityGroupSourceV1 string

const (
	EndpointSecurityGroupPlanExisting    EndpointSecurityGroupSourceV1 = "plan_existing"
	EndpointSecurityGroupWorkerDedicated EndpointSecurityGroupSourceV1 = "worker_dedicated"
)

type SnapshotOperationDispositionV1 string

const (
	SnapshotDeleteWithDeployment     SnapshotOperationDispositionV1 = "delete_with_deployment"
	SnapshotRetainWithManagedService SnapshotOperationDispositionV1 = "retain_with_managed_service"
)

// ServiceOperationScopeV1 contains only templates that must already be visible
// to, priced for, and signed by the owner device. Runtime code resolves current
// resource facts later and must not accept raw provider IDs from a caller.
type ServiceOperationScopeV1 struct {
	PrivateEndpoints []PrivateEndpointOperationSpecV1 `json:"private_endpoints,omitempty"`
	Snapshots        []SnapshotOperationSpecV1        `json:"snapshots,omitempty"`
}

type PrivateEndpointOperationSpecV1 struct {
	OperationKey        string                        `json:"operation_key"`
	Service             PrivateEndpointServiceV1      `json:"service"`
	SecurityGroupSource EndpointSecurityGroupSourceV1 `json:"security_group_source"`
	PrivateDNSEnabled   bool                          `json:"private_dns_enabled"`
	MonthlyHours        uint32                        `json:"monthly_hours"`
	DataMiBPerMonth     uint64                        `json:"data_mib_per_month"`
}

type SnapshotOperationSpecV1 struct {
	OperationKey           string                         `json:"operation_key"`
	SourceVolumeSlotID     string                         `json:"source_volume_slot_id"`
	SourceVolumeSpecDigest string                         `json:"source_volume_spec_digest"`
	Disposition            SnapshotOperationDispositionV1 `json:"disposition"`
	MaxRetentionSeconds    uint64                         `json:"max_retention_seconds"`
}

func (s ServiceOperationScopeV1) Empty() bool {
	return len(s.PrivateEndpoints) == 0 && len(s.Snapshots) == 0
}

// VolumeScopeDigest binds a snapshot template to the exact approved logical
// volume shape, rather than a future AWS vol-* identifier.
func VolumeScopeDigest(value VolumeScopeV1) (string, error) {
	if err := ValidateVolumeScopes([]VolumeScopeV1{value}); err != nil {
		return "", err
	}
	return canonical.Digest(struct {
		SchemaVersion string        `json:"schema_version"`
		Volume        VolumeScopeV1 `json:"volume"`
	}{SchemaVersion: "dirextalk.agent.cloud.volume-scope/v1", Volume: value})
}

// ValidateServiceOperations validates the v2-only templates in the context of
// their enclosing approved scope. It is exported so Plan validation can use
// exactly the same closed rules without duplicating business policy.
func ValidateServiceOperations(value ServiceOperationScopeV1, resource ResourceScopeV1, network NetworkScopeV1, retention RetentionScopeV1) error {
	if value.Empty() {
		return fmt.Errorf("service_operations must declare at least one operation")
	}
	if len(value.PrivateEndpoints) > 4 || len(value.Snapshots) > len(resource.VolumeScopes) || len(value.PrivateEndpoints)+len(value.Snapshots) > 16 {
		return fmt.Errorf("service_operations exceed the supported operation budget")
	}
	seenKeys := make(map[string]struct{}, len(value.PrivateEndpoints)+len(value.Snapshots))
	for index, endpoint := range value.PrivateEndpoints {
		name := fmt.Sprintf("service_operations.private_endpoints[%d]", index)
		if err := validateIdentifier(name+".operation_key", endpoint.OperationKey); err != nil {
			return err
		}
		if _, exists := seenKeys[endpoint.OperationKey]; exists {
			return fmt.Errorf("service_operations contain duplicate operation keys")
		}
		seenKeys[endpoint.OperationKey] = struct{}{}
		if endpoint.Service != PrivateEndpointServiceS3 {
			return fmt.Errorf("%s.service is not in the approved endpoint allowlist", name)
		}
		switch endpoint.SecurityGroupSource {
		case EndpointSecurityGroupPlanExisting:
			if normalizedSecurityGroupMode(network) != SecurityGroupExisting || network.SecurityGroupID == "" {
				return fmt.Errorf("%s.security_group_source requires the exact plan existing security group", name)
			}
		case EndpointSecurityGroupWorkerDedicated:
			if normalizedSecurityGroupMode(network) != SecurityGroupCreateDedicated || network.SecurityGroupID != "" {
				return fmt.Errorf("%s.security_group_source requires the plan worker dedicated security group", name)
			}
		default:
			return fmt.Errorf("%s.security_group_source is invalid", name)
		}
		if endpoint.MonthlyHours == 0 || endpoint.MonthlyHours > 744 || endpoint.DataMiBPerMonth > 1<<50 {
			return fmt.Errorf("%s usage assumptions are invalid", name)
		}
	}
	slots := make(map[string]VolumeScopeV1, len(resource.VolumeScopes))
	for _, slot := range resource.VolumeScopes {
		slots[slot.SlotID] = slot
	}
	seenSnapshotSlots := make(map[string]struct{}, len(value.Snapshots))
	for index, snapshot := range value.Snapshots {
		name := fmt.Sprintf("service_operations.snapshots[%d]", index)
		if err := validateIdentifier(name+".operation_key", snapshot.OperationKey); err != nil {
			return err
		}
		if _, exists := seenKeys[snapshot.OperationKey]; exists {
			return fmt.Errorf("service_operations contain duplicate operation keys")
		}
		seenKeys[snapshot.OperationKey] = struct{}{}
		slot, exists := slots[snapshot.SourceVolumeSlotID]
		if !exists || !slot.Persistent {
			return fmt.Errorf("%s.source_volume_slot_id must identify a persistent approved volume", name)
		}
		if _, duplicate := seenSnapshotSlots[snapshot.SourceVolumeSlotID]; duplicate {
			return fmt.Errorf("service_operations contain duplicate snapshot source volumes")
		}
		seenSnapshotSlots[snapshot.SourceVolumeSlotID] = struct{}{}
		expectedDigest, err := VolumeScopeDigest(slot)
		if err != nil || snapshot.SourceVolumeSpecDigest != expectedDigest {
			return fmt.Errorf("%s.source_volume_spec_digest does not bind the approved volume", name)
		}
		switch retention.Class {
		case RetentionEphemeral:
			if slot.Disposition != VolumeDeleteWithDeployment || snapshot.Disposition != SnapshotDeleteWithDeployment || snapshot.MaxRetentionSeconds != retention.MaxLifetimeSeconds {
				return fmt.Errorf("%s must inherit the ephemeral deployment deletion deadline", name)
			}
		case RetentionManaged:
			if slot.Disposition != VolumeRetainWithManagedService || snapshot.Disposition != SnapshotRetainWithManagedService || snapshot.MaxRetentionSeconds == 0 || snapshot.MaxRetentionSeconds > 365*24*60*60 {
				return fmt.Errorf("%s managed retention is invalid or unbounded", name)
			}
		default:
			return fmt.Errorf("%s has an invalid plan retention scope", name)
		}
	}
	return nil
}

func validateServiceOperationUsage(scope *ServiceOperationScopeV1, resource ResourceScopeV1, usage UsageV1) error {
	if scope == nil {
		return fmt.Errorf("service_operations are required")
	}
	var expectedHours uint64
	var expectedData uint64
	for _, endpoint := range scope.PrivateEndpoints {
		var ok bool
		if expectedHours, ok = checkedAdd(expectedHours, uint64(endpoint.MonthlyHours)); !ok {
			return fmt.Errorf("private endpoint hourly usage overflows")
		}
		if expectedData, ok = checkedAdd(expectedData, endpoint.DataMiBPerMonth); !ok {
			return fmt.Errorf("private endpoint data usage overflows")
		}
	}
	if expectedHours > 1<<32-1 || usage.PrivateEndpointHours != uint32(expectedHours) || usage.PrivateEndpointDataMiB != expectedData {
		return fmt.Errorf("private endpoint usage does not match the signed service operation scope")
	}
	slots := make(map[string]VolumeScopeV1, len(resource.VolumeScopes))
	for _, slot := range resource.VolumeScopes {
		slots[slot.SlotID] = slot
	}
	const secondsPerThirtyDayMonth = uint64(30 * 24 * 60 * 60)
	var expectedSnapshotGiBMonths uint64
	for _, snapshot := range scope.Snapshots {
		slot := slots[snapshot.SourceVolumeSlotID]
		units := uint64(slot.SizeGiB) * snapshot.MaxRetentionSeconds
		months := units / secondsPerThirtyDayMonth
		if units%secondsPerThirtyDayMonth != 0 {
			months++
		}
		var ok bool
		if expectedSnapshotGiBMonths, ok = checkedAdd(expectedSnapshotGiBMonths, months); !ok {
			return fmt.Errorf("snapshot usage overflows")
		}
	}
	if usage.SnapshotGiBMonths != expectedSnapshotGiBMonths {
		return fmt.Errorf("snapshot usage does not match the signed service operation scope")
	}
	return nil
}

// NormalizeServiceOperations returns the deterministic public ordering used by
// every scope digest and device-signing projection.
func NormalizeServiceOperations(value *ServiceOperationScopeV1) *ServiceOperationScopeV1 {
	if value == nil {
		return nil
	}
	copy := *value
	copy.PrivateEndpoints = append([]PrivateEndpointOperationSpecV1(nil), value.PrivateEndpoints...)
	copy.Snapshots = append([]SnapshotOperationSpecV1(nil), value.Snapshots...)
	sort.Slice(copy.PrivateEndpoints, func(i, j int) bool {
		return copy.PrivateEndpoints[i].OperationKey < copy.PrivateEndpoints[j].OperationKey
	})
	sort.Slice(copy.Snapshots, func(i, j int) bool { return copy.Snapshots[i].OperationKey < copy.Snapshots[j].OperationKey })
	return &copy
}

// PrivateEndpointServiceName derives the only provider-facing name supported
// by the v2 contract. Region validation belongs to the enclosing scope.
func PrivateEndpointServiceName(region string, service PrivateEndpointServiceV1) (string, error) {
	if !regionPattern.MatchString(region) || service != PrivateEndpointServiceS3 {
		return "", fmt.Errorf("private endpoint service scope is invalid")
	}
	return "com.amazonaws." + region + ".s3", nil
}

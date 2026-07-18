package approval

import (
	"testing"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
)

func TestPlanV2ServiceOperationsBindHashAndApproval(t *testing.T) {
	plan := serviceOperationPlan(t)
	baselineHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}

	reordered := cloneServiceOperationPlan(plan)
	reordered.ServiceOperations.PrivateEndpoints[0], reordered.ServiceOperations.PrivateEndpoints[1] =
		reordered.ServiceOperations.PrivateEndpoints[1], reordered.ServiceOperations.PrivateEndpoints[0]
	if err := refreshServiceOperationScopeDigest(&reordered); err != nil {
		t.Fatal(err)
	}
	reorderedHash, err := reordered.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if reorderedHash != baselineHash {
		t.Fatal("service operation ordering changed the V2 Plan hash")
	}

	drifted := cloneServiceOperationPlan(plan)
	drifted.ServiceOperations.PrivateEndpoints[0].DataMiBPerMonth++
	if err := refreshServiceOperationScopeDigest(&drifted); err != nil {
		t.Fatal(err)
	}
	driftedHash, err := drifted.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if driftedHash == baselineHash {
		t.Fatal("private endpoint cost input did not change the V2 Plan hash")
	}

	approval, err := NewApprovalV1(plan, "approval-v2", "challenge-v2", "device-key-v2", plan.Quote.ValidUntil.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if approval.SchemaVersion != ApprovalSchemaV2 || approval.ServiceOperations == nil {
		t.Fatalf("approval omitted V2 service operation scope: %+v", approval)
	}
	payload, err := approval.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	changedApproval := approval
	changedApproval.ServiceOperations = cloudquote.NormalizeServiceOperations(&ServiceOperationScopeV1{
		PrivateEndpoints: []PrivateEndpointOperationSpecV1{
			approval.ServiceOperations.PrivateEndpoints[0], approval.ServiceOperations.PrivateEndpoints[1],
		},
		Snapshots: append([]SnapshotOperationSpecV1(nil), approval.ServiceOperations.Snapshots...),
	})
	changedApproval.ServiceOperations.Snapshots[0].MaxRetentionSeconds++
	if _, err := changedApproval.SigningPayload(); err == nil {
		t.Fatal("approval accepted a snapshot deadline that no longer matches the Plan retention")
	}
	changedApproval = approval
	changedApproval.ServiceOperations = cloudquote.NormalizeServiceOperations(&ServiceOperationScopeV1{
		PrivateEndpoints: append([]PrivateEndpointOperationSpecV1(nil), approval.ServiceOperations.PrivateEndpoints...),
		Snapshots:        append([]SnapshotOperationSpecV1(nil), approval.ServiceOperations.Snapshots...),
	})
	changedApproval.ServiceOperations.PrivateEndpoints[0].DataMiBPerMonth++
	changedPayload, err := changedApproval.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	if string(changedPayload) == string(payload) {
		t.Fatal("private endpoint scope drift did not change the device signing payload")
	}
	if err := approval.ValidateAgainstPlan(drifted, plan.Quote.ValidUntil.Add(-time.Minute)); err == nil {
		t.Fatal("approval accepted Plan V2 service-operation drift")
	}
}

func TestPlanV1RejectsServiceOperationFields(t *testing.T) {
	plan := validPlan()
	plan.ServiceOperations = &ServiceOperationScopeV1{}
	if err := plan.Validate(); err == nil {
		t.Fatal("legacy PlanV1 accepted an added service_operations field")
	}
}

func TestPrivateNetworkFactsChangePlanHashAndSigningPayload(t *testing.T) {
	plan := validPlan()
	plan.SchemaVersion = PlanSchemaV2
	plan.NetworkScope = NetworkScopeV1{
		VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
		SecurityGroupMode: SecurityGroupCreateDedicated, EntryPoint: EntryPointNone,
		RouteTableID: "rtb-0123456789abcdef0", ControlPlaneEndpoint: "grpcs://agent.example.com:443",
		PrivateConnectivity: PrivateConnectivityNoNATEndpointsV1,
	}
	plan.ServiceOperations = &ServiceOperationScopeV1{PrivateEndpoints: []PrivateEndpointOperationSpecV1{
		{OperationKey: "worker-s3-gateway", Service: PrivateEndpointServiceS3, EndpointType: PrivateEndpointTypeGateway},
		{OperationKey: "worker-secretsmanager-interface", Service: PrivateEndpointServiceSecretsManager, EndpointType: PrivateEndpointTypeInterface,
			SecurityGroupSource: EndpointSecurityGroupEndpointDedicatedFromWorker, PrivateDNSEnabled: true, MonthlyHours: 730, DataMiBPerMonth: 1},
	}}
	if err := refreshServiceOperationScopeDigest(&plan); err != nil {
		t.Fatal(err)
	}
	baselineHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := NewApprovalV1(plan, "approval-private", "challenge-private", "device-private", plan.Quote.ValidUntil.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	baselinePayload, err := approval.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}

	drifted := cloneServiceOperationPlan(plan)
	drifted.NetworkScope.RouteTableID = "rtb-0bbbbbbbbbbbbbbbb"
	if err := refreshServiceOperationScopeDigest(&drifted); err != nil {
		t.Fatal(err)
	}
	driftedHash, err := drifted.Hash()
	if err != nil || driftedHash == baselineHash {
		t.Fatalf("route table drift hash=%q baseline=%q err=%v", driftedHash, baselineHash, err)
	}
	driftedApproval, err := NewApprovalV1(drifted, "approval-private", "challenge-private", "device-private", drifted.Quote.ValidUntil.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	driftedPayload, err := driftedApproval.SigningPayload()
	if err != nil || string(driftedPayload) == string(baselinePayload) {
		t.Fatal("route table drift did not change the device signing payload")
	}
}

func serviceOperationPlan(t *testing.T) PlanV1 {
	t.Helper()
	plan := validPlan()
	plan.SchemaVersion = PlanSchemaV2
	plan.ResourceScope.AvailabilityZones = []string{"us-east-1a"}
	plan.ResourceScope.VolumeScopes = []VolumeScopeV1{{
		SlotID: "data", SizeGiB: 30, VolumeType: "gp3", IOPS: 3000, ThroughputMiBPS: 125,
		Encrypted: true, KMSKeyID: "alias/dirextalk/data", DeviceName: "/dev/sdf", MountPath: "/srv/data",
		Persistent: true, Disposition: VolumeDeleteWithDeployment,
	}}
	specDigest, err := cloudquote.VolumeScopeDigest(plan.ResourceScope.VolumeScopes[0])
	if err != nil {
		t.Fatal(err)
	}
	plan.ServiceOperations = &ServiceOperationScopeV1{
		PrivateEndpoints: []PrivateEndpointOperationSpecV1{
			{OperationKey: "endpoint-b", Service: PrivateEndpointServiceS3, SecurityGroupSource: EndpointSecurityGroupPlanExisting, PrivateDNSEnabled: true, MonthlyHours: 700, DataMiBPerMonth: 12},
			{OperationKey: "endpoint-a", Service: PrivateEndpointServiceS3, SecurityGroupSource: EndpointSecurityGroupPlanExisting, PrivateDNSEnabled: true, MonthlyHours: 720, DataMiBPerMonth: 24},
		},
		Snapshots: []SnapshotOperationSpecV1{{
			OperationKey: "snapshot-data", SourceVolumeSlotID: "data", SourceVolumeSpecDigest: specDigest,
			Disposition: SnapshotDeleteWithDeployment, MaxRetentionSeconds: plan.RetentionScope.MaxLifetimeSeconds,
		}},
	}
	if err := refreshServiceOperationScopeDigest(&plan); err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	return plan
}

func cloneServiceOperationPlan(value PlanV1) PlanV1 {
	copy := value
	copy.ResourceScope.AvailabilityZones = append([]string(nil), value.ResourceScope.AvailabilityZones...)
	copy.ResourceScope.VolumeScopes = append([]VolumeScopeV1(nil), value.ResourceScope.VolumeScopes...)
	copy.ServiceOperations = cloudquote.NormalizeServiceOperations(value.ServiceOperations)
	return copy
}

func refreshServiceOperationScopeDigest(value *PlanV1) error {
	digest, err := value.PricingScopeDigest()
	if err != nil {
		return err
	}
	value.Quote.ScopeDigest = digest
	return nil
}

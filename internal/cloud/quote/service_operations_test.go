package quote

import (
	"testing"
)

func TestServiceOperationScopeRequiresExactUsageAndEndpointCost(t *testing.T) {
	request := quoteRequest(t, quoteRecipe(t), PurchaseOnDemand)
	for index := range request.Scopes {
		scope := &request.Scopes[index]
		scope.SchemaVersion = ScopeSchemaV2
		scope.Resource.AvailabilityZones = []string{"us-east-1a"}
		scope.Resource.VolumeScopes = []VolumeScopeV1{{
			SlotID: "data", SizeGiB: 30, VolumeType: "gp3", IOPS: 3000, ThroughputMiBPS: 125,
			Encrypted: true, KMSKeyID: "alias/dirextalk/data", DeviceName: "/dev/sdf", MountPath: "/srv/data",
			Persistent: true, Disposition: VolumeDeleteWithDeployment,
		}}
		specDigest, err := VolumeScopeDigest(scope.Resource.VolumeScopes[0])
		if err != nil {
			t.Fatal(err)
		}
		scope.ServiceOperations = &ServiceOperationScopeV1{
			PrivateEndpoints: []PrivateEndpointOperationSpecV1{{
				OperationKey: "endpoint-s3", Service: PrivateEndpointServiceS3,
				SecurityGroupSource: EndpointSecurityGroupPlanExisting, PrivateDNSEnabled: true,
				MonthlyHours: 720, DataMiBPerMonth: 96,
			}},
			Snapshots: []SnapshotOperationSpecV1{{
				OperationKey: "snapshot-data", SourceVolumeSlotID: "data", SourceVolumeSpecDigest: specDigest,
				Disposition: SnapshotDeleteWithDeployment, MaxRetentionSeconds: scope.Retention.MaxLifetimeSeconds,
			}},
		}
	}
	request.Usage.SnapshotGiBMonths = 1
	request.Usage.PrivateEndpointHours = 720
	request.Usage.PrivateEndpointDataMiB = 96
	if err := request.Validate(); err != nil {
		t.Fatalf("valid V2 service operation quote request: %v", err)
	}

	legacySecrets := request
	legacySecrets.Scopes = append([]ScopeV1(nil), request.Scopes...)
	for index := range legacySecrets.Scopes {
		operations := *request.Scopes[index].ServiceOperations
		operations.PrivateEndpoints = append([]PrivateEndpointOperationSpecV1(nil), operations.PrivateEndpoints...)
		operations.PrivateEndpoints[0].Service = PrivateEndpointServiceSecretsManager
		legacySecrets.Scopes[index].ServiceOperations = &operations
	}
	if err := legacySecrets.Validate(); err == nil {
		t.Fatal("legacy omitted endpoint type accepted a non-S3 Interface service")
	}

	wrongUsage := request
	wrongUsage.Usage.PrivateEndpointDataMiB++
	if err := wrongUsage.Validate(); err == nil {
		t.Fatal("request accepted endpoint data usage that differs from its signed scope")
	}

	candidate := CandidateV1{CandidateID: CandidateEconomic, Scope: request.Scopes[0], Quotas: []QuotaEvidenceV1{{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 2, RequiredUnits: 1}}}
	candidate.CostItems = []CostItemV1{
		costItem(CostComputeOnDemand, "compute", "compute", 1, 1, 1),
		costItem(CostEBS, "ebs", "ebs", 1, 1, 1),
		costItem(CostPublicIPv4, "ipv4", "ipv4", 0, 0, 0),
		costItem(CostLogs, "logs", "logs", 0, 0, 0),
		costItem(CostSnapshot, "snapshot", "snapshot", 0, 0, 0),
		costItem(CostEntry, "entry", "entry", 0, 0, 0),
		costItem(CostTraffic, "traffic", "traffic", 0, 0, 0),
	}
	if err := validateCosts(candidate); err == nil {
		t.Fatal("endpoint scope did not require an explicit PrivateLink cost item")
	}
	candidate.CostItems = append(candidate.CostItems, costItem(CostPrivateEndpoint, "PrivateLink endpoint", "private-link", 1, 1, 1))
	candidate.HourlyEstimateMicros, candidate.MonthlyEstimateMicros, candidate.MaximumLaunchAmountMicros = 3, 3, 3
	if err := validateCosts(candidate); err != nil {
		t.Fatalf("endpoint cost item was rejected: %v", err)
	}
}

func TestNoNATServiceOperationsBindExactGatewayAndSecretsInterfaceUsage(t *testing.T) {
	request := quoteRequest(t, quoteRecipe(t), PurchaseOnDemand)
	for index := range request.Scopes {
		scope := &request.Scopes[index]
		scope.SchemaVersion = ScopeSchemaV2
		scope.Network = NetworkScopeV1{
			VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
			SecurityGroupMode: SecurityGroupCreateDedicated, EntryPoint: EntryPointNone,
			RouteTableID: "rtb-0123456789abcdef0", ControlPlaneEndpoint: "grpcs://agent.example.com:443",
			PrivateConnectivity: PrivateConnectivityNoNATEndpointsV1,
		}
		scope.ServiceOperations = &ServiceOperationScopeV1{PrivateEndpoints: []PrivateEndpointOperationSpecV1{
			{OperationKey: "worker-s3-gateway", Service: PrivateEndpointServiceS3, EndpointType: PrivateEndpointTypeGateway},
			{OperationKey: "worker-secretsmanager-interface", Service: PrivateEndpointServiceSecretsManager, EndpointType: PrivateEndpointTypeInterface,
				SecurityGroupSource: EndpointSecurityGroupEndpointDedicatedFromWorker, PrivateDNSEnabled: true, MonthlyHours: 730, DataMiBPerMonth: 1},
		}}
	}
	request.Usage.PrivateEndpointHours = 730
	request.Usage.PrivateEndpointDataMiB = 1
	request.Usage.SnapshotGiBMonths = 0
	if err := request.Validate(); err != nil {
		t.Fatalf("valid no-NAT endpoint request: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*RequestV1)
	}{
		{name: "route table", mutate: func(value *RequestV1) { value.Scopes[0].Network.RouteTableID = "" }},
		{name: "control port", mutate: func(value *RequestV1) {
			value.Scopes[0].Network.ControlPlaneEndpoint = "grpcs://agent.example.com:7443"
		}},
		{name: "gateway usage", mutate: func(value *RequestV1) { value.Scopes[0].ServiceOperations.PrivateEndpoints[0].MonthlyHours = 1 }},
		{name: "interface service", mutate: func(value *RequestV1) {
			value.Scopes[0].ServiceOperations.PrivateEndpoints[1].Service = PrivateEndpointServiceS3
		}},
		{name: "usage sum", mutate: func(value *RequestV1) { value.Usage.PrivateEndpointHours++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := request
			copy.Scopes = append([]ScopeV1(nil), request.Scopes...)
			for index := range copy.Scopes {
				operations := *request.Scopes[index].ServiceOperations
				operations.PrivateEndpoints = append([]PrivateEndpointOperationSpecV1(nil), operations.PrivateEndpoints...)
				copy.Scopes[index].ServiceOperations = &operations
			}
			test.mutate(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("drifted no-NAT endpoint request was accepted")
			}
		})
	}
}

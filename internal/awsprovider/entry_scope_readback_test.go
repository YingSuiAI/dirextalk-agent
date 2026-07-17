package awsprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestEntryScopeReadBackBindsOnlyVerifiedPrivateWorkerCertificateAndPublicSubnets(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 17, 9, 30, 0, 0, time.UTC)
	instanceTags := entryReadBackOwnershipTags("11111111-1111-4111-8111-111111111111")
	securityGroupTags := entryReadBackOwnershipTags("22222222-2222-4222-8222-222222222222")
	reader := &entryScopeReadEC2Fake{
		instance:       entryReadBackInstance(instanceTags),
		securityGroups: []ec2types.SecurityGroup{{GroupId: aws.String("sg-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), Tags: ec2Tags(securityGroupTags)}},
		subnets: []ec2types.Subnet{
			{SubnetId: aws.String("subnet-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), AvailabilityZone: aws.String("us-east-1a"), State: ec2types.SubnetStateAvailable},
			{SubnetId: aws.String("subnet-0fedcba9876543210"), VpcId: aws.String("vpc-0123456789abcdef0"), AvailabilityZone: aws.String("us-east-1b"), State: ec2types.SubnetStateAvailable},
		},
		routesBySubnet: map[string][]ec2types.RouteTable{
			"subnet-0123456789abcdef0": {entryReadBackRouteTable("rtb-0123456789abcdef0", "subnet-0123456789abcdef0")},
			"subnet-0fedcba9876543210": {entryReadBackRouteTable("rtb-0fedcba9876543210", "subnet-0fedcba9876543210")},
		},
		gateways: []ec2types.InternetGateway{{
			InternetGatewayId: aws.String("igw-0123456789abcdef0"), Attachments: []ec2types.InternetGatewayAttachment{{
				VpcId: aws.String("vpc-0123456789abcdef0"), State: ec2types.AttachmentStatusAttached,
			}},
		}},
	}
	certificates := &entryScopeReadCertificateFake{certificate: &acmtypes.CertificateDetail{
		CertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		Status:         acmtypes.CertificateStatusIssued,
		SubjectAlternativeNames: []string{
			"*.example.test", "service.example.test",
		},
	}}
	provider := newEntryScopeReadBackProvider(t, now, reader, certificates)

	worker, err := provider.ReadBackEntryWorker(context.Background(), EntryWorkerReadBackRequestV1{
		InstanceID: "i-0123456789abcdef0", ExpectedInstanceTags: instanceTags, ExpectedSecurityGroupTags: securityGroupTags,
	})
	if err != nil {
		t.Fatalf("read back private worker: %v", err)
	}
	if worker.InstanceID != "i-0123456789abcdef0" || worker.VPCID != "vpc-0123456789abcdef0" || worker.SubnetID != "subnet-0123456789abcdef0" ||
		worker.SecurityGroupID != "sg-0123456789abcdef0" || worker.ObservedAt != now || !digestPattern.MatchString(worker.OwnershipDigest) {
		t.Fatalf("worker evidence = %#v", worker)
	}

	certificate, err := provider.ReadBackEntryCertificate(context.Background(), EntryCertificateReadBackRequestV1{
		CertificateARN: aws.ToString(certificates.certificate.CertificateArn), Hostname: "service.example.test",
	})
	if err != nil {
		t.Fatalf("read back issued certificate: %v", err)
	}
	if certificate.Status != EntryCertificateStatusIssued || certificate.Region != "us-east-1" || certificate.Hostname != "service.example.test" ||
		!digestPattern.MatchString(certificate.ReadBackDigest) || certificate.ObservedAt != now || !entryReadBackContainsString(certificate.SubjectAlternativeNames, "service.example.test") {
		t.Fatalf("certificate evidence = %#v", certificate)
	}

	subnets, err := provider.ReadBackEntryPublicSubnets(context.Background(), EntryPublicSubnetsReadBackRequestV1{
		WorkerVPCID: "vpc-0123456789abcdef0", SubnetIDs: []string{"subnet-0fedcba9876543210", "subnet-0123456789abcdef0"},
	})
	if err != nil {
		t.Fatalf("read back public ALB subnets: %v", err)
	}
	if len(subnets) != 2 || subnets[0].SubnetID != "subnet-0123456789abcdef0" || subnets[1].SubnetID != "subnet-0fedcba9876543210" ||
		!subnets[0].Public || !subnets[1].Public || subnets[0].AvailabilityZone == subnets[1].AvailabilityZone ||
		!digestPattern.MatchString(subnets[0].ReadBackDigest) || !digestPattern.MatchString(subnets[1].ReadBackDigest) {
		t.Fatalf("public subnet evidence = %#v", subnets)
	}
	if reader.instanceCalls != 1 || reader.securityGroupCalls != 1 || reader.subnetCalls != 1 || reader.gatewayCalls != 1 || reader.routeCalls != 2 {
		t.Fatalf("unexpected entry read calls: %+v", reader)
	}
}

func TestEntryScopeReadBackFailsClosedForUntrustedOrUnavailableFacts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 17, 9, 30, 0, 0, time.UTC)
	instanceTags := entryReadBackOwnershipTags("11111111-1111-4111-8111-111111111111")
	securityGroupTags := entryReadBackOwnershipTags("22222222-2222-4222-8222-222222222222")
	certificateARN := "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	tests := []struct {
		name string
		run  func(*EC2ResourceProvider) error
		read func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake)
	}{
		{
			name: "worker public IPv4",
			run: func(provider *EC2ResourceProvider) error {
				_, err := provider.ReadBackEntryWorker(context.Background(), EntryWorkerReadBackRequestV1{InstanceID: "i-0123456789abcdef0", ExpectedInstanceTags: instanceTags, ExpectedSecurityGroupTags: securityGroupTags})
				return err
			},
			read: func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake) {
				instance := entryReadBackInstance(instanceTags)
				instance.PublicIpAddress = aws.String("198.51.100.8")
				return entryReadBackReader(instance, securityGroupTags), entryReadBackCertificate(certificateARN, acmtypes.CertificateStatusIssued, "service.example.test")
			},
		},
		{
			name: "worker security group ownership drift",
			run: func(provider *EC2ResourceProvider) error {
				_, err := provider.ReadBackEntryWorker(context.Background(), EntryWorkerReadBackRequestV1{InstanceID: "i-0123456789abcdef0", ExpectedInstanceTags: instanceTags, ExpectedSecurityGroupTags: securityGroupTags})
				return err
			},
			read: func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake) {
				drifted := entryReadBackOwnershipTags("22222222-2222-4222-8222-222222222222")
				drifted[resource.TagOwnerID] = "other-owner"
				return entryReadBackReader(entryReadBackInstance(instanceTags), drifted), entryReadBackCertificate(certificateARN, acmtypes.CertificateStatusIssued, "service.example.test")
			},
		},
		{
			name: "certificate pending validation",
			run: func(provider *EC2ResourceProvider) error {
				_, err := provider.ReadBackEntryCertificate(context.Background(), EntryCertificateReadBackRequestV1{CertificateARN: certificateARN, Hostname: "service.example.test"})
				return err
			},
			read: func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake) {
				return entryReadBackReader(entryReadBackInstance(instanceTags), securityGroupTags), entryReadBackCertificate(certificateARN, acmtypes.CertificateStatusPendingValidation, "service.example.test")
			},
		},
		{
			name: "certificate SAN does not cover approved hostname",
			run: func(provider *EC2ResourceProvider) error {
				_, err := provider.ReadBackEntryCertificate(context.Background(), EntryCertificateReadBackRequestV1{CertificateARN: certificateARN, Hostname: "service.example.test"})
				return err
			},
			read: func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake) {
				return entryReadBackReader(entryReadBackInstance(instanceTags), securityGroupTags), entryReadBackCertificate(certificateARN, acmtypes.CertificateStatusIssued, "other.example.test")
			},
		},
		{
			name: "ALB subnets do not span availability zones",
			run: func(provider *EC2ResourceProvider) error {
				_, err := provider.ReadBackEntryPublicSubnets(context.Background(), EntryPublicSubnetsReadBackRequestV1{WorkerVPCID: "vpc-0123456789abcdef0", SubnetIDs: []string{"subnet-0123456789abcdef0", "subnet-0fedcba9876543210"}})
				return err
			},
			read: func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake) {
				reader := entryReadBackReader(entryReadBackInstance(instanceTags), securityGroupTags)
				reader.subnets[1].AvailabilityZone = aws.String("us-east-1a")
				return reader, entryReadBackCertificate(certificateARN, acmtypes.CertificateStatusIssued, "service.example.test")
			},
		},
		{
			name: "ALB subnet does not have an active internet gateway route",
			run: func(provider *EC2ResourceProvider) error {
				_, err := provider.ReadBackEntryPublicSubnets(context.Background(), EntryPublicSubnetsReadBackRequestV1{WorkerVPCID: "vpc-0123456789abcdef0", SubnetIDs: []string{"subnet-0123456789abcdef0", "subnet-0fedcba9876543210"}})
				return err
			},
			read: func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake) {
				reader := entryReadBackReader(entryReadBackInstance(instanceTags), securityGroupTags)
				reader.routesBySubnet["subnet-0123456789abcdef0"][0].Routes[0].State = ec2types.RouteState("blackhole")
				return reader, entryReadBackCertificate(certificateARN, acmtypes.CertificateStatusIssued, "service.example.test")
			},
		},
		{
			name: "route table is not explicitly associated with the candidate subnet",
			run: func(provider *EC2ResourceProvider) error {
				_, err := provider.ReadBackEntryPublicSubnets(context.Background(), EntryPublicSubnetsReadBackRequestV1{WorkerVPCID: "vpc-0123456789abcdef0", SubnetIDs: []string{"subnet-0123456789abcdef0", "subnet-0fedcba9876543210"}})
				return err
			},
			read: func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake) {
				reader := entryReadBackReader(entryReadBackInstance(instanceTags), securityGroupTags)
				reader.routesBySubnet["subnet-0123456789abcdef0"][0].Associations[0].SubnetId = aws.String("subnet-0fedcba9876543210")
				return reader, entryReadBackCertificate(certificateARN, acmtypes.CertificateStatusIssued, "service.example.test")
			},
		},
		{
			name: "AWS detail is not exposed",
			run: func(provider *EC2ResourceProvider) error {
				_, err := provider.ReadBackEntryWorker(context.Background(), EntryWorkerReadBackRequestV1{InstanceID: "i-0123456789abcdef0", ExpectedInstanceTags: instanceTags, ExpectedSecurityGroupTags: securityGroupTags})
				return err
			},
			read: func() (*entryScopeReadEC2Fake, *entryScopeReadCertificateFake) {
				reader := entryReadBackReader(entryReadBackInstance(instanceTags), securityGroupTags)
				reader.instanceErr = errors.New("SDK detail must not leave the provider")
				return reader, entryReadBackCertificate(certificateARN, acmtypes.CertificateStatusIssued, "service.example.test")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, certificates := test.read()
			provider := newEntryScopeReadBackProvider(t, now, reader, certificates)
			err := test.run(provider)
			if !errors.Is(err, resource.ErrReadBack) || strings.Contains(err.Error(), "SDK detail") {
				t.Fatalf("unsafe read-back error = %v", err)
			}
		})
	}
}

func TestNewEC2ResourceProviderFromConfigEnablesEntryScopeReadBack(t *testing.T) {
	t.Parallel()
	provider, err := NewEC2ResourceProviderFromConfig(aws.Config{
		Region: "us-east-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("example", "example", "")),
	})
	if err != nil || provider.entryReadClient == nil || provider.certificateClient == nil {
		t.Fatalf("from config did not configure entry read-back clients: provider=%#v err=%v", provider, err)
	}
}

func newEntryScopeReadBackProvider(t *testing.T, now time.Time, reader EntryScopeEC2ReadAPI, certificates ACMCertificateAPI) *EC2ResourceProvider {
	t.Helper()
	provider, err := NewEC2ResourceProvider(&entryReadBackBaseEC2{}, "us-east-1", func() time.Time { return now }, WithEntryScopeReadBackClients(reader, certificates))
	if err != nil {
		t.Fatalf("new entry scope read-back provider: %v", err)
	}
	return provider
}

type entryReadBackBaseEC2 struct{ EC2ResourceAPI }

type entryScopeReadEC2Fake struct {
	instance           ec2types.Instance
	instanceErr        error
	securityGroups     []ec2types.SecurityGroup
	securityGroupErr   error
	subnets            []ec2types.Subnet
	subnetErr          error
	routesBySubnet     map[string][]ec2types.RouteTable
	mainRouteTables    []ec2types.RouteTable
	routeErr           error
	gateways           []ec2types.InternetGateway
	gatewayErr         error
	instanceCalls      int
	securityGroupCalls int
	subnetCalls        int
	routeCalls         int
	gatewayCalls       int
}

func (fake *entryScopeReadEC2Fake) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	fake.instanceCalls++
	if fake.instanceErr != nil {
		return nil, fake.instanceErr
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{OwnerId: aws.String("123456789012"), Instances: []ec2types.Instance{fake.instance}}}}, nil
}

func (fake *entryScopeReadEC2Fake) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	fake.securityGroupCalls++
	if fake.securityGroupErr != nil {
		return nil, fake.securityGroupErr
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: append([]ec2types.SecurityGroup(nil), fake.securityGroups...)}, nil
}

func (fake *entryScopeReadEC2Fake) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	fake.subnetCalls++
	if fake.subnetErr != nil {
		return nil, fake.subnetErr
	}
	return &ec2.DescribeSubnetsOutput{Subnets: append([]ec2types.Subnet(nil), fake.subnets...)}, nil
}

func (fake *entryScopeReadEC2Fake) DescribeRouteTables(_ context.Context, input *ec2.DescribeRouteTablesInput, _ ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	fake.routeCalls++
	if fake.routeErr != nil {
		return nil, fake.routeErr
	}
	for _, filter := range input.Filters {
		if aws.ToString(filter.Name) == "association.subnet-id" && len(filter.Values) == 1 {
			return &ec2.DescribeRouteTablesOutput{RouteTables: append([]ec2types.RouteTable(nil), fake.routesBySubnet[filter.Values[0]]...)}, nil
		}
	}
	return &ec2.DescribeRouteTablesOutput{RouteTables: append([]ec2types.RouteTable(nil), fake.mainRouteTables...)}, nil
}

func (fake *entryScopeReadEC2Fake) DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	fake.gatewayCalls++
	if fake.gatewayErr != nil {
		return nil, fake.gatewayErr
	}
	return &ec2.DescribeInternetGatewaysOutput{InternetGateways: append([]ec2types.InternetGateway(nil), fake.gateways...)}, nil
}

type entryScopeReadCertificateFake struct {
	certificate *acmtypes.CertificateDetail
	err         error
}

func (fake *entryScopeReadCertificateFake) DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	if fake.err != nil {
		return nil, fake.err
	}
	return &acm.DescribeCertificateOutput{Certificate: fake.certificate}, nil
}

func entryReadBackReader(instance ec2types.Instance, securityGroupTags map[string]string) *entryScopeReadEC2Fake {
	return &entryScopeReadEC2Fake{
		instance:       instance,
		securityGroups: []ec2types.SecurityGroup{{GroupId: aws.String("sg-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), Tags: ec2Tags(securityGroupTags)}},
		subnets: []ec2types.Subnet{
			{SubnetId: aws.String("subnet-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), AvailabilityZone: aws.String("us-east-1a"), State: ec2types.SubnetStateAvailable},
			{SubnetId: aws.String("subnet-0fedcba9876543210"), VpcId: aws.String("vpc-0123456789abcdef0"), AvailabilityZone: aws.String("us-east-1b"), State: ec2types.SubnetStateAvailable},
		},
		routesBySubnet: map[string][]ec2types.RouteTable{
			"subnet-0123456789abcdef0": {entryReadBackRouteTable("rtb-0123456789abcdef0", "subnet-0123456789abcdef0")},
			"subnet-0fedcba9876543210": {entryReadBackRouteTable("rtb-0fedcba9876543210", "subnet-0fedcba9876543210")},
		},
		gateways: []ec2types.InternetGateway{{InternetGatewayId: aws.String("igw-0123456789abcdef0"), Attachments: []ec2types.InternetGatewayAttachment{{
			VpcId: aws.String("vpc-0123456789abcdef0"), State: ec2types.AttachmentStatusAttached,
		}}}},
	}
}

func entryReadBackCertificate(arn string, status acmtypes.CertificateStatus, sans ...string) *entryScopeReadCertificateFake {
	return &entryScopeReadCertificateFake{certificate: &acmtypes.CertificateDetail{CertificateArn: aws.String(arn), Status: status, SubjectAlternativeNames: sans}}
}

func entryReadBackOwnershipTags(resourceID string) map[string]string {
	return map[string]string{
		resource.TagAgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", resource.TagOwnerID: "owner-1",
		resource.TagTaskID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", resource.TagDeploymentID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		resource.TagResourceID: resourceID, resource.TagRetention: "ephemeral_auto_destroy", resource.TagDestroyDeadline: "2026-07-17T10:00:00Z",
		resource.TagApprovedPlanHash: digestOf('a'), resource.TagApprovalID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
	}
}

func entryReadBackInstance(tags map[string]string) ec2types.Instance {
	return ec2types.Instance{
		InstanceId: aws.String("i-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), SubnetId: aws.String("subnet-0123456789abcdef0"),
		State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}, Tags: ec2Tags(tags),
		SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-0123456789abcdef0")}},
		NetworkInterfaces: []ec2types.InstanceNetworkInterface{{
			NetworkInterfaceId: aws.String("eni-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), SubnetId: aws.String("subnet-0123456789abcdef0"),
			Status: ec2types.NetworkInterfaceStatusInUse, Groups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-0123456789abcdef0")}},
			Attachment: &ec2types.InstanceNetworkInterfaceAttachment{DeviceIndex: aws.Int32(0), NetworkCardIndex: aws.Int32(0), Status: ec2types.AttachmentStatusAttached},
		}},
	}
}

func entryReadBackRouteTable(routeTableID, subnetID string) ec2types.RouteTable {
	return ec2types.RouteTable{
		RouteTableId: aws.String(routeTableID), VpcId: aws.String("vpc-0123456789abcdef0"), Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String(subnetID)}},
		Routes: []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String("igw-0123456789abcdef0"), State: ec2types.RouteStateActive}},
	}
}

func entryReadBackContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

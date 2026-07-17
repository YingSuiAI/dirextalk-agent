package awsprovider

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	entryWorkerReadBackSchemaV1      = "dirextalk.agent.aws.entry-worker-read-back/v1"
	entryCertificateReadBackSchemaV1 = "dirextalk.agent.aws.entry-certificate-read-back/v1"
	entrySubnetReadBackSchemaV1      = "dirextalk.agent.aws.entry-subnet-read-back/v1"
)

// EntryScopeEC2ReadAPI is the closed, read-only EC2 surface required before a
// public entry plan can be signed. It deliberately excludes EIP, endpoints,
// security-group mutation, RunInstances, and all other provider mutations.
// It is separate from EC2ResourceAPI so existing resource-provider fakes do
// not grow a public-entry read-back surface.
type EntryScopeEC2ReadAPI interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error)
}

// EntryScopeReadBackProvider is the narrow provider-facing contract consumed
// by the application scope builder. It returns AWS facts only: no Worker URL,
// Worker log, EIP, VPC endpoint, or Worker-provided endpoint can become a
// public health target through this interface.
type EntryScopeReadBackProvider interface {
	ReadBackEntryWorker(context.Context, EntryWorkerReadBackRequestV1) (EntryWorkerReadBackV1, error)
	ReadBackEntryCertificate(context.Context, EntryCertificateReadBackRequestV1) (EntryCertificateReadBackV1, error)
	ReadBackEntryPublicSubnets(context.Context, EntryPublicSubnetsReadBackRequestV1) ([]EntryPublicSubnetReadBackV1, error)
}

// EntryWorkerReadBackRequestV1 identifies one already-ledgered Worker and its
// one already-ledgered dedicated security group. The exact ownership tags are
// passed from the durable ledger, not from a Worker report.
type EntryWorkerReadBackRequestV1 struct {
	InstanceID                string
	ExpectedInstanceTags      map[string]string
	ExpectedSecurityGroupTags map[string]string
}

// EntryWorkerReadBackV1 is independent EC2 evidence for an ALB target. A
// successful value proves the Worker is running, private, single-NIC, and
// attached to exactly one agent-owned dedicated security group.
type EntryWorkerReadBackV1 struct {
	InstanceID      string
	AccountID       string
	Region          string
	VPCID           string
	SubnetID        string
	SecurityGroupID string
	OwnershipDigest string
	ObservedAt      time.Time
}

// EntryCertificateStatus is intentionally closed to the first public-entry
// certificate state. A plan cannot be signed for pending or imported-in-flight
// certificate states.
type EntryCertificateStatus string

const EntryCertificateStatusIssued EntryCertificateStatus = "ISSUED"

// EntryCertificateReadBackRequestV1 identifies an existing ACM certificate
// and the exact approved hostname it must cover. It does not request ACM or
// Route53 mutation.
type EntryCertificateReadBackRequestV1 struct {
	CertificateARN string
	Hostname       string
}

// EntryCertificateReadBackV1 contains only the certificate facts needed by
// the signed entry scope. ReadBackDigest binds the issued certificate, Region,
// approved hostname, and complete normalized SAN set.
type EntryCertificateReadBackV1 struct {
	CertificateARN          string
	Region                  string
	Hostname                string
	SubjectAlternativeNames []string
	Status                  EntryCertificateStatus
	ReadBackDigest          string
	ObservedAt              time.Time
}

// EntryPublicSubnetsReadBackRequestV1 asks the provider to prove that an ALB
// candidate set belongs to the Worker VPC, spans availability zones, and has
// an active Internet Gateway default route. It intentionally has no EIP or
// endpoint fields.
type EntryPublicSubnetsReadBackRequestV1 struct {
	WorkerVPCID string
	SubnetIDs   []string
}

// EntryPublicSubnetReadBackV1 is a read-only public-subnet proof. Its digest
// also binds the effective route table and attached Internet Gateway even
// though those implementation IDs are not exposed to entry-plan callers.
type EntryPublicSubnetReadBackV1 struct {
	SubnetID         string
	VPCID            string
	AvailabilityZone string
	Public           bool
	ReadBackDigest   string
	ObservedAt       time.Time
}

var _ EntryScopeReadBackProvider = (*EC2ResourceProvider)(nil)

// ReadBackEntryWorker independently verifies the target Worker immediately
// before an entry plan is signed or revalidated. All AWS response failures and
// malformed/ambiguous AWS facts fail closed as resource.ErrReadBack; SDK error
// text is never returned through this public-facing evidence boundary.
func (provider *EC2ResourceProvider) ReadBackEntryWorker(ctx context.Context, request EntryWorkerReadBackRequestV1) (EntryWorkerReadBackV1, error) {
	if provider == nil || provider.entryReadClient == nil || provider.now == nil {
		return EntryWorkerReadBackV1{}, resource.ErrReadBack
	}
	if ctx == nil || !validEntryEC2ID(request.InstanceID, "i-") || !validEntryOwnershipRequest(request.ExpectedInstanceTags, request.ExpectedSecurityGroupTags) {
		return EntryWorkerReadBackV1{}, resource.ErrInvalid
	}
	output, err := provider.entryReadClient.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{request.InstanceID}})
	if err != nil {
		return EntryWorkerReadBackV1{}, resource.ErrReadBack
	}
	instance, accountID, ok := exactWorkerInstance(output)
	if !ok || aws.ToString(instance.InstanceId) != request.InstanceID || instance.State == nil || instance.State.Name != ec2types.InstanceStateNameRunning {
		return EntryWorkerReadBackV1{}, resource.ErrReadBack
	}
	instanceTags, ok := verifiedEntryOwnershipTags(tagsFromEC2(instance.Tags), request.ExpectedInstanceTags)
	if !ok {
		return EntryWorkerReadBackV1{}, resource.ErrReadBack
	}
	primary, securityGroupID, vpcID, subnetID, ok := verifiedEntryPrivateInterface(instance)
	if !ok || aws.ToString(instance.VpcId) != vpcID || aws.ToString(instance.SubnetId) != subnetID ||
		aws.ToString(instance.PublicIpAddress) != "" || hasEntryPublicAssociation(primary.Association) || len(primary.Ipv6Addresses) != 0 ||
		!singleEntrySecurityGroup(instance.SecurityGroups, securityGroupID) {
		return EntryWorkerReadBackV1{}, resource.ErrReadBack
	}
	groups, describeErr := provider.entryReadClient.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{securityGroupID}})
	if describeErr != nil || groups == nil || len(groups.SecurityGroups) != 1 || aws.ToString(groups.SecurityGroups[0].GroupId) != securityGroupID ||
		aws.ToString(groups.SecurityGroups[0].VpcId) != vpcID {
		return EntryWorkerReadBackV1{}, resource.ErrReadBack
	}
	securityGroupTags, ok := verifiedEntryOwnershipTags(tagsFromEC2(groups.SecurityGroups[0].Tags), request.ExpectedSecurityGroupTags)
	if !ok || !sameEntryOwnershipScope(instanceTags, securityGroupTags) {
		return EntryWorkerReadBackV1{}, resource.ErrReadBack
	}
	digest, err := canonical.Digest(entryWorkerReadBackDigestV1{
		SchemaVersion: entryWorkerReadBackSchemaV1, InstanceID: request.InstanceID, AccountID: accountID, Region: provider.region,
		VPCID: vpcID, SubnetID: subnetID, SecurityGroupID: securityGroupID, InstanceTags: instanceTags, SecurityGroupTags: securityGroupTags,
	})
	if err != nil {
		return EntryWorkerReadBackV1{}, resource.ErrReadBack
	}
	return EntryWorkerReadBackV1{
		InstanceID: request.InstanceID, AccountID: accountID, Region: provider.region, VPCID: vpcID, SubnetID: subnetID,
		SecurityGroupID: securityGroupID, OwnershipDigest: digest, ObservedAt: provider.now().UTC(),
	}, nil
}

// ReadBackEntryCertificate verifies that a pre-existing, same-Region ACM
// certificate is already ISSUED and its SANs cover exactly the approved
// hostname. It never creates, imports, renews, or deletes a certificate.
func (provider *EC2ResourceProvider) ReadBackEntryCertificate(ctx context.Context, request EntryCertificateReadBackRequestV1) (EntryCertificateReadBackV1, error) {
	if provider == nil || provider.certificateClient == nil || provider.now == nil {
		return EntryCertificateReadBackV1{}, resource.ErrReadBack
	}
	if ctx == nil {
		return EntryCertificateReadBackV1{}, resource.ErrInvalid
	}
	certificateARN := strings.TrimSpace(request.CertificateARN)
	hostname := strings.ToLower(strings.TrimSpace(request.Hostname))
	certificate, err := arn.Parse(certificateARN)
	if err != nil || hostname == "" || certificate.Service != "acm" || certificate.Region != provider.region ||
		!sdkAccountPattern.MatchString(certificate.AccountID) || !strings.HasPrefix(certificate.Resource, "certificate/") {
		return EntryCertificateReadBackV1{}, resource.ErrInvalid
	}
	output, describeErr := provider.certificateClient.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: aws.String(certificateARN)})
	if describeErr != nil || output == nil || output.Certificate == nil || aws.ToString(output.Certificate.CertificateArn) != certificateARN || output.Certificate.Status != acmtypes.CertificateStatusIssued {
		return EntryCertificateReadBackV1{}, resource.ErrReadBack
	}
	sans, ok := normalizedEntryCertificateSANs(output.Certificate.SubjectAlternativeNames)
	if !ok || !certificateCoversHostname(sans, hostname) {
		return EntryCertificateReadBackV1{}, resource.ErrReadBack
	}
	digest, digestErr := canonical.Digest(entryCertificateReadBackDigestV1{
		SchemaVersion: entryCertificateReadBackSchemaV1, CertificateARN: certificateARN, Region: provider.region, Hostname: hostname,
		SubjectAlternativeNames: sans, Status: string(EntryCertificateStatusIssued),
	})
	if digestErr != nil {
		return EntryCertificateReadBackV1{}, resource.ErrReadBack
	}
	return EntryCertificateReadBackV1{
		CertificateARN: certificateARN, Region: provider.region, Hostname: hostname, SubjectAlternativeNames: sans,
		Status: EntryCertificateStatusIssued, ReadBackDigest: digest, ObservedAt: provider.now().UTC(),
	}, nil
}

// ReadBackEntryPublicSubnets verifies the complete public ALB topology before
// the entry scope is signed. A returned subnet is in the Worker VPC, available,
// in a distinct regional AZ, and uses an active 0.0.0.0/0 route to an Internet
// Gateway that is currently attached to that VPC.
func (provider *EC2ResourceProvider) ReadBackEntryPublicSubnets(ctx context.Context, request EntryPublicSubnetsReadBackRequestV1) ([]EntryPublicSubnetReadBackV1, error) {
	if provider == nil || provider.entryReadClient == nil || provider.now == nil {
		return nil, resource.ErrReadBack
	}
	if ctx == nil || !validEntrySubnetRequest(request) {
		return nil, resource.ErrInvalid
	}
	subnets, err := provider.entrySubnets(ctx, request.SubnetIDs)
	if err != nil {
		return nil, err
	}
	gateways, err := provider.entryInternetGateways(ctx, request.WorkerVPCID)
	if err != nil {
		return nil, err
	}
	mainLoaded := false
	var mainRouteTable ec2types.RouteTable
	result := make([]EntryPublicSubnetReadBackV1, 0, len(request.SubnetIDs))
	for _, subnetID := range request.SubnetIDs {
		subnet, ok := subnets[subnetID]
		if !ok || aws.ToString(subnet.SubnetId) != subnetID || subnet.State != ec2types.SubnetStateAvailable ||
			aws.ToString(subnet.VpcId) != request.WorkerVPCID || !entryAvailabilityZoneInRegion(aws.ToString(subnet.AvailabilityZone), provider.region) {
			return nil, resource.ErrReadBack
		}
		routeTable, found, routeErr := provider.entryRouteTableForSubnet(ctx, request.WorkerVPCID, subnetID)
		if routeErr != nil {
			return nil, routeErr
		}
		if !found {
			if !mainLoaded {
				mainRouteTable, routeErr = provider.entryMainRouteTable(ctx, request.WorkerVPCID)
				if routeErr != nil {
					return nil, routeErr
				}
				mainLoaded = true
			}
			routeTable = mainRouteTable
		}
		if aws.ToString(routeTable.VpcId) != request.WorkerVPCID {
			return nil, resource.ErrReadBack
		}
		gatewayID, ok := activeEntryInternetGatewayRoute(routeTable, gateways)
		if !ok {
			return nil, resource.ErrReadBack
		}
		digest, digestErr := canonical.Digest(entrySubnetReadBackDigestV1{
			SchemaVersion: entrySubnetReadBackSchemaV1, SubnetID: subnetID, VPCID: request.WorkerVPCID,
			AvailabilityZone: aws.ToString(subnet.AvailabilityZone), RouteTableID: aws.ToString(routeTable.RouteTableId), InternetGatewayID: gatewayID, Public: true,
		})
		if digestErr != nil {
			return nil, resource.ErrReadBack
		}
		result = append(result, EntryPublicSubnetReadBackV1{
			SubnetID: subnetID, VPCID: request.WorkerVPCID, AvailabilityZone: aws.ToString(subnet.AvailabilityZone), Public: true,
			ReadBackDigest: digest, ObservedAt: provider.now().UTC(),
		})
	}
	seenZones := make(map[string]struct{}, len(result))
	for _, subnet := range result {
		if _, exists := seenZones[subnet.AvailabilityZone]; exists {
			return nil, resource.ErrReadBack
		}
		seenZones[subnet.AvailabilityZone] = struct{}{}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].SubnetID < result[right].SubnetID })
	return result, nil
}

func validEntryOwnershipRequest(instanceTags, securityGroupTags map[string]string) bool {
	if !validResourceOwnershipTags(instanceTags, instanceTags[resource.TagResourceID], true) ||
		!validResourceOwnershipTags(securityGroupTags, securityGroupTags[resource.TagResourceID], true) ||
		instanceTags[resource.TagResourceID] == securityGroupTags[resource.TagResourceID] {
		return false
	}
	return sameEntryOwnershipScope(instanceTags, securityGroupTags)
}

func verifiedEntryOwnershipTags(actual, expected map[string]string) (map[string]string, bool) {
	if !validResourceOwnershipTags(expected, expected[resource.TagResourceID], true) || !containsTags(actual, expected) {
		return nil, false
	}
	result := make(map[string]string, len(workerOwnershipTagKeys))
	for _, key := range workerOwnershipTagKeys {
		result[key] = actual[key]
	}
	return result, true
}

func sameEntryOwnershipScope(instanceTags, securityGroupTags map[string]string) bool {
	for _, key := range []string{resource.TagAgentInstanceID, resource.TagOwnerID, resource.TagTaskID, resource.TagDeploymentID, resource.TagRetention, resource.TagDestroyDeadline} {
		if instanceTags[key] == "" || instanceTags[key] != securityGroupTags[key] {
			return false
		}
	}
	return instanceTags[resource.TagResourceID] != "" && securityGroupTags[resource.TagResourceID] != "" &&
		instanceTags[resource.TagResourceID] != securityGroupTags[resource.TagResourceID]
}

func verifiedEntryPrivateInterface(instance ec2types.Instance) (ec2types.InstanceNetworkInterface, string, string, string, bool) {
	if _, ok := verifiedExclusivePrimaryInterface(instance.NetworkInterfaces); !ok || len(instance.NetworkInterfaces) != 1 {
		return ec2types.InstanceNetworkInterface{}, "", "", "", false
	}
	primary := instance.NetworkInterfaces[0]
	vpcID, subnetID := aws.ToString(primary.VpcId), aws.ToString(primary.SubnetId)
	if !validEntryEC2ID(vpcID, "vpc-") || !validEntryEC2ID(subnetID, "subnet-") || len(primary.Groups) != 1 {
		return ec2types.InstanceNetworkInterface{}, "", "", "", false
	}
	securityGroupID := aws.ToString(primary.Groups[0].GroupId)
	if !validEntryEC2ID(securityGroupID, "sg-") {
		return ec2types.InstanceNetworkInterface{}, "", "", "", false
	}
	return primary, securityGroupID, vpcID, subnetID, true
}

func singleEntrySecurityGroup(groups []ec2types.GroupIdentifier, securityGroupID string) bool {
	return len(groups) == 1 && aws.ToString(groups[0].GroupId) == securityGroupID
}

func hasEntryPublicAssociation(value *ec2types.InstanceNetworkInterfaceAssociation) bool {
	// An association is the EC2 control-plane signal for a directly reachable
	// IPv4/EIP mapping. Reject even a malformed empty association rather than
	// treating an incomplete response as evidence that the Worker is private.
	return value != nil
}

func normalizedEntryCertificateSANs(values []string) ([]string, bool) {
	if len(values) == 0 || len(values) > 100 {
		return nil, false
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return nil, false
		}
		if _, exists := seen[value]; exists {
			return nil, false
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, true
}

func validEntrySubnetRequest(request EntryPublicSubnetsReadBackRequestV1) bool {
	if !validEntryEC2ID(request.WorkerVPCID, "vpc-") || len(request.SubnetIDs) < 2 || len(request.SubnetIDs) > 16 {
		return false
	}
	seen := make(map[string]struct{}, len(request.SubnetIDs))
	for _, subnetID := range request.SubnetIDs {
		if !validEntryEC2ID(subnetID, "subnet-") {
			return false
		}
		if _, exists := seen[subnetID]; exists {
			return false
		}
		seen[subnetID] = struct{}{}
	}
	return true
}

func (provider *EC2ResourceProvider) entrySubnets(ctx context.Context, subnetIDs []string) (map[string]ec2types.Subnet, error) {
	result := make(map[string]ec2types.Subnet, len(subnetIDs))
	seenTokens := make(map[string]struct{})
	nextToken := ""
	for {
		output, err := provider.entryReadClient.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: append([]string(nil), subnetIDs...), NextToken: optionalToken(nextToken)})
		if err != nil || output == nil {
			return nil, resource.ErrReadBack
		}
		for _, subnet := range output.Subnets {
			id := aws.ToString(subnet.SubnetId)
			if id == "" {
				return nil, resource.ErrReadBack
			}
			if _, exists := result[id]; exists {
				return nil, resource.ErrReadBack
			}
			result[id] = subnet
		}
		var ok bool
		nextToken, ok = entryNextPageToken(output.NextToken, seenTokens)
		if !ok {
			return nil, resource.ErrReadBack
		}
		if nextToken == "" {
			break
		}
	}
	if len(result) != len(subnetIDs) {
		return nil, resource.ErrReadBack
	}
	for _, subnetID := range subnetIDs {
		if _, exists := result[subnetID]; !exists {
			return nil, resource.ErrReadBack
		}
	}
	return result, nil
}

func (provider *EC2ResourceProvider) entryInternetGateways(ctx context.Context, vpcID string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	seenTokens := make(map[string]struct{})
	nextToken := ""
	for {
		output, err := provider.entryReadClient.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
			Filters: []ec2types.Filter{{Name: aws.String("attachment.vpc-id"), Values: []string{vpcID}}}, NextToken: optionalToken(nextToken),
		})
		if err != nil || output == nil {
			return nil, resource.ErrReadBack
		}
		for _, gateway := range output.InternetGateways {
			gatewayID := aws.ToString(gateway.InternetGatewayId)
			if !validEntryEC2ID(gatewayID, "igw-") {
				return nil, resource.ErrReadBack
			}
			for _, attachment := range gateway.Attachments {
				if aws.ToString(attachment.VpcId) == vpcID && (attachment.State == ec2types.AttachmentStatusAttached || string(attachment.State) == "available") {
					result[gatewayID] = struct{}{}
				}
			}
		}
		var ok bool
		nextToken, ok = entryNextPageToken(output.NextToken, seenTokens)
		if !ok {
			return nil, resource.ErrReadBack
		}
		if nextToken == "" {
			break
		}
	}
	if len(result) == 0 {
		return nil, resource.ErrReadBack
	}
	return result, nil
}

func (provider *EC2ResourceProvider) entryRouteTableForSubnet(ctx context.Context, vpcID, subnetID string) (ec2types.RouteTable, bool, error) {
	tables, err := provider.entryRouteTables(ctx, []ec2types.Filter{{Name: aws.String("association.subnet-id"), Values: []string{subnetID}}})
	if err != nil {
		return ec2types.RouteTable{}, false, err
	}
	if len(tables) == 0 {
		return ec2types.RouteTable{}, false, nil
	}
	if len(tables) != 1 || aws.ToString(tables[0].VpcId) != vpcID || !entryRouteTableAssociatedWithSubnet(tables[0].Associations, subnetID) {
		return ec2types.RouteTable{}, false, resource.ErrReadBack
	}
	return tables[0], true, nil
}

func (provider *EC2ResourceProvider) entryMainRouteTable(ctx context.Context, vpcID string) (ec2types.RouteTable, error) {
	tables, err := provider.entryRouteTables(ctx, []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}})
	if err != nil {
		return ec2types.RouteTable{}, err
	}
	var main *ec2types.RouteTable
	for index := range tables {
		if aws.ToString(tables[index].VpcId) != vpcID || !entryMainRouteTableAssociation(tables[index].Associations) {
			continue
		}
		if main != nil {
			return ec2types.RouteTable{}, resource.ErrReadBack
		}
		value := tables[index]
		main = &value
	}
	if main == nil {
		return ec2types.RouteTable{}, resource.ErrReadBack
	}
	return *main, nil
}

func (provider *EC2ResourceProvider) entryRouteTables(ctx context.Context, filters []ec2types.Filter) ([]ec2types.RouteTable, error) {
	result := make([]ec2types.RouteTable, 0)
	seenIDs := make(map[string]struct{})
	seenTokens := make(map[string]struct{})
	nextToken := ""
	for {
		output, err := provider.entryReadClient.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{Filters: append([]ec2types.Filter(nil), filters...), NextToken: optionalToken(nextToken)})
		if err != nil || output == nil {
			return nil, resource.ErrReadBack
		}
		for _, table := range output.RouteTables {
			id := aws.ToString(table.RouteTableId)
			if !validEntryEC2ID(id, "rtb-") {
				return nil, resource.ErrReadBack
			}
			if _, exists := seenIDs[id]; exists {
				return nil, resource.ErrReadBack
			}
			seenIDs[id] = struct{}{}
			result = append(result, table)
		}
		var ok bool
		nextToken, ok = entryNextPageToken(output.NextToken, seenTokens)
		if !ok {
			return nil, resource.ErrReadBack
		}
		if nextToken == "" {
			break
		}
	}
	return result, nil
}

func activeEntryInternetGatewayRoute(table ec2types.RouteTable, gateways map[string]struct{}) (string, bool) {
	matched := ""
	for _, route := range table.Routes {
		gatewayID := aws.ToString(route.GatewayId)
		if route.State != ec2types.RouteStateActive || aws.ToString(route.DestinationCidrBlock) != "0.0.0.0/0" {
			continue
		}
		if _, exists := gateways[gatewayID]; !exists {
			continue
		}
		if matched != "" && matched != gatewayID {
			return "", false
		}
		matched = gatewayID
	}
	return matched, matched != ""
}

func entryMainRouteTableAssociation(associations []ec2types.RouteTableAssociation) bool {
	for _, association := range associations {
		if aws.ToBool(association.Main) {
			return true
		}
	}
	return false
}

func entryRouteTableAssociatedWithSubnet(associations []ec2types.RouteTableAssociation, subnetID string) bool {
	for _, association := range associations {
		if aws.ToString(association.SubnetId) == subnetID {
			return true
		}
	}
	return false
}

func entryAvailabilityZoneInRegion(zone, region string) bool {
	return strings.HasPrefix(zone, region) && len(zone) == len(region)+1 && zone[len(zone)-1] >= 'a' && zone[len(zone)-1] <= 'z'
}

func entryNextPageToken(value *string, seen map[string]struct{}) (string, bool) {
	next := aws.ToString(value)
	if next == "" {
		return "", true
	}
	if _, exists := seen[next]; exists {
		return "", false
	}
	seen[next] = struct{}{}
	return next, true
}

type entryWorkerReadBackDigestV1 struct {
	SchemaVersion     string            `json:"schema_version"`
	InstanceID        string            `json:"instance_id"`
	AccountID         string            `json:"account_id"`
	Region            string            `json:"region"`
	VPCID             string            `json:"vpc_id"`
	SubnetID          string            `json:"subnet_id"`
	SecurityGroupID   string            `json:"security_group_id"`
	InstanceTags      map[string]string `json:"instance_tags"`
	SecurityGroupTags map[string]string `json:"security_group_tags"`
}

type entryCertificateReadBackDigestV1 struct {
	SchemaVersion           string   `json:"schema_version"`
	CertificateARN          string   `json:"certificate_arn"`
	Region                  string   `json:"region"`
	Hostname                string   `json:"hostname"`
	SubjectAlternativeNames []string `json:"subject_alternative_names"`
	Status                  string   `json:"status"`
}

type entrySubnetReadBackDigestV1 struct {
	SchemaVersion     string `json:"schema_version"`
	SubnetID          string `json:"subnet_id"`
	VPCID             string `json:"vpc_id"`
	AvailabilityZone  string `json:"availability_zone"`
	RouteTableID      string `json:"route_table_id"`
	InternetGatewayID string `json:"internet_gateway_id"`
	Public            bool   `json:"public"`
}

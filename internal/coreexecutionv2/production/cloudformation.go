package production

// CloudFormationProvisioner is the typed EC2 reservation -> instance bridge.
// It uses only change-set create/describe/execute, stack describe and stack
// delete.  The stack name and client token are deterministic fences derived
// from the reservation identity; callers cannot supply a template, URL, SDK
// request, shell command or arbitrary CloudFormation operation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfn "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/google/uuid"
)

var (
	ErrProvisionInvalid   = errors.New("execution.v2 production: provision request invalid")
	ErrProvisionUncertain = errors.New("execution.v2 production: provision outcome uncertain")
	ErrProvisionPending   = errors.New("execution.v2 production: provision pending")
)

var serviceRoleARNRE = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]{1,512}$`)

type ComputeProvisionRequest struct {
	OwnerID             string
	AccountGeneration   int64
	ReservationTargetID string
	ReservationDigest   string
	CredentialID        string
	CredentialRevision  uint64
	AccountID           string
	Region              string
	InstanceType        string
	AvailabilityZone    string
	VolumeGiB           uint64
	AMIParameter        string
	PublicIP            bool
	PublicInbound       bool
	StackName           string
	RequestDigest       string
}

type ComputeProvisionResult struct {
	StackName           string
	StackID             string
	ReservationTargetID string
	Status              string
	InstanceID          string
	PublicIP            string
	AvailabilityZone    string
	InstanceType        string
	PendingReason       string
	ResourceIDs         map[string]string
}

type ComputeProvisioner interface {
	Ready() bool
	Create(context.Context, ComputeProvisionRequest, workaws.CredentialHandle) (ComputeProvisionResult, error)
	Reconcile(context.Context, ComputeProvisionRequest, workaws.CredentialHandle) (ComputeProvisionResult, error)
	Destroy(context.Context, ComputeProvisionRequest, workaws.CredentialHandle) error
	ReconcileDestroy(context.Context, ComputeProvisionRequest, workaws.CredentialHandle) (ComputeProvisionResult, error)
}

type CloudFormationClient interface {
	CreateChangeSet(context.Context, *cloudformation.CreateChangeSetInput, ...func(*cloudformation.Options)) (*cloudformation.CreateChangeSetOutput, error)
	DescribeChangeSet(context.Context, *cloudformation.DescribeChangeSetInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeChangeSetOutput, error)
	ExecuteChangeSet(context.Context, *cloudformation.ExecuteChangeSetInput, ...func(*cloudformation.Options)) (*cloudformation.ExecuteChangeSetOutput, error)
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	DeleteStack(context.Context, *cloudformation.DeleteStackInput, ...func(*cloudformation.Options)) (*cloudformation.DeleteStackOutput, error)
}

type CloudFormationFactory interface {
	New(workaws.CredentialHandle) (CloudFormationClient, error)
}

type SDKCloudFormationFactory struct{}

func (SDKCloudFormationFactory) New(h workaws.CredentialHandle) (CloudFormationClient, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	cfg := aws.Config{Region: h.Region, Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(h.AccessKeyID, h.SecretAccessKey, h.SessionToken)), RetryMode: aws.RetryModeStandard, RetryMaxAttempts: 3}
	return cloudformation.NewFromConfig(cfg), nil
}

type AWSCloudFormationProvisioner struct {
	factory        CloudFormationFactory
	now            func() time.Time
	timeout        time.Duration
	serviceRoleARN string
}

func NewAWSCloudFormationProvisioner(factory CloudFormationFactory, now func() time.Time, serviceRoleARN ...string) *AWSCloudFormationProvisioner {
	if factory == nil {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	role := ""
	if len(serviceRoleARN) > 0 {
		role = strings.TrimSpace(serviceRoleARN[0])
	}
	return &AWSCloudFormationProvisioner{factory: factory, now: now, timeout: 2 * time.Minute, serviceRoleARN: role}
}

func (p *AWSCloudFormationProvisioner) Ready() bool {
	return p != nil && p.factory != nil && p.now != nil && p.timeout > 0 && p.timeout <= 10*time.Minute && serviceRoleARNRE.MatchString(p.serviceRoleARN)
}

func (p *AWSCloudFormationProvisioner) Create(ctx context.Context, req ComputeProvisionRequest, credential workaws.CredentialHandle) (ComputeProvisionResult, error) {
	if !p.Ready() {
		return ComputeProvisionResult{}, ErrProvisionInvalid
	}
	req, err := normalizeProvisionRequest(req, credential)
	if err != nil {
		return ComputeProvisionResult{}, err
	}
	if err := p.validateServiceRole(req); err != nil {
		return ComputeProvisionResult{}, err
	}
	client, err := p.factory.New(credential)
	if err != nil || client == nil {
		return ComputeProvisionResult{}, ErrProvisionUncertain
	}
	callCtx, cancel := context.WithTimeout(ctxOrBackground(ctx), p.timeout)
	defer cancel()
	changeSetName := changeSetName(req)
	_, err = client.CreateChangeSet(callCtx, &cloudformation.CreateChangeSetInput{StackName: aws.String(req.StackName), ChangeSetName: aws.String(changeSetName), ChangeSetType: cfn.ChangeSetTypeCreate, Description: aws.String("dirextalk.execution.v2:" + req.RequestDigest), ClientToken: aws.String(req.RequestDigest), RoleARN: aws.String(p.serviceRoleARN), TemplateBody: aws.String(provisionTemplate()), Parameters: provisionParameters(req), Tags: provisionStackTags(req), Capabilities: []cfn.Capability{cfn.CapabilityCapabilityNamedIam}})
	if err != nil && !looksAlreadyExists(err) {
		return ComputeProvisionResult{}, ErrProvisionUncertain
	}
	if err = waitChangeSet(callCtx, client, req.StackName, changeSetName); err != nil {
		return ComputeProvisionResult{}, err
	}
	if _, err = client.ExecuteChangeSet(callCtx, &cloudformation.ExecuteChangeSetInput{StackName: aws.String(req.StackName), ChangeSetName: aws.String(changeSetName), ClientRequestToken: aws.String(req.RequestDigest)}); err != nil && !looksAlreadyExecuted(err) {
		return ComputeProvisionResult{}, ErrProvisionUncertain
	}
	return p.Reconcile(callCtx, req, credential)
}

func (p *AWSCloudFormationProvisioner) Reconcile(ctx context.Context, req ComputeProvisionRequest, credential workaws.CredentialHandle) (ComputeProvisionResult, error) {
	if !p.Ready() {
		return ComputeProvisionResult{}, ErrProvisionInvalid
	}
	req, err := normalizeProvisionRequest(req, credential)
	if err != nil {
		return ComputeProvisionResult{}, err
	}
	if err := p.validateServiceRole(req); err != nil {
		return ComputeProvisionResult{}, err
	}
	client, err := p.factory.New(credential)
	if err != nil || client == nil {
		return ComputeProvisionResult{}, ErrProvisionUncertain
	}
	callCtx, cancel := context.WithTimeout(ctxOrBackground(ctx), p.timeout)
	defer cancel()
	out, err := client.DescribeStacks(callCtx, &cloudformation.DescribeStacksInput{StackName: aws.String(req.StackName)})
	if err != nil || out == nil || len(out.Stacks) != 1 {
		return ComputeProvisionResult{}, ErrProvisionUncertain
	}
	stack := out.Stacks[0]
	result := ComputeProvisionResult{StackName: aws.ToString(stack.StackName), StackID: aws.ToString(stack.StackId), ReservationTargetID: req.ReservationTargetID, Status: string(stack.StackStatus), InstanceType: req.InstanceType, AvailabilityZone: req.AvailabilityZone, ResourceIDs: map[string]string{}}
	for _, output := range stack.Outputs {
		switch aws.ToString(output.OutputKey) {
		case "InstanceId":
			result.InstanceID = aws.ToString(output.OutputValue)
		case "PublicIP":
			result.PublicIP = aws.ToString(output.OutputValue)
		}
	}
	if resourceReader, ok := client.(interface {
		DescribeStackResources(context.Context, *cloudformation.DescribeStackResourcesInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStackResourcesOutput, error)
	}); ok {
		resources, resourcesErr := resourceReader.DescribeStackResources(callCtx, &cloudformation.DescribeStackResourcesInput{StackName: aws.String(req.StackName)})
		if resourcesErr != nil {
			return ComputeProvisionResult{}, ErrProvisionUncertain
		}
		for _, resource := range resources.StackResources {
			result.ResourceIDs[aws.ToString(resource.LogicalResourceId)] = aws.ToString(resource.PhysicalResourceId)
		}
		if result.InstanceID == "" {
			result.InstanceID = result.ResourceIDs["Instance"]
		}
	}
	if result.Status == "CREATE_IN_PROGRESS" || result.Status == "REVIEW_IN_PROGRESS" {
		return result, ErrProvisionPending
	}
	if result.Status != "CREATE_COMPLETE" {
		return result, ErrProvisionUncertain
	}
	if !validInstanceID(result.InstanceID) || result.PublicIP == "" {
		result.PendingReason = "ssm_registration_pending"
		return result, ErrProvisionPending
	}
	return result, nil
}

func (p *AWSCloudFormationProvisioner) Destroy(ctx context.Context, req ComputeProvisionRequest, credential workaws.CredentialHandle) error {
	if !p.Ready() {
		return ErrProvisionInvalid
	}
	req, err := normalizeProvisionRequest(req, credential)
	if err != nil {
		return err
	}
	if err := p.validateServiceRole(req); err != nil {
		return err
	}
	client, err := p.factory.New(credential)
	if err != nil || client == nil {
		return ErrProvisionUncertain
	}
	callCtx, cancel := context.WithTimeout(ctxOrBackground(ctx), p.timeout)
	defer cancel()
	_, err = client.DeleteStack(callCtx, &cloudformation.DeleteStackInput{StackName: aws.String(req.StackName), ClientRequestToken: aws.String(req.RequestDigest)})
	if err != nil && !looksNotFound(err) {
		return ErrProvisionUncertain
	}
	return nil
}

func (p *AWSCloudFormationProvisioner) ReconcileDestroy(ctx context.Context, req ComputeProvisionRequest, credential workaws.CredentialHandle) (ComputeProvisionResult, error) {
	if !p.Ready() {
		return ComputeProvisionResult{}, ErrProvisionInvalid
	}
	req, err := normalizeProvisionRequest(req, credential)
	if err != nil {
		return ComputeProvisionResult{}, err
	}
	if err := p.validateServiceRole(req); err != nil {
		return ComputeProvisionResult{}, err
	}
	client, err := p.factory.New(credential)
	if err != nil || client == nil {
		return ComputeProvisionResult{}, ErrProvisionUncertain
	}
	callCtx, cancel := context.WithTimeout(ctxOrBackground(ctx), p.timeout)
	defer cancel()
	out, err := client.DescribeStacks(callCtx, &cloudformation.DescribeStacksInput{StackName: aws.String(req.StackName)})
	if looksNotFound(err) || out == nil || len(out.Stacks) == 0 {
		return ComputeProvisionResult{StackName: req.StackName, ReservationTargetID: req.ReservationTargetID, Status: "DELETE_COMPLETE", InstanceType: req.InstanceType, AvailabilityZone: req.AvailabilityZone}, nil
	}
	if err != nil {
		return ComputeProvisionResult{}, ErrProvisionUncertain
	}
	stack := out.Stacks[0]
	result := ComputeProvisionResult{StackName: aws.ToString(stack.StackName), StackID: aws.ToString(stack.StackId), ReservationTargetID: req.ReservationTargetID, Status: string(stack.StackStatus), InstanceType: req.InstanceType, AvailabilityZone: req.AvailabilityZone}
	if stack.StackStatus == cfn.StackStatusDeleteInProgress {
		return result, ErrProvisionPending
	}
	if stack.StackStatus == cfn.StackStatusDeleteComplete {
		return result, nil
	}
	return result, ErrProvisionUncertain
}

func normalizeProvisionRequest(req ComputeProvisionRequest, h workaws.CredentialHandle) (ComputeProvisionRequest, error) {
	if h.Validate() != nil || strings.TrimSpace(req.OwnerID) == "" || req.AccountGeneration <= 0 || !validUUID(req.ReservationTargetID) || !validDigest(req.ReservationDigest) || req.CredentialID != h.ReferenceID || req.CredentialRevision == 0 || req.AccountID != h.AccountID || req.Region != h.Region || !validRegion(req.Region) || !validInstanceType(req.InstanceType) || !validAZ(req.Region, req.AvailabilityZone) || req.VolumeGiB < 8 || req.VolumeGiB > 16384 || strings.TrimSpace(req.AMIParameter) == "" || !req.PublicIP || req.PublicInbound {
		return ComputeProvisionRequest{}, ErrProvisionInvalid
	}
	if req.StackName == "" {
		req.StackName = deterministicStackName(req.ReservationTargetID)
	}
	if !validStackName(req.StackName) {
		return ComputeProvisionRequest{}, ErrProvisionInvalid
	}
	if req.RequestDigest == "" {
		req.RequestDigest = provisionRequestDigest(req)
	}
	if !validDigest(req.RequestDigest) {
		return ComputeProvisionRequest{}, ErrProvisionInvalid
	}
	return req, nil
}

func (p *AWSCloudFormationProvisioner) validateServiceRole(req ComputeProvisionRequest) error {
	if p == nil || !serviceRoleARNRE.MatchString(p.serviceRoleARN) || !strings.HasPrefix(p.serviceRoleARN, "arn:aws:iam::"+req.AccountID+":role/") {
		return ErrProvisionInvalid
	}
	return nil
}

func provisionParameters(req ComputeProvisionRequest) []cfn.Parameter {
	return []cfn.Parameter{{ParameterKey: aws.String("AMIParameter"), ParameterValue: aws.String(req.AMIParameter)}, {ParameterKey: aws.String("InstanceType"), ParameterValue: aws.String(req.InstanceType)}, {ParameterKey: aws.String("AvailabilityZone"), ParameterValue: aws.String(req.AvailabilityZone)}, {ParameterKey: aws.String("VolumeGiB"), ParameterValue: aws.String(fmt.Sprint(req.VolumeGiB))}, {ParameterKey: aws.String("ManagedStackName"), ParameterValue: aws.String(req.StackName)}, {ParameterKey: aws.String("ReservationTargetID"), ParameterValue: aws.String(req.ReservationTargetID)}}
}

func provisionTemplate() string {
	return buildProvisionTemplate()
}

func provisionStackTags(req ComputeProvisionRequest) []cfn.Tag {
	return []cfn.Tag{{Key: aws.String("dirextalk-managed"), Value: aws.String("execution-v2")}, {Key: aws.String("dirextalk-stack"), Value: aws.String(req.StackName)}, {Key: aws.String("dirextalk-reservation-target"), Value: aws.String(req.ReservationTargetID)}, {Key: aws.String("dirextalk-account-generation"), Value: aws.String(fmt.Sprint(req.AccountGeneration))}}
}

func resourceTags() []any {
	return []any{
		map[string]any{"Key": "dirextalk-managed", "Value": "execution-v2"},
		map[string]any{"Key": "dirextalk-stack", "Value": map[string]any{"Ref": "ManagedStackName"}},
		map[string]any{"Key": "dirextalk-reservation-target", "Value": map[string]any{"Ref": "ReservationTargetID"}},
	}
}

// buildProvisionTemplate returns a deterministic, schema-valid JSON document.
// Keeping this in typed Go data makes future edits compile and test as ordinary
// values instead of relying on hand-balanced braces in a raw string.
func buildProvisionTemplate() string {
	template := map[string]any{
		"AWSTemplateFormatVersion": "2010-09-09",
		"Parameters": map[string]any{
			"AMIParameter":        map[string]any{"Type": "String"},
			"InstanceType":        map[string]any{"Type": "String"},
			"AvailabilityZone":    map[string]any{"Type": "String"},
			"VolumeGiB":           map[string]any{"Type": "Number"},
			"ManagedStackName":    map[string]any{"Type": "String"},
			"ReservationTargetID": map[string]any{"Type": "String"},
		},
		"Resources": map[string]any{
			"VPC": map[string]any{"Type": "AWS::EC2::VPC", "Properties": map[string]any{
				"CidrBlock": "10.42.0.0/16", "EnableDnsSupport": true, "EnableDnsHostnames": true,
				"Tags": resourceTags(),
			}},
			"Subnet": map[string]any{"Type": "AWS::EC2::Subnet", "Properties": map[string]any{
				"VpcId": map[string]any{"Ref": "VPC"}, "CidrBlock": "10.42.0.0/24", "AvailabilityZone": map[string]any{"Ref": "AvailabilityZone"}, "MapPublicIpOnLaunch": true,
				"Tags": resourceTags(),
			}},
			"IGW":              map[string]any{"Type": "AWS::EC2::InternetGateway", "Properties": map[string]any{"Tags": resourceTags()}},
			"AttachIGW":        map[string]any{"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": map[string]any{"VpcId": map[string]any{"Ref": "VPC"}, "InternetGatewayId": map[string]any{"Ref": "IGW"}}},
			"RouteTable":       map[string]any{"Type": "AWS::EC2::RouteTable", "Properties": map[string]any{"VpcId": map[string]any{"Ref": "VPC"}, "Tags": resourceTags()}},
			"Route":            map[string]any{"Type": "AWS::EC2::Route", "DependsOn": "AttachIGW", "Properties": map[string]any{"RouteTableId": map[string]any{"Ref": "RouteTable"}, "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": map[string]any{"Ref": "IGW"}}},
			"RouteAssociation": map[string]any{"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": map[string]any{"SubnetId": map[string]any{"Ref": "Subnet"}, "RouteTableId": map[string]any{"Ref": "RouteTable"}}},
			"SG": map[string]any{"Type": "AWS::EC2::SecurityGroup", "Properties": map[string]any{
				"GroupDescription": "Dirextalk execution v2 egress-only", "VpcId": map[string]any{"Ref": "VPC"},
				"SecurityGroupEgress": []any{map[string]any{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}},
				"Tags":                resourceTags(),
			}},
			"Role": map[string]any{"Type": "AWS::IAM::Role", "Properties": map[string]any{
				"AssumeRolePolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"Service": []any{"ec2.amazonaws.com"}}, "Action": []any{"sts:AssumeRole"}}}},
				"ManagedPolicyArns":        []any{"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"},
				"Tags":                     resourceTags(),
			}},
			"Profile": map[string]any{"Type": "AWS::IAM::InstanceProfile", "Properties": map[string]any{"Roles": []any{map[string]any{"Ref": "Role"}}, "Tags": resourceTags()}},
			"Instance": map[string]any{"Type": "AWS::EC2::Instance", "Properties": map[string]any{
				"ImageId": map[string]any{"Ref": "AMIParameter"}, "InstanceType": map[string]any{"Ref": "InstanceType"}, "AvailabilityZone": map[string]any{"Ref": "AvailabilityZone"}, "SubnetId": map[string]any{"Ref": "Subnet"},
				"SecurityGroupIds": []any{map[string]any{"Fn::GetAtt": []any{"SG", "GroupId"}}}, "IamInstanceProfile": map[string]any{"Ref": "Profile"},
				"BlockDeviceMappings": []any{map[string]any{"DeviceName": "/dev/xvda", "Ebs": map[string]any{"VolumeSize": map[string]any{"Ref": "VolumeGiB"}, "VolumeType": "gp3", "DeleteOnTermination": true}}},
				"Tags":                resourceTags(),
			}},
		},
		"Outputs": map[string]any{
			"InstanceId": map[string]any{"Value": map[string]any{"Ref": "Instance"}},
			"PublicIP":   map[string]any{"Value": map[string]any{"Fn::GetAtt": []any{"Instance", "PublicIp"}}},
		},
	}
	raw, err := json.Marshal(template)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func waitChangeSet(ctx context.Context, client CloudFormationClient, stack, name string) error {
	for {
		out, err := client.DescribeChangeSet(ctx, &cloudformation.DescribeChangeSetInput{StackName: aws.String(stack), ChangeSetName: aws.String(name)})
		if err == nil && out != nil {
			switch string(out.Status) {
			case "CREATE_COMPLETE":
				return nil
			case "FAILED", "DELETE_COMPLETE":
				return ErrProvisionUncertain
			}
		}
		select {
		case <-ctx.Done():
			return ErrProvisionPending
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func deterministicStackName(targetID string) string {
	return "dirextalk-exec-" + strings.ReplaceAll(targetID, "-", "")[:24]
}
func changeSetName(req ComputeProvisionRequest) string { return "create-" + req.RequestDigest[:24] }
func provisionRequestDigest(req ComputeProvisionRequest) string {
	value := fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s\x00%s\x00%d\x00%s", req.OwnerID, req.AccountGeneration, req.ReservationTargetID, req.ReservationDigest, req.Region, req.InstanceType, req.VolumeGiB, req.AvailabilityZone)
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func validUUID(value string) bool {
	id, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && id != uuid.Nil && id.String() == strings.TrimSpace(value)
}
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func validRegion(value string) bool {
	ok, _ := regexp.MatchString(`^[a-z]{2}(?:-gov)?-[a-z]+-\d$`, value)
	return ok
}
func validInstanceType(value string) bool {
	ok, _ := regexp.MatchString(`^[a-z0-9][a-z0-9-]{0,31}\.[a-z0-9][a-z0-9-]{0,31}$`, value)
	return ok
}
func validAZ(region, value string) bool {
	return len(value) == len(region)+1 && strings.HasPrefix(value, region) && value[len(value)-1] >= 'a' && value[len(value)-1] <= 'z'
}
func validStackName(value string) bool {
	ok, _ := regexp.MatchString(`^[A-Za-z][A-Za-z0-9-]{0,127}$`, value)
	return ok
}
func validInstanceID(value string) bool {
	ok, _ := regexp.MatchString(`^i-[0-9a-f]{8,32}$`, value)
	return ok
}
func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
func looksAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "already exists") || strings.Contains(value, "alreadyexists") || strings.Contains(value, "already_exist")
}
func looksAlreadyExecuted(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "already executed") || strings.Contains(value, "alreadyexecuted") || strings.Contains(value, "already_execute")
}
func looksNotFound(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "does not exist") || strings.Contains(value, "not exist") || strings.Contains(value, "notfound") || strings.Contains(value, "not_found")
}

var _ ComputeProvisioner = (*AWSCloudFormationProvisioner)(nil)

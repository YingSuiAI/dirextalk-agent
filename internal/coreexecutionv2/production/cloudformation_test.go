package production

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfn "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func TestSDKCloudFormationFactoryDoesNotRetryMutationHTTP(t *testing.T) {
	var calls atomic.Int64
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "retryable provider failure", http.StatusInternalServerError)
	}))
	defer endpoint.Close()

	client, err := (SDKCloudFormationFactory{}).New(provisionTestCredential())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.ExecuteChangeSet(context.Background(), &cloudformation.ExecuteChangeSetInput{
		StackName:          aws.String("retry-counter"),
		ChangeSetName:      aws.String("retry-counter"),
		ClientRequestToken: aws.String("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}, func(options *cloudformation.Options) {
		options.BaseEndpoint = aws.String(endpoint.URL)
	})
	if got := calls.Load(); got != 1 {
		t.Fatalf("ExecuteChangeSet HTTP calls = %d, want one Agent submission", got)
	}
}

type provisionCloudFormationFake struct {
	createInput                                                                               *cloudformation.CreateChangeSetInput
	createCalls, describeChangeSetCalls, executeCalls, stackCalls, resourceCalls, deleteCalls int
	stackStatus                                                                               cfn.StackStatus
	instanceID, publicIP                                                                      string
	createErr                                                                                 error
}

func (f *provisionCloudFormationFake) CreateChangeSet(_ context.Context, in *cloudformation.CreateChangeSetInput, _ ...func(*cloudformation.Options)) (*cloudformation.CreateChangeSetOutput, error) {
	f.createCalls++
	f.createInput = in
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &cloudformation.CreateChangeSetOutput{Id: aws.String("arn:aws:cloudformation:us-east-1:123456789012:changeSet/create")}, nil
}
func (f *provisionCloudFormationFake) DescribeChangeSet(context.Context, *cloudformation.DescribeChangeSetInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeChangeSetOutput, error) {
	f.describeChangeSetCalls++
	return &cloudformation.DescribeChangeSetOutput{Status: cfn.ChangeSetStatusCreateComplete}, nil
}
func (f *provisionCloudFormationFake) ExecuteChangeSet(context.Context, *cloudformation.ExecuteChangeSetInput, ...func(*cloudformation.Options)) (*cloudformation.ExecuteChangeSetOutput, error) {
	f.executeCalls++
	return &cloudformation.ExecuteChangeSetOutput{}, nil
}
func (f *provisionCloudFormationFake) DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	f.stackCalls++
	return &cloudformation.DescribeStacksOutput{Stacks: []cfn.Stack{{StackName: aws.String("dirextalk-exec-aaaaaaaaaaaaaaaaaaaaaaaa"), StackId: aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/id"), StackStatus: f.stackStatus, Outputs: []cfn.Output{{OutputKey: aws.String("InstanceId"), OutputValue: aws.String(f.instanceID)}, {OutputKey: aws.String("PublicIP"), OutputValue: aws.String(f.publicIP)}}}}}, nil
}
func (f *provisionCloudFormationFake) DescribeStackResources(context.Context, *cloudformation.DescribeStackResourcesInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStackResourcesOutput, error) {
	f.resourceCalls++
	return &cloudformation.DescribeStackResourcesOutput{StackResources: []cfn.StackResource{
		{LogicalResourceId: aws.String("VPC"), PhysicalResourceId: aws.String("vpc-0123456789abcdef0")},
		{LogicalResourceId: aws.String("Instance"), PhysicalResourceId: aws.String(f.instanceID)},
	}}, nil
}
func (f *provisionCloudFormationFake) DeleteStack(context.Context, *cloudformation.DeleteStackInput, ...func(*cloudformation.Options)) (*cloudformation.DeleteStackOutput, error) {
	f.deleteCalls++
	return &cloudformation.DeleteStackOutput{}, nil
}

type provisionFactoryFake struct{ client CloudFormationClient }

func (f provisionFactoryFake) New(workaws.CredentialHandle) (CloudFormationClient, error) {
	return f.client, nil
}

func provisionTestCredential() workaws.CredentialHandle {
	return workaws.CredentialHandle{ReferenceID: productionCred, Region: "us-east-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:role/execution", AccessKeyID: "access", SecretAccessKey: "secret"}
}

func provisionTestRequest() ComputeProvisionRequest {
	return ComputeProvisionRequest{OwnerID: productionOwner, ReservationTargetID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ReservationDigest: strings.Repeat("a", 64), CredentialID: productionCred, CredentialRevision: 3, AccountID: "123456789012", Region: "us-east-1", InstanceType: "t3.small", AvailabilityZone: "us-east-1a", VolumeGiB: 20, AMIParameter: "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64", PublicIP: true}
}

func TestAWSCloudFormationProvisionerUsesDeterministicChangeSetAndNoInboundRules(t *testing.T) {
	client := &provisionCloudFormationFake{stackStatus: cfn.StackStatusCreateComplete, instanceID: "i-0123456789abcdef0", publicIP: "203.0.113.10"}
	provisioner := NewAWSCloudFormationProvisioner(provisionFactoryFake{client: client}, time.Now, "arn:aws:iam::123456789012:role/dirextalk-cfn-execution")
	result, err := provisioner.Create(context.Background(), provisionTestRequest(), provisionTestCredential())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "CREATE_COMPLETE" || result.InstanceID != "i-0123456789abcdef0" || client.createCalls != 1 || client.executeCalls != 1 || client.stackCalls != 1 {
		t.Fatalf("result=%+v calls create=%d execute=%d stacks=%d", result, client.createCalls, client.executeCalls, client.stackCalls)
	}
	if client.createInput == nil || aws.ToString(client.createInput.StackName) != deterministicStackName(provisionTestRequest().ReservationTargetID) || aws.ToString(client.createInput.ChangeSetName) == "" {
		t.Fatalf("unfenced change-set input: %#v", client.createInput)
	}
	if aws.ToString(client.createInput.RoleARN) != "arn:aws:iam::123456789012:role/dirextalk-cfn-execution" || len(client.createInput.Tags) != 3 {
		t.Fatalf("service role/stack tags missing: role=%q tags=%v", aws.ToString(client.createInput.RoleARN), client.createInput.Tags)
	}
	template := aws.ToString(client.createInput.TemplateBody)
	if !json.Valid([]byte(template)) || strings.Contains(template, "SecurityGroupIngress") || !strings.Contains(template, "AmazonSSMManagedInstanceCore") || strings.Count(template, "dirextalk-reservation-target") < 3 {
		t.Fatalf("unsafe template: %s", template)
	}
	var templateDoc map[string]any
	if err := json.Unmarshal([]byte(template), &templateDoc); err != nil {
		t.Fatal(err)
	}
	resources, _ := templateDoc["Resources"].(map[string]any)
	instance, _ := resources["Instance"].(map[string]any)
	instanceProperties, _ := instance["Properties"].(map[string]any)
	instanceTags, _ := instanceProperties["Tags"].([]any)
	if len(instanceTags) != 3 {
		t.Fatalf("instance tags=%v, want bounded managed/stack/reservation tags", instanceTags)
	}
}

func TestAWSCloudFormationProvisionerReconcileAndDeleteAreTyped(t *testing.T) {
	client := &provisionCloudFormationFake{stackStatus: cfn.StackStatusCreateInProgress}
	provisioner := NewAWSCloudFormationProvisioner(provisionFactoryFake{client: client}, time.Now, "arn:aws:iam::123456789012:role/dirextalk-cfn-execution")
	result, err := provisioner.Reconcile(context.Background(), provisionTestRequest(), provisionTestCredential())
	if !errors.Is(err, ErrProvisionPending) || result.Status != "CREATE_IN_PROGRESS" {
		t.Fatalf("pending result=%+v err=%v", result, err)
	}
	if err := provisioner.Destroy(context.Background(), provisionTestRequest(), provisionTestCredential()); err != nil {
		t.Fatal(err)
	}
	if client.deleteCalls != 1 {
		t.Fatalf("delete calls=%d", client.deleteCalls)
	}
}

func TestAWSCloudFormationProvisionerReadbackReturnsResourceIdentifiers(t *testing.T) {
	client := &provisionCloudFormationFake{stackStatus: cfn.StackStatusCreateComplete, instanceID: "i-0123456789abcdef0", publicIP: "203.0.113.10"}
	provisioner := NewAWSCloudFormationProvisioner(provisionFactoryFake{client: client}, time.Now, "arn:aws:iam::123456789012:role/dirextalk-cfn-execution")
	result, err := provisioner.Reconcile(context.Background(), provisionTestRequest(), provisionTestCredential())
	if err != nil {
		t.Fatal(err)
	}
	if client.resourceCalls != 1 || result.ResourceIDs["VPC"] != "vpc-0123456789abcdef0" || result.ResourceIDs["Instance"] != "i-0123456789abcdef0" {
		t.Fatalf("resource readback=%+v calls=%d", result.ResourceIDs, client.resourceCalls)
	}
}

func TestAWSCloudFormationProvisionerRejectsUnsafeRequest(t *testing.T) {
	client := &provisionCloudFormationFake{stackStatus: cfn.StackStatusCreateComplete, instanceID: "i-0123456789abcdef0", publicIP: "203.0.113.10"}
	provisioner := NewAWSCloudFormationProvisioner(provisionFactoryFake{client: client}, time.Now, "arn:aws:iam::123456789012:role/dirextalk-cfn-execution")
	req := provisionTestRequest()
	req.PublicInbound = true
	if _, err := provisioner.Create(context.Background(), req, provisionTestCredential()); !errors.Is(err, ErrProvisionInvalid) {
		t.Fatalf("inbound request accepted: %v", err)
	}
	req = provisionTestRequest()
	req.AccountID = "999999999999"
	if _, err := provisioner.Create(context.Background(), req, provisionTestCredential()); !errors.Is(err, ErrProvisionInvalid) {
		t.Fatalf("cross-account request accepted: %v", err)
	}
}

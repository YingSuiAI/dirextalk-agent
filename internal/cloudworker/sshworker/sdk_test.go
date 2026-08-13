package sshworker

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type stubSTS struct{}

func (stubSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
}

type mutationProbeEC2 struct{ importCalls int }

func (*mutationProbeEC2) DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) DescribeKeyPairs(context.Context, *ec2.DescribeKeyPairsInput, ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error) {
	return nil, errors.New("unused")
}
func (probe *mutationProbeEC2) ImportKeyPair(context.Context, *ec2.ImportKeyPairInput, ...func(*ec2.Options)) (*ec2.ImportKeyPairOutput, error) {
	probe.importCalls++
	return &ec2.ImportKeyPairOutput{KeyName: aws.String("key"), KeyPairId: aws.String("key-1")}, nil
}
func (*mutationProbeEC2) DeleteKeyPair(context.Context, *ec2.DeleteKeyPairInput, ...func(*ec2.Options)) (*ec2.DeleteKeyPairOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) CreateSecurityGroup(context.Context, *ec2.CreateSecurityGroupInput, ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) AuthorizeSecurityGroupIngress(context.Context, *ec2.AuthorizeSecurityGroupIngressInput, ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) DeleteSecurityGroup(context.Context, *ec2.DeleteSecurityGroupInput, ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) RunInstances(context.Context, *ec2.RunInstancesInput, ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	return nil, errors.New("unused")
}

type staticIP struct{}

func (staticIP) PublicIP(context.Context) (netip.Addr, error) {
	return netip.MustParseAddr("198.51.100.7"), nil
}

func TestSDKBlocksMutationBeforeEC2WithoutConfirmation(t *testing.T) {
	probe := &mutationProbeEC2{}
	client := newSDK("ap-east-1", probe, stubSTS{}, staticIP{})
	_, err := client.ImportKeyPair(context.Background(), credentialFixture(), Confirmation{}, "key", []byte("public"), ResourceTags{"owner": "test"})
	if !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("ImportKeyPair() error = %v, want ErrNotConfirmed", err)
	}
	if probe.importCalls != 0 {
		t.Fatalf("EC2 mutation called %d times before confirmation", probe.importCalls)
	}
}

func TestSDKAllowsExactConfirmedMutation(t *testing.T) {
	probe := &mutationProbeEC2{}
	client := newSDK("ap-east-1", probe, stubSTS{}, staticIP{})
	key, err := client.ImportKeyPair(context.Background(), credentialFixture(), Confirmation{Confirmed: true, Proof: "confirmation-1"}, "key", []byte("public"), ResourceTags{"owner": "test"})
	if err != nil || key.ID != "key-1" || probe.importCalls != 1 {
		t.Fatalf("ImportKeyPair() = %#v, %v; calls=%d", key, err, probe.importCalls)
	}
}

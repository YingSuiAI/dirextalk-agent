package sshworker

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type stubSTS struct{}

func (stubSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
}

type identityProbeSTS struct {
	accounts []string
	calls    int
	events   *[]string
}

func (probe *identityProbeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	probe.calls++
	if probe.events != nil {
		*probe.events = append(*probe.events, "verify")
	}
	account := "123456789012"
	if probe.calls <= len(probe.accounts) {
		account = probe.accounts[probe.calls-1]
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String(account)}, nil
}

type mutationProbeEC2 struct {
	importCalls, runCalls, authorizeCalls int
	runInput                              *ec2.RunInstancesInput
	group                                 ec2types.SecurityGroup
	authorizeErr                          error
	applyAuthorizeOnError                 bool
	events                                *[]string
}

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
func (probe *mutationProbeEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if probe.events != nil {
		*probe.events = append(*probe.events, "read")
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{probe.group}}, nil
}
func (*mutationProbeEC2) CreateSecurityGroup(context.Context, *ec2.CreateSecurityGroupInput, ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error) {
	return nil, errors.New("unused")
}
func (probe *mutationProbeEC2) AuthorizeSecurityGroupIngress(_ context.Context, input *ec2.AuthorizeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	probe.authorizeCalls++
	if probe.events != nil {
		*probe.events = append(*probe.events, "authorize")
	}
	if probe.authorizeErr == nil || probe.applyAuthorizeOnError {
		probe.group.IpPermissions = append(probe.group.IpPermissions, input.IpPermissions...)
	}
	return &ec2.AuthorizeSecurityGroupIngressOutput{}, probe.authorizeErr
}
func (probe *mutationProbeEC2) RevokeSecurityGroupIngress(_ context.Context, input *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	if probe.events != nil {
		*probe.events = append(*probe.events, "revoke")
	}
	probe.group.IpPermissions = nil
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}
func (*mutationProbeEC2) DeleteSecurityGroup(context.Context, *ec2.DeleteSecurityGroupInput, ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	return nil, errors.New("unused")
}
func (*mutationProbeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return nil, errors.New("unused")
}
func (probe *mutationProbeEC2) RunInstances(_ context.Context, input *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	probe.runCalls++
	probe.runInput = input
	return &ec2.RunInstancesOutput{Instances: []ec2types.Instance{{InstanceId: aws.String("i-1"), PublicIpAddress: aws.String("203.0.113.20")}}}, nil
}

func TestSDKRunUsesAutoPublicIPv4WithoutEIP(t *testing.T) {
	probe := &mutationProbeEC2{}
	client := newSDK("ap-east-1", probe, stubSTS{}, staticIP{})
	instance, err := client.RunInstance(context.Background(), credentialFixture(), Confirmation{Confirmed: true, Proof: "confirmation-1"}, LaunchRequest{
		WorkerID: "worker-1", ClientToken: "token-1", InstanceType: "t3.small", VolumeGiB: 16, KeyName: "key", SecurityGroupID: "sg-1", Discovery: discoveryFixture(), Tags: ResourceTags{"owner": "test"}})
	if err != nil || instance.PublicIP != "203.0.113.20" || probe.runCalls != 1 {
		t.Fatalf("RunInstance=%#v,%v calls=%d", instance, err, probe.runCalls)
	}
	if probe.runInput == nil || len(probe.runInput.NetworkInterfaces) != 1 || !aws.ToBool(probe.runInput.NetworkInterfaces[0].AssociatePublicIpAddress) {
		t.Fatalf("public IPv4 not requested: %#v", probe.runInput)
	}
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

func TestSDKAuthorizeSSHReadsBeforeAndAfterMutation(t *testing.T) {
	events := []string{}
	probe := &mutationProbeEC2{group: ec2types.SecurityGroup{GroupId: aws.String("sg-1")}, events: &events}
	identity := &identityProbeSTS{events: &events}
	client := newSDK("ap-east-1", probe, identity, staticIP{})
	group := SecurityGroup{ID: "sg-1", Name: "worker"}
	confirmation := Confirmation{Confirmed: true, Proof: "confirmation-1"}
	if err := client.AuthorizeSSH(context.Background(), credentialFixture(), confirmation, group, "198.51.100.7/32"); err != nil {
		t.Fatal(err)
	}
	want := []string{"verify", "read", "verify", "authorize", "verify", "read"}
	if !slices.Equal(events, want) || identity.calls != 3 {
		t.Fatalf("AuthorizeSSH call order = %v, identity calls=%d; want %v, 3", events, identity.calls, want)
	}
	if err := client.AuthorizeSSH(context.Background(), credentialFixture(), confirmation, group, "198.51.100.7/32"); err != nil || probe.authorizeCalls != 1 {
		t.Fatalf("idempotent retry err=%v calls=%d", err, probe.authorizeCalls)
	}
}

func TestSDKAuthorizeSSHStopsOnAccountDriftAtMutationBoundaries(t *testing.T) {
	for _, test := range []struct {
		name     string
		accounts []string
		want     []string
		writes   int
	}{
		{"before write", []string{"123456789012", "999999999999"}, []string{"verify", "read", "verify"}, 0},
		{"before readback", []string{"123456789012", "123456789012", "999999999999"}, []string{"verify", "read", "verify", "authorize", "verify"}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			ec2Probe := &mutationProbeEC2{group: ec2types.SecurityGroup{GroupId: aws.String("sg-1")}, events: &events}
			identity := &identityProbeSTS{accounts: test.accounts, events: &events}
			client := newSDK("ap-east-1", ec2Probe, identity, staticIP{})
			err := client.AuthorizeSSH(context.Background(), credentialFixture(), Confirmation{Confirmed: true, Proof: "confirmation-1"}, SecurityGroup{ID: "sg-1"}, "198.51.100.7/32")
			if !errors.Is(err, ErrIdentity) || !slices.Equal(events, test.want) || ec2Probe.authorizeCalls != test.writes || identity.calls != len(test.accounts) {
				t.Fatalf("AuthorizeSSH error=%v order=%v writes=%d verifies=%d; want ErrIdentity, %v, %d, %d", err, events, ec2Probe.authorizeCalls, identity.calls, test.want, test.writes, len(test.accounts))
			}
		})
	}
}

func TestSDKAuthorizeSSHAcceptsLostSuccessAfterReadback(t *testing.T) {
	probe := &mutationProbeEC2{group: ec2types.SecurityGroup{GroupId: aws.String("sg-1")}, authorizeErr: errors.New("connection reset"), applyAuthorizeOnError: true}
	client := newSDK("ap-east-1", probe, stubSTS{}, staticIP{})
	err := client.AuthorizeSSH(context.Background(), credentialFixture(), Confirmation{Confirmed: true, Proof: "confirmation-1"}, SecurityGroup{ID: "sg-1"}, "198.51.100.7/32")
	if err != nil || probe.authorizeCalls != 1 {
		t.Fatalf("lost success err=%v calls=%d", err, probe.authorizeCalls)
	}
}

func TestSDKAuthorizeSSHReportsWriteFailureWhenRuleIsAbsent(t *testing.T) {
	probe := &mutationProbeEC2{group: ec2types.SecurityGroup{GroupId: aws.String("sg-1")}, authorizeErr: errors.New("denied")}
	client := newSDK("ap-east-1", probe, stubSTS{}, staticIP{})
	err := client.AuthorizeSSH(context.Background(), credentialFixture(), Confirmation{Confirmed: true, Proof: "confirmation-1"}, SecurityGroup{ID: "sg-1"}, "198.51.100.7/32")
	if !errors.Is(err, ErrAmbiguous) || probe.authorizeCalls != 1 {
		t.Fatalf("write failure err=%v calls=%d", err, probe.authorizeCalls)
	}
}

func TestSDKPublicServicePortBindAndUnbind(t *testing.T) {
	events := []string{}
	probe := &mutationProbeEC2{group: ec2types.SecurityGroup{GroupId: aws.String("sg-1")}, events: &events}
	identity := &identityProbeSTS{events: &events}
	client := newSDK("ap-east-1", probe, identity, staticIP{})
	group := SecurityGroup{ID: "sg-1", Name: "worker"}
	if err := client.SetPublicPort(context.Background(), credentialFixture(), group, 8080, true); err != nil {
		t.Fatal(err)
	}
	wantBind := []string{"verify", "read", "verify", "authorize", "verify", "read"}
	if !slices.Equal(events, wantBind) || identity.calls != 3 {
		t.Fatalf("SetPublicPort bind order = %v, identity calls=%d; want %v, 3", events, identity.calls, wantBind)
	}
	if open, _ := client.publicPortState(context.Background(), group.ID, 8080); !open {
		t.Fatal("service port was not opened")
	}
	events = events[:0]
	identity.calls = 0
	if err := client.SetPublicPort(context.Background(), credentialFixture(), group, 8080, false); err != nil {
		t.Fatal(err)
	}
	wantUnbind := []string{"verify", "read", "verify", "revoke", "verify", "read"}
	if !slices.Equal(events, wantUnbind) || identity.calls != 3 {
		t.Fatalf("SetPublicPort unbind order = %v, identity calls=%d; want %v, 3", events, identity.calls, wantUnbind)
	}
	if open, _ := client.publicPortState(context.Background(), group.ID, 8080); open {
		t.Fatal("service port was not revoked")
	}
}

func TestSDKSetPublicPortStopsOnAccountDriftAtMutationBoundaries(t *testing.T) {
	for _, test := range []struct {
		name     string
		accounts []string
		want     []string
		writes   int
	}{
		{"before write", []string{"123456789012", "999999999999"}, []string{"verify", "read", "verify"}, 0},
		{"before readback", []string{"123456789012", "123456789012", "999999999999"}, []string{"verify", "read", "verify", "authorize", "verify"}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			ec2Probe := &mutationProbeEC2{group: ec2types.SecurityGroup{GroupId: aws.String("sg-1")}, events: &events}
			identity := &identityProbeSTS{accounts: test.accounts, events: &events}
			client := newSDK("ap-east-1", ec2Probe, identity, staticIP{})
			err := client.SetPublicPort(context.Background(), credentialFixture(), SecurityGroup{ID: "sg-1"}, 8080, true)
			if !errors.Is(err, ErrIdentity) || !slices.Equal(events, test.want) || ec2Probe.authorizeCalls != test.writes || identity.calls != len(test.accounts) {
				t.Fatalf("SetPublicPort error=%v order=%v writes=%d verifies=%d; want ErrIdentity, %v, %d, %d", err, events, ec2Probe.authorizeCalls, identity.calls, test.want, test.writes, len(test.accounts))
			}
		})
	}
}

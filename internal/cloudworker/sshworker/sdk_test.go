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
	deleteKeyCalls, deleteGroupCalls      int
	terminateCalls                        int
	runInput                              *ec2.RunInstancesInput
	key                                   *ec2types.KeyPairInfo
	group                                 ec2types.SecurityGroup
	instance                              *ec2types.Instance
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
func (probe *mutationProbeEC2) DescribeKeyPairs(context.Context, *ec2.DescribeKeyPairsInput, ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error) {
	if probe.events != nil {
		*probe.events = append(*probe.events, "read")
	}
	if probe.key == nil {
		return &ec2.DescribeKeyPairsOutput{}, nil
	}
	return &ec2.DescribeKeyPairsOutput{KeyPairs: []ec2types.KeyPairInfo{*probe.key}}, nil
}
func (probe *mutationProbeEC2) ImportKeyPair(context.Context, *ec2.ImportKeyPairInput, ...func(*ec2.Options)) (*ec2.ImportKeyPairOutput, error) {
	probe.importCalls++
	return &ec2.ImportKeyPairOutput{KeyName: aws.String("key"), KeyPairId: aws.String("key-1")}, nil
}
func (probe *mutationProbeEC2) DeleteKeyPair(context.Context, *ec2.DeleteKeyPairInput, ...func(*ec2.Options)) (*ec2.DeleteKeyPairOutput, error) {
	probe.deleteKeyCalls++
	probe.key = nil
	if probe.events != nil {
		*probe.events = append(*probe.events, "delete")
	}
	return &ec2.DeleteKeyPairOutput{}, nil
}
func (probe *mutationProbeEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if probe.events != nil {
		*probe.events = append(*probe.events, "read")
	}
	if aws.ToString(probe.group.GroupId) == "" {
		return &ec2.DescribeSecurityGroupsOutput{}, nil
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
func (probe *mutationProbeEC2) DeleteSecurityGroup(context.Context, *ec2.DeleteSecurityGroupInput, ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	probe.deleteGroupCalls++
	probe.group = ec2types.SecurityGroup{}
	if probe.events != nil {
		*probe.events = append(*probe.events, "delete")
	}
	return &ec2.DeleteSecurityGroupOutput{}, nil
}
func (probe *mutationProbeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if probe.events != nil {
		*probe.events = append(*probe.events, "read")
	}
	if probe.instance == nil {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{*probe.instance}}}}, nil
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
func (probe *mutationProbeEC2) TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	probe.terminateCalls++
	probe.instance.State = &ec2types.InstanceState{Name: ec2types.InstanceStateNameShuttingDown}
	if probe.events != nil {
		*probe.events = append(*probe.events, "terminate")
	}
	return &ec2.TerminateInstancesOutput{}, nil
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
	tags := ResourceTags{"worker": "worker-1"}
	probe := &mutationProbeEC2{group: securityGroupFixture(tags), events: &events}
	identity := &identityProbeSTS{events: &events}
	client := newSDK("ap-east-1", probe, identity, staticIP{})
	group := SecurityGroup{ID: "sg-1", Name: "worker"}
	if err := client.SetPublicPort(context.Background(), credentialFixture(), group, tags, 8080, true); err != nil {
		t.Fatal(err)
	}
	wantBind := []string{"verify", "read", "verify", "authorize", "verify", "read"}
	if !slices.Equal(events, wantBind) || identity.calls != 3 {
		t.Fatalf("SetPublicPort bind order = %v, identity calls=%d; want %v, 3", events, identity.calls, wantBind)
	}
	if open, _ := client.publicPortState(context.Background(), group, tags, 8080); !open {
		t.Fatal("service port was not opened")
	}
	events = events[:0]
	identity.calls = 0
	if err := client.SetPublicPort(context.Background(), credentialFixture(), group, tags, 8080, false); err != nil {
		t.Fatal(err)
	}
	wantUnbind := []string{"verify", "read", "verify", "revoke", "verify", "read"}
	if !slices.Equal(events, wantUnbind) || identity.calls != 3 {
		t.Fatalf("SetPublicPort unbind order = %v, identity calls=%d; want %v, 3", events, identity.calls, wantUnbind)
	}
	if open, _ := client.publicPortState(context.Background(), group, tags, 8080); open {
		t.Fatal("service port was not revoked")
	}
}

func TestSDKSetPublicPortStopsOnAccountDriftAtMutationBoundaries(t *testing.T) {
	tags := ResourceTags{"worker": "worker-1"}
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
			ec2Probe := &mutationProbeEC2{group: securityGroupFixture(tags), events: &events}
			identity := &identityProbeSTS{accounts: test.accounts, events: &events}
			client := newSDK("ap-east-1", ec2Probe, identity, staticIP{})
			err := client.SetPublicPort(context.Background(), credentialFixture(), SecurityGroup{ID: "sg-1", Name: "worker"}, tags, 8080, true)
			if !errors.Is(err, ErrIdentity) || !slices.Equal(events, test.want) || ec2Probe.authorizeCalls != test.writes || identity.calls != len(test.accounts) {
				t.Fatalf("SetPublicPort error=%v order=%v writes=%d verifies=%d; want ErrIdentity, %v, %d, %d", err, events, ec2Probe.authorizeCalls, identity.calls, test.want, test.writes, len(test.accounts))
			}
		})
	}
}

func TestSDKSetPublicPortRejectsWrongTagsWithoutMutation(t *testing.T) {
	probe := &mutationProbeEC2{group: securityGroupFixture(ResourceTags{"worker": "other"})}
	client := newSDK("ap-east-1", probe, stubSTS{}, staticIP{})
	err := client.SetPublicPort(context.Background(), credentialFixture(), SecurityGroup{ID: "sg-1", Name: "worker"}, ResourceTags{"worker": "worker-1"}, 8080, true)
	if !errors.Is(err, ErrIdentity) || probe.authorizeCalls != 0 {
		t.Fatalf("SetPublicPort error=%v writes=%d", err, probe.authorizeCalls)
	}
}

func TestSDKDestroyMutationsRequireExactResourceAndReadBack(t *testing.T) {
	tags := ResourceTags{"worker": "worker-1"}
	auth := DestroyAuthorization{Authorized: true, Proof: "destroy-1"}
	t.Run("key pair", func(t *testing.T) {
		events := []string{}
		probe := &mutationProbeEC2{key: &ec2types.KeyPairInfo{KeyPairId: aws.String("key-1"), KeyName: aws.String("worker"), Tags: sdkTags(tags)}, events: &events}
		identity := &identityProbeSTS{events: &events}
		client := newSDK("ap-east-1", probe, identity, staticIP{})
		if err := client.DeleteKeyPair(context.Background(), credentialFixture(), auth, KeyPair{ID: "key-1", Name: "worker"}, tags); err != nil {
			t.Fatal(err)
		}
		want := []string{"verify", "read", "verify", "delete", "verify", "read"}
		if !slices.Equal(events, want) || probe.deleteKeyCalls != 1 {
			t.Fatalf("events=%v writes=%d want=%v,1", events, probe.deleteKeyCalls, want)
		}
	})
	t.Run("security group", func(t *testing.T) {
		events := []string{}
		probe := &mutationProbeEC2{group: securityGroupFixture(tags), events: &events}
		identity := &identityProbeSTS{events: &events}
		client := newSDK("ap-east-1", probe, identity, staticIP{})
		if err := client.DeleteSecurityGroup(context.Background(), credentialFixture(), auth, SecurityGroup{ID: "sg-1", Name: "worker"}, tags); err != nil {
			t.Fatal(err)
		}
		want := []string{"verify", "read", "verify", "delete", "verify", "read"}
		if !slices.Equal(events, want) || probe.deleteGroupCalls != 1 {
			t.Fatalf("events=%v writes=%d want=%v,1", events, probe.deleteGroupCalls, want)
		}
	})
	t.Run("instance", func(t *testing.T) {
		events := []string{}
		raw := instanceFixture(tags)
		probe := &mutationProbeEC2{instance: &raw, events: &events}
		identity := &identityProbeSTS{events: &events}
		client := newSDK("ap-east-1", probe, identity, staticIP{})
		if err := client.TerminateInstance(context.Background(), credentialFixture(), auth, sdkInstance(raw), tags); err != nil {
			t.Fatal(err)
		}
		want := []string{"verify", "read", "verify", "terminate", "verify", "read"}
		if !slices.Equal(events, want) || probe.terminateCalls != 1 {
			t.Fatalf("events=%v writes=%d want=%v,1", events, probe.terminateCalls, want)
		}
	})
}

func TestSDKDestroyRetryAcceptsAlreadyAbsentResourceAfterAuthorization(t *testing.T) {
	tags := ResourceTags{"worker": "worker-1"}
	auth := DestroyAuthorization{Authorized: true, Proof: "destroy-1"}
	for _, test := range []struct {
		name    string
		destroy func(*SDK) error
		writes  func(*mutationProbeEC2) int
	}{
		{"key pair", func(client *SDK) error {
			return client.DeleteKeyPair(context.Background(), credentialFixture(), auth, KeyPair{ID: "key-1", Name: "worker"}, tags)
		}, func(probe *mutationProbeEC2) int { return probe.deleteKeyCalls }},
		{"security group", func(client *SDK) error {
			return client.DeleteSecurityGroup(context.Background(), credentialFixture(), auth, SecurityGroup{ID: "sg-1", Name: "worker"}, tags)
		}, func(probe *mutationProbeEC2) int { return probe.deleteGroupCalls }},
		{"instance", func(client *SDK) error {
			return client.TerminateInstance(context.Background(), credentialFixture(), auth, Instance{ID: "i-1"}, tags)
		}, func(probe *mutationProbeEC2) int { return probe.terminateCalls }},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			probe := &mutationProbeEC2{events: &events}
			identity := &identityProbeSTS{events: &events}
			if err := test.destroy(newSDK("ap-east-1", probe, identity, staticIP{})); err != nil {
				t.Fatal(err)
			}
			if want := []string{"verify", "read"}; !slices.Equal(events, want) || identity.calls != 1 || test.writes(probe) != 0 {
				t.Fatalf("events=%v verifies=%d writes=%d want=%v,1,0", events, identity.calls, test.writes(probe), want)
			}
		})
	}
}

func TestSDKDestroyAbsentResourceStillRequiresAuthorization(t *testing.T) {
	probe := &mutationProbeEC2{}
	identity := &identityProbeSTS{}
	err := newSDK("ap-east-1", probe, identity, staticIP{}).DeleteKeyPair(context.Background(), credentialFixture(), DestroyAuthorization{}, KeyPair{ID: "key-1", Name: "worker"}, ResourceTags{"worker": "worker-1"})
	if !errors.Is(err, ErrNotAuthorized) || identity.calls != 0 || probe.deleteKeyCalls != 0 {
		t.Fatalf("error=%v verifies=%d writes=%d", err, identity.calls, probe.deleteKeyCalls)
	}
}

func TestSDKDestroyRejectsMismatchedResourceWithoutMutation(t *testing.T) {
	tags := ResourceTags{"worker": "worker-1"}
	wrongTags := ResourceTags{"worker": "other"}
	auth := DestroyAuthorization{Authorized: true, Proof: "destroy-1"}
	for _, test := range []struct {
		name string
		key  ec2types.KeyPairInfo
	}{
		{"wrong ID", ec2types.KeyPairInfo{KeyPairId: aws.String("key-other"), KeyName: aws.String("worker"), Tags: sdkTags(tags)}},
		{"wrong name", ec2types.KeyPairInfo{KeyPairId: aws.String("key-1"), KeyName: aws.String("other"), Tags: sdkTags(tags)}},
		{"wrong tags", ec2types.KeyPairInfo{KeyPairId: aws.String("key-1"), KeyName: aws.String("worker"), Tags: sdkTags(wrongTags)}},
	} {
		t.Run("key pair "+test.name, func(t *testing.T) {
			probe := &mutationProbeEC2{key: &test.key}
			err := newSDK("ap-east-1", probe, stubSTS{}, staticIP{}).DeleteKeyPair(context.Background(), credentialFixture(), auth, KeyPair{ID: "key-1", Name: "worker"}, tags)
			if !errors.Is(err, ErrIdentity) || probe.deleteKeyCalls != 0 {
				t.Fatalf("error=%v writes=%d", err, probe.deleteKeyCalls)
			}
		})
	}
	for _, test := range []struct {
		name  string
		group ec2types.SecurityGroup
	}{
		{"wrong ID", ec2types.SecurityGroup{GroupId: aws.String("sg-other"), GroupName: aws.String("worker"), Tags: sdkTags(tags)}},
		{"wrong name", ec2types.SecurityGroup{GroupId: aws.String("sg-1"), GroupName: aws.String("other"), Tags: sdkTags(tags)}},
		{"wrong tags", securityGroupFixture(wrongTags)},
	} {
		t.Run("security group "+test.name, func(t *testing.T) {
			probe := &mutationProbeEC2{group: test.group}
			err := newSDK("ap-east-1", probe, stubSTS{}, staticIP{}).DeleteSecurityGroup(context.Background(), credentialFixture(), auth, SecurityGroup{ID: "sg-1", Name: "worker"}, tags)
			if !errors.Is(err, ErrIdentity) || probe.deleteGroupCalls != 0 {
				t.Fatalf("error=%v writes=%d", err, probe.deleteGroupCalls)
			}
		})
	}
	raw := instanceFixture(tags)
	instanceProbe := &mutationProbeEC2{instance: &raw}
	changed := sdkInstance(raw)
	changed.PublicIP = "203.0.113.99"
	if err := newSDK("ap-east-1", instanceProbe, stubSTS{}, staticIP{}).TerminateInstance(context.Background(), credentialFixture(), auth, changed, tags); !errors.Is(err, ErrIdentity) || instanceProbe.terminateCalls != 0 {
		t.Fatalf("instance error=%v writes=%d", err, instanceProbe.terminateCalls)
	}
	raw = instanceFixture(wrongTags)
	instanceProbe = &mutationProbeEC2{instance: &raw}
	if err := newSDK("ap-east-1", instanceProbe, stubSTS{}, staticIP{}).TerminateInstance(context.Background(), credentialFixture(), auth, sdkInstance(raw), tags); !errors.Is(err, ErrIdentity) || instanceProbe.terminateCalls != 0 {
		t.Fatalf("instance tags error=%v writes=%d", err, instanceProbe.terminateCalls)
	}
}

func TestSDKDeleteStopsOnAccountDriftAtMutationBoundaries(t *testing.T) {
	tags := ResourceTags{"worker": "worker-1"}
	for _, test := range []struct {
		name     string
		accounts []string
		writes   int
	}{
		{"before write", []string{"123456789012", "999999999999"}, 0},
		{"after write", []string{"123456789012", "123456789012", "999999999999"}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &mutationProbeEC2{key: &ec2types.KeyPairInfo{KeyPairId: aws.String("key-1"), KeyName: aws.String("worker"), Tags: sdkTags(tags)}}
			identity := &identityProbeSTS{accounts: test.accounts}
			err := newSDK("ap-east-1", probe, identity, staticIP{}).DeleteKeyPair(context.Background(), credentialFixture(), DestroyAuthorization{Authorized: true, Proof: "destroy-1"}, KeyPair{ID: "key-1", Name: "worker"}, tags)
			if !errors.Is(err, ErrIdentity) || probe.deleteKeyCalls != test.writes || identity.calls != len(test.accounts) {
				t.Fatalf("error=%v writes=%d verifies=%d", err, probe.deleteKeyCalls, identity.calls)
			}
		})
	}
}

func securityGroupFixture(tags ResourceTags) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{GroupId: aws.String("sg-1"), GroupName: aws.String("worker"), Tags: sdkTags(tags)}
}

func instanceFixture(tags ResourceTags) ec2types.Instance {
	return ec2types.Instance{InstanceId: aws.String("i-1"), ClientToken: aws.String("token-1"), PrivateIpAddress: aws.String("10.0.0.1"),
		PublicIpAddress: aws.String("203.0.113.20"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}, Tags: sdkTags(tags)}
}

package cloudapp

import (
	"context"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

type activePlacementOpener struct {
	credentials awsprovider.SourceCredentials
	binding     awsfoundation.SourceCredentialBinding
	calls       int
}

func (opener *activePlacementOpener) Open(_ context.Context, binding awsfoundation.SourceCredentialBinding) (awsprovider.SourceCredentials, error) {
	opener.calls++
	opener.binding = binding
	return awsprovider.SourceCredentials{
		AccessKeyID: append([]byte(nil), opener.credentials.AccessKeyID...), SecretAccessKey: append([]byte(nil), opener.credentials.SecretAccessKey...),
	}, nil
}

type activePlacementPort struct {
	result  awsprovider.PlacementV1
	request awsprovider.PlacementRequestV1
	calls   int
}

func (port *activePlacementPort) Resolve(_ context.Context, request awsprovider.PlacementRequestV1) (awsprovider.PlacementV1, error) {
	port.calls++
	port.request = request
	return port.result, nil
}

type activePlacementFactory struct {
	port       PlacementPort
	region     string
	roleARN    string
	session    string
	source     *awsprovider.SourceCredentials
	sourceSeen bool
	calls      int
}

func (factory *activePlacementFactory) NewPlacementPort(region string, source *awsprovider.SourceCredentials, roleARN, roleSessionName string) (PlacementPort, error) {
	factory.calls++
	factory.region, factory.roleARN, factory.session = region, roleARN, roleSessionName
	factory.source = source
	factory.sourceSeen = source != nil && len(source.AccessKeyID) != 0 && len(source.SecretAccessKey) != 0
	return factory.port, nil
}

func TestActivePlacementUsesOnlyBoundControlRoleAndWipesSourceCredential(t *testing.T) {
	connection := activePlacementConnection(t)
	request := ActivePlacementRequestV1{
		OwnerID: connection.OwnerID, ConnectionID: connection.ConnectionID,
		Placement: awsprovider.PlacementRequestV1{Requirements: recipe.ResourceRequirementsV1{
			MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64,
		}, PublicIPv4: true, RuntimeHoursPerMonth: 730},
	}
	opener := &activePlacementOpener{credentials: awsprovider.SourceCredentials{
		AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("synthetic-source-secret-material-000000"),
	}}
	port := &activePlacementPort{result: awsprovider.PlacementV1{Region: connection.Region}}
	factory := &activePlacementFactory{port: port}
	resolver, err := NewAWSActivePlacementResolver(testAgentID, opener, factory)
	if err != nil {
		t.Fatal(err)
	}

	got, err := resolver.Resolve(context.Background(), connection, request)
	if err != nil {
		t.Fatal(err)
	}
	if got.Region != connection.Region || opener.calls != 1 || factory.calls != 1 || port.calls != 1 || !factory.sourceSeen {
		t.Fatalf("result=%#v opener=%d factory=%d port=%d source_seen=%v", got, opener.calls, factory.calls, port.calls, factory.sourceSeen)
	}
	if factory.region != connection.Region || factory.roleARN != connection.ControlRoleARN || !strings.HasPrefix(factory.session, "dtx-place-") {
		t.Fatalf("factory binding region=%q role=%q session=%q", factory.region, factory.roleARN, factory.session)
	}
	if factory.source == nil || len(factory.source.AccessKeyID) != 0 || len(factory.source.SecretAccessKey) != 0 {
		t.Fatal("source credential was not wiped after placement discovery")
	}
	if opener.binding.AgentInstanceID != testAgentID || opener.binding.AccountID != connection.AccountID || opener.binding.Region != connection.Region {
		t.Fatalf("credential binding=%#v", opener.binding)
	}
}

func TestActivePlacementRejectsUntrustedConnectionBeforeCredentialUse(t *testing.T) {
	valid := activePlacementConnection(t)
	tests := []struct {
		name   string
		mutate func(*Connection, *ActivePlacementRequestV1)
	}{
		{name: "inactive", mutate: func(connection *Connection, _ *ActivePlacementRequestV1) { connection.Status = "pending" }},
		{name: "owner drift", mutate: func(_ *Connection, request *ActivePlacementRequestV1) { request.OwnerID = "other-owner" }},
		{name: "connection drift", mutate: func(_ *Connection, request *ActivePlacementRequestV1) {
			request.ConnectionID = "b57af865-4e70-4a72-8b40-f13df4285c60"
		}},
		{name: "foundation drift", mutate: func(connection *Connection, _ *ActivePlacementRequestV1) {
			connection.FoundationStack = "untrusted-stack"
		}},
		{name: "role drift", mutate: func(connection *Connection, _ *ActivePlacementRequestV1) {
			connection.ControlRoleARN = "arn:aws:iam::123456789012:role/Admin"
		}},
		{name: "invalid usage", mutate: func(_ *Connection, request *ActivePlacementRequestV1) {
			request.Placement.RuntimeHoursPerMonth = 0
		}},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			connection := valid
			request := ActivePlacementRequestV1{OwnerID: connection.OwnerID, ConnectionID: connection.ConnectionID, Placement: awsprovider.PlacementRequestV1{
				Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64}, PublicIPv4: true, RuntimeHoursPerMonth: 730,
			}}
			current.mutate(&connection, &request)
			opener := &activePlacementOpener{}
			resolver, err := NewAWSActivePlacementResolver(testAgentID, opener, &activePlacementFactory{port: &activePlacementPort{}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = resolver.Resolve(context.Background(), connection, request); err == nil {
				t.Fatal("expected invalid active placement binding")
			}
			if opener.calls != 0 {
				t.Fatalf("credential opened %d times", opener.calls)
			}
		})
	}
}

func activePlacementConnection(t *testing.T) Connection {
	t.Helper()
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: testAgentID, Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	return Connection{
		ConnectionID: "0f0d3b95-a044-42be-a7f4-d758277e4b4b", OwnerID: "owner-1", AccountID: "123456789012", Region: "us-east-1",
		ControlRoleARN:  "arn:aws:iam::123456789012:role/" + spec.ControlRoleName,
		FoundationStack: "arn:aws:cloudformation:us-east-1:123456789012:stack/" + spec.StackName + "/01234567-89ab-4def-8123-456789abcdef",
		Status:          "active", Revision: 1,
	}
}

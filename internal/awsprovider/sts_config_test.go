package awsprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

func TestAssumedControlAWSConfigUsesFixedShortSession(t *testing.T) {
	expires := time.Now().UTC().Add(controlSessionDuration)
	client := &fakeAssumeRole{output: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("ASIAABCDEFGHIJKLMNOP"), SecretAccessKey: aws.String("temporary-secret-access-key-value-123"), SessionToken: aws.String("temporary-session-token"), Expiration: aws.Time(expires),
	}}}
	source := &SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("source-secret-access-key-value-123456")}
	config, err := AssumedControlAWSConfigWithSTS("us-east-1", source, "arn:aws:iam::123456789012:role/dtx-agent-0123456789ab-control", "dtx-runtime-01", client)
	if err != nil {
		t.Fatalf("assumed config: %v", err)
	}
	credentials, err := config.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if credentials.AccessKeyID != "ASIAABCDEFGHIJKLMNOP" || credentials.SessionToken == "" || client.input == nil || aws.ToString(client.input.RoleArn) != "arn:aws:iam::123456789012:role/dtx-agent-0123456789ab-control" || aws.ToString(client.input.RoleSessionName) != "dtx-runtime-01" || aws.ToInt32(client.input.DurationSeconds) != int32(controlSessionDuration/time.Second) {
		t.Fatalf("unexpected AssumeRole contract: credentials=%#v input=%#v", credentials, client.input)
	}
}

func TestAssumedControlAWSConfigRejectsArbitraryRoleAndRedactsSTSFailure(t *testing.T) {
	source := &SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("source-secret-access-key-value-123456")}
	if _, err := AssumedControlAWSConfigWithSTS("us-east-1", source, "arn:aws:iam::123456789012:role/Admin", "dtx-runtime-01", &fakeAssumeRole{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("arbitrary role error = %v", err)
	}
	secret := "source-secret-must-not-leak"
	client := &fakeAssumeRole{err: &smithy.GenericAPIError{Code: "AccessDenied", Message: secret}}
	config, err := AssumedControlAWSConfigWithSTS("us-east-1", source, "arn:aws:iam::123456789012:role/dtx-agent-0123456789ab-control", "dtx-runtime-01", client)
	if err != nil {
		t.Fatal(err)
	}
	_, err = config.Credentials.Retrieve(context.Background())
	if !errors.Is(err, ErrPermissionDenied) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe AssumeRole error = %v", err)
	}
}

type fakeAssumeRole struct {
	input  *sts.AssumeRoleInput
	output *sts.AssumeRoleOutput
	err    error
}

func (client *fakeAssumeRole) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	client.input = input
	return client.output, client.err
}

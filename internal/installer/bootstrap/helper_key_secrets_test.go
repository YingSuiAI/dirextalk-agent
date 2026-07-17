package bootstrap

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
)

func TestHelperKeyCanaryCallsExactGetSecretValueWithoutDescribe(t *testing.T) {
	client := &canarySecretsFake{}
	access, _ := NewHelperKeySecretsAccess(client)
	source := RootHelperKeySourceV1{SecretARN: "arn:secret:exact", VersionID: "version-exact"}
	err := access.CanaryRootHelperKey(context.Background(), source)
	if !accessDenied(err) || client.gets != 1 || client.describes != 0 ||
		client.secretID != source.SecretARN || client.versionID != source.VersionID {
		t.Fatalf("err=%v gets=%d describes=%d secret=%q version=%q", err, client.gets, client.describes, client.secretID, client.versionID)
	}
}

type canarySecretsFake struct {
	gets, describes     int
	secretID, versionID string
}

func (f *canarySecretsFake) DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	f.describes++
	return nil, nil
}

func (f *canarySecretsFake) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.gets++
	f.secretID, f.versionID = *input.SecretId, *input.VersionId
	return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}
}

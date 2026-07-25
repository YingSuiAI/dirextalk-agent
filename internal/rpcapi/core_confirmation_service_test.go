package rpcapi

import (
	"strings"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

func TestConfirmationProtoMapsSecretGrants(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	d := coreconfirmation.Digest(strings.Repeat("a", 64))
	c := coreconfirmation.Confirmation{ConfirmationID: id, Binding: coreconfirmation.Binding{OperationDomain: "aws", TargetID: id, TargetRevision: 1, SourceVersion: "v1", ContentDigest: d, ParameterDigest: d, NetworkDigest: d, SecretGrantDigest: d, SecretGrants: []coreconfirmation.SecretGrant{{ReferenceID: id, Purpose: coreconfirmation.SecretPurposeAWSCredential, BindingDigest: d}}}}
	out := confirmationProto(c)
	if len(out.GetBinding().GetSecretGrants()) != 1 || out.GetBinding().GetSecretGrants()[0].GetReferenceId() != id || out.GetBinding().GetSecretGrants()[0].GetPurpose() != agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_AWS_CREDENTIAL {
		t.Fatalf("secret grants not mapped: %+v", out.GetBinding().GetSecretGrants())
	}
}

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/google/uuid"
)

type credentialStore struct{ value coreaws.Credentials }

func (s credentialStore) GetCredential(context.Context, string) (coreaws.Credentials, error) {
	return s.value, nil
}

func TestDurableCredentialResolverRequiresVerifiedCurrentRevision(t *testing.T) {
	id := uuid.NewString()
	now := time.Now().UTC()
	base := coreaws.RehydrateCredentials(id, "prod", "us-east-1", "123456789012", "arn:aws:iam::123456789012:user/prod", []byte("AKIA"), []byte("secret"), nil, 1, 1, now, now)
	r, err := NewCredentialResolver(credentialStore{value: base})
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.ResolveCredential(context.Background(), id)
	if err != nil || h.SecretAccessKey != "secret" || h.ReferenceID != id {
		t.Fatalf("handle=%+v err=%v", h, err)
	}
	raw, _ := json.Marshal(h)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "AKIA") {
		t.Fatalf("credential secret serialized: %s", raw)
	}
	for _, c := range []coreaws.Credentials{
		coreaws.RehydrateCredentials(id, "prod", "us-east-1", "123456789012", "", []byte("AKIA"), []byte("secret"), nil, 0, 1, now, now),
		coreaws.RehydrateCredentials(id, "prod", "us-east-1", "123456789012", "", []byte("AKIA"), []byte("rotated"), nil, 1, 2, now, now),
	} {
		bad, _ := NewCredentialResolver(credentialStore{value: c})
		if _, err := bad.ResolveCredential(context.Background(), id); !errors.Is(err, ErrPrecondition) {
			t.Fatalf("unverified/rotated credential accepted: %v", err)
		}
	}
}

func TestCanonicalSecretResolverAndTargetBinding(t *testing.T) {
	r := CanonicalSecretReference{}
	arn, err := r.ResolveSecretReference(context.Background(), "arn:aws:ssm:us-east-1:123456789012:parameter/app/token")
	if err != nil || arn == "" {
		t.Fatalf("canonical ARN rejected: %q %v", arn, err)
	}
	for _, value := range []string{"plaintext", "arn:aws:ssm:us-east-1:123456789012:wrong/x", "arn:aws:secretsmanager:us-east-1:123456789012:secret:x//bad"} {
		if _, err := r.ResolveSecretReference(context.Background(), value); err == nil {
			t.Fatalf("invalid ARN accepted: %q", value)
		}
	}
	if err := ValidateSecretARNForTarget(arn, "us-east-1", "123456789012"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecretARNForTarget(arn, "us-west-2", "123456789012"); err == nil {
		t.Fatal("cross-region ARN accepted")
	}
	gov := "arn:aws-us-gov:ssm:us-gov-west-1:123456789012:parameter/app/token"
	if err := ValidateSecretARNForTarget(gov, "us-gov-west-1", "123456789012"); err != nil {
		t.Fatalf("gov partition rejected: %v", err)
	}
	if err := ValidateSecretARNForTarget(arn, "cn-north-1", "123456789012"); err == nil {
		t.Fatal("commercial partition accepted for China region")
	}
	if _, err := r.ResolveSecretReferenceExact(context.Background(), uuid.NewString(), coreconfirmation.SecretPurposeSkillSecret, coreconfirmation.Digest(coreworkload.SecretGrantBindingDigest(arn, coreconfirmation.SecretPurposeSkillSecret))); err == nil {
		t.Fatal("UUID secret reference accepted")
	}
	if _, err := r.ResolveSecretReferenceExact(context.Background(), arn, coreconfirmation.SecretPurposeSkillSecret, "bad"); err == nil {
		t.Fatal("invalid binding accepted")
	}
	if _, err := r.ResolveSecretReferenceExact(context.Background(), arn, coreconfirmation.SecretPurposeSkillSecret, coreconfirmation.Digest(coreworkload.SecretGrantBindingDigest(arn, coreconfirmation.SecretPurposeSkillSecret))); err != nil {
		t.Fatalf("derived binding rejected: %v", err)
	}
}

func TestResolveApplicationRefsRejectsUUIDAndRequiresExactARNBinding(t *testing.T) {
	arn := "arn:aws:ssm:us-east-1:123456789012:parameter/app/token"
	purpose := coreconfirmation.SecretPurposeSkillSecret
	plan := coreworkload.Plan{Target: coreworkload.TargetSettings{Region: "us-east-1", AccountID: "123456789012"}, SecretGrantRefs: []coreworkload.SecretGrantRef{{ReferenceID: arn, Purpose: purpose, BindingDigest: coreconfirmation.Digest(coreworkload.SecretGrantBindingDigest(arn, purpose))}}}
	if err := ResolveApplicationRefs(context.Background(), plan, CanonicalSecretReference{}); err != nil {
		t.Fatalf("exact ARN resolver rejected: %v", err)
	}
	plan.SecretGrantRefs[0].ReferenceID = uuid.NewString()
	if err := ResolveApplicationRefs(context.Background(), plan, CanonicalSecretReference{}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("UUID application reference accepted: %v", err)
	}
}

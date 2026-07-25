// Package aws contains typed, opt-in AWS workload providers. It deliberately
// exposes no generic AWS operation or endpoint override.
package aws

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
)

var (
	ErrInvalid      = coreworkload.ErrInvalid
	ErrProvider     = coreworkload.ErrProvider
	ErrUncertain    = errors.New("coreworkload/aws: provider response uncertain")
	ErrPrecondition = errors.New("coreworkload/aws: precondition failed")
)

// CredentialHandle is populated by the Agent credential store. Providers
// accept this handle only; they never consult environment, profile, IMDS, or
// endpoint overrides.
type CredentialHandle struct {
	ReferenceID                                string
	Region, AccountID                          string
	AccessKeyID, SecretAccessKey, SessionToken string
}

func (h CredentialHandle) Validate() error {
	if strings.TrimSpace(h.ReferenceID) == "" || strings.TrimSpace(h.Region) == "" || strings.TrimSpace(h.AccountID) == "" || h.AccessKeyID == "" || h.SecretAccessKey == "" {
		return ErrInvalid
	}
	return nil
}

type CredentialResolver interface {
	ResolveCredential(context.Context, string) (CredentialHandle, error)
}
type SecretResolver interface {
	ResolveSecretReference(context.Context, string) (string, error)
}

func credentialRef(plan coreworkload.Plan) (string, error) {
	var ref string
	for _, grant := range plan.SecretGrantRefs {
		if grant.Purpose != coreconfirmation.SecretPurposeAWSCredential {
			continue
		}
		if ref != "" || strings.TrimSpace(grant.ReferenceID) == "" {
			return "", ErrInvalid
		}
		ref = grant.ReferenceID
	}
	if ref == "" {
		return "", ErrPrecondition
	}
	return ref, nil
}

func resolveApplicationRefs(ctx context.Context, plan coreworkload.Plan, resolver SecretResolver) error {
	for _, grant := range plan.SecretGrantRefs {
		if grant.Purpose == coreconfirmation.SecretPurposeAWSCredential {
			continue
		}
		if resolver == nil {
			return ErrPrecondition
		}
		arn, err := resolver.ResolveSecretReference(ctx, grant.ReferenceID)
		if err != nil || !validSecretARN(arn) {
			return ErrPrecondition
		}
	}
	return nil
}

func validSecretARN(v string) bool {
	return strings.HasPrefix(strings.TrimSpace(v), "arn:aws:secretsmanager:") || strings.HasPrefix(strings.TrimSpace(v), "arn:aws:ssm:")
}

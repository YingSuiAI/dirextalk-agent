package postgres

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
)

// NewCoreWorkloadCredentialResolver exposes the durable CoreAWS credential
// read path through the workload provider's verified, non-caching adapter.
func NewCoreWorkloadCredentialResolver(s *CoreAWSStore) (aws.CredentialResolver, error) {
	return aws.NewCredentialResolver(s)
}

// CoreWorkloadSecretResolver is reference-only by design. Agent-owned AWS
// workload plans carry canonical ARN references; no secret bytes are read.
type CoreWorkloadSecretResolver struct{}

func NewCoreWorkloadSecretResolver() aws.SecretResolver { return CoreWorkloadSecretResolver{} }

func (CoreWorkloadSecretResolver) ResolveSecretReference(ctx context.Context, ref string) (string, error) {
	return aws.CanonicalSecretReference{}.ResolveSecretReference(ctx, ref)
}

func (CoreWorkloadSecretResolver) ResolveSecretReferenceExact(ctx context.Context, ref string, purpose coreconfirmation.SecretPurpose, binding coreconfirmation.Digest) (string, error) {
	return aws.CanonicalSecretReference{}.ResolveSecretReferenceExact(ctx, ref, purpose, binding)
}

package postgres

import "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"

// NewAWSCredentialResolver exposes verified current and exact historical AWS
// credential revisions without caching secret material.
func NewAWSCredentialResolver(store *CoreAWSStore) (awscredential.CredentialResolver, error) {
	return awscredential.NewCredentialResolver(store)
}

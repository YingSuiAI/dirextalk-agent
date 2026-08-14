// Package awscredential exposes the verified AWS credential boundary shared
// by Cloud Worker pricing, selection, and execution.
package awscredential

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/google/uuid"
)

var (
	ErrInvalid      = errors.New("awscredential: invalid input")
	ErrPrecondition = errors.New("awscredential: precondition failed")
)

// CredentialHandle contains the exact credential revision resolved for one
// operation. It never falls back to environment, profile, or instance-role
// credentials.
type CredentialHandle struct {
	ReferenceID                                string
	Region, AccountID                          string
	PrincipalARN                               string
	AccessKeyID, SecretAccessKey, SessionToken string
}

func (handle CredentialHandle) Validate() error {
	if strings.TrimSpace(handle.ReferenceID) == "" || strings.TrimSpace(handle.Region) == "" || strings.TrimSpace(handle.AccountID) == "" || strings.TrimSpace(handle.PrincipalARN) == "" || handle.AccessKeyID == "" || handle.SecretAccessKey == "" {
		return ErrInvalid
	}
	return nil
}

func (CredentialHandle) String() string   { return "[redacted-aws-credential]" }
func (CredentialHandle) GoString() string { return "awscredential.CredentialHandle{[redacted]}" }
func (handle CredentialHandle) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ReferenceID, Region, AccountID, PrincipalARN string
		HasAccessKey, HasSecretKey, HasSessionToken  bool
	}{handle.ReferenceID, handle.Region, handle.AccountID, handle.PrincipalARN, handle.AccessKeyID != "", handle.SecretAccessKey != "", handle.SessionToken != ""})
}

type CredentialResolver interface {
	ResolveCredential(context.Context, string) (CredentialHandle, error)
}

type CredentialRevisionResolver interface {
	CredentialRevision(context.Context, string) (uint64, error)
}

// ExactCredentialResolver resolves an immutable revision already bound to a
// confirmed Worker operation. Disabled or rotated revisions are unavailable
// to new work but remain resolvable by their exact binding.
type ExactCredentialResolver interface {
	ResolveCredentialRevision(context.Context, string, uint64) (CredentialHandle, error)
}

type CredentialStore interface {
	GetCredential(context.Context, string) (coreaws.Credentials, error)
	GetCredentialRevision(context.Context, string, int64) (coreaws.Credentials, error)
}

type DurableCredentialResolver struct{ store CredentialStore }

func NewCredentialResolver(store CredentialStore) (*DurableCredentialResolver, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &DurableCredentialResolver{store: store}, nil
}

func (resolver *DurableCredentialResolver) ResolveCredential(ctx context.Context, referenceID string) (CredentialHandle, error) {
	if resolver == nil || resolver.store == nil || !canonicalUUID(referenceID) {
		return CredentialHandle{}, ErrPrecondition
	}
	credential, err := resolver.store.GetCredential(ctx, referenceID)
	return credentialHandle(referenceID, credential, err)
}

func (resolver *DurableCredentialResolver) ResolveCredentialRevision(ctx context.Context, referenceID string, revision uint64) (CredentialHandle, error) {
	if resolver == nil || resolver.store == nil || !canonicalUUID(referenceID) || revision == 0 || revision > uint64(^uint64(0)>>1) {
		return CredentialHandle{}, ErrPrecondition
	}
	credential, err := resolver.store.GetCredentialRevision(ctx, referenceID, int64(revision))
	if err == nil && uint64(credential.Revision) != revision {
		err = ErrPrecondition
	}
	return credentialHandle(referenceID, credential, err)
}

func (resolver *DurableCredentialResolver) CredentialRevision(ctx context.Context, referenceID string) (uint64, error) {
	if resolver == nil || resolver.store == nil || !canonicalUUID(referenceID) {
		return 0, ErrPrecondition
	}
	credential, err := resolver.store.GetCredential(ctx, referenceID)
	if err != nil || credential.ID != referenceID || credential.Revision <= 0 || credential.VerifiedRevision != credential.Revision {
		return 0, ErrPrecondition
	}
	return uint64(credential.Revision), nil
}

func credentialHandle(referenceID string, credential coreaws.Credentials, err error) (CredentialHandle, error) {
	if err != nil || credential.ID != referenceID || credential.Revision <= 0 || credential.VerifiedRevision != credential.Revision || strings.TrimSpace(credential.Region) == "" || strings.TrimSpace(credential.AccountID) == "" || strings.TrimSpace(credential.UserARN) == "" {
		return CredentialHandle{}, ErrPrecondition
	}
	accessKeyID, secretAccessKey, sessionToken := credential.StoredSecretBytes()
	handle := CredentialHandle{
		ReferenceID: referenceID, Region: credential.Region, AccountID: credential.AccountID,
		PrincipalARN: credential.UserARN, AccessKeyID: string(accessKeyID),
		SecretAccessKey: string(secretAccessKey), SessionToken: string(sessionToken),
	}
	if handle.Validate() != nil {
		return CredentialHandle{}, ErrPrecondition
	}
	return handle, nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

var (
	_ CredentialResolver         = (*DurableCredentialResolver)(nil)
	_ CredentialRevisionResolver = (*DurableCredentialResolver)(nil)
	_ ExactCredentialResolver    = (*DurableCredentialResolver)(nil)
)

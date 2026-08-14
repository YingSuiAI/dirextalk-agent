package coreaws

import "context"

// STSProvider verifies one explicitly supplied credential. It never consults
// ambient AWS configuration.
type STSProvider interface {
	GetCallerIdentity(context.Context, CredentialHandle) (Identity, error)
}

// FakeSTSProvider is retained only for credential-domain tests.
type FakeSTSProvider struct {
	AccountID string
	UserARN   string
}

func (f *FakeSTSProvider) GetCallerIdentity(_ context.Context, handle CredentialHandle) (Identity, error) {
	if handle.credential == nil || handle.credential.accessKeyID == "" || handle.credential.secretAccessKey == "" {
		return Identity{}, ErrProvider
	}
	account := f.AccountID
	if account == "" {
		account = "123456789012"
	}
	arn := f.UserARN
	if arn == "" {
		arn = "arn:aws:iam::" + account + ":user/dirextalk"
	}
	return Identity{AccountID: account, UserARN: arn, PrincipalID: "dirextalk"}, nil
}

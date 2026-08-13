package main

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

// cloudWorkerCredentialAuthority performs a fresh, double-revision-fenced
// read through the durable CoreAWS credential store. A verified sole active
// credential becomes proposal-ready immediately; no deployment binding is
// cached in process configuration.
type cloudWorkerCredentialAuthority struct {
	credentials workaws.CredentialResolver
	revisions   workaws.CredentialRevisionResolver
	exact       workaws.ExactCredentialResolver
	list        func(context.Context, int, string) (coreaws.CredentialPage, error)
}

func newCloudWorkerCredentialAuthority(
	credentials workaws.CredentialResolver,
	revisions workaws.CredentialRevisionResolver,
	exact workaws.ExactCredentialResolver,
	list func(context.Context, int, string) (coreaws.CredentialPage, error),
) (*cloudWorkerCredentialAuthority, error) {
	if credentials == nil || revisions == nil || exact == nil || list == nil {
		return nil, cloudworker.ErrInvalid
	}
	return &cloudWorkerCredentialAuthority{credentials: credentials, revisions: revisions, exact: exact, list: list}, nil
}

func (authority *cloudWorkerCredentialAuthority) ResolveCurrentAWSBinding(ctx context.Context) (cloudworker.AWSBinding, error) {
	if authority == nil || authority.credentials == nil || authority.revisions == nil || authority.exact == nil || ctx == nil {
		return cloudworker.AWSBinding{}, cloudworker.ErrInvalid
	}
	page, err := authority.list(ctx, 2, "")
	if err != nil || len(page.Items) != 1 || page.NextPageToken != "" {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	view := page.Items[0]
	if view.Revision <= 0 || view.VerifiedRevision != view.Revision || view.TestedAt.IsZero() {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	credentialID := view.ID
	before, err := authority.revisions.CredentialRevision(ctx, credentialID)
	if err != nil || before == 0 {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	credential, err := authority.credentials.ResolveCredential(ctx, credentialID)
	if err != nil {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	after, err := authority.revisions.CredentialRevision(ctx, credentialID)
	binding := cloudworker.AWSBinding{AccountID: credential.AccountID, Region: credential.Region,
		CredentialID: credential.ReferenceID, CredentialRevision: after}
	if err != nil || before != after || credential.Validate() != nil ||
		binding.AccountID != view.AccountID || binding.Region != view.Region || binding.CredentialID != view.ID ||
		int64(binding.CredentialRevision) != view.Revision {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	return binding, nil
}

func (authority *cloudWorkerCredentialAuthority) HasCurrentVerifiedAWSBinding(ctx context.Context) bool {
	if authority == nil || authority.list == nil || ctx == nil {
		return false
	}
	page, err := authority.list(ctx, 2, "")
	if err != nil || len(page.Items) != 1 || page.NextPageToken != "" {
		return false
	}
	view := page.Items[0]
	return view.Revision > 0 && view.VerifiedRevision == view.Revision && !view.TestedAt.IsZero()
}

func (authority *cloudWorkerCredentialAuthority) ResolveExactAWSBinding(ctx context.Context, expected cloudworker.AWSBinding) (cloudworker.AWSBinding, error) {
	_, err := authority.ResolveExactCredential(ctx, expected)
	if err != nil {
		return cloudworker.AWSBinding{}, err
	}
	return expected, nil
}

func (authority *cloudWorkerCredentialAuthority) ResolveExactCredential(ctx context.Context, expected cloudworker.AWSBinding) (workaws.CredentialHandle, error) {
	if authority == nil || authority.exact == nil || ctx == nil || expected.CredentialRevision == 0 {
		return workaws.CredentialHandle{}, cloudworker.ErrInvalid
	}
	credential, err := authority.exact.ResolveCredentialRevision(ctx, expected.CredentialID, expected.CredentialRevision)
	if err != nil {
		return workaws.CredentialHandle{}, cloudworker.ErrStaleAuthorization
	}
	if credential.Validate() != nil || credential.ReferenceID != expected.CredentialID ||
		credential.AccountID != expected.AccountID || credential.Region != expected.Region {
		return workaws.CredentialHandle{}, cloudworker.ErrStaleAuthorization
	}
	return credential, nil
}

// cloudWorkerAWSCredentialsProvider deliberately is not wrapped in the AWS SDK
// credentials cache. The SDK therefore calls Retrieve for every request, and
// every request repeats the durable double-revision and account/region fence
// before any signed AWS traffic can leave the process.
type cloudWorkerAWSCredentialsProvider struct {
	authority *cloudWorkerCredentialAuthority
	binding   cloudworker.AWSBinding
}

func newCloudWorkerAWSCredentialsProvider(authority *cloudWorkerCredentialAuthority, binding cloudworker.AWSBinding) (*cloudWorkerAWSCredentialsProvider, error) {
	if authority == nil || authority.exact == nil || binding.CredentialRevision == 0 {
		return nil, cloudworker.ErrInvalid
	}
	return &cloudWorkerAWSCredentialsProvider{authority: authority, binding: binding}, nil
}

func (provider *cloudWorkerAWSCredentialsProvider) Retrieve(ctx context.Context) (awssdk.Credentials, error) {
	if provider == nil || provider.authority == nil || ctx == nil {
		return awssdk.Credentials{}, cloudworker.ErrInvalid
	}
	credential, err := provider.authority.ResolveExactCredential(ctx, provider.binding)
	if err != nil {
		return awssdk.Credentials{}, err
	}
	resolved := awssdk.Credentials{
		AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey,
		SessionToken: credential.SessionToken, Source: "dirextalk-cloud-worker-durable",
	}
	credential.AccessKeyID = ""
	credential.SecretAccessKey = ""
	credential.SessionToken = ""
	return resolved, nil
}

var _ cloudworker.AWSBindingResolver = (*cloudWorkerCredentialAuthority)(nil)
var _ cloudworker.ExactAWSBindingResolver = (*cloudWorkerCredentialAuthority)(nil)
var _ awssdk.CredentialsProvider = (*cloudWorkerAWSCredentialsProvider)(nil)

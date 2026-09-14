package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

// cloudWorkerCredentialAuthority performs a fresh, double-revision-fenced
// read through the durable CoreAWS credential store. A verified sole active
// credential becomes proposal-ready immediately. New placement is selected
// after credential verification, never from its uploaded default Region.
type cloudWorkerCredentialAuthority struct {
	credentials workaws.CredentialResolver
	revisions   workaws.CredentialRevisionResolver
	exact       workaws.ExactCredentialResolver
	// list reads one credential scope: the empty room is the owner's own
	// credential set, a room is that group's. The scope never comes from a
	// model or tool argument, only from the authenticated turn origin.
	list      func(context.Context, string, int, string) (coreaws.CredentialPage, error)
	placement *cloudWorkerPlacement
}

func newCloudWorkerCredentialAuthority(
	credentials workaws.CredentialResolver,
	revisions workaws.CredentialRevisionResolver,
	exact workaws.ExactCredentialResolver,
	hostRegion string,
	list func(context.Context, string, int, string) (coreaws.CredentialPage, error),
) (*cloudWorkerCredentialAuthority, error) {
	regionConfig := config.Config{CoreCloudWorkerHostRegion: hostRegion}
	if credentials == nil || revisions == nil || exact == nil || list == nil ||
		config.ValidateCoreCloudWorker(&regionConfig) != nil {
		return nil, cloudworker.ErrInvalid
	}
	return &cloudWorkerCredentialAuthority{credentials: credentials, revisions: revisions, exact: exact, list: list, placement: newCloudWorkerPlacement(hostRegion)}, nil
}

func (authority *cloudWorkerCredentialAuthority) ResolveCurrentAWSBinding(ctx context.Context) (cloudworker.AWSBinding, error) {
	if authority == nil || authority.placement == nil || ctx == nil {
		return cloudworker.AWSBinding{}, cloudworker.ErrInvalid
	}
	// A verified-view eligibility read allows credential-free endpoint probing;
	// the full current credential fence must happen AFTER that network wait.
	if !authority.HasCurrentVerifiedAWSBinding(ctx) {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	region, err := authority.placement.region(ctx)
	if err != nil {
		return cloudworker.AWSBinding{}, err
	}
	binding, err := authority.resolveCurrentCredentialBinding(ctx)
	if err != nil {
		return cloudworker.AWSBinding{}, err
	}
	binding.Region = region
	return binding, nil
}

// A persisted operation's Region is immutable even after process restart or a
// new placement decision. Its account and current credential revision fences
// are identical to a new proposal's; its recorded Region is not new placement.
func (authority *cloudWorkerCredentialAuthority) resolveCurrentAWSBindingInRegion(ctx context.Context, region string) (cloudworker.AWSBinding, error) {
	if strings.TrimSpace(region) == "" {
		return cloudworker.AWSBinding{}, cloudworker.ErrInvalid
	}
	binding, err := authority.resolveCurrentCredentialBinding(ctx)
	if err != nil {
		return cloudworker.AWSBinding{}, err
	}
	binding.Region = region
	return binding, nil
}

func (authority *cloudWorkerCredentialAuthority) resolveCurrentCredentialBinding(ctx context.Context) (cloudworker.AWSBinding, error) {
	if authority == nil || authority.credentials == nil || authority.revisions == nil || authority.exact == nil || ctx == nil {
		return cloudworker.AWSBinding{}, cloudworker.ErrInvalid
	}
	view, err := authority.currentCredentialView(ctx)
	if err != nil {
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
	credentialBinding := cloudworker.AWSBinding{AccountID: credential.AccountID, Region: credential.Region,
		CredentialID: credential.ReferenceID, CredentialRevision: after}
	if err != nil || before != after || credential.Validate() != nil ||
		credentialBinding.AccountID != view.AccountID || credentialBinding.Region != view.Region || credentialBinding.CredentialID != view.ID ||
		int64(credentialBinding.CredentialRevision) != view.Revision {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	return credentialBinding, nil
}

// currentCredentialView resolves the single usable credential for this turn:
// the group's own credential when the turn belongs to a group that configured
// one, and the owner's credential otherwise. A group whose own credential exists
// but cannot be used fails closed instead of silently spending on the personal
// one; a group with no credential of its own keeps inheriting the owner's.
func (authority *cloudWorkerCredentialAuthority) currentCredentialView(ctx context.Context) (coreaws.CredentialView, error) {
	return authority.currentCredentialViewFor(ctx, cloudWorkerTurnRoom(ctx))
}

// currentCredentialViewFor resolves the credential of one explicit turn scope,
// so the inheritance and fail-closed rules are testable without forging a group
// turn context.
func (authority *cloudWorkerCredentialAuthority) currentCredentialViewFor(ctx context.Context, roomID string) (coreaws.CredentialView, error) {
	if roomID == "" {
		return authority.singleUsableCredential(ctx, "")
	}
	group, err := authority.singleUsableCredential(ctx, roomID)
	if err == nil {
		return group, nil
	}
	if errors.Is(err, errCloudWorkerCredentialUnconfigured) {
		// Inherited: the group has no cloud credential of its own.
		return authority.singleUsableCredential(ctx, "")
	}
	slog.Warn("[cloud-worker] group cloud credential unusable; refusing to spend with the owner's credential", "room_id", roomID, "error", groupAgentErrorSummary(err))
	return coreaws.CredentialView{}, err
}

// errCloudWorkerCredentialUnconfigured distinguishes "this scope has no
// credential" (which may inherit) from "this scope's credential is unusable"
// (which must fail closed).
var errCloudWorkerCredentialUnconfigured = errors.New("cloud worker credential is not configured for this scope")

func (authority *cloudWorkerCredentialAuthority) singleUsableCredential(ctx context.Context, roomID string) (coreaws.CredentialView, error) {
	page, err := authority.list(ctx, roomID, 2, "")
	if err != nil {
		return coreaws.CredentialView{}, err
	}
	if len(page.Items) == 0 && page.NextPageToken == "" {
		return coreaws.CredentialView{}, errCloudWorkerCredentialUnconfigured
	}
	if len(page.Items) != 1 || page.NextPageToken != "" {
		return coreaws.CredentialView{}, cloudworker.ErrStaleAuthorization
	}
	view := page.Items[0]
	if view.Revision <= 0 || view.VerifiedRevision != view.Revision || view.TestedAt.IsZero() {
		return coreaws.CredentialView{}, cloudworker.ErrStaleAuthorization
	}
	return view, nil
}

// cloudWorkerTurnRoom reports the room scope of this turn: the room of an
// authenticated group turn, and empty for the owner's own work.
func cloudWorkerTurnRoom(ctx context.Context) string {
	origin, group := coreconversation.GroupOriginFromContext(ctx)
	if !group || origin.Validate() != nil {
		return ""
	}
	return strings.TrimSpace(origin.RoomID)
}

func (authority *cloudWorkerCredentialAuthority) HasCurrentVerifiedAWSBinding(ctx context.Context) bool {
	if authority == nil || authority.list == nil || ctx == nil {
		return false
	}
	_, err := authority.currentCredentialView(ctx)
	return err == nil
}

func (authority *cloudWorkerCredentialAuthority) ResolveExactAWSBinding(ctx context.Context, expected cloudworker.AWSBinding) (cloudworker.AWSBinding, error) {
	_, err := authority.ResolveExactCredential(ctx, expected)
	if err != nil {
		return cloudworker.AWSBinding{}, err
	}
	return expected, nil
}

func (authority *cloudWorkerCredentialAuthority) ResolveExactCredential(ctx context.Context, expected cloudworker.AWSBinding) (workaws.CredentialHandle, error) {
	if authority == nil || authority.exact == nil || ctx == nil || expected.CredentialRevision == 0 || strings.TrimSpace(expected.Region) == "" {
		return workaws.CredentialHandle{}, cloudworker.ErrInvalid
	}
	credential, err := authority.exact.ResolveCredentialRevision(ctx, expected.CredentialID, expected.CredentialRevision)
	if err != nil {
		return workaws.CredentialHandle{}, cloudworker.ErrStaleAuthorization
	}
	if credential.Validate() != nil || credential.ReferenceID != expected.CredentialID || credential.AccountID != expected.AccountID {
		return workaws.CredentialHandle{}, cloudworker.ErrStaleAuthorization
	}
	return credential, nil
}

// cloudWorkerAWSCredentialsProvider deliberately is not wrapped in the AWS SDK
// credentials cache. The SDK therefore calls Retrieve for every request, and
// every request repeats the durable credential ID/revision/account fence
// before any signed AWS traffic can leave the process.
type cloudWorkerAWSCredentialsProvider struct {
	authority *cloudWorkerCredentialAuthority
	binding   cloudworker.AWSBinding
}

func newCloudWorkerAWSCredentialsProvider(authority *cloudWorkerCredentialAuthority, binding cloudworker.AWSBinding) (*cloudWorkerAWSCredentialsProvider, error) {
	if authority == nil || authority.exact == nil || binding.CredentialRevision == 0 || strings.TrimSpace(binding.Region) == "" {
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

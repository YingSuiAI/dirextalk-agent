package main

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws/sdkclient"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/google/uuid"
)

const cloudWorkerAWSRequestTimeout = 60 * time.Second

// cloudWorkerSDKFactory is the single revision-aware construction boundary.
// It never caches SDK clients or secret bytes: every external operation first
// resolves the immutable revision encoded in the persisted ProviderID, and
// every SDK request resolves that same revision again through Retrieve.
type cloudWorkerSDKFactory struct {
	authority         *cloudWorkerCredentialAuthority
	accountGeneration uint64
}

func newCloudWorkerSDKFactory(authority *cloudWorkerCredentialAuthority, accountGeneration uint64) (*cloudWorkerSDKFactory, error) {
	if authority == nil || authority.exact == nil || accountGeneration == 0 {
		return nil, cloudworker.ErrInvalid
	}
	return &cloudWorkerSDKFactory{authority: authority, accountGeneration: accountGeneration}, nil
}

func cloudWorkerCredentialProviderID(binding cloudworker.AWSBinding) string {
	return "credential:" + binding.CredentialID + ":revision:" + strconv.FormatUint(binding.CredentialRevision, 10)
}

func cloudWorkerBindingFromProvider(accountID, region, providerID string) (cloudworker.AWSBinding, error) {
	const prefix = "credential:"
	value := strings.TrimPrefix(providerID, prefix)
	parts := strings.Split(value, ":revision:")
	if value == providerID || len(parts) != 2 || uuid.Validate(parts[0]) != nil || parts[0] != strings.ToLower(parts[0]) {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	revision, err := strconv.ParseUint(parts[1], 10, 64)
	binding := cloudworker.AWSBinding{AccountID: accountID, Region: region, CredentialID: parts[0], CredentialRevision: revision}
	if err != nil || revision == 0 || cloudWorkerCredentialProviderID(binding) != providerID {
		return cloudworker.AWSBinding{}, cloudworker.ErrStaleAuthorization
	}
	return binding, nil
}

func (factory *cloudWorkerSDKFactory) sdkForBinding(ctx context.Context, binding cloudworker.AWSBinding) (awssdk.Config, sdkclient.Config, error) {
	if factory == nil || factory.authority == nil || ctx == nil {
		return awssdk.Config{}, sdkclient.Config{}, cloudworker.ErrInvalid
	}
	if _, err := factory.authority.ResolveExactAWSBinding(ctx, binding); err != nil {
		return awssdk.Config{}, sdkclient.Config{}, err
	}
	credentials, err := newCloudWorkerAWSCredentialsProvider(factory.authority, binding)
	if err != nil {
		return awssdk.Config{}, sdkclient.Config{}, err
	}
	sdkConfig := awssdk.Config{Region: binding.Region, Credentials: credentials,
		HTTPClient: awshttp.NewBuildableClient().WithTimeout(cloudWorkerAWSRequestTimeout),
		Retryer:    func() awssdk.Retryer { return awssdk.NopRetryer{} }}
	adapter := sdkclient.Config{AccountID: binding.AccountID, AccountGeneration: factory.accountGeneration,
		Region: binding.Region, ProviderID: cloudWorkerCredentialProviderID(binding)}
	return sdkConfig, adapter, nil
}

func (factory *cloudWorkerSDKFactory) sdkForProvider(ctx context.Context, accountID, region, providerID string) (awssdk.Config, sdkclient.Config, error) {
	binding, err := cloudWorkerBindingFromProvider(accountID, region, providerID)
	if err != nil {
		return awssdk.Config{}, sdkclient.Config{}, err
	}
	return factory.sdkForBinding(ctx, binding)
}

type cloudWorkerAWSClientRouter struct{ factory *cloudWorkerSDKFactory }

type cloudWorkerArtifactDestinationRouter struct{ factory *cloudWorkerSDKFactory }

func (router cloudWorkerArtifactDestinationRouter) CheckArtifactDestination(ctx context.Context, binding cloudworker.AWSBinding, bucket, kmsKeyARN string) error {
	if router.factory == nil {
		return cloudworker.ErrInvalid
	}
	sdkConfig, adapter, err := router.factory.sdkForBinding(ctx, binding)
	if err != nil {
		return err
	}
	readiness, err := sdkclient.NewS3ArtifactDestinationReadiness(sdkConfig, adapter)
	if err != nil {
		return err
	}
	return readiness.Readiness(ctx, bucket, kmsKeyARN)
}

func (router cloudWorkerAWSClientRouter) client(ctx context.Context, identity cloudaws.ExecutionIdentity) (*sdkclient.Client, error) {
	if router.factory == nil || identity.Validate() != nil {
		return nil, cloudaws.ErrIdentityMismatch
	}
	sdkConfig, adapter, err := router.factory.sdkForProvider(ctx, identity.AccountID, identity.Region, identity.ProviderID)
	if err != nil || adapter.AccountGeneration != identity.AccountGeneration {
		return nil, cloudaws.ErrIdentityMismatch
	}
	return sdkclient.New(sdkConfig, adapter)
}

func (router cloudWorkerAWSClientRouter) VerifyProviderIdentity(ctx context.Context, request cloudaws.ProviderIdentityRequest) (cloudaws.ProviderIdentityObservation, error) {
	client, err := router.client(ctx, request.Identity)
	if err != nil {
		return cloudaws.ProviderIdentityObservation{}, err
	}
	return client.VerifyProviderIdentity(ctx, request)
}
func (router cloudWorkerAWSClientRouter) CreateStack(ctx context.Context, request cloudaws.CreateStackRequest) (cloudaws.StackReference, error) {
	client, err := router.client(ctx, request.Identity)
	if err != nil {
		return cloudaws.StackReference{}, err
	}
	return client.CreateStack(ctx, request)
}
func (router cloudWorkerAWSClientRouter) FindStackByIntent(ctx context.Context, request cloudaws.FindStackRequest) (cloudaws.StackReference, bool, error) {
	client, err := router.client(ctx, request.Identity)
	if err != nil {
		return cloudaws.StackReference{}, false, err
	}
	return client.FindStackByIntent(ctx, request)
}
func (router cloudWorkerAWSClientRouter) ObserveGraph(ctx context.Context, request cloudaws.ObserveGraphRequest) (cloudaws.ObservedGraph, error) {
	client, err := router.client(ctx, request.Identity)
	if err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	return client.ObserveGraph(ctx, request)
}
func (router cloudWorkerAWSClientRouter) ObserveResource(ctx context.Context, request cloudaws.ObserveResourceRequest) (cloudaws.ResourceObservation, error) {
	client, err := router.client(ctx, request.Identity)
	if err != nil {
		return cloudaws.ResourceObservation{}, err
	}
	return client.ObserveResource(ctx, request)
}
func (router cloudWorkerAWSClientRouter) ResolveIAMResourceIdentities(ctx context.Context, request cloudaws.ResolveIAMResourceIdentitiesRequest) (cloudaws.IAMResourceIdentityProof, error) {
	client, err := router.client(ctx, request.Identity)
	if err != nil {
		return cloudaws.IAMResourceIdentityProof{}, err
	}
	return client.ResolveIAMResourceIdentities(ctx, request)
}
func (router cloudWorkerAWSClientRouter) EnsureResourceIdentity(ctx context.Context, request cloudaws.EnsureResourceIdentityRequest) error {
	client, err := router.client(ctx, request.Identity)
	if err != nil {
		return err
	}
	return client.EnsureResourceIdentity(ctx, request)
}
func (router cloudWorkerAWSClientRouter) DeleteResource(ctx context.Context, request cloudaws.DeleteResourceRequest) error {
	client, err := router.client(ctx, request.Identity)
	if err != nil {
		return err
	}
	return client.DeleteResource(ctx, request)
}

func (router cloudWorkerAWSClientRouter) ReadWorkerIdentity(ctx context.Context, accountID, region, providerID, instanceID string) (control.ProviderInstanceIdentity, error) {
	sdkConfig, adapter, err := router.factory.sdkForProvider(ctx, accountID, region, providerID)
	if err != nil {
		return control.ProviderInstanceIdentity{}, err
	}
	client, err := sdkclient.New(sdkConfig, adapter)
	if err != nil {
		return control.ProviderInstanceIdentity{}, err
	}
	return client.ReadWorkerIdentity(ctx, accountID, region, providerID, instanceID)
}

type cloudWorkerStagingStoreRouter struct{ factory *cloudWorkerSDKFactory }

func (router cloudWorkerStagingStoreRouter) store(ctx context.Context, identity cloudworker.StagingObjectIdentity) (*sdkclient.S3StagingStore, error) {
	sdkConfig, adapter, err := router.factory.sdkForProvider(ctx, identity.AccountID, identity.Region, identity.ProviderID)
	if err != nil || adapter.AccountGeneration != identity.AccountGeneration {
		return nil, cloudworker.ErrStaleAuthorization
	}
	return sdkclient.NewS3StagingStore(sdkConfig, adapter)
}
func (router cloudWorkerStagingStoreRouter) PutVersion(ctx context.Context, request cloudworker.StagingPutRequest) (cloudworker.StagingObjectObservation, error) {
	store, err := router.store(ctx, request.Identity)
	if err != nil {
		return cloudworker.StagingObjectObservation{}, err
	}
	return store.PutVersion(ctx, request)
}
func (router cloudWorkerStagingStoreRouter) FindVersion(ctx context.Context, identity cloudworker.StagingObjectIdentity) (cloudworker.StagingObjectObservation, bool, error) {
	store, err := router.store(ctx, identity)
	if err != nil {
		return cloudworker.StagingObjectObservation{}, false, err
	}
	return store.FindVersion(ctx, identity)
}
func (router cloudWorkerStagingStoreRouter) ObserveVersion(ctx context.Context, request cloudworker.StagingVersionRequest) (cloudworker.StagingObjectObservation, error) {
	store, err := router.store(ctx, request.Identity)
	if err != nil {
		return cloudworker.StagingObjectObservation{}, err
	}
	return store.ObserveVersion(ctx, request)
}
func (router cloudWorkerStagingStoreRouter) DeleteVersion(ctx context.Context, request cloudworker.StagingVersionRequest) error {
	store, err := router.store(ctx, request.Identity)
	if err != nil {
		return err
	}
	return store.DeleteVersion(ctx, request)
}

type cloudWorkerResultReaderRouter struct{ factory *cloudWorkerSDKFactory }

func (router cloudWorkerResultReaderRouter) ReaderForResult(ctx context.Context, plan cloudworker.Plan, execution cloudworker.Execution, authorization cloudworker.LaunchAuthorization) (cloudresult.ObjectReader, error) {
	sdkConfig, adapter, err := router.factory.sdkForBinding(ctx, plan.AWS)
	if err != nil {
		return nil, err
	}
	reader, err := sdkclient.NewExactResultReaderFactory(sdkConfig, adapter)
	if err != nil {
		return nil, err
	}
	return reader.ReaderForResult(ctx, plan, execution, authorization)
}

type cloudWorkerArtifactReaderRouter struct{ factory *cloudWorkerSDKFactory }

func (router cloudWorkerArtifactReaderRouter) ReaderForArtifact(ctx context.Context, authority cloudworker.ArtifactDownloadAuthority) (cloudresult.ObjectReader, error) {
	identity := authority.Retention.Identity
	binding := cloudworker.AWSBinding{AccountID: identity.AccountID, Region: identity.Region, CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision}
	sdkConfig, adapter, err := router.factory.sdkForBinding(ctx, binding)
	if err != nil {
		return nil, err
	}
	reader, err := sdkclient.NewExactArtifactReaderFactory(sdkConfig, adapter)
	if err != nil {
		return nil, err
	}
	return reader.ReaderForArtifact(ctx, authority)
}

type cloudWorkerArtifactObjectStoreRouter struct{ factory *cloudWorkerSDKFactory }

func (router cloudWorkerArtifactObjectStoreRouter) store(ctx context.Context, identity cloudworker.ArtifactRetentionIdentity) (*sdkclient.S3ArtifactRetentionStore, error) {
	binding := cloudworker.AWSBinding{AccountID: identity.AccountID, Region: identity.Region, CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision}
	sdkConfig, adapter, err := router.factory.sdkForBinding(ctx, binding)
	if err != nil {
		return nil, err
	}
	if adapter.AccountGeneration != identity.AccountGeneration || adapter.ProviderID != identity.ProviderID {
		return nil, cloudworker.ErrStaleAuthorization
	}
	return sdkclient.NewS3ArtifactRetentionStore(sdkConfig, adapter)
}
func (router cloudWorkerArtifactObjectStoreRouter) ObserveExactArtifact(ctx context.Context, identity cloudworker.ArtifactRetentionIdentity) (cloudworker.ArtifactObjectObservation, error) {
	store, err := router.store(ctx, identity)
	if err != nil {
		return cloudworker.ArtifactObjectObservation{}, err
	}
	return store.ObserveExactArtifact(ctx, identity)
}
func (router cloudWorkerArtifactObjectStoreRouter) DeleteExactArtifact(ctx context.Context, identity cloudworker.ArtifactRetentionIdentity) error {
	store, err := router.store(ctx, identity)
	if err != nil {
		return err
	}
	return store.DeleteExactArtifact(ctx, identity)
}

type cloudWorkerOutputVersionStoreRouter struct{ factory *cloudWorkerSDKFactory }

func (router cloudWorkerOutputVersionStoreRouter) StoreForOutput(
	ctx context.Context,
	identity cloudworker.OutputExecutionIdentity,
) (cloudworker.OutputVersionStore, error) {
	if router.factory == nil || identity.Validate() != nil {
		return nil, cloudworker.ErrInvalid
	}
	binding := cloudworker.AWSBinding{
		AccountID: identity.AccountID, Region: identity.Region,
		CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision,
	}
	if cloudWorkerCredentialProviderID(binding) != identity.ProviderID {
		return nil, cloudworker.ErrStaleAuthorization
	}
	sdkConfig, adapter, err := router.factory.sdkForBinding(ctx, binding)
	if err != nil || adapter.AccountGeneration != identity.AccountGeneration || adapter.ProviderID != identity.ProviderID {
		return nil, cloudworker.ErrStaleAuthorization
	}
	factory, err := sdkclient.NewExactOutputVersionStoreFactory(sdkConfig, adapter)
	if err != nil {
		return nil, err
	}
	return factory.StoreForOutput(ctx, identity)
}

var _ cloudaws.AWSClient = cloudWorkerAWSClientRouter{}
var _ cloudworker.ArtifactDestinationReadiness = cloudWorkerArtifactDestinationRouter{}
var _ control.ProviderIdentityReader = cloudWorkerAWSClientRouter{}
var _ cloudworker.StagingObjectStore = cloudWorkerStagingStoreRouter{}
var _ cloudworker.ResultObjectReaderFactory = cloudWorkerResultReaderRouter{}
var _ cloudworker.ArtifactDownloadReaderFactory = cloudWorkerArtifactReaderRouter{}
var _ cloudworker.ArtifactObjectStore = cloudWorkerArtifactObjectStoreRouter{}
var _ cloudworker.OutputVersionStoreFactory = cloudWorkerOutputVersionStoreRouter{}

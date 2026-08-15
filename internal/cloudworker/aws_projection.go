package cloudworker

import (
	"fmt"
	"strconv"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
)

// LaunchPrerequisite is the fresh transactional output of BeginExecution.
// It proves confirmation consumption and the current task fence, but cannot
// authorize AWS mutation until confirmed inputs have been staged and the
// canonical runtime task has been persisted by AuthorizeLaunch.
type LaunchPrerequisite struct {
	ConfirmationBindingDigest string    `json:"confirmation_binding_digest"`
	ConfirmationRevision      int64     `json:"confirmation_revision"`
	ConfirmedAt               time.Time `json:"confirmed_at"`
	TaskAttempt               uint32    `json:"task_attempt"`
	LeaseEpoch                uint64    `json:"lease_epoch"`
	AccountGeneration         uint64    `json:"account_generation"`
}

func (prerequisite LaunchPrerequisite) validate(plan Plan, expectedConfirmationDigest string) error {
	if !validDigest(prerequisite.ConfirmationBindingDigest) || prerequisite.ConfirmationBindingDigest != expectedConfirmationDigest ||
		prerequisite.ConfirmationRevision < 3 || prerequisite.ConfirmedAt.IsZero() || prerequisite.ConfirmedAt != prerequisite.ConfirmedAt.UTC() ||
		prerequisite.TaskAttempt == 0 || prerequisite.LeaseEpoch == 0 || prerequisite.AccountGeneration != plan.AccountGeneration {
		return ErrStaleAuthorization
	}
	return nil
}

func (prerequisite LaunchPrerequisite) RuntimeFence(plan Plan) (RuntimeTaskFence, error) {
	if prerequisite.validate(plan, prerequisite.ConfirmationBindingDigest) != nil {
		return RuntimeTaskFence{}, ErrStaleAuthorization
	}
	return RuntimeTaskFence{ExecutionID: plan.ExecutionID, TaskID: plan.TaskID, AccountGeneration: plan.AccountGeneration, Attempt: prerequisite.TaskAttempt, LeaseEpoch: prerequisite.LeaseEpoch}, nil
}

// LaunchAuthorization is written only by AuthorizeLaunch after re-locking the
// same task/confirmation/plan and persisting exact claim material.
type LaunchAuthorization struct {
	LaunchPrerequisite
	RuntimeTaskSHA256    string    `json:"runtime_task_sha256"`
	InputManifestSHA256  string    `json:"input_manifest_sha256"`
	StagedManifestSHA256 string    `json:"staged_manifest_sha256"`
	AuthorizedAt         time.Time `json:"authorized_at"`
}

func (authorization LaunchAuthorization) validate(plan Plan, expectedConfirmationDigest, expectedStagedDigest string, material RuntimeTaskMaterial) error {
	if authorization.LaunchPrerequisite.validate(plan, expectedConfirmationDigest) != nil ||
		!validDigest(authorization.RuntimeTaskSHA256) || authorization.RuntimeTaskSHA256 != material.RuntimeTaskSHA256 ||
		!validDigest(authorization.InputManifestSHA256) || authorization.InputManifestSHA256 != material.InputManifestSHA256 ||
		!validDigest(authorization.StagedManifestSHA256) || authorization.StagedManifestSHA256 != expectedStagedDigest || authorization.StagedManifestSHA256 != material.StagedManifestSHA256 ||
		authorization.AuthorizedAt.IsZero() || authorization.AuthorizedAt != authorization.AuthorizedAt.UTC() || authorization.AuthorizedAt.Before(authorization.ConfirmedAt) ||
		material.Fence.ExecutionID != plan.ExecutionID || material.Fence.TaskID != plan.TaskID || material.Fence.AccountGeneration != plan.AccountGeneration ||
		material.Fence.Attempt != authorization.TaskAttempt || material.Fence.LeaseEpoch != authorization.LeaseEpoch {
		return ErrStaleAuthorization
	}
	return nil
}

// BuildAWSDispatch is the only Core→AWS projection. It binds the immutable
// plan, consumed confirmation, current session fence and exact S3 grants into
// one deterministic ledger intent before Provider.Ensure can mutate AWS.
func BuildAWSDispatch(plan Plan, execution Execution, authorization LaunchAuthorization, staged StagedInputManifest, material RuntimeTaskMaterial, freshQuote Quote, recordedAt time.Time) (cloudaws.Plan, cloudaws.DispatchIntent, error) {
	recordedAt = recordedAt.UTC()
	copy := plan
	if err := copy.Seal(); err != nil || execution.Seal() != nil || recordedAt.IsZero() || copy.ExecutionID != execution.ExecutionID ||
		copy.TaskID != execution.TaskID || copy.Digest != execution.PlanDigest || copy.ExecutionDigest != execution.ExecutionDigest ||
		freshQuote.Digest != copy.Quote.Digest || freshQuote.BasisDigest != copy.AuthorizationBasisDigest || freshQuote.AmountMicros != copy.Quote.AmountMicros ||
		freshQuote.MaximumAuthorizedCostMicros != copy.Quote.MaximumAuthorizedCostMicros {
		return cloudaws.Plan{}, cloudaws.DispatchIntent{}, ErrStaleAuthorization
	}
	expectedBinding, err := BindingForPlan(copy)
	if err != nil || recordedAt.Before(authorization.AuthorizedAt) || !recordedAt.Before(copy.Quote.ExpiresAt) {
		return cloudaws.Plan{}, cloudaws.DispatchIntent{}, ErrStaleAuthorization
	}
	// SourceTime identifies the pinned rate catalog, not the issuance time of
	// this offer. A long-lived operator-pinned catalog may be older than the
	// short-lived quote while the quote itself is still valid and owner-bound.
	quoteLifetime := copy.Quote.ExpiresAt.Sub(copy.CreatedAt)
	if quoteLifetime <= 0 || quoteLifetime > time.Hour {
		return cloudaws.Plan{}, cloudaws.DispatchIntent{}, ErrStaleAuthorization
	}
	if copy.ArtifactGrant.KMSKeyARN == "" {
		return cloudaws.Plan{}, cloudaws.DispatchIntent{}, ErrInvalid
	}
	stagedDigest, err := staged.Seal(copy.InputManifest)
	if err != nil || staged.ExecutionID != copy.ExecutionID || !validDigest(stagedDigest) {
		return cloudaws.Plan{}, cloudaws.DispatchIntent{}, ErrInvalid
	}
	if authorization.validate(copy, string(expectedBinding.Digest), stagedDigest, material) != nil {
		return cloudaws.Plan{}, cloudaws.DispatchIntent{}, ErrStaleAuthorization
	}
	identity := cloudaws.ExecutionIdentity{
		OwnerID: copy.OwnerID, AccountID: copy.AWS.AccountID, AccountGeneration: copy.AccountGeneration, Region: copy.AWS.Region,
		ExecutionID: copy.ExecutionID, TaskID: copy.TaskID, TaskAttempt: authorization.TaskAttempt, LeaseEpoch: authorization.LeaseEpoch,
		ProviderID: providerIDForCredential(copy.AWS),
		Generation: copy.Revision,
	}
	identity.LaunchIdentity = cloudaws.DeriveLaunchIdentity(identity)
	architecture := "arm64"
	if copy.Compute.Architecture == "x86_64" {
		architecture = "amd64"
	}
	s3Grants := make([]cloudaws.S3ObjectGrant, 0, len(staged.Items)+1)
	for _, item := range staged.Items {
		s3Grants = append(s3Grants, cloudaws.S3ObjectGrant{Access: cloudaws.S3ReadExactVersion, Bucket: item.S3Bucket, Key: item.S3Key, VersionID: item.S3VersionID})
	}
	s3Grants = append(s3Grants, cloudaws.S3ObjectGrant{Access: cloudaws.S3WritePrefix, Bucket: copy.ArtifactGrant.Bucket, Key: copy.ArtifactGrant.KeyPrefix})
	projected, err := cloudaws.SealPlan(cloudaws.Plan{
		Identity: identity, Recipe: cloudaws.RecipePiTask, Adapter: cloudaws.AdapterPiJSON,
		AMIID: copy.Compute.AMIID, AMIDigest: copy.Compute.AMIDigest, WorkerDigest: copy.Compute.WorkerReleaseDigest,
		PiDigest: copy.Compute.PiRuntimeDigest, HostNetworkPolicySHA256: copy.Compute.HostNetworkPolicySHA256,
		Architecture: architecture, InstanceType: copy.Compute.InstanceType,
		RootVolumeGiB: uint32(copy.Compute.VolumeGiB), RootDeviceName: copy.Compute.RootDeviceName, RootVolumeType: copy.Compute.VolumeType,
		RootVolumeIOPS: uint32(copy.Compute.VolumeIOPS), RootVolumeThroughput: uint32(copy.Compute.VolumeThroughputMiB),
		RootKMSKeyARN: copy.ArtifactGrant.KMSKeyARN, VPCID: copy.Placement.VPCID, SubnetID: copy.Placement.SubnetID,
		Network: cloudaws.NetworkPolicy{DNSResolverCIDRs: append([]string(nil), copy.NetworkPolicy.DNSResolverCIDRs...),
			TLSProxyCIDRs: append([]string(nil), copy.NetworkPolicy.TLSProxyCIDRs...), AllowedFQDNs: append([]string(nil), copy.NetworkPolicy.AllowedFQDNs...),
			OutboundProxyURL: copy.NetworkPolicy.OutboundProxyURL, OutboundProxyServerName: copy.NetworkPolicy.OutboundProxyServerName,
			OutboundProxyTrustBundleSHA256: copy.NetworkPolicy.OutboundProxyTrustBundleSHA256,
			OutboundProxyBindingDigest:     copy.NetworkPolicy.OutboundProxyBindingDigest},
		ControlPlaneEndpoint: copy.WorkerBootstrap.Endpoint, ControlPlaneServerName: copy.WorkerBootstrap.TLSServerName,
		ControlPlaneTrustBundleSHA256: copy.WorkerBootstrap.TrustBundleDigest,
		ModelEndpointServerName:       copy.ModelEndpoint.TLSServerName,
		WorkspaceMode:                 cloudaws.WorkspaceMode(copy.WorkspaceMode), ExecutionSHA256: copy.ExecutionDigest,
		TaskSHA256: authorization.RuntimeTaskSHA256, InputManifestDigest: authorization.InputManifestSHA256,
		ModelAuthorizationDigest: copy.ModelAuthorization.BindingDigest, ArtifactBindingDigest: copy.ArtifactGrant.Digest,
		S3Grants: s3Grants, ArtifactRetentionSeconds: uint32(copy.ArtifactRetentionSeconds),
		DestroyDeadline: recordedAt.Add(time.Duration(copy.Limits.MaxRuntimeSeconds+EphemeralCleanupReserveSeconds) * time.Second),
		Digest:          copy.Digest,
	})
	if err != nil {
		return cloudaws.Plan{}, cloudaws.DispatchIntent{}, fmt.Errorf("%w: AWS projection", ErrInvalid)
	}
	binding := cloudaws.AuthorizationBinding{
		AuthorizedQuoteDigest: copy.Quote.Digest, FreshQuoteDigest: freshQuote.Digest,
		ExpectedConfirmationDigest: string(expectedBinding.Digest), ConfirmationDigest: authorization.ConfirmationBindingDigest,
		FreshQuotedAt: copy.CreatedAt, QuoteExpiresAt: copy.Quote.ExpiresAt, ConfirmedAt: authorization.ConfirmedAt,
		MaximumQuoteAgeSeconds: uint32(quoteLifetime / time.Second),
	}
	intent, err := cloudaws.NewDispatchIntent(projected, binding, recordedAt)
	if err != nil {
		return cloudaws.Plan{}, cloudaws.DispatchIntent{}, fmt.Errorf("%w: AWS dispatch intent", ErrStaleAuthorization)
	}
	return projected, intent, nil
}

func providerIDForCredential(binding AWSBinding) string {
	return "credential:" + binding.CredentialID + ":revision:" + strconv.FormatUint(binding.CredentialRevision, 10)
}

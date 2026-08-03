// Package teamprovision projects one approved Team role into the closed,
// typed AWS resource model. It has no AWS SDK client or mutation capability.
package teamprovision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
)

var (
	ErrInvalid      = errors.New("invalid Team AWS provision request")
	ErrFactMismatch = errors.New("Team AWS provision fact mismatch")
	ErrExpired      = errors.New("Team AWS provision authorization expired")
)

type BuildRequest struct {
	Dispatch      teamdispatch.Fact
	Authorization teamlaunch.AuthorizationV1
	FreshQuote    teamlaunch.FreshQuoteV1
	Input         teaminput.CompiledInput
	Published     cloudexecution.PublishedBundles
	Bootstrap     cloudexecution.BootstrapArtifact
	Deployment    worker.Deployment
	Now           time.Time
}

type Graph struct {
	Specs               []resource.ProvisionSpec
	CreateAuthorization resource.ProviderCreateAuthorization
	FreshQuoteDigest    string
	ReconcileOnly       bool
}

// Build creates exactly one no-ingress security group, one exclusive ENI, one
// outbound Elastic IP, and one on-demand EC2 Worker. The graph is deterministic
// for a role deployment and can therefore be reconciled after response loss.
func Build(request BuildRequest) (Graph, error) {
	now := request.Now.UTC()
	if request.Now.IsZero() ||
		request.Dispatch.Validate() != nil ||
		request.FreshQuote.Validate() != nil {
		return Graph{}, ErrInvalid
	}
	if request.Authorization.Validate() != nil {
		return Graph{}, ErrInvalid
	}
	if request.Dispatch.Phase != teamdispatch.PhaseProvisioning ||
		request.Dispatch.ProvisioningQuote == nil ||
		request.Dispatch.ProvisioningStartedAt == nil ||
		request.Dispatch.ProvisioningEnrollmentExpires == nil {
		return Graph{}, ErrInvalid
	}
	if !request.Dispatch.CreatedAt.After(now) &&
		!request.Dispatch.UpdatedAt.After(now) {
		// Continue below. This positive form keeps all future-time rejection in
		// one branch without accepting a zero timestamp.
	} else {
		return Graph{}, ErrFactMismatch
	}
	intent := request.Dispatch.Intent
	authorization := request.Authorization
	authorizationDigest, err := authorization.Digest()
	quoteDigest, quoteDigestErr := request.FreshQuote.Digest()
	if err != nil ||
		quoteDigestErr != nil ||
		intent.AgentInstanceID != authorization.AgentInstanceID ||
		intent.OwnerID != authorization.OwnerID ||
		intent.PlanID != authorization.PlanID ||
		intent.PlanRevision != authorization.PlanRevision ||
		intent.PlanDigest != authorization.PlanDigest ||
		intent.ApprovalID != authorization.ApprovalID ||
		intent.LaunchAuthorizationID != authorization.AuthorizationID ||
		intent.LaunchAuthorizationDigest != authorizationDigest ||
		request.FreshQuote.AuthorizationID != authorization.AuthorizationID ||
		request.FreshQuote.AuthorizationDigest != authorizationDigest ||
		request.FreshQuote.PlanID != authorization.PlanID ||
		request.FreshQuote.PlanRevision != authorization.PlanRevision ||
		request.FreshQuote.PlanDigest != authorization.PlanDigest ||
		request.FreshQuote.ProviderScope != authorization.ProviderScope ||
		request.FreshQuote.Region != authorization.Region ||
		request.FreshQuote.Currency != authorization.Currency ||
		request.FreshQuote.HardBudgetMicros !=
			authorization.HardBudgetMicros ||
		request.FreshQuote.MaximumQuoteAgeSeconds !=
			authorization.MaximumQuoteAgeSeconds ||
		request.FreshQuote.ValidateAgainstAuthorization(
			authorization,
		) != nil ||
		request.Dispatch.ProvisioningQuoteDigest != quoteDigest {
		return Graph{}, ErrFactMismatch
	}
	persistedQuoteDigest, err :=
		request.Dispatch.ProvisioningQuote.Digest()
	if err != nil || persistedQuoteDigest != quoteDigest {
		return Graph{}, ErrFactMismatch
	}
	role, found := launchRole(authorization, intent.RoleID)
	quotedRole, quoteFound := freshRole(request.FreshQuote, intent.RoleID)
	if !found || !quoteFound ||
		role.MaximumApprovedCostMicros !=
			intent.MaximumApprovedCostMicros ||
		quotedRole.TotalMaximumMicros >
			role.MaximumApprovedCostMicros {
		return Graph{}, ErrFactMismatch
	}
	if err := validateInput(intent, request.Input); err != nil {
		return Graph{}, err
	}
	if err := validatePublished(
		intent,
		request.Input,
		request.Published,
		request.Bootstrap,
	); err != nil {
		return Graph{}, err
	}
	deploymentCreateEligible, err := validateDeployment(
		intent,
		request.Input,
		request.Published,
		request.Deployment,
		authorization.Network.ControlPlaneEndpoint,
		request.Dispatch.ProvisioningWorkerRevision,
		*request.Dispatch.ProvisioningEnrollmentExpires,
		*request.Dispatch.ProvisioningStartedAt,
		now,
	)
	if err != nil {
		return Graph{}, err
	}

	deadline := request.Dispatch.CreatedAt.UTC().Add(
		time.Duration(authorization.Retention.MaximumLifetimeSeconds) *
			time.Second,
	)
	if !deadline.After(now) {
		return Graph{}, ErrExpired
	}
	trust, err := cloneTrust(request.Published.InstallerRootTrust)
	if err != nil {
		return Graph{}, err
	}
	common := resource.ProvisionSpec{
		AgentInstanceID:     authorization.AgentInstanceID,
		OwnerID:             authorization.OwnerID,
		TaskID:              intent.TaskID,
		DeploymentID:        intent.DeploymentID,
		Region:              authorization.Region,
		ApprovedPlanHash:    authorization.PlanDigest,
		ApprovalID:          authorization.ApprovalID,
		Retention:           task.RetentionEphemeralAutoDestroy,
		DestroyDeadline:     deadline,
		AutoDestroyApproved: true,
	}
	groupID := deterministicID(intent.DeploymentID, "security-group")
	eniID := deterministicID(intent.DeploymentID, "eni")
	eipID := deterministicID(intent.DeploymentID, "eip")
	instanceID := deterministicID(intent.DeploymentID, "ec2")

	egress := make(
		[]resource.AWSNetworkRuleV1,
		0,
		len(authorization.Network.Egress),
	)
	for _, rule := range authorization.Network.Egress {
		egress = append(egress, resource.AWSNetworkRuleV1{
			Protocol: rule.Protocol,
			FromPort: rule.FromPort,
			ToPort:   rule.ToPort,
			CIDRv4:   rule.CIDRv4,
		})
	}
	groupAWS := &resource.AWSResourceSpecV1{
		SchemaVersion: resource.AWSResourceSpecSchemaV1,
		SecurityGroup: &resource.AWSSecurityGroupSpecV1{
			VPCID: authorization.Network.VPCID,
			Description: "Dirextalk Team Worker " +
				intent.DeploymentID,
			Egress: egress,
		},
	}
	eniAWS := &resource.AWSResourceSpecV1{
		SchemaVersion: resource.AWSResourceSpecSchemaV1,
		NetworkInterface: &resource.AWSNetworkInterfaceSpecV1{
			SubnetID: authorization.Network.SubnetID,
			Description: "Dirextalk Team Worker " +
				intent.DeploymentID,
		},
	}
	eipAWS := &resource.AWSResourceSpecV1{
		SchemaVersion: resource.AWSResourceSpecSchemaV1,
		ElasticIP: &resource.AWSElasticIPSpecV1{
			Domain: "vpc",
		},
	}
	instanceAWS := &resource.AWSResourceSpecV1{
		SchemaVersion: resource.AWSResourceSpecSchemaV1,
		Instance: &resource.AWSEC2InstanceSpecV1{
			ImageID:                role.WorkerImage.ImageID,
			ImageDigest:            role.WorkerImage.ImageDigest,
			Architecture:           role.Architecture,
			InstanceType:           role.InstanceType,
			InstanceProfileName:    role.InstanceProfileName,
			UserDataArtifactRef:    request.Bootstrap.Reference,
			UserDataArtifactDigest: digestBytes(request.Bootstrap.SHA256),
			Bootstrap: resource.AWSWorkerBootstrapSpecV1{
				DeploymentID: intent.DeploymentID,
				WorkerID:     intent.ExpectedWorkerID,
				ControlPlaneEndpoint: authorization.Network.
					ControlPlaneEndpoint,
				EnrollmentExpectedRevision: int64(
					request.Dispatch.ProvisioningWorkerRevision,
				),
				InstallerTrust: trust,
				InstallerArtifacts: append(
					[]installerbootstrap.ArtifactSourceV1(nil),
					request.Published.InstallerArtifacts...,
				),
				InstallerSecrets: append(
					[]installerbootstrap.SecretSourceV1(nil),
					request.Published.InstallerSecrets...,
				),
			},
			RootDeviceName: role.RootStorage.DeviceName,
			RootVolumeGiB:  uint32(role.RootStorage.SizeGiB),
			RootKMSKeyID:   role.RootStorage.KMSKeyID,
			Market:         resource.AWSMarketOnDemand,
			EBSOptimized:   role.EBSOptimized,
		},
	}
	specs := []resource.ProvisionSpec{
		resourceSpec(
			common,
			groupID,
			resource.TypeSG,
			"team-worker-"+intent.RoleID+"-security-group",
			nil,
			groupAWS,
		),
		resourceSpec(
			common,
			eniID,
			resource.TypeENI,
			"team-worker-"+intent.RoleID+"-network-interface",
			[]string{groupID},
			eniAWS,
		),
		resourceSpec(
			common,
			eipID,
			resource.TypeEIP,
			"team-worker-"+intent.RoleID+"-outbound-ipv4",
			[]string{eniID},
			eipAWS,
		),
		resourceSpec(
			common,
			instanceID,
			resource.TypeEC2,
			"team-worker-"+intent.RoleID,
			[]string{eniID, eipID},
			instanceAWS,
		),
	}
	for _, spec := range specs {
		if spec.Validate(now) != nil {
			return Graph{}, ErrFactMismatch
		}
	}
	createEligible := deploymentCreateEligible &&
		authorization.ValidateAt(now) == nil &&
		!now.Before(request.FreshQuote.CapturedAt) &&
		now.Before(request.FreshQuote.ValidUntil) &&
		now.Sub(request.FreshQuote.CapturedAt) <=
			time.Duration(
				authorization.MaximumQuoteAgeSeconds,
			)*time.Second
	createAuthorization := resource.ProviderCreateAuthorization{
		ApprovalExpiresAt: authorization.LaunchNotAfter,
		QuoteValidUntil:   request.FreshQuote.ValidUntil,
	}
	if !createEligible {
		// Resource.Service can still find and read back an existing
		// deterministic provider resource, but its irreversible create
		// boundary will reject any missing resource.
		createAuthorization.QuoteValidUntil =
			*request.Dispatch.ProvisioningStartedAt
	}
	return Graph{
		Specs:               specs,
		CreateAuthorization: createAuthorization,
		FreshQuoteDigest:    quoteDigest,
		ReconcileOnly:       !createEligible,
	}, nil
}

func validateInput(
	intent teamdispatch.IntentV1,
	input teaminput.CompiledInput,
) error {
	manifest := input.Manifest
	if manifest.ExecutionID != intent.ExecutionID ||
		manifest.ExecutionDigest != intent.ExecutionDigest ||
		manifest.PlanID != intent.PlanID ||
		manifest.PlanDigest != intent.PlanDigest ||
		manifest.TaskID != intent.TaskID ||
		manifest.TaskStepID != intent.TaskStepID ||
		manifest.RoleID != intent.RoleID ||
		manifest.RoleDigest != intent.RoleDigest ||
		manifest.DeploymentID != intent.DeploymentID ||
		manifest.ExpectedWorkerID != intent.ExpectedWorkerID ||
		input.CredentialGrant.ExecutionID != intent.ExecutionID ||
		input.CredentialGrant.RoleID != intent.RoleID ||
		input.CredentialGrant.DeploymentID != intent.DeploymentID ||
		input.CredentialGrant.ExpectedWorkerID != intent.ExpectedWorkerID ||
		input.CredentialGrant.MaximumDurationSeconds == 0 ||
		manifest.CredentialSlot !=
			input.CredentialGrant.CredentialSlot ||
		input.CredentialTargetPath == "" ||
		len(input.ManifestBytes) == 0 ||
		len(input.ExecutionBytes) == 0 {
		return ErrFactMismatch
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil ||
		!bytes.Equal(manifestBytes, input.ManifestBytes) ||
		digestContent(input.ManifestBytes) != input.ManifestDigest ||
		digestContent(input.ExecutionBytes) !=
			input.ExecutionBundleDigest {
		clear(manifestBytes)
		return ErrFactMismatch
	}
	clear(manifestBytes)
	return nil
}

func validatePublished(
	intent teamdispatch.IntentV1,
	input teaminput.CompiledInput,
	published cloudexecution.PublishedBundles,
	bootstrap cloudexecution.BootstrapArtifact,
) error {
	recipeDigest, err := parseDigest(input.ManifestDigest)
	if err != nil || published.Recipe.SHA256 != recipeDigest {
		return ErrFactMismatch
	}
	executionDigest, err := parseDigest(input.ExecutionBundleDigest)
	if err != nil || published.Execution.SHA256 != executionDigest ||
		published.Recipe.Validate() != nil ||
		published.Execution.Validate() != nil ||
		published.Access.Validate() != nil ||
		published.InstallerRootTrust == nil ||
		len(published.InstallerArtifacts) != 0 ||
		len(published.InstallerSecrets) != 1 ||
		len(published.SecretBindings) != 1 ||
		len(published.Access.SecretRefs) != 1 ||
		bootstrap.Reference != published.Launch.Reference ||
		bootstrap.SHA256 != published.Launch.SHA256 ||
		bootstrap.EnrollmentMaterialRef !=
			"identity://aws-sts/"+intent.DeploymentID {
		return ErrFactMismatch
	}
	manifest := published.InstallerRootTrust.ArtifactManifest.Manifest
	if len(manifest.Secrets) != 1 ||
		manifest.Binding.AgentInstanceID != intent.AgentInstanceID ||
		manifest.Binding.DeploymentID != intent.DeploymentID ||
		manifest.Binding.TaskID != intent.TaskID ||
		manifest.Binding.PlanHash != intent.PlanDigest ||
		manifest.Binding.ApprovalID != intent.ApprovalID ||
		manifest.Binding.RecipeDigest != input.ManifestDigest ||
		manifest.Secrets[0].SlotID !=
			input.CredentialGrant.CredentialSlot ||
		manifest.Secrets[0].SecretRef !=
			intent.ModelCredentialRef ||
		manifest.Secrets[0].TargetPath !=
			input.CredentialTargetPath ||
		published.InstallerSecrets[0].SecretRef !=
			intent.ModelCredentialRef ||
		published.SecretBindings[intent.ModelCredentialRef] !=
			published.Access.SecretRefs[0] {
		return ErrFactMismatch
	}
	recipe, execution, launch, err := exactPublishedURLs(
		intent.DeploymentID,
		published,
		bootstrap,
	)
	if err != nil ||
		recipe.Host != execution.Host ||
		execution.Host != launch.Host {
		return ErrFactMismatch
	}
	base := "s3://" + recipe.Host + "/deployments/" +
		intent.DeploymentID + "/"
	if published.Access.ArtifactPrefix != base+"artifacts/" ||
		published.Access.CheckpointPrefix != base+"checkpoints/" ||
		published.Access.EvidencePrefix != base+"evidence/" {
		return ErrFactMismatch
	}
	return nil
}

func validateDeployment(
	intent teamdispatch.IntentV1,
	input teaminput.CompiledInput,
	published cloudexecution.PublishedBundles,
	deployment worker.Deployment,
	controlPlaneEndpoint string,
	provisioningWorkerRevision uint64,
	provisioningEnrollmentExpires time.Time,
	provisioningStartedAt time.Time,
	now time.Time,
) (bool, error) {
	expectedWorkerID, err := workeridentity.DeriveWorkerID(intent.DeploymentID)
	var emptyDigest [sha256.Size]byte
	if err != nil ||
		expectedWorkerID != intent.ExpectedWorkerID ||
		deployment.DeploymentID != intent.DeploymentID ||
		deployment.OwnerID != intent.OwnerID ||
		deployment.TaskID != intent.TaskID ||
		deployment.StepID != intent.TaskStepID ||
		deployment.ControlPlaneEndpoint == "" ||
		deployment.ControlPlaneEndpoint != controlPlaneEndpoint ||
		deployment.RecipeBundle != published.Recipe ||
		deployment.ExecutionBundle != published.Execution ||
		!reflect.DeepEqual(deployment.Access, published.Access) ||
		deployment.ExecutionTimeout != time.Duration(
			input.CredentialGrant.MaximumDurationSeconds,
		)*time.Second ||
		provisioningWorkerRevision == 0 ||
		provisioningWorkerRevision > uint64(math.MaxInt64) ||
		deployment.Revision < int64(provisioningWorkerRevision) ||
		!deployment.Enrollment.ExpiresAt.Equal(
			provisioningEnrollmentExpires,
		) ||
		deployment.CreatedAt.After(provisioningStartedAt) ||
		deployment.UpdatedAt.After(now) ||
		deployment.Enrollment.CredentialDigest == emptyDigest ||
		deployment.InstallerDelivery == nil ||
		len(deployment.InstallerCommandIDs) != 0 {
		return false, ErrFactMismatch
	}
	createEligible := false
	if deployment.Revision == int64(provisioningWorkerRevision) {
		if deployment.State != worker.StatePendingEnrollment ||
			deployment.Outcome != worker.OutcomePending ||
			deployment.WorkerID != "" ||
			deployment.ProviderInstanceID != "" {
			return false, ErrFactMismatch
		}
		createEligible = now.Before(deployment.Enrollment.ExpiresAt)
	}
	if deployment.Revision > int64(provisioningWorkerRevision) {
		switch deployment.State {
		case worker.StateReady,
			worker.StateLeased,
			worker.StateCancelRequested,
			worker.StateFinished:
		default:
			return false, ErrFactMismatch
		}
		createEligible = false
	}
	if err := worker.ValidateInstallerCapability(
		deployment.DeploymentID,
		deployment.TaskID,
		deployment.RecipeBundle,
		deployment.InstallerDelivery,
		deployment.InstallerCommandIDs,
	); err != nil {
		return false, ErrFactMismatch
	}
	root, err := deployment.InstallerDelivery.RootTrustMaterial(
		provisioningStartedAt,
	)
	if err != nil {
		return false, ErrFactMismatch
	}
	trust, err := installerbootstrap.NewRootTrustMaterial(root)
	if err != nil ||
		!reflect.DeepEqual(&trust, published.InstallerRootTrust) {
		return false, ErrFactMismatch
	}
	return createEligible, nil
}

func exactPublishedURLs(
	deploymentID string,
	published cloudexecution.PublishedBundles,
	bootstrap cloudexecution.BootstrapArtifact,
) (*url.URL, *url.URL, *url.URL, error) {
	recipe, recipeErr := exactS3Object(
		published.Recipe.S3Ref,
		path.Join("deployments", deploymentID, "bundles", "recipe.cbor"),
	)
	execution, executionErr := exactS3Object(
		published.Execution.S3Ref,
		path.Join(
			"deployments",
			deploymentID,
			"bundles",
			"execution.json",
		),
	)
	launch, launchErr := exactS3Object(
		bootstrap.Reference,
		path.Join("deployments", deploymentID, "launch", "config.json"),
	)
	if recipeErr != nil || executionErr != nil || launchErr != nil {
		return nil, nil, nil, ErrFactMismatch
	}
	return recipe, execution, launch, nil
}

func exactS3Object(raw, expectedKey string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil ||
		parsed.Scheme != "s3" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		strings.TrimPrefix(parsed.Path, "/") != expectedKey {
		return nil, ErrFactMismatch
	}
	return parsed, nil
}

func launchRole(
	authorization teamlaunch.AuthorizationV1,
	roleID string,
) (teamlaunch.RoleLaunchV1, bool) {
	for _, role := range authorization.Roles {
		if role.RoleID == roleID {
			return role, true
		}
	}
	return teamlaunch.RoleLaunchV1{}, false
}

func freshRole(
	quote teamlaunch.FreshQuoteV1,
	roleID string,
) (teamlaunch.FreshRoleQuoteV1, bool) {
	for _, role := range quote.Roles {
		if role.RoleID == roleID {
			return role, true
		}
	}
	return teamlaunch.FreshRoleQuoteV1{}, false
}

func resourceSpec(
	common resource.ProvisionSpec,
	resourceID string,
	kind resource.Type,
	logicalName string,
	dependencies []string,
	aws *resource.AWSResourceSpecV1,
) resource.ProvisionSpec {
	value := common
	value.ResourceID = resourceID
	value.Type = kind
	value.LogicalName = logicalName
	value.DependsOn = append([]string(nil), dependencies...)
	value.AWS = aws
	if aws != nil {
		value.SpecDigest, _ = aws.Digest(kind)
	}
	return value
}

func cloneTrust(
	value *installerbootstrap.RootTrustMaterialV1,
) (*installerbootstrap.RootTrustMaterialV1, error) {
	if value == nil {
		return nil, ErrFactMismatch
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, ErrFactMismatch
	}
	var cloned installerbootstrap.RootTrustMaterialV1
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		clear(encoded)
		return nil, ErrFactMismatch
	}
	clear(encoded)
	return &cloned, nil
}

func deterministicID(namespace, label string) string {
	return uuid.NewSHA1(
		uuid.MustParse(namespace),
		[]byte(label),
	).String()
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(raw) != sha256.Size ||
		value != "sha256:"+hex.EncodeToString(raw) {
		clear(raw)
		return result, ErrFactMismatch
	}
	copy(result[:], raw)
	clear(raw)
	return result, nil
}

func digestBytes(value [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(value[:])
}

func digestContent(value []byte) string {
	digest := sha256.Sum256(value)
	return digestBytes(digest)
}

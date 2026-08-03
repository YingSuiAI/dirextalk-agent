package teamlaunch

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/google/uuid"
)

const (
	maximumLaunchWindow    = 7 * 24 * time.Hour
	maximumWorkerLifetime  = 7 * 24 * 60 * 60
	minimumDestroyGrace    = 60
	maximumDestroyGrace    = 60 * 60
	maximumQuoteAgeSeconds = 15 * 60
	maximumPlanCostMicros  = 10_000_000_000_000
	vpcResolverCIDR        = "169.254.169.253/32"
)

var (
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	awsIDPattern        = regexp.MustCompile(`^(?:ami|snap|vpc|subnet)-[0-9a-f]{8,17}$`)
	availabilityZone    = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+[a-z]$`)
	regionPattern       = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$`)
	accountPattern      = regexp.MustCompile(`^[0-9]{12}$`)
	instanceTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)
	instanceProfile     = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,128}$`)
	kmsKeyPattern       = regexp.MustCompile(`^(?:alias/[A-Za-z0-9/_-]{1,240}|arn:(?:aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:[0-9]{12}:(?:key/[0-9a-f-]{36}|alias/[A-Za-z0-9/_-]{1,240}))$`)
	currencyPattern     = regexp.MustCompile(`^[A-Z]{3}$`)
	hostnamePattern     = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
)

func NewAuthorizationV1(request BuildRequest) (AuthorizationV1, error) {
	plan := request.Plan
	network, networkErr := normalizedNetwork(request.Network, plan.Region)
	foundation, foundationErr := awsfoundation.BuildSpec(
		awsfoundation.SpecInput{
			AgentInstanceID: request.AgentInstanceID,
			Partition:       partitionForRegion(plan.Region),
			AccountID:       plan.ProviderScope.AccountID,
			Region:          plan.Region,
		},
	)
	kmsAlias, kmsAliasErr := awsfoundation.KMSAliasForAgent(
		request.AgentInstanceID,
	)
	if plan.Validate() != nil ||
		!canonicalUUID(request.AgentInstanceID) ||
		!canonicalUUID(request.ApprovalID) ||
		!utcMicrosecond(request.LaunchNotBefore) ||
		!utcMicrosecond(request.LaunchNotAfter) ||
		!request.LaunchNotBefore.Before(request.LaunchNotAfter) ||
		request.LaunchNotAfter.Sub(request.LaunchNotBefore) >
			maximumLaunchWindow ||
		request.LaunchNotBefore.Before(plan.QuotedAt) ||
		networkErr != nil ||
		foundationErr != nil ||
		kmsAliasErr != nil ||
		validateRetention(request.Retention) != nil ||
		len(request.RoleSelections) != len(plan.Assignments) {
		return AuthorizationV1{}, ErrInvalid
	}
	planDigest, err := plan.Digest()
	if err != nil {
		return AuthorizationV1{}, ErrInvalid
	}
	authorizationID, err := AuthorizationID(
		plan.PlanID,
		plan.Revision,
		request.ApprovalID,
	)
	if err != nil {
		return AuthorizationV1{}, err
	}
	selections := append([]RoleSelection(nil), request.RoleSelections...)
	slices.SortFunc(
		selections,
		func(left, right RoleSelection) int {
			return strings.Compare(left.RoleID, right.RoleID)
		},
	)
	costs := make(map[string]teamplan.RoleCostEstimate, len(plan.Cost.Roles))
	for _, cost := range plan.Cost.Roles {
		costs[cost.RoleID] = cost
	}
	roles := make([]RoleLaunchV1, 0, len(plan.Assignments))
	for index, assignment := range plan.Assignments {
		selection := selections[index]
		cost, found := costs[assignment.RoleID]
		release, releaseErr := workerrelease.ValidateStored(
			selection.WorkerRelease,
		)
		if !found || releaseErr != nil ||
			selection.RoleID != assignment.RoleID ||
			release.Architecture !=
				assignment.Resources.Arch ||
			release.AgentInstanceID !=
				request.AgentInstanceID ||
			release.AccountID !=
				plan.ProviderScope.AccountID ||
			release.Region != plan.Region ||
			release.ObservedAt.After(request.LaunchNotBefore) ||
			!digestPattern.MatchString(
				selection.RuntimeInstallationDigest,
			) ||
			!digestPattern.MatchString(
				selection.RuntimeExecutableDigest,
			) {
			return AuthorizationV1{}, ErrInvalid
		}
		var marketplace *teamplan.WorkerMarketplaceBindingV1
		if assignment.Marketplace != nil {
			value := assignment.Marketplace.Clone()
			marketplace = &value
		}
		role := RoleLaunchV1{
			RoleID:                    assignment.RoleID,
			RuntimeReleaseID:          assignment.RuntimeReleaseID,
			RuntimeImageDigest:        assignment.RuntimeImageDigest,
			Marketplace:               marketplace,
			RuntimeInstallationDigest: selection.RuntimeInstallationDigest,
			RuntimeExecutableDigest:   selection.RuntimeExecutableDigest,
			ComputeOfferID:            assignment.ComputeOfferID,
			InstanceType:              assignment.InstanceType,
			Architecture:              assignment.Resources.Arch,
			VCPU:                      assignment.Resources.VCPU,
			MemoryMiB:                 assignment.Resources.MemoryMiB,
			PurchaseOption:            PurchaseOnDemand,
			InstanceProfileName:       foundation.WorkerProfileName,
			EBSOptimized:              true,
			RequireIMDSv2:             true,
			MetadataResponseHopLimit:  1,
			ShutdownBehavior:          ShutdownTerminate,
			RootStorage: RootStorageV1{
				DeviceName:          "/dev/sda1",
				SizeGiB:             assignment.Resources.DiskGiB,
				VolumeType:          "gp3",
				IOPS:                3000,
				ThroughputMiBPS:     125,
				KMSKeyID:            kmsAlias,
				Encrypted:           true,
				DeleteOnTermination: true,
			},
			WorkerImage:               workerImageFromRelease(release),
			MaximumApprovedCostMicros: cost.TotalMaximumMicros,
		}
		if validateRole(role, request.AgentInstanceID, plan) != nil {
			return AuthorizationV1{}, ErrInvalid
		}
		roles = append(roles, role)
	}
	authorization := AuthorizationV1{
		SchemaVersion:                SchemaV1,
		AuthorizationID:              authorizationID,
		AgentInstanceID:              request.AgentInstanceID,
		OwnerID:                      plan.OwnerID,
		PlanID:                       plan.PlanID,
		PlanRevision:                 plan.Revision,
		PlanDigest:                   planDigest,
		ApprovalID:                   request.ApprovalID,
		ProviderScope:                plan.ProviderScope,
		Region:                       plan.Region,
		Network:                      network,
		Retention:                    request.Retention,
		WorkerCount:                  plan.WorkerCount,
		MaxConcurrentBillableWorkers: plan.MaxConcurrentWorkers,
		Currency:                     plan.Cost.Currency,
		HardBudgetMicros:             plan.Cost.HardBudgetMicros,
		RequiresFreshQuote:           true,
		MaximumQuoteAgeSeconds:       maximumQuoteAgeSeconds,
		LaunchNotBefore:              request.LaunchNotBefore,
		LaunchNotAfter:               request.LaunchNotAfter,
		Roles:                        roles,
	}
	if authorization.ValidateAgainst(plan) != nil {
		return AuthorizationV1{}, ErrInvalid
	}
	return authorization, nil
}

func AuthorizationID(
	planID string,
	planRevision uint64,
	approvalID string,
) (string, error) {
	parsedPlan, err := uuid.Parse(planID)
	if err != nil ||
		parsedPlan == uuid.Nil ||
		parsedPlan.String() != planID ||
		planRevision == 0 ||
		planRevision > uint64(math.MaxInt64) ||
		!canonicalUUID(approvalID) {
		return "", ErrInvalid
	}
	return uuid.NewSHA1(
		parsedPlan,
		[]byte(
			fmt.Sprintf(
				"team-launch-authorization/v1:%d:%s",
				planRevision,
				approvalID,
			),
		),
	).String(), nil
}

func (authorization AuthorizationV1) Validate() error {
	expectedID, err := AuthorizationID(
		authorization.PlanID,
		authorization.PlanRevision,
		authorization.ApprovalID,
	)
	if err != nil ||
		authorization.SchemaVersion != SchemaV1 ||
		authorization.AuthorizationID != expectedID ||
		!canonicalUUID(authorization.AgentInstanceID) ||
		!safeText(authorization.OwnerID, 255) ||
		!digestPattern.MatchString(authorization.PlanDigest) ||
		authorization.ProviderScope.Validate() != nil ||
		authorization.ProviderScope.Provider !=
			teamplan.CloudProviderAWS ||
		!accountPattern.MatchString(
			authorization.ProviderScope.AccountID,
		) ||
		!validRegion(authorization.Region) ||
		validateNetwork(authorization.Network, authorization.Region) != nil ||
		validateRetention(authorization.Retention) != nil ||
		authorization.WorkerCount == 0 ||
		authorization.WorkerCount > 8 ||
		authorization.WorkerCount != uint32(len(authorization.Roles)) ||
		authorization.MaxConcurrentBillableWorkers == 0 ||
		authorization.MaxConcurrentBillableWorkers >
			authorization.WorkerCount ||
		!currencyPattern.MatchString(authorization.Currency) ||
		authorization.HardBudgetMicros == 0 ||
		authorization.HardBudgetMicros > maximumPlanCostMicros ||
		!authorization.RequiresFreshQuote ||
		authorization.MaximumQuoteAgeSeconds == 0 ||
		authorization.MaximumQuoteAgeSeconds >
			maximumQuoteAgeSeconds ||
		!utcMicrosecond(authorization.LaunchNotBefore) ||
		!utcMicrosecond(authorization.LaunchNotAfter) ||
		!authorization.LaunchNotBefore.Before(
			authorization.LaunchNotAfter,
		) ||
		authorization.LaunchNotAfter.Sub(
			authorization.LaunchNotBefore,
		) > maximumLaunchWindow ||
		!slices.IsSortedFunc(
			authorization.Roles,
			func(left, right RoleLaunchV1) int {
				return strings.Compare(left.RoleID, right.RoleID)
			},
		) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(authorization.Roles))
	var maximumTotal uint64
	for _, role := range authorization.Roles {
		if _, duplicate := seen[role.RoleID]; duplicate ||
			validateRole(
				role,
				authorization.AgentInstanceID,
				teamplan.Plan{
					ProviderScope: authorization.ProviderScope,
					Region:        authorization.Region,
				},
			) != nil ||
			math.MaxUint64-maximumTotal <
				role.MaximumApprovedCostMicros {
			return ErrInvalid
		}
		if role.WorkerImage.ObservedAt.After(
			authorization.LaunchNotBefore,
		) {
			return ErrInvalid
		}
		seen[role.RoleID] = struct{}{}
		maximumTotal += role.MaximumApprovedCostMicros
	}
	if maximumTotal > authorization.HardBudgetMicros {
		return ErrInvalid
	}
	return nil
}

// ValidateAt applies the provider-launch time fence. A signed historic
// authorization remains readable after expiry, but it cannot authorize a new
// provider mutation.
func (authorization AuthorizationV1) ValidateAt(now time.Time) error {
	if authorization.Validate() != nil || now.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	if now.Before(authorization.LaunchNotBefore) ||
		!now.Before(authorization.LaunchNotAfter) {
		return ErrExpired
	}
	return nil
}

func (authorization AuthorizationV1) ValidateAgainst(
	plan teamplan.Plan,
) error {
	if authorization.Validate() != nil || plan.Validate() != nil {
		return ErrPlanChanged
	}
	planDigest, err := plan.Digest()
	if err != nil ||
		authorization.OwnerID != plan.OwnerID ||
		authorization.PlanID != plan.PlanID ||
		authorization.PlanRevision != plan.Revision ||
		authorization.PlanDigest != planDigest ||
		authorization.ProviderScope != plan.ProviderScope ||
		authorization.Region != plan.Region ||
		authorization.LaunchNotBefore.Before(plan.QuotedAt) ||
		authorization.WorkerCount != plan.WorkerCount ||
		authorization.MaxConcurrentBillableWorkers !=
			plan.MaxConcurrentWorkers ||
		authorization.Currency != plan.Cost.Currency ||
		authorization.HardBudgetMicros != plan.Cost.HardBudgetMicros ||
		len(authorization.Roles) != len(plan.Assignments) {
		return ErrPlanChanged
	}
	costs := make(map[string]teamplan.RoleCostEstimate, len(plan.Cost.Roles))
	for _, cost := range plan.Cost.Roles {
		costs[cost.RoleID] = cost
	}
	for index, assignment := range plan.Assignments {
		role := authorization.Roles[index]
		cost, found := costs[assignment.RoleID]
		if !found ||
			role.RoleID != assignment.RoleID ||
			role.RuntimeReleaseID != assignment.RuntimeReleaseID ||
			role.RuntimeImageDigest != assignment.RuntimeImageDigest ||
			!marketplaceBindingsMatch(
				role.Marketplace,
				assignment.Marketplace,
			) ||
			role.ComputeOfferID != assignment.ComputeOfferID ||
			role.InstanceType != assignment.InstanceType ||
			role.Architecture != assignment.Resources.Arch ||
			role.VCPU != assignment.Resources.VCPU ||
			role.MemoryMiB != assignment.Resources.MemoryMiB ||
			role.RootStorage.SizeGiB != assignment.Resources.DiskGiB ||
			role.MaximumApprovedCostMicros !=
				cost.TotalMaximumMicros {
			return ErrPlanChanged
		}
	}
	return nil
}

func (authorization AuthorizationV1) CanonicalCBOR() ([]byte, error) {
	if authorization.Validate() != nil {
		return nil, ErrInvalid
	}
	return canonical.Marshal(authorization)
}

func (authorization AuthorizationV1) Digest() (string, error) {
	if authorization.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(authorization)
}

// ValidateWorkerReleases revalidates the retained publication bytes and binds
// every projected AMI field immediately before dispatch. A matching digest
// string without the original evidence is insufficient.
func (authorization AuthorizationV1) ValidateWorkerReleases(
	releases []workerrelease.ReleaseV1,
) error {
	if authorization.Validate() != nil ||
		len(releases) == 0 ||
		len(releases) > len(authorization.Roles) {
		return ErrImageChanged
	}
	byDigest := make(map[string]WorkerImageV1, len(releases))
	for _, candidate := range releases {
		release, err := workerrelease.ValidateStored(candidate)
		if err != nil {
			return ErrImageChanged
		}
		image := workerImageFromRelease(release)
		if _, duplicate := byDigest[image.PublicationDigest]; duplicate {
			return ErrImageChanged
		}
		byDigest[image.PublicationDigest] = image
	}
	for _, role := range authorization.Roles {
		image, found := byDigest[role.WorkerImage.PublicationDigest]
		if !found || image != role.WorkerImage {
			return ErrImageChanged
		}
	}
	return nil
}

func validateRole(
	role RoleLaunchV1,
	agentInstanceID string,
	plan teamplan.Plan,
) error {
	foundation, foundationErr := awsfoundation.BuildSpec(
		awsfoundation.SpecInput{
			AgentInstanceID: agentInstanceID,
			Partition:       partitionForRegion(plan.Region),
			AccountID:       plan.ProviderScope.AccountID,
			Region:          plan.Region,
		},
	)
	if !validRoleID(role.RoleID) ||
		!canonicalUUID(role.RuntimeReleaseID) ||
		!digestPattern.MatchString(role.RuntimeImageDigest) ||
		(role.Marketplace != nil &&
			role.Marketplace.Validate(
				role.RuntimeReleaseID,
				role.RuntimeImageDigest,
			) != nil) ||
		!digestPattern.MatchString(role.RuntimeInstallationDigest) ||
		!digestPattern.MatchString(role.RuntimeExecutableDigest) ||
		!canonicalUUID(role.ComputeOfferID) ||
		!instanceTypePattern.MatchString(role.InstanceType) ||
		!recipe.ValidArchitecture(role.Architecture) ||
		role.VCPU == 0 ||
		role.MemoryMiB == 0 ||
		role.PurchaseOption != PurchaseOnDemand ||
		!instanceProfile.MatchString(role.InstanceProfileName) ||
		security.ContainsLikelySecret(role.InstanceProfileName) ||
		foundationErr != nil ||
		role.InstanceProfileName != foundation.WorkerProfileName ||
		!role.EBSOptimized ||
		!role.RequireIMDSv2 ||
		role.MetadataResponseHopLimit != 1 ||
		role.ShutdownBehavior != ShutdownTerminate ||
		validateRootStorage(
			role.RootStorage,
			agentInstanceID,
		) != nil ||
		validateWorkerImage(
			role.WorkerImage,
			agentInstanceID,
			plan.ProviderScope.AccountID,
			plan.Region,
			role.Architecture,
		) != nil ||
		role.MaximumApprovedCostMicros == 0 ||
		role.MaximumApprovedCostMicros > maximumPlanCostMicros {
		return ErrInvalid
	}
	return nil
}

func marketplaceBindingsMatch(
	left,
	right *teamplan.WorkerMarketplaceBindingV1,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func validateWorkerImage(
	image WorkerImageV1,
	agentInstanceID,
	accountID,
	region string,
	architecture recipe.Architecture,
) error {
	if !digestPattern.MatchString(image.PublicationDigest) ||
		image.AgentInstanceID != agentInstanceID ||
		image.AccountID != accountID ||
		image.Region != region ||
		image.Architecture != architecture ||
		!awsIDPattern.MatchString(image.ImageID) ||
		!strings.HasPrefix(image.ImageID, "ami-") ||
		!digestPattern.MatchString(image.ImageDigest) ||
		!awsIDPattern.MatchString(image.RootSnapshotID) ||
		!strings.HasPrefix(image.RootSnapshotID, "snap-") ||
		!digestPattern.MatchString(image.ReleaseManifestDigest) ||
		!digestPattern.MatchString(image.WorkerRootFSDigest) ||
		!digestPattern.MatchString(image.WorkerBinaryDigest) ||
		!utcMicrosecond(image.ObservedAt) {
		return ErrInvalid
	}
	return nil
}

func validateNetwork(value NetworkV1, region string) error {
	endpoint, controlPort, err := parseControlEndpoint(
		value.ControlPlaneEndpoint,
	)
	if value.ConnectivityMode != ConnectivityDirectPublicTLSV1 ||
		!awsIDPattern.MatchString(value.VPCID) ||
		!strings.HasPrefix(value.VPCID, "vpc-") ||
		!awsIDPattern.MatchString(value.SubnetID) ||
		!strings.HasPrefix(value.SubnetID, "subnet-") ||
		!availabilityZone.MatchString(value.AvailabilityZone) ||
		availabilityZoneRegion(value.AvailabilityZone) != region ||
		value.SecurityGroupMode != SecurityGroupDedicatedNoIngress ||
		!value.PublicIPv4 ||
		value.PublicInbound ||
		err != nil ||
		endpoint == nil ||
		len(value.ControlPlaneEndpoint) > 2048 ||
		security.ContainsLikelySecret(value.ControlPlaneEndpoint) ||
		len(value.Egress) == 0 ||
		len(value.Egress) > 8 ||
		!slices.IsSortedFunc(
			value.Egress,
			compareEgressRules,
		) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(value.Egress))
	hasHTTPS := false
	hasControl := false
	for _, rule := range value.Egress {
		if validateEgressRule(rule, controlPort) != nil {
			return ErrInvalid
		}
		key := egressRuleKey(rule)
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalid
		}
		seen[key] = struct{}{}
		if rule.Protocol == "tcp" &&
			rule.FromPort == 443 &&
			rule.CIDRv4 == "0.0.0.0/0" {
			hasHTTPS = true
		}
		if rule.Protocol == "tcp" &&
			rule.FromPort == controlPort &&
			rule.CIDRv4 == "0.0.0.0/0" {
			hasControl = true
		}
	}
	if !hasHTTPS || !hasControl {
		return ErrInvalid
	}
	return nil
}

func validateRetention(value RetentionV1) error {
	if value.Class != RetentionEphemeralAutoDestroy ||
		!value.AutoDestroy ||
		value.MaximumLifetimeSeconds == 0 ||
		value.MaximumLifetimeSeconds > maximumWorkerLifetime ||
		value.DestroyGraceSeconds < minimumDestroyGrace ||
		value.DestroyGraceSeconds > maximumDestroyGrace ||
		value.DestroyGraceSeconds >= value.MaximumLifetimeSeconds {
		return ErrInvalid
	}
	return nil
}

func validateRootStorage(
	value RootStorageV1,
	agentInstanceID string,
) error {
	expectedAlias, err := awsfoundation.KMSAliasForAgent(agentInstanceID)
	if value.DeviceName != "/dev/sda1" ||
		value.SizeGiB < 8 ||
		value.SizeGiB > 1024 ||
		value.VolumeType != "gp3" ||
		value.IOPS != 3000 ||
		value.ThroughputMiBPS != 125 ||
		!kmsKeyPattern.MatchString(value.KMSKeyID) ||
		err != nil ||
		value.KMSKeyID != expectedAlias ||
		!value.Encrypted ||
		!value.DeleteOnTermination ||
		security.ContainsLikelySecret(value.KMSKeyID) {
		return ErrInvalid
	}
	return nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == value
}

func validRegion(value string) bool {
	return regionPattern.MatchString(value)
}

func validRoleID(value string) bool {
	if len(value) == 0 || len(value) > 64 ||
		value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' {
					return false
				}
			}
		}
	}
	return true
}

func safeText(value string, maximum int) bool {
	if value == "" ||
		value != strings.TrimSpace(value) ||
		len(value) > maximum ||
		!utf8.ValidString(value) ||
		strings.IndexByte(value, 0) >= 0 ||
		security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func utcMicrosecond(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Nanosecond()%1000 == 0
}

func normalizedNetwork(value NetworkV1, region string) (NetworkV1, error) {
	value.Egress = append([]EgressRuleV1(nil), value.Egress...)
	slices.SortFunc(value.Egress, compareEgressRules)
	if validateNetwork(value, region) != nil {
		return NetworkV1{}, ErrInvalid
	}
	return value, nil
}

func compareEgressRules(left, right EgressRuleV1) int {
	return strings.Compare(egressRuleKey(left), egressRuleKey(right))
}

func egressRuleKey(rule EgressRuleV1) string {
	return fmt.Sprintf(
		"%s:%05d:%05d:%s",
		rule.Protocol,
		rule.FromPort,
		rule.ToPort,
		rule.CIDRv4,
	)
}

func validateEgressRule(rule EgressRuleV1, controlPort uint16) error {
	ip, network, err := net.ParseCIDR(rule.CIDRv4)
	if err != nil ||
		ip.To4() == nil ||
		network.String() != rule.CIDRv4 ||
		rule.FromPort == 0 ||
		rule.FromPort != rule.ToPort {
		return ErrInvalid
	}
	switch {
	case rule.Protocol == "tcp" &&
		(rule.FromPort == 443 || rule.FromPort == controlPort):
		return nil
	case (rule.Protocol == "tcp" || rule.Protocol == "udp") &&
		rule.FromPort == 53 &&
		rule.CIDRv4 == vpcResolverCIDR:
		return nil
	default:
		return ErrInvalid
	}
}

func parseControlEndpoint(value string) (*url.URL, uint16, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return nil, 0, ErrInvalid
	}
	endpoint, err := url.Parse(value)
	if err != nil ||
		endpoint.Scheme != "grpcs" ||
		endpoint.Host == "" ||
		endpoint.User != nil ||
		endpoint.Opaque != "" ||
		endpoint.Path != "" ||
		endpoint.RawPath != "" ||
		endpoint.RawQuery != "" ||
		endpoint.ForceQuery ||
		endpoint.Fragment != "" ||
		endpoint.String() != value {
		return nil, 0, ErrInvalid
	}
	hostname := endpoint.Hostname()
	if len(hostname) > 253 ||
		!hostnamePattern.MatchString(hostname) ||
		net.ParseIP(hostname) != nil {
		return nil, 0, ErrInvalid
	}
	port := uint64(443)
	if endpoint.Port() != "" {
		port, err = strconv.ParseUint(endpoint.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, 0, ErrInvalid
		}
	}
	return endpoint, uint16(port), nil
}

func availabilityZoneRegion(zone string) string {
	if !availabilityZone.MatchString(zone) || len(zone) < 2 {
		return ""
	}
	return zone[:len(zone)-1]
}

func partitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	default:
		return "aws"
	}
}

func workerImageFromRelease(release workerrelease.ReleaseV1) WorkerImageV1 {
	return WorkerImageV1{
		PublicationDigest:     release.PublicationDigest,
		AgentInstanceID:       release.AgentInstanceID,
		AccountID:             release.AccountID,
		Region:                release.Region,
		Architecture:          release.Architecture,
		ImageID:               release.ImageID,
		ImageDigest:           release.ImageDigest,
		RootSnapshotID:        release.RootSnapshotID,
		ReleaseManifestDigest: release.ReleaseManifestDigest,
		WorkerRootFSDigest:    release.WorkerRootFSDigest,
		WorkerBinaryDigest:    release.WorkerBinaryDigest,
		ObservedAt:            release.ObservedAt.UTC(),
	}
}

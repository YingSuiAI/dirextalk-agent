package quote

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

var (
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	regionPattern       = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	availabilityPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+[a-z]$`)
	instanceTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)
	amiPattern          = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	awsIDPattern        = regexp.MustCompile(`^(?:vpc|subnet|sg)-[0-9a-f]{8,17}$`)
	secretRefPattern    = regexp.MustCompile(`^secret_ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	currencyPattern     = regexp.MustCompile(`^[A-Z]{3}$`)
	volumeTypePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	credentialPattern   = regexp.MustCompile(`(?i)(?:AKIA|ASIA)[A-Z0-9]{16}|aws[_ -]?(?:secret[_ -]?access[_ -]?key|session[_ -]?token)|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|(?:^|[^A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|sk[-_][A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})`)
)

func (s ScopeV1) Validate() error {
	if s.SchemaVersion != ScopeSchemaV1 {
		return fmt.Errorf("scope.schema_version must be %q", ScopeSchemaV1)
	}
	for name, value := range map[string]string{
		"scope.agent_instance_id": s.AgentInstanceID,
		"scope.owner_id":          s.OwnerID,
		"scope.connection_id":     s.ConnectionID,
		"scope.recipe.recipe_id":  s.Recipe.RecipeID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if err := recipe.ValidateDigest(s.Recipe.Digest); err != nil {
		return fmt.Errorf("scope.recipe.digest %w", err)
	}
	if !recipe.ValidMaturity(s.Recipe.Maturity) {
		return fmt.Errorf("scope.recipe.maturity is invalid")
	}
	if err := validateResource(s.Resource); err != nil {
		return err
	}
	if err := validateNetwork(s.Network); err != nil {
		return err
	}
	if err := validateSecrets(s.SecretScope); err != nil {
		return err
	}
	if err := validateIntegrations(s.IntegrationScope); err != nil {
		return err
	}
	return validateRetention(s.Retention)
}

func validateResource(value ResourceScopeV1) error {
	if candidateRank(value.CandidateID) > 2 {
		return fmt.Errorf("scope.resource.candidate_id is invalid")
	}
	if !regionPattern.MatchString(value.Region) {
		return fmt.Errorf("scope.resource.region is invalid")
	}
	if err := validateZones(value.Region, value.AvailabilityZones); err != nil {
		return fmt.Errorf("scope.resource.availability_zones %w", err)
	}
	if !instanceTypePattern.MatchString(value.InstanceType) {
		return fmt.Errorf("scope.resource.instance_type is invalid")
	}
	if value.InstanceCount != 1 {
		return fmt.Errorf("scope.resource.instance_count must be one for an exclusive Worker")
	}
	if !recipe.ValidArchitecture(value.Architecture) {
		return fmt.Errorf("scope.resource.architecture is invalid")
	}
	if value.VCPU == 0 || value.VCPU > 1024 || value.MemoryMiB == 0 || value.MemoryMiB > 64*1024*1024 || value.DiskGiB == 0 || value.DiskGiB > 64*1024 {
		return fmt.Errorf("scope.resource compute, memory, and disk values are invalid")
	}
	if value.GPUCount == 0 {
		if value.GPUType != "" || value.GPUMemoryMiB != 0 {
			return fmt.Errorf("scope.resource GPU details require gpu_count")
		}
	} else {
		if value.GPUCount > 64 || value.GPUMemoryMiB == 0 || value.GPUMemoryMiB > 16*1024*1024 {
			return fmt.Errorf("scope.resource GPU count or memory is invalid")
		}
		if err := validateText("scope.resource.gpu_type", value.GPUType, 1, 128); err != nil {
			return err
		}
	}
	if !volumeTypePattern.MatchString(value.VolumeType) || !value.VolumeEncrypted {
		return fmt.Errorf("scope.resource requires a valid encrypted volume")
	}
	if value.VolumeIOPS > 256000 || value.VolumeThroughputMiBPS > 10000 {
		return fmt.Errorf("scope.resource volume performance is out of range")
	}
	if value.PurchaseOption != PurchaseOnDemand && value.PurchaseOption != PurchaseSpot {
		return fmt.Errorf("scope.resource.purchase_option is invalid")
	}
	if !amiPattern.MatchString(value.WorkerImageID) {
		return fmt.Errorf("scope.resource.worker_image_id is invalid")
	}
	if err := recipe.ValidateDigest(value.WorkerImageDigest); err != nil {
		return fmt.Errorf("scope.resource.worker_image_digest %w", err)
	}
	return nil
}

func validateNetwork(value NetworkScopeV1) error {
	if !awsIDPattern.MatchString(value.VPCID) || !strings.HasPrefix(value.VPCID, "vpc-") ||
		!awsIDPattern.MatchString(value.SubnetID) || !strings.HasPrefix(value.SubnetID, "subnet-") ||
		!awsIDPattern.MatchString(value.SecurityGroupID) || !strings.HasPrefix(value.SecurityGroupID, "sg-") {
		return fmt.Errorf("scope.network contains an invalid AWS network identifier")
	}
	if err := validatePorts(value.IngressPorts); err != nil {
		return err
	}
	if value.EntryPoint == EntryPointNone {
		if value.PublicExposure || len(value.IngressPorts) != 0 || value.Hostname != "" || value.TLSRequired || value.AuthenticationRequired {
			return fmt.Errorf("scope.network with no entry point cannot declare public exposure")
		}
		return nil
	}
	if value.EntryPoint != EntryPointALB && value.EntryPoint != EntryPointCloudFront {
		return fmt.Errorf("scope.network.entry_point is invalid")
	}
	if !value.PublicExposure || len(value.IngressPorts) == 0 || value.Hostname == "" || !value.TLSRequired || !value.AuthenticationRequired {
		return fmt.Errorf("public scope.network requires ports, hostname, TLS, and authentication")
	}
	return validateText("scope.network.hostname", value.Hostname, 1, 253)
}

func validateSecrets(values []SecretScopeV1) error {
	if len(values) > 32 {
		return fmt.Errorf("scope.secret_scope must contain at most 32 entries")
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		name := fmt.Sprintf("scope.secret_scope[%d]", index)
		if !secretRefPattern.MatchString(value.SecretRef) {
			return fmt.Errorf("%s.secret_ref is invalid", name)
		}
		if _, exists := seen[value.SecretRef]; exists {
			return fmt.Errorf("scope.secret_scope contains duplicate references")
		}
		seen[value.SecretRef] = struct{}{}
		if err := validateText(name+".purpose", value.Purpose, 1, 256); err != nil {
			return err
		}
		if !recipe.ValidSecretDelivery(value.Delivery) {
			return fmt.Errorf("%s.delivery is invalid", name)
		}
	}
	return nil
}

func validateIntegrations(values []IntegrationScopeV1) error {
	if len(values) > 32 {
		return fmt.Errorf("scope.integration_scope must contain at most 32 entries")
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		name := fmt.Sprintf("scope.integration_scope[%d]", index)
		switch value.Kind {
		case IntegrationMCP, IntegrationACP, IntegrationGRPC, IntegrationWeb:
		default:
			return fmt.Errorf("%s.kind is invalid", name)
		}
		if err := validateText(name+".name", value.Name, 1, 160); err != nil {
			return err
		}
		key := string(value.Kind) + "\x00" + value.Name
		if _, exists := seen[key]; exists {
			return fmt.Errorf("scope.integration_scope contains duplicate entries")
		}
		seen[key] = struct{}{}
		if err := validateTextSet(name+".scopes", value.Scopes, 32); err != nil {
			return err
		}
	}
	return nil
}

func validateRetention(value RetentionScopeV1) error {
	switch value.Class {
	case RetentionEphemeral:
		if !value.AutoDestroy || value.GracePeriodSeconds == 0 || value.MaxLifetimeSeconds == 0 || uint64(value.GracePeriodSeconds) > value.MaxLifetimeSeconds || value.MaxLifetimeSeconds > 365*24*60*60 {
			return fmt.Errorf("scope.retention ephemeral deadlines are invalid")
		}
	case RetentionManaged:
		if value.AutoDestroy || value.GracePeriodSeconds != 0 || value.MaxLifetimeSeconds != 0 {
			return fmt.Errorf("scope.retention managed resources cannot auto-destroy")
		}
	default:
		return fmt.Errorf("scope.retention.class is invalid")
	}
	return nil
}

func (r RequestV1) Validate() error {
	if err := validateIdentifier("quote_id", r.QuoteID); err != nil {
		return err
	}
	if len(r.Scopes) != 3 {
		return fmt.Errorf("quote request must contain exactly three candidate scopes")
	}
	if err := validateUsage(r.Usage); err != nil {
		return err
	}
	normalized := make([]ScopeV1, len(r.Scopes))
	seen := make(map[CandidateProfile]struct{}, 3)
	for index, scope := range r.Scopes {
		if err := scope.Validate(); err != nil {
			return fmt.Errorf("scopes[%d]: %w", index, err)
		}
		if _, exists := seen[scope.Resource.CandidateID]; exists {
			return fmt.Errorf("candidate scopes contain duplicate profiles")
		}
		seen[scope.Resource.CandidateID] = struct{}{}
		normalized[index] = normalizeScope(scope)
	}
	for _, required := range []CandidateProfile{CandidateEconomic, CandidateRecommended, CandidatePerformance} {
		if _, exists := seen[required]; !exists {
			return fmt.Errorf("candidate profile %q is required", required)
		}
	}
	sort.Slice(normalized, func(i, j int) bool {
		return candidateRank(normalized[i].Resource.CandidateID) < candidateRank(normalized[j].Resource.CandidateID)
	})
	base := normalized[0]
	for index := 1; index < len(normalized); index++ {
		current := normalized[index]
		if base.AgentInstanceID != current.AgentInstanceID || base.OwnerID != current.OwnerID || base.ConnectionID != current.ConnectionID ||
			!reflect.DeepEqual(base.Recipe, current.Recipe) || !reflect.DeepEqual(base.Network, current.Network) ||
			!reflect.DeepEqual(base.SecretScope, current.SecretScope) || !reflect.DeepEqual(base.IntegrationScope, current.IntegrationScope) ||
			!reflect.DeepEqual(base.Retention, current.Retention) || base.Resource.Region != current.Resource.Region ||
			!reflect.DeepEqual(base.Resource.AvailabilityZones, current.Resource.AvailabilityZones) {
			return fmt.Errorf("candidate scopes must share identity, Region, network, secret, integration, and retention scope")
		}
	}
	for index := 1; index < len(normalized); index++ {
		previous, current := normalized[index-1].Resource, normalized[index].Resource
		if current.VCPU < previous.VCPU || current.MemoryMiB < previous.MemoryMiB || current.DiskGiB < previous.DiskGiB || current.GPUCount < previous.GPUCount || current.GPUMemoryMiB < previous.GPUMemoryMiB {
			return fmt.Errorf("recommended/performance candidates cannot reduce resources")
		}
	}
	return nil
}

func (q QuoteV1) Validate() error {
	if q.SchemaVersion != SchemaV1 {
		return fmt.Errorf("schema_version must be %q", SchemaV1)
	}
	if err := validateIdentifier("quote_id", q.QuoteID); err != nil {
		return err
	}
	if q.QuotedAt.IsZero() || q.ValidUntil.IsZero() || !q.ValidUntil.Equal(q.QuotedAt.Add(Validity)) {
		return fmt.Errorf("valid_until must be exactly 15 minutes after quoted_at")
	}
	if !currencyPattern.MatchString(q.Currency) {
		return fmt.Errorf("currency must be an uppercase ISO-style code")
	}
	if len(q.Candidates) != 3 {
		return fmt.Errorf("quote must contain exactly three candidates")
	}
	if err := validateUsage(q.Usage); err != nil {
		return err
	}
	if err := validateTextSetRequired("assumptions", q.Assumptions, 32); err != nil {
		return err
	}
	if err := validateTextSetRequired("exclusions", q.Exclusions, 32); err != nil {
		return err
	}
	seen := make(map[CandidateProfile]struct{}, 3)
	hasSpot := false
	requestProjection := RequestV1{QuoteID: q.QuoteID, Usage: q.Usage, SpotQualification: q.SpotEvidence}
	for index, candidate := range q.Candidates {
		if err := validateCandidate(candidate, q.Currency); err != nil {
			return fmt.Errorf("candidates[%d]: %w", index, err)
		}
		if _, exists := seen[candidate.CandidateID]; exists {
			return fmt.Errorf("quote contains duplicate candidate profiles")
		}
		seen[candidate.CandidateID] = struct{}{}
		hasSpot = hasSpot || candidate.Scope.Resource.PurchaseOption == PurchaseSpot
		requestProjection.Scopes = append(requestProjection.Scopes, candidate.Scope)
	}
	for _, required := range []CandidateProfile{CandidateEconomic, CandidateRecommended, CandidatePerformance} {
		if _, exists := seen[required]; !exists {
			return fmt.Errorf("quote candidate %q is required", required)
		}
	}
	if err := requestProjection.Validate(); err != nil {
		return fmt.Errorf("quote candidate scopes: %w", err)
	}
	if hasSpot {
		if q.SpotEvidence == nil {
			return fmt.Errorf("Spot quote requires qualification evidence")
		}
		if err := validateSpotEvidence(*q.SpotEvidence); err != nil {
			return err
		}
		for _, candidate := range q.Candidates {
			if candidate.Scope.Resource.PurchaseOption == PurchaseSpot && candidate.Scope.Recipe.Digest != q.SpotEvidence.RecipeDigest {
				return fmt.Errorf("Spot evidence does not bind candidate Recipe")
			}
		}
	} else if q.SpotEvidence != nil {
		return fmt.Errorf("Spot evidence is not allowed without a Spot candidate")
	}
	return nil
}

func validateCandidate(value CandidateV1, _ string) error {
	if value.CandidateID != value.Scope.Resource.CandidateID {
		return fmt.Errorf("candidate_id does not match scope")
	}
	if err := value.Scope.Validate(); err != nil {
		return err
	}
	digest, err := value.Scope.Digest()
	if err != nil {
		return err
	}
	if value.ScopeDigest != digest {
		return fmt.Errorf("scope_digest does not match complete scope")
	}
	if err := validateZones(value.Scope.Resource.Region, value.OfferedAvailabilityZones); err != nil {
		return fmt.Errorf("offered_availability_zones %w", err)
	}
	if !hasIntersection(value.Scope.Resource.AvailabilityZones, value.OfferedAvailabilityZones) {
		return fmt.Errorf("candidate is unavailable in requested availability zones")
	}
	if len(value.Quotas) == 0 || len(value.Quotas) > 16 {
		return fmt.Errorf("candidate requires quota evidence")
	}
	seenQuotas := make(map[string]struct{}, len(value.Quotas))
	for _, quota := range value.Quotas {
		if err := validateIdentifier("quota.service_code", quota.ServiceCode); err != nil {
			return err
		}
		if err := validateIdentifier("quota.quota_code", quota.QuotaCode); err != nil {
			return err
		}
		key := quota.ServiceCode + "\x00" + quota.QuotaCode
		if _, exists := seenQuotas[key]; exists {
			return fmt.Errorf("candidate contains duplicate quota evidence")
		}
		seenQuotas[key] = struct{}{}
		if quota.RequiredUnits == 0 || quota.UsedUnits > quota.LimitUnits || quota.RequiredUnits > quota.LimitUnits-quota.UsedUnits {
			return fmt.Errorf("candidate exceeds current account quota")
		}
	}
	return validateCosts(value)
}

func validateCosts(value CandidateV1) error {
	if len(value.CostItems) < 7 || len(value.CostItems) > 32 {
		return fmt.Errorf("candidate must include compute, EBS, IPv4, logs, snapshot, entry, and traffic estimates")
	}
	required := map[CostCategory]bool{CostEBS: false, CostPublicIPv4: false, CostLogs: false, CostSnapshot: false, CostEntry: false, CostTraffic: false}
	compute := CostComputeOnDemand
	if value.Scope.Resource.PurchaseOption == PurchaseSpot {
		compute = CostComputeSpot
	}
	required[compute] = false
	seenSource := make(map[string]struct{}, len(value.CostItems))
	var hourly, monthly, launch uint64
	for index, item := range value.CostItems {
		if _, exists := required[item.Category]; !exists {
			return fmt.Errorf("cost_items[%d].category is not applicable", index)
		}
		required[item.Category] = true
		if err := validateText(fmt.Sprintf("cost_items[%d].description", index), item.Description, 1, 256); err != nil {
			return err
		}
		if err := validateIdentifier(fmt.Sprintf("cost_items[%d].source_id", index), item.SourceID); err != nil {
			return err
		}
		if _, exists := seenSource[item.SourceID]; exists {
			return fmt.Errorf("cost_items contain duplicate source_id")
		}
		seenSource[item.SourceID] = struct{}{}
		var ok bool
		if hourly, ok = checkedAdd(hourly, item.HourlyEstimateMicros); !ok {
			return fmt.Errorf("hourly estimate overflows")
		}
		if monthly, ok = checkedAdd(monthly, item.MonthlyEstimateMicros); !ok {
			return fmt.Errorf("monthly estimate overflows")
		}
		if launch, ok = checkedAdd(launch, item.MaximumLaunchAmountMicros); !ok {
			return fmt.Errorf("maximum launch amount overflows")
		}
	}
	for category, present := range required {
		if !present {
			return fmt.Errorf("cost category %q is required, including zero-cost estimates", category)
		}
	}
	if hourly != value.HourlyEstimateMicros || monthly != value.MonthlyEstimateMicros || launch != value.MaximumLaunchAmountMicros {
		return fmt.Errorf("candidate aggregate estimates do not equal exact cost-item sums")
	}
	return nil
}

func validateUsage(value UsageV1) error {
	if value.RuntimeHoursPerMonth == 0 || value.RuntimeHoursPerMonth > 744 || value.PublicIPv4Hours > 744 || value.EntryHours > 744 {
		return fmt.Errorf("usage hourly assumptions are invalid")
	}
	const maxUsage = uint64(1 << 50)
	if value.LogIngestMiB > maxUsage || value.LogStoredMiBMonths > maxUsage || value.SnapshotGiBMonths > maxUsage || value.InternetEgressMiB > maxUsage {
		return fmt.Errorf("usage assumptions are out of range")
	}
	return nil
}

func validateSpotEvidence(value SpotQualificationV1) error {
	if err := validateIdentifier("spot_evidence.evidence_id", value.EvidenceID); err != nil {
		return err
	}
	if err := recipe.ValidateDigest(value.RecipeDigest); err != nil {
		return fmt.Errorf("spot_evidence.recipe_digest %w", err)
	}
	if err := validateIdentifier("spot_evidence.checkpoint_name", value.CheckpointName); err != nil {
		return err
	}
	if err := validateIdentifier("spot_evidence.resume_action", value.ResumeAction); err != nil {
		return err
	}
	if value.MaxRetries == 0 || value.MaxRetries > 100 || value.CheckpointVerifiedAt.IsZero() || value.InterruptionTestedAt.IsZero() || value.InterruptionTestedAt.Before(value.CheckpointVerifiedAt) {
		return fmt.Errorf("Spot evidence requires checkpoint/resume verification, interruption test, and bounded retries")
	}
	return nil
}

func validateZones(region string, zones []string) error {
	if len(zones) == 0 || len(zones) > 16 {
		return fmt.Errorf("must contain between 1 and 16 entries")
	}
	seen := make(map[string]struct{}, len(zones))
	for _, zone := range zones {
		if !availabilityPattern.MatchString(zone) || !strings.HasPrefix(zone, region) {
			return fmt.Errorf("contains invalid zone")
		}
		if _, exists := seen[zone]; exists {
			return fmt.Errorf("contains duplicates")
		}
		seen[zone] = struct{}{}
	}
	return nil
}

func validatePorts(values []uint32) error {
	seen := make(map[uint32]struct{}, len(values))
	for _, port := range values {
		if port == 0 || port > 65535 {
			return fmt.Errorf("scope.network.ingress_ports contains invalid port")
		}
		if _, exists := seen[port]; exists {
			return fmt.Errorf("scope.network.ingress_ports contains duplicates")
		}
		seen[port] = struct{}{}
	}
	return nil
}

func validateIdentifier(name, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s is not a valid identifier", name)
	}
	return nil
}

func validateText(name, value string, minimum, maximum int) error {
	if value != strings.TrimSpace(value) || len(value) < minimum || len(value) > maximum {
		return fmt.Errorf("%s must contain %d-%d trimmed bytes", name, minimum, maximum)
	}
	if credentialPattern.MatchString(value) {
		return fmt.Errorf("%s contains credential-like material", name)
	}
	return nil
}

func validateTextSet(name string, values []string, maximum int) error {
	if len(values) > maximum {
		return fmt.Errorf("%s must contain at most %d entries", name, maximum)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if err := validateText(fmt.Sprintf("%s[%d]", name, index), value, 1, 256); err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicates", name)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateTextSetRequired(name string, values []string, maximum int) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must explicitly state at least one item", name)
	}
	return validateTextSet(name, values, maximum)
}

func hasIntersection(left, right []string) bool {
	set := make(map[string]struct{}, len(left))
	for _, value := range left {
		set[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := set[value]; exists {
			return true
		}
	}
	return false
}

func checkedAdd(left, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}
	return left + right, true
}

func normalizeRequest(value RequestV1) RequestV1 {
	value.Scopes = append([]ScopeV1(nil), value.Scopes...)
	for index := range value.Scopes {
		value.Scopes[index] = normalizeScope(value.Scopes[index])
	}
	sort.Slice(value.Scopes, func(i, j int) bool {
		return candidateRank(value.Scopes[i].Resource.CandidateID) < candidateRank(value.Scopes[j].Resource.CandidateID)
	})
	if value.SpotQualification != nil {
		copy := *value.SpotQualification
		copy.CheckpointVerifiedAt = copy.CheckpointVerifiedAt.UTC()
		copy.InterruptionTestedAt = copy.InterruptionTestedAt.UTC()
		value.SpotQualification = &copy
	}
	return value
}

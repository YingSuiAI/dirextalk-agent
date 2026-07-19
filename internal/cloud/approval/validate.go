package approval

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

var (
	identifierPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	regionPattern        = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	availabilityPattern  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+[a-z]$`)
	instanceTypePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)
	amiPattern           = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	vpcPattern           = regexp.MustCompile(`^vpc-[0-9a-f]{8,17}$`)
	subnetPattern        = regexp.MustCompile(`^subnet-[0-9a-f]{8,17}$`)
	securityGroupPattern = regexp.MustCompile(`^sg-[0-9a-f]{8,17}$`)
	routeTablePattern    = regexp.MustCompile(`^rtb-[0-9a-f]{8,17}$`)
	secretRefPattern     = regexp.MustCompile(`^secret_ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	volumeTypePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	credentialPattern    = regexp.MustCompile(`(?i)(?:AKIA|ASIA)[A-Z0-9]{16}|aws[_ -]?(?:secret[_ -]?access[_ -]?key|session[_ -]?token)|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|(?:^|[^A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|sk[-_][A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})`)
)

func (p PlanV1) Validate() error {
	if p.SchemaVersion != PlanSchemaV1 && p.SchemaVersion != PlanSchemaV2 {
		return fmt.Errorf("schema_version must be %q or %q", PlanSchemaV1, PlanSchemaV2)
	}
	for name, value := range map[string]string{
		"agent_instance_id": p.AgentInstanceID,
		"owner_id":          p.OwnerID,
		"plan_id":           p.PlanID,
		"connection_id":     p.ConnectionID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if p.Revision == 0 {
		return fmt.Errorf("revision must be positive")
	}
	if !validPlanStatus(p.Status) {
		return fmt.Errorf("status is invalid")
	}
	if err := validateRecipeBinding(p.Recipe); err != nil {
		return err
	}
	if err := validateQuoteBinding(p.Quote); err != nil {
		return err
	}
	if err := validateResourceScope(p.ResourceScope); err != nil {
		return err
	}
	if err := validateNetworkScope(p.NetworkScope); err != nil {
		return err
	}
	if err := validateSecretScope(p.SecretScope); err != nil {
		return err
	}
	if err := validateIntegrationScope(p.IntegrationScope); err != nil {
		return err
	}
	if err := validateRetentionScope(p.RetentionScope); err != nil {
		return err
	}
	if err := validateVolumeDisposition(p.ResourceScope.VolumeScopes, p.RetentionScope); err != nil {
		return err
	}
	if p.SchemaVersion == PlanSchemaV1 {
		if p.ServiceOperations != nil {
			return fmt.Errorf("service_operations require %q", PlanSchemaV2)
		}
	} else if p.ServiceOperations == nil {
		return fmt.Errorf("service_operations are required for %q", PlanSchemaV2)
	} else if err := validateServiceOperations(*p.ServiceOperations, p.ResourceScope, p.NetworkScope, p.RetentionScope); err != nil {
		return fmt.Errorf("service_operations: %w", err)
	}
	scopeDigest, err := p.PricingScopeDigest()
	if err != nil {
		return fmt.Errorf("quote scope: %w", err)
	}
	if p.Quote.ScopeDigest != scopeDigest {
		return fmt.Errorf("quote.scope_digest does not match complete price-sensitive plan scope; requote required")
	}
	return nil
}

func validPlanStatus(value PlanStatus) bool {
	switch value {
	case PlanResearching, PlanQuoting, PlanReadyForConfirmation, PlanApproved, PlanExpired, PlanSuperseded:
		return true
	default:
		return false
	}
}

func validateRecipeBinding(value RecipeBindingV1) error {
	if err := validateIdentifier("recipe.recipe_id", value.RecipeID); err != nil {
		return err
	}
	if err := recipe.ValidateDigest(value.Digest); err != nil {
		return fmt.Errorf("recipe.digest %w", err)
	}
	if !recipe.ValidMaturity(value.Maturity) {
		return fmt.Errorf("recipe.maturity is invalid")
	}
	return nil
}

func validateQuoteBinding(value QuoteBindingV1) error {
	if err := validateIdentifier("quote.quote_id", value.QuoteID); err != nil {
		return err
	}
	if err := recipe.ValidateDigest(value.Digest); err != nil {
		return fmt.Errorf("quote.digest %w", err)
	}
	if err := recipe.ValidateDigest(value.ScopeDigest); err != nil {
		return fmt.Errorf("quote.scope_digest %w", err)
	}
	if err := validateIdentifier("quote.candidate_id", value.CandidateID); err != nil {
		return err
	}
	if value.ValidUntil.IsZero() {
		return fmt.Errorf("quote.valid_until is required")
	}
	return nil
}

func validateResourceScope(value ResourceScopeV1) error {
	if !regionPattern.MatchString(value.Region) {
		return fmt.Errorf("resource_scope.region is invalid")
	}
	if len(value.AvailabilityZones) == 0 || len(value.AvailabilityZones) > 16 {
		return fmt.Errorf("resource_scope.availability_zones must contain between 1 and 16 entries")
	}
	seenZones := make(map[string]struct{}, len(value.AvailabilityZones))
	for _, zone := range value.AvailabilityZones {
		if !availabilityPattern.MatchString(zone) || !strings.HasPrefix(zone, value.Region) {
			return fmt.Errorf("resource_scope.availability_zones contains an invalid zone")
		}
		if _, exists := seenZones[zone]; exists {
			return fmt.Errorf("resource_scope.availability_zones contains duplicates")
		}
		seenZones[zone] = struct{}{}
	}
	if !instanceTypePattern.MatchString(value.InstanceType) {
		return fmt.Errorf("resource_scope.instance_type is invalid")
	}
	if !recipe.ValidArchitecture(value.Architecture) {
		return fmt.Errorf("resource_scope.architecture is invalid")
	}
	if value.InstanceCount != 1 {
		return fmt.Errorf("resource_scope.instance_count must be one for an exclusive Worker")
	}
	if value.VCPU == 0 || value.VCPU > 1024 || value.MemoryMiB == 0 || value.DiskGiB == 0 {
		return fmt.Errorf("resource_scope compute and disk values must be positive and bounded")
	}
	if value.MemoryMiB > 64*1024*1024 || value.DiskGiB > 64*1024 {
		return fmt.Errorf("resource_scope memory or disk value is out of range")
	}
	if value.GPUCount == 0 {
		if value.GPUType != "" || value.GPUMemoryMiB != 0 {
			return fmt.Errorf("resource_scope GPU details require gpu_count")
		}
	} else {
		if value.GPUCount > 64 || value.GPUMemoryMiB == 0 || value.GPUMemoryMiB > 16*1024*1024 {
			return fmt.Errorf("resource_scope GPU count or memory is invalid")
		}
		if err := validateText("resource_scope.gpu_type", value.GPUType, 1, 128); err != nil {
			return err
		}
	}
	if !volumeTypePattern.MatchString(value.VolumeType) || !value.VolumeEncrypted {
		return fmt.Errorf("resource_scope requires a valid encrypted volume")
	}
	if value.VolumeIOPS > 256000 || value.VolumeThroughputMiBPS > 10000 {
		return fmt.Errorf("resource_scope volume performance is out of range")
	}
	if value.PurchaseOption != PurchaseOnDemand && value.PurchaseOption != PurchaseSpot {
		return fmt.Errorf("resource_scope.purchase_option is invalid")
	}
	if !amiPattern.MatchString(value.WorkerImageID) {
		return fmt.Errorf("resource_scope.worker_image_id is invalid")
	}
	if err := recipe.ValidateDigest(value.WorkerImageDigest); err != nil {
		return fmt.Errorf("resource_scope.worker_image_digest %w", err)
	}
	if err := cloudquote.ValidateVolumeScopes(value.VolumeScopes); err != nil {
		return fmt.Errorf("resource_scope.volume_scopes are invalid: %w", err)
	}
	return nil
}

func validateNetworkScope(value NetworkScopeV1) error {
	if !vpcPattern.MatchString(value.VPCID) || !subnetPattern.MatchString(value.SubnetID) {
		return fmt.Errorf("network_scope contains an invalid AWS network identifier")
	}
	mode := normalizedSecurityGroupMode(value)
	if (mode == SecurityGroupExisting && !securityGroupPattern.MatchString(value.SecurityGroupID)) ||
		(mode == SecurityGroupCreateDedicated && value.SecurityGroupID != "") ||
		(mode != SecurityGroupExisting && mode != SecurityGroupCreateDedicated) {
		return fmt.Errorf("network_scope security group intent is invalid")
	}
	seenPorts := make(map[uint32]struct{}, len(value.IngressPorts))
	for _, port := range value.IngressPorts {
		if port == 0 || port > 65535 {
			return fmt.Errorf("network_scope.ingress_ports contains an invalid port")
		}
		if _, exists := seenPorts[port]; exists {
			return fmt.Errorf("network_scope.ingress_ports contains duplicates")
		}
		seenPorts[port] = struct{}{}
	}
	if value.PrivateConnectivity == "" {
		if value.RouteTableID != "" || value.ControlPlaneEndpoint != "" {
			return fmt.Errorf("network_scope private connectivity fields require an explicit mode")
		}
	} else if value.PrivateConnectivity == PrivateConnectivityNoNATEndpointsV1 {
		if !routeTablePattern.MatchString(value.RouteTableID) || value.PublicIPv4 || mode != SecurityGroupCreateDedicated || value.SecurityGroupID != "" ||
			value.EntryPoint != EntryPointNone || value.PublicExposure || len(value.IngressPorts) != 0 || value.Hostname != "" || value.TLSRequired || value.AuthenticationRequired ||
			cloudquote.ValidatePrivateControlPlaneEndpoint(value.ControlPlaneEndpoint) != nil {
			return fmt.Errorf("network_scope no-NAT private connectivity scope is invalid")
		}
	} else {
		return fmt.Errorf("network_scope.private_connectivity is invalid")
	}
	if value.EntryPoint == EntryPointNone {
		if value.PublicExposure || len(value.IngressPorts) != 0 || value.Hostname != "" || value.TLSRequired || value.AuthenticationRequired {
			return fmt.Errorf("network_scope with no entry point cannot declare public exposure")
		}
		return nil
	}
	if value.EntryPoint != EntryPointALB && value.EntryPoint != EntryPointCloudFront {
		return fmt.Errorf("network_scope.entry_point is invalid")
	}
	if !value.PublicExposure || len(value.IngressPorts) == 0 || value.Hostname == "" || !value.TLSRequired || !value.AuthenticationRequired {
		return fmt.Errorf("public network_scope requires explicit ports, hostname, TLS, and authentication")
	}
	if err := validateText("network_scope.hostname", value.Hostname, 1, 253); err != nil {
		return err
	}
	return nil
}

func validateSecretScope(values []SecretReferenceV1) error {
	if len(values) > 32 {
		return fmt.Errorf("secret_scope must contain at most 32 entries")
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		name := fmt.Sprintf("secret_scope[%d]", index)
		if !secretRefPattern.MatchString(value.SecretRef) {
			return fmt.Errorf("%s.secret_ref is invalid", name)
		}
		if _, exists := seen[value.SecretRef]; exists {
			return fmt.Errorf("secret_scope contains duplicate references")
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

func validateIntegrationScope(values []IntegrationScopeV1) error {
	if len(values) > 32 {
		return fmt.Errorf("integration_scope must contain at most 32 entries")
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		name := fmt.Sprintf("integration_scope[%d]", index)
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
			return fmt.Errorf("integration_scope contains duplicate integrations")
		}
		seen[key] = struct{}{}
		if err := validateStringSet(name+".scopes", value.Scopes, 32); err != nil {
			return err
		}
	}
	return nil
}

func validateRetentionScope(value RetentionScopeV1) error {
	switch value.Class {
	case RetentionEphemeral:
		if !value.AutoDestroy || value.GracePeriodSeconds == 0 || value.MaxLifetimeSeconds == 0 {
			return fmt.Errorf("ephemeral retention requires automatic destruction and positive deadlines")
		}
		if uint64(value.GracePeriodSeconds) > value.MaxLifetimeSeconds || value.MaxLifetimeSeconds > 365*24*60*60 {
			return fmt.Errorf("ephemeral retention deadlines are invalid")
		}
	case RetentionManaged:
		if value.AutoDestroy || value.GracePeriodSeconds != 0 || value.MaxLifetimeSeconds != 0 {
			return fmt.Errorf("managed retention cannot have automatic destruction deadlines")
		}
	default:
		return fmt.Errorf("retention_scope.class is invalid")
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

func validateStringSet(name string, values []string, maximum int) error {
	if len(values) > maximum {
		return fmt.Errorf("%s must contain at most %d entries", name, maximum)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if err := validateText(fmt.Sprintf("%s[%d]", name, index), value, 1, 128); err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicates", name)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (a ApprovalV1) validate(requireSignature bool) error {
	if a.SchemaVersion != ApprovalSchemaV1 && a.SchemaVersion != ApprovalSchemaV2 {
		return fmt.Errorf("schema_version must be %q or %q", ApprovalSchemaV1, ApprovalSchemaV2)
	}
	if a.HashAlgorithm != canonical.Algorithm {
		return fmt.Errorf("hash_algorithm must be %q", canonical.Algorithm)
	}
	for name, value := range map[string]string{
		"approval_id":        a.ApprovalID,
		"agent_instance_id":  a.AgentInstanceID,
		"owner_id":           a.OwnerID,
		"plan_id":            a.PlanID,
		"connection_id":      a.ConnectionID,
		"quote_id":           a.QuoteID,
		"quote_candidate_id": a.QuoteCandidateID,
		"challenge_id":       a.ChallengeID,
		"signer_key_id":      a.SignerKeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if a.PlanRevision == 0 {
		return fmt.Errorf("plan_revision must be positive")
	}
	for name, value := range map[string]string{
		"plan_hash":          a.PlanHash,
		"recipe_digest":      a.RecipeDigest,
		"quote_digest":       a.QuoteDigest,
		"quote_scope_digest": a.QuoteScopeDigest,
	} {
		if err := recipe.ValidateDigest(value); err != nil {
			return fmt.Errorf("%s %w", name, err)
		}
	}
	if a.QuoteValidUntil.IsZero() || a.ExpiresAt.IsZero() || a.ExpiresAt.After(a.QuoteValidUntil) {
		return fmt.Errorf("approval expiry must be present and no later than quote validity")
	}
	if err := validateResourceScope(a.ResourceScope); err != nil {
		return err
	}
	if err := validateNetworkScope(a.NetworkScope); err != nil {
		return err
	}
	if err := validateSecretScope(a.SecretScope); err != nil {
		return err
	}
	if err := validateIntegrationScope(a.IntegrationScope); err != nil {
		return err
	}
	if err := validateRetentionScope(a.RetentionScope); err != nil {
		return err
	}
	if err := validateVolumeDisposition(a.ResourceScope.VolumeScopes, a.RetentionScope); err != nil {
		return err
	}
	if a.SchemaVersion == ApprovalSchemaV1 {
		if a.ServiceOperations != nil {
			return fmt.Errorf("service_operations require %q", ApprovalSchemaV2)
		}
	} else if a.ServiceOperations == nil {
		return fmt.Errorf("service_operations are required for %q", ApprovalSchemaV2)
	} else if err := validateServiceOperations(*a.ServiceOperations, a.ResourceScope, a.NetworkScope, a.RetentionScope); err != nil {
		return fmt.Errorf("service_operations: %w", err)
	}
	if a.Signature == "" {
		if requireSignature {
			return fmt.Errorf("signature is required")
		}
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil || len(decoded) != 64 {
		return fmt.Errorf("signature must be a base64url Ed25519 signature")
	}
	return nil
}

func normalizeResource(value ResourceScopeV1) ResourceScopeV1 {
	value.AvailabilityZones = append([]string(nil), value.AvailabilityZones...)
	sort.Strings(value.AvailabilityZones)
	value.VolumeScopes = append([]VolumeScopeV1(nil), value.VolumeScopes...)
	sort.Slice(value.VolumeScopes, func(i, j int) bool { return value.VolumeScopes[i].SlotID < value.VolumeScopes[j].SlotID })
	return value
}

func validateVolumeDisposition(values []VolumeScopeV1, retention RetentionScopeV1) error {
	for _, value := range values {
		if retention.Class == RetentionEphemeral && value.Disposition != VolumeDeleteWithDeployment {
			return fmt.Errorf("ephemeral volume scope must be deleted with the deployment")
		}
		if retention.Class == RetentionManaged && value.Disposition != VolumeRetainWithManagedService {
			return fmt.Errorf("managed volume scope must be retained with the managed service")
		}
	}
	return nil
}

func validateServiceOperations(value ServiceOperationScopeV1, resource ResourceScopeV1, network NetworkScopeV1, retention RetentionScopeV1) error {
	return cloudquote.ValidateServiceOperations(value,
		cloudquote.ResourceScopeV1{Region: resource.Region, VolumeScopes: append([]cloudquote.VolumeScopeV1(nil), resource.VolumeScopes...)},
		cloudquote.NetworkScopeV1{SecurityGroupMode: cloudquote.SecurityGroupMode(network.SecurityGroupMode), SecurityGroupID: network.SecurityGroupID, ControlPlaneEndpoint: network.ControlPlaneEndpoint, PrivateConnectivity: cloudquote.PrivateConnectivityMode(network.PrivateConnectivity)},
		cloudquote.RetentionScopeV1{Class: cloudquote.RetentionClass(retention.Class), AutoDestroy: retention.AutoDestroy, GracePeriodSeconds: retention.GracePeriodSeconds, MaxLifetimeSeconds: retention.MaxLifetimeSeconds},
	)
}

func normalizeNetwork(value NetworkScopeV1) NetworkScopeV1 {
	value.SecurityGroupMode = normalizedSecurityGroupMode(value)
	value.IngressPorts = append([]uint32(nil), value.IngressPorts...)
	sort.Slice(value.IngressPorts, func(i, j int) bool { return value.IngressPorts[i] < value.IngressPorts[j] })
	return value
}

func normalizedSecurityGroupMode(value NetworkScopeV1) SecurityGroupMode {
	if value.SecurityGroupMode == "" && value.SecurityGroupID != "" {
		return SecurityGroupExisting
	}
	return value.SecurityGroupMode
}

func normalizeSecrets(values []SecretReferenceV1) []SecretReferenceV1 {
	values = append([]SecretReferenceV1(nil), values...)
	sort.Slice(values, func(i, j int) bool {
		if values[i].SecretRef != values[j].SecretRef {
			return values[i].SecretRef < values[j].SecretRef
		}
		if values[i].Delivery != values[j].Delivery {
			return values[i].Delivery < values[j].Delivery
		}
		return values[i].Purpose < values[j].Purpose
	})
	return values
}

func normalizeIntegrations(values []IntegrationScopeV1) []IntegrationScopeV1 {
	values = append([]IntegrationScopeV1(nil), values...)
	for index := range values {
		values[index].Scopes = append([]string(nil), values[index].Scopes...)
		sort.Strings(values[index].Scopes)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Kind != values[j].Kind {
			return values[i].Kind < values[j].Kind
		}
		return values[i].Name < values[j].Name
	})
	return values
}

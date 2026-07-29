package teamplan

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

var (
	ErrInvalid            = errors.New("invalid team plan input")
	ErrNoRuntime          = errors.New("no qualified runtime can satisfy role")
	ErrNoModel            = errors.New("no configured model can satisfy role")
	ErrNoCompute          = errors.New("no compute offer can satisfy role")
	ErrBudgetExceeded     = errors.New("team plan exceeds cost policy")
	ErrArithmeticOverflow = errors.New("team plan estimate overflow")
	ErrCatalogChanged     = errors.New("team plan runtime catalog changed")
)

var (
	roleIDPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	sha256Pattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitPattern        = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	currencyPattern      = regexp.MustCompile(`^[A-Z]{3}$`)
	regionPattern        = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d+$`)
	instanceTypePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	credentialRefPattern = regexp.MustCompile(
		`^secret_ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`,
	)
)

const (
	absoluteMaxWorkers       = 8
	absoluteMaxRoleDuration  = 7 * 24 * time.Hour
	absoluteMaxColdStart     = 30 * time.Minute
	absoluteMaxTokens        = 100_000_000
	absoluteMaxRateMicros    = 10_000_000_000
	absoluteMaxHourlyMicros  = 10_000_000_000
	absoluteMaxPlanMicros    = 10_000_000_000_000
	absoluteMaxContextTokens = 10_000_000
)

func validateCompileRequest(request CompileRequest) error {
	if !canonicalUUID(request.PlanID) || request.Revision == 0 ||
		!validText(request.OwnerID, 255) || !sha256Pattern.MatchString(request.GoalDigest) ||
		!regionPattern.MatchString(request.Region) ||
		!sha256Pattern.MatchString(request.CatalogRevision) ||
		!canonicalUUID(request.PricingSnapshotID) ||
		!currencyPattern.MatchString(request.Currency) ||
		!validQuoteWindow(request.QuotedAt, request.ValidUntil) {
		return ErrInvalid
	}
	if err := validatePolicy(request.Policy); err != nil {
		return err
	}
	if err := validateTeamProposal(request.Proposal, request.Policy); err != nil {
		return err
	}
	if len(request.RuntimeReleases) == 0 || len(request.RuntimeReleases) > 64 ||
		len(request.ModelOffers) == 0 || len(request.ModelOffers) > 64 ||
		len(request.ComputeOffers) == 0 || len(request.ComputeOffers) > 128 {
		return ErrInvalid
	}
	releases := make(map[string]struct{}, len(request.RuntimeReleases))
	activeRuntimeKeys := make(map[string]struct{}, len(request.RuntimeReleases))
	for _, release := range request.RuntimeReleases {
		if err := validateRuntimeRelease(release); err != nil {
			return err
		}
		if _, exists := releases[release.ReleaseID]; exists {
			return ErrInvalid
		}
		releases[release.ReleaseID] = struct{}{}
		if release.Trust == RuntimeTrustQualified {
			key := string(release.Family) + "\x00" + string(release.Minimum.Arch)
			if _, exists := activeRuntimeKeys[key]; exists {
				return fmt.Errorf("%w: multiple qualified releases for one runtime and architecture", ErrInvalid)
			}
			activeRuntimeKeys[key] = struct{}{}
		}
	}
	models := make(map[string]struct{}, len(request.ModelOffers))
	for _, offer := range request.ModelOffers {
		if err := validateModelOffer(offer); err != nil {
			return err
		}
		if _, exists := models[offer.ProfileID]; exists {
			return ErrInvalid
		}
		models[offer.ProfileID] = struct{}{}
	}
	compute := make(map[string]struct{}, len(request.ComputeOffers))
	for _, offer := range request.ComputeOffers {
		if err := validateComputeOffer(offer); err != nil {
			return err
		}
		if _, exists := compute[offer.OfferID]; exists {
			return ErrInvalid
		}
		compute[offer.OfferID] = struct{}{}
	}
	return nil
}

func validatePolicy(policy Policy) error {
	if policy.MaxWorkers == 0 || policy.MaxWorkers > absoluteMaxWorkers ||
		policy.MaxConcurrentWorkers == 0 ||
		policy.MaxConcurrentWorkers > policy.MaxWorkers ||
		policy.MaxRoleDuration < time.Minute ||
		policy.MaxRoleDuration > absoluteMaxRoleDuration ||
		policy.MaxVCPUPerWorker == 0 || policy.MaxVCPUPerWorker > 1024 ||
		policy.MaxMemoryMiBPerWorker == 0 ||
		policy.MaxMemoryMiBPerWorker > 64*1024*1024 ||
		policy.MaxDiskGiBPerWorker == 0 || policy.MaxDiskGiBPerWorker > 64*1024 ||
		policy.MaxPlanCostMicros == 0 ||
		policy.MaxPlanCostMicros > absoluteMaxPlanMicros ||
		policy.SafetyMarginBasisPoints > 5000 ||
		policy.FixedWorkerOverheadMicros > absoluteMaxRateMicros ||
		len(policy.AllowedRuntimeFamilies) == 0 ||
		len(policy.AllowedRuntimeFamilies) > len(validRuntimeFamilies()) {
		return ErrInvalid
	}
	if !uniqueValues(policy.AllowedRuntimeFamilies, validRuntimeFamily) {
		return ErrInvalid
	}
	return nil
}

func validateTeamProposal(proposal TeamProposal, policy Policy) error {
	if len(proposal.Roles) == 0 || len(proposal.Roles) > int(policy.MaxWorkers) ||
		proposal.Confidence == 0 || proposal.Confidence > 100 ||
		!validSafeText(proposal.Rationale, 4096) {
		return ErrInvalid
	}
	roles := make(map[string]RoleProposal, len(proposal.Roles))
	for _, role := range proposal.Roles {
		if err := validateRoleProposal(role, policy); err != nil {
			return err
		}
		if _, exists := roles[role.RoleID]; exists {
			return ErrInvalid
		}
		roles[role.RoleID] = role
	}
	for _, role := range proposal.Roles {
		for _, dependency := range role.DependsOnRoleIDs {
			if dependency == role.RoleID {
				return ErrInvalid
			}
			if _, exists := roles[dependency]; !exists {
				return ErrInvalid
			}
		}
	}
	if hasRoleCycle(roles) || hasUnsafeExclusiveConcurrency(roles) {
		return ErrInvalid
	}
	return nil
}

func validateRoleProposal(role RoleProposal, policy Policy) error {
	if !roleIDPattern.MatchString(role.RoleID) ||
		!validSafeText(role.Title, 160) ||
		!validSafeText(role.Objective, 8192) ||
		!validWorkClass(role.WorkClass) ||
		!validWorkspaceMode(role.Workspace) ||
		len(role.RequiredCapabilities) == 0 ||
		len(role.RequiredCapabilities) > 24 ||
		!uniqueValues(role.RequiredCapabilities, validCapability) ||
		len(role.PreferredFamilies) > len(validRuntimeFamilies()) ||
		!uniqueValues(role.PreferredFamilies, validRuntimeFamily) ||
		len(role.DependsOnRoleIDs) > absoluteMaxWorkers-1 ||
		!uniqueValues(role.DependsOnRoleIDs, func(value string) bool {
			return roleIDPattern.MatchString(value)
		}) ||
		validateDuration(role.Duration, policy.MaxRoleDuration) != nil ||
		validateTokens(role.Tokens) != nil ||
		validateModelNeed(role.ModelNeed) != nil ||
		validateRoleResources(role.MinimumResources, policy) != nil {
		return ErrInvalid
	}
	if slices.Contains(role.RequiredCapabilities, CapabilityRepositoryWrite) &&
		role.Workspace == WorkspaceReadOnly {
		return ErrInvalid
	}
	return nil
}

func validateDuration(value DurationEstimate, maximum time.Duration) error {
	if value.Minimum <= 0 || value.Minimum > value.Expected ||
		value.Expected > value.Maximum || value.Maximum > maximum ||
		value.Minimum%time.Second != 0 ||
		value.Expected%time.Second != 0 ||
		value.Maximum%time.Second != 0 {
		return ErrInvalid
	}
	return nil
}

func validateTokens(value TokenEstimate) error {
	if value.InputMinimum == 0 || value.InputMinimum > value.InputExpected ||
		value.InputExpected > value.InputMaximum ||
		value.InputMaximum > absoluteMaxTokens ||
		value.OutputMinimum == 0 || value.OutputMinimum > value.OutputExpected ||
		value.OutputExpected > value.OutputMaximum ||
		value.OutputMaximum > absoluteMaxTokens {
		return ErrInvalid
	}
	return nil
}

func validateModelNeed(value ModelNeed) error {
	if !validQuality(value.MinimumQuality) || value.MinimumContextTokens == 0 ||
		value.MinimumContextTokens > absoluteMaxContextTokens {
		return ErrInvalid
	}
	return nil
}

func validateRoleResources(value ResourceEnvelope, policy Policy) error {
	if value.VCPU == 0 || value.MemoryMiB == 0 || value.DiskGiB == 0 ||
		value.VCPU > policy.MaxVCPUPerWorker ||
		value.MemoryMiB > policy.MaxMemoryMiBPerWorker ||
		value.DiskGiB > policy.MaxDiskGiBPerWorker ||
		(value.Arch != "" && !recipe.ValidArchitecture(value.Arch)) {
		return ErrInvalid
	}
	return nil
}

func validateRuntimeRelease(value RuntimeRelease) error {
	parsed, err := url.Parse(value.SourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Fragment != "" ||
		!canonicalUUID(value.ReleaseID) ||
		!validRuntimeFamily(value.Family) ||
		runtimeAdapterFor(value.Family) != value.Adapter ||
		!validVersion(value.Version) ||
		!commitPattern.MatchString(value.SourceCommit) ||
		!validText(value.License, 128) ||
		!sha256Pattern.MatchString(value.ImageDigest) ||
		len(value.Capabilities) == 0 || len(value.Capabilities) > 32 ||
		!uniqueValues(value.Capabilities, validCapability) ||
		len(value.ModelInterfaces) == 0 || len(value.ModelInterfaces) > 3 ||
		!uniqueValues(value.ModelInterfaces, validModelInterface) ||
		len(value.Suitability) == 0 || len(value.Suitability) > len(validWorkClasses()) ||
		validateRuntimeResources(value.Minimum, value.Recommended) != nil ||
		value.ColdStart < 0 || value.ColdStart > absoluteMaxColdStart ||
		value.ColdStart%time.Second != 0 ||
		!validRuntimeTrust(value.Trust) ||
		!utcTimestamp(value.QualifiedAt) {
		return ErrInvalid
	}
	seenWork := make(map[WorkClass]struct{}, len(value.Suitability))
	for _, suitability := range value.Suitability {
		if !validWorkClass(suitability.WorkClass) ||
			suitability.Score == 0 || suitability.Score > 100 {
			return ErrInvalid
		}
		if _, exists := seenWork[suitability.WorkClass]; exists {
			return ErrInvalid
		}
		seenWork[suitability.WorkClass] = struct{}{}
	}
	return nil
}

func validateRuntimeResources(minimum, recommended ResourceEnvelope) error {
	if !recipe.ValidArchitecture(minimum.Arch) ||
		!recipe.ValidArchitecture(recommended.Arch) ||
		minimum.Arch != recommended.Arch ||
		minimum.VCPU == 0 || minimum.MemoryMiB == 0 || minimum.DiskGiB == 0 ||
		recommended.VCPU < minimum.VCPU ||
		recommended.MemoryMiB < minimum.MemoryMiB ||
		recommended.DiskGiB < minimum.DiskGiB {
		return ErrInvalid
	}
	return nil
}

func validateModelOffer(value ModelOffer) error {
	if !validText(value.ProfileID, 160) ||
		!validText(value.Provider, 128) ||
		!validText(value.Model, 256) ||
		!validModelInterface(value.Interface) ||
		!validQuality(value.Quality) ||
		value.ContextTokens < 1024 ||
		value.ContextTokens > absoluteMaxContextTokens ||
		value.InputMicrosPerMillion > absoluteMaxRateMicros ||
		value.OutputMicrosPerMillion > absoluteMaxRateMicros ||
		!credentialRefPattern.MatchString(value.CredentialRef) {
		return ErrInvalid
	}
	return nil
}

func validateComputeOffer(value ComputeOffer) error {
	if !canonicalUUID(value.OfferID) ||
		!regionPattern.MatchString(value.Region) ||
		!instanceTypePattern.MatchString(value.InstanceType) ||
		!recipe.ValidArchitecture(value.Architecture) ||
		value.VCPU == 0 || value.MemoryMiB == 0 || value.DiskGiB == 0 ||
		value.HourlyMicros == 0 ||
		value.HourlyMicros > absoluteMaxHourlyMicros ||
		value.PurchaseOption != "on_demand" {
		return ErrInvalid
	}
	return nil
}

func validQuoteWindow(quotedAt, validUntil time.Time) bool {
	return utcTimestamp(quotedAt) && utcTimestamp(validUntil) &&
		validUntil.After(quotedAt) &&
		validUntil.Sub(quotedAt) <= time.Hour
}

func hasRoleCycle(roles map[string]RoleProposal) bool {
	const (
		unseen = iota
		visiting
		visited
	)
	state := make(map[string]int, len(roles))
	var visit func(string) bool
	visit = func(roleID string) bool {
		switch state[roleID] {
		case visiting:
			return true
		case visited:
			return false
		}
		state[roleID] = visiting
		for _, dependency := range roles[roleID].DependsOnRoleIDs {
			if visit(dependency) {
				return true
			}
		}
		state[roleID] = visited
		return false
	}
	for roleID := range roles {
		if visit(roleID) {
			return true
		}
	}
	return false
}

func hasUnsafeExclusiveConcurrency(roles map[string]RoleProposal) bool {
	var exclusive []string
	for roleID, role := range roles {
		if role.Workspace == WorkspaceExclusive {
			exclusive = append(exclusive, roleID)
		}
	}
	for left := 0; left < len(exclusive); left++ {
		for right := left + 1; right < len(exclusive); right++ {
			if !roleDependsOn(roles, exclusive[left], exclusive[right]) &&
				!roleDependsOn(roles, exclusive[right], exclusive[left]) {
				return true
			}
		}
	}
	return false
}

func roleDependsOn(roles map[string]RoleProposal, roleID, dependencyID string) bool {
	seen := make(map[string]struct{}, len(roles))
	var visit func(string) bool
	visit = func(current string) bool {
		if current == dependencyID {
			return true
		}
		if _, exists := seen[current]; exists {
			return false
		}
		seen[current] = struct{}{}
		for _, dependency := range roles[current].DependsOnRoleIDs {
			if visit(dependency) {
				return true
			}
		}
		return false
	}
	return visit(roleID)
}

func runtimeAdapterFor(family RuntimeFamily) RuntimeAdapter {
	switch family {
	case RuntimeClaudeCode:
		return AdapterClaudeCodeV1
	case RuntimeCodex:
		return AdapterCodexV1
	case RuntimeOpenClaw:
		return AdapterOpenClawV1
	case RuntimeHermes:
		return AdapterHermesV1
	case RuntimeOpenCode:
		return AdapterOpenCodeV1
	default:
		return ""
	}
}

func validRuntimeFamilies() []RuntimeFamily {
	return []RuntimeFamily{
		RuntimeClaudeCode,
		RuntimeCodex,
		RuntimeOpenClaw,
		RuntimeHermes,
		RuntimeOpenCode,
	}
}

func validRuntimeFamily(value RuntimeFamily) bool {
	return slices.Contains(validRuntimeFamilies(), value)
}

func validRuntimeTrust(value RuntimeTrust) bool {
	return value == RuntimeTrustCandidate ||
		value == RuntimeTrustQualified ||
		value == RuntimeTrustDisabled
}

func validCapabilities() []Capability {
	return []Capability{
		CapabilityRepositoryRead,
		CapabilityRepositoryWrite,
		CapabilityCodeReview,
		CapabilityShell,
		CapabilityGit,
		CapabilityTest,
		CapabilityWebResearch,
		CapabilityBrowser,
		CapabilityMCPClient,
		CapabilityACP,
		CapabilityLongMemory,
		CapabilitySubagents,
		CapabilityMessaging,
		CapabilityDocument,
		CapabilityDataAnalysis,
		CapabilityLongRunning,
		CapabilityStructuredResults,
	}
}

func validCapability(value Capability) bool {
	return slices.Contains(validCapabilities(), value)
}

func validWorkClasses() []WorkClass {
	return []WorkClass{
		WorkSoftwareImplementation,
		WorkSoftwareReview,
		WorkSoftwareTest,
		WorkResearch,
		WorkBrowserAutomation,
		WorkCommunication,
		WorkGeneralTool,
		WorkLongRunningOperations,
	}
}

func validWorkClass(value WorkClass) bool {
	return slices.Contains(validWorkClasses(), value)
}

func validWorkspaceMode(value WorkspaceMode) bool {
	return value == WorkspaceReadOnly ||
		value == WorkspaceIsolated ||
		value == WorkspaceExclusive
}

func validModelInterface(value ModelInterface) bool {
	return value == ModelAnthropicAPI ||
		value == ModelOpenAIResponses ||
		value == ModelOpenAICompatible
}

func validQuality(value QualityTier) bool {
	return value == QualityEconomy ||
		value == QualityBalanced ||
		value == QualityPremium
}

func qualityRank(value QualityTier) int {
	switch value {
	case QualityEconomy:
		return 1
	case QualityBalanced:
		return 2
	case QualityPremium:
		return 3
	default:
		return 0
	}
}

func validVersion(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 128 || trimmed != value ||
		strings.EqualFold(trimmed, "latest") ||
		strings.Contains(strings.ToLower(trimmed), ":latest") {
		return false
	}
	for _, character := range trimmed {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validText(value string, maximum int) bool {
	if value != strings.TrimSpace(value) || value == "" || len(value) > maximum ||
		!utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validSafeText(value string, maximum int) bool {
	return validText(value, maximum) && !security.ContainsLikelySecret(value)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func utcTimestamp(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Nanosecond()%1000 == 0
}

func uniqueValues[T comparable](values []T, valid func(T) bool) bool {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if !valid(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

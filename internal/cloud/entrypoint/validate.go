package entrypoint

import (
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

var (
	regionPattern        = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	availabilityPattern  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+[a-z]$`)
	vpcPattern           = regexp.MustCompile(`^vpc-[0-9a-f]{8,17}$`)
	subnetPattern        = regexp.MustCompile(`^subnet-[0-9a-f]{8,17}$`)
	securityGroupPattern = regexp.MustCompile(`^sg-[0-9a-f]{8,17}$`)
	instancePattern      = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	digestPattern        = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	currencyPattern      = regexp.MustCompile(`^[A-Z]{3}$`)
	keyIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	acmARNPattern        = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):acm:([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+):[0-9]{12}:certificate/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	hostLabelPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// NormalizeScope returns the exact stable form hashed and signed by this
// package. It never fills missing values or derives a target from a Worker.
func NormalizeScope(value ScopeV1) ScopeV1 {
	value.Region = strings.ToLower(value.Region)
	value.Worker.ReadBack.ObservedAt = value.Worker.ReadBack.ObservedAt.UTC()
	value.Worker.SucceededAt = value.Worker.SucceededAt.UTC()
	value.Worker.Retention.DestroyDeadline = value.Worker.Retention.DestroyDeadline.UTC()
	value.Certificate.Region = strings.ToLower(value.Certificate.Region)
	value.Certificate.Hostname = strings.ToLower(value.Certificate.Hostname)
	value.Certificate.SubjectAlternativeNames = slices.Clone(value.Certificate.SubjectAlternativeNames)
	for index := range value.Certificate.SubjectAlternativeNames {
		value.Certificate.SubjectAlternativeNames[index] = strings.ToLower(value.Certificate.SubjectAlternativeNames[index])
	}
	slices.Sort(value.Certificate.SubjectAlternativeNames)
	value.Certificate.ObservedAt = value.Certificate.ObservedAt.UTC()
	value.ALB.IngressCIDRs = slices.Clone(value.ALB.IngressCIDRs)
	slices.Sort(value.ALB.IngressCIDRs)
	value.ALB.PublicSubnets = slices.Clone(value.ALB.PublicSubnets)
	for index := range value.ALB.PublicSubnets {
		value.ALB.PublicSubnets[index].AvailabilityZone = strings.ToLower(value.ALB.PublicSubnets[index].AvailabilityZone)
		value.ALB.PublicSubnets[index].ObservedAt = value.ALB.PublicSubnets[index].ObservedAt.UTC()
	}
	slices.SortFunc(value.ALB.PublicSubnets, func(left, right PublicSubnetScopeV1) int {
		return strings.Compare(left.SubnetID, right.SubnetID)
	})
	value.Cost.QuotedAt = value.Cost.QuotedAt.UTC()
	value.Cost.ValidUntil = value.Cost.ValidUntil.UTC()
	value.Retention.DestroyDeadline = value.Retention.DestroyDeadline.UTC()
	return value
}

func (value ScopeV1) Validate() error { return validateScope(NormalizeScope(value)) }

func validateScope(value ScopeV1) error {
	if value.SchemaVersion != ScopeSchemaV1 {
		return invalidf("schema_version must be %q", ScopeSchemaV1)
	}
	if value.Kind != EntryKindALB {
		return fmt.Errorf("%w: only an ALB entrypoint is supported", ErrUnsupportedEntry)
	}
	for name, identifier := range map[string]string{
		"agent_instance_id": value.AgentInstanceID,
		"connection_id":     value.ConnectionID,
	} {
		if err := validateUUID(name, identifier); err != nil {
			return err
		}
	}
	if err := validateOwner(value.OwnerID); err != nil {
		return err
	}
	if !regionPattern.MatchString(value.Region) {
		return invalidf("region is invalid")
	}
	if err := validateWorker(value.Worker); err != nil {
		return err
	}
	if err := validateRecipe(value.Recipe); err != nil {
		return err
	}
	if err := validateCertificate(value.Certificate, value.Region); err != nil {
		return err
	}
	if err := validateALB(value.ALB, value.Region, value.Worker); err != nil {
		return err
	}
	if err := validateHealth(value.Health, value.Recipe); err != nil {
		return err
	}
	if err := validateAuthentication(value.Authentication, value.Recipe); err != nil {
		return err
	}
	if err := validateCost(value.Cost); err != nil {
		return err
	}
	if err := validateRetention(value.Retention); err != nil {
		return err
	}
	if value.Retention != value.Worker.Retention {
		return invalidf("entry retention must exactly match worker retention")
	}
	return nil
}

func validateWorker(value WorkerReadBackScopeV1) error {
	for name, identifier := range map[string]string{
		"worker.deployment_id":        value.DeploymentID,
		"worker.task_id":              value.TaskID,
		"worker.original_plan_id":     value.OriginalPlanID,
		"worker.original_approval_id": value.OriginalApprovalID,
		"worker.resource_id":          value.WorkerResourceID,
	} {
		if err := validateUUID(name, identifier); err != nil {
			return err
		}
	}
	if value.DeploymentRevision < 1 || value.WorkerResourceRevision < 1 {
		return invalidf("worker revisions must be positive")
	}
	for name, digest := range map[string]string{
		"worker.original_plan_hash":   value.OriginalPlanHash,
		"worker.spec_digest":          value.WorkerSpecDigest,
		"worker.read_back.tag_digest": value.ReadBack.TagDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return invalidf("%s must be a sha256 digest", name)
		}
	}
	if !instancePattern.MatchString(value.InstanceID) || !vpcPattern.MatchString(value.VPCID) || !subnetPattern.MatchString(value.SubnetID) || !securityGroupPattern.MatchString(value.SecurityGroupID) {
		return invalidf("worker AWS identity is invalid")
	}
	if value.ExecutionOutcome != WorkerOutcomeSucceeded || value.SucceededAt.IsZero() {
		return fmt.Errorf("%w: worker execution is not succeeded", ErrWorkerNotReady)
	}
	if !value.ReadBack.Observed || !value.ReadBack.Exists || value.ReadBack.State != EC2InstanceRunning || value.ReadBack.ObservedAt.IsZero() {
		return fmt.Errorf("%w: worker EC2 read-back is incomplete", ErrWorkerNotReady)
	}
	if value.ReadBack.ObservedAt.Before(value.SucceededAt) {
		return fmt.Errorf("%w: worker read-back predates worker success", ErrWorkerNotReady)
	}
	if err := validateRetention(value.Retention); err != nil {
		return fmt.Errorf("worker retention: %w", err)
	}
	return nil
}

func validateRecipe(value RecipeHealthBindingV1) error {
	for name, digest := range map[string]string{
		"recipe.digest":                         value.RecipeDigest,
		"recipe.health_contract_digest":         value.HealthContractDigest,
		"recipe.authentication_contract_digest": value.AuthenticationContractDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return invalidf("%s must be a sha256 digest", name)
		}
	}
	return nil
}

func validateCertificate(value CertificateScopeV1, region string) error {
	matches := acmARNPattern.FindStringSubmatch(value.CertificateARN)
	if matches == nil || matches[2] != region {
		return fmt.Errorf("%w: certificate ARN must be an ACM certificate in the entry region", ErrReadBackRequired)
	}
	if value.Region != region || value.Status != CertificateStatusIssued || value.ObservedAt.IsZero() || !digestPattern.MatchString(value.ReadBackDigest) {
		return fmt.Errorf("%w: issued same-region ACM certificate read-back is required", ErrReadBackRequired)
	}
	if err := validateHostname("certificate.hostname", value.Hostname, false); err != nil {
		return err
	}
	if len(value.SubjectAlternativeNames) == 0 || len(value.SubjectAlternativeNames) > 100 {
		return invalidf("certificate subject alternative names are invalid")
	}
	seen := make(map[string]struct{}, len(value.SubjectAlternativeNames))
	covered := false
	for _, name := range value.SubjectAlternativeNames {
		if err := validateHostname("certificate.subject_alternative_name", name, true); err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return invalidf("certificate subject alternative names contain duplicates")
		}
		seen[name] = struct{}{}
		covered = covered || certificateCovers(value.Hostname, name)
	}
	if !covered {
		return fmt.Errorf("%w: certificate SAN does not cover hostname", ErrReadBackRequired)
	}
	return nil
}

func validateALB(value ALBScopeV1, region string, worker WorkerReadBackScopeV1) error {
	if value.Scheme != ALBSchemeInternetFacing || value.ListenerPort != HTTPSPort || value.ListenerProtocol != ListenerProtocolHTTPS || value.TLSPolicy != TLSPolicyTLS13_2021_06 {
		return fmt.Errorf("%w: only the fixed public ALB HTTPS/TLS scope is supported", ErrUnsupportedEntry)
	}
	if len(value.IngressCIDRs) != 1 || value.IngressCIDRs[0] != "0.0.0.0/0" {
		return fmt.Errorf("%w: first-release ALB ingress must be explicitly approved as 0.0.0.0/0:443", ErrUnsupportedEntry)
	}
	if prefix, err := netip.ParsePrefix(value.IngressCIDRs[0]); err != nil || prefix.String() != value.IngressCIDRs[0] {
		return invalidf("ALB ingress CIDR is invalid")
	}
	// The first provider implementation deliberately terminates TLS at the ALB
	// and has a closed HTTP target-group spec. Do not accept a signed HTTPS
	// Worker target until the resource provider can independently read it back.
	if value.TargetProtocol != TargetProtocolHTTP || value.TargetPort == 0 || value.TargetPort > 65535 {
		return invalidf("ALB target protocol or port is invalid")
	}
	if value.TargetSource != TargetSourceApprovedWorkerReadBack {
		return fmt.Errorf("%w: target source must be approved_worker_read_back", ErrReadBackRequired)
	}
	if value.WorkerPublicIPv4 || value.EIPRequested {
		return fmt.Errorf("%w: a public Worker IPv4 or EIP is prohibited", ErrUnsupportedEntry)
	}
	if len(value.PublicSubnets) < 2 || len(value.PublicSubnets) > 16 {
		return fmt.Errorf("%w: ALB requires at least two public subnets", ErrReadBackRequired)
	}
	seenSubnet := make(map[string]struct{}, len(value.PublicSubnets))
	seenAZ := make(map[string]struct{}, len(value.PublicSubnets))
	for _, subnet := range value.PublicSubnets {
		if !subnetPattern.MatchString(subnet.SubnetID) || subnet.VPCID != worker.VPCID || !subnet.Public || !availabilityPattern.MatchString(subnet.AvailabilityZone) || !strings.HasPrefix(subnet.AvailabilityZone, region) || subnet.ObservedAt.IsZero() || !digestPattern.MatchString(subnet.ReadBackDigest) {
			return fmt.Errorf("%w: ALB public subnet read-back is invalid", ErrReadBackRequired)
		}
		if _, exists := seenSubnet[subnet.SubnetID]; exists {
			return invalidf("ALB public subnet IDs contain duplicates")
		}
		if _, exists := seenAZ[subnet.AvailabilityZone]; exists {
			return fmt.Errorf("%w: ALB public subnets must span distinct availability zones", ErrReadBackRequired)
		}
		seenSubnet[subnet.SubnetID] = struct{}{}
		seenAZ[subnet.AvailabilityZone] = struct{}{}
	}
	return nil
}

func validateHealth(value HealthRouteScopeV1, recipe RecipeHealthBindingV1) error {
	// Target groups and the independent HTTPS probe both use the first-release
	// exact 200 contract. Accepting an arbitrary 2xx value here would make the
	// signed scope claim stronger behavior than either verifier enforces.
	if !value.NoCredentialRoute || value.ExpectedStatusCode != 200 || value.EvidenceDigest != recipe.HealthContractDigest {
		return fmt.Errorf("%w: health route must be an exact no-credential Recipe health contract", ErrReadBackRequired)
	}
	if !digestPattern.MatchString(value.EvidenceDigest) {
		return invalidf("health evidence digest is invalid")
	}
	if err := validateHealthPath(value.Path); err != nil {
		return err
	}
	return nil
}

func validateAuthentication(value AuthenticationScopeV1, recipe RecipeHealthBindingV1) error {
	if !value.Required || value.ContractDigest != recipe.AuthenticationContractDigest || !digestPattern.MatchString(value.ContractDigest) {
		return invalidf("normal service authentication must be required and bind the Recipe contract")
	}
	return nil
}

func validateCost(value EntryCostScopeV1) error {
	if err := validateUUID("cost.quote_id", value.QuoteID); err != nil {
		return err
	}
	if !digestPattern.MatchString(value.QuoteDigest) || !digestPattern.MatchString(value.AssumptionsDigest) || !currencyPattern.MatchString(value.Currency) {
		return invalidf("entry quote identity is invalid")
	}
	if value.QuotedAt.IsZero() || value.ValidUntil.IsZero() || !value.QuotedAt.Before(value.ValidUntil) || value.ValidUntil.Sub(value.QuotedAt) > 15*time.Minute {
		return invalidf("entry quote validity is invalid")
	}
	if value.ALBHourlyEstimateMicros == 0 || value.LCUHourlyEstimateMicros == 0 || value.EstimatedLCUMilliUnits == 0 || value.MaximumLaunchAmountMicros == 0 {
		return invalidf("entry quote must include ALB, LCU, and maximum-launch estimates")
	}
	if value.MaximumLaunchAmountMicros < value.ALBHourlyEstimateMicros || value.MaximumLaunchAmountMicros-value.ALBHourlyEstimateMicros < value.LCUHourlyEstimateMicros {
		return invalidf("entry maximum launch amount is lower than required fixed costs")
	}
	return nil
}

func validateRetention(value RetentionScopeV1) error {
	switch value.Class {
	case RetentionEphemeral:
		if !value.AutoDestroy || value.DestroyDeadline.IsZero() {
			return invalidf("ephemeral entry retention requires auto destroy and deadline")
		}
	case RetentionManaged:
		if value.AutoDestroy || !value.DestroyDeadline.IsZero() {
			return invalidf("managed entry retention cannot have auto destroy or deadline")
		}
	default:
		return invalidf("entry retention class is invalid")
	}
	return nil
}

func validateUUID(name, value string) error {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil || parsed == uuid.Nil {
		return invalidf("%s must be a non-zero UUID", name)
	}
	return nil
}

func validateOwner(value string) error {
	if value != strings.TrimSpace(value) || value == "" || len(value) > 255 || security.ContainsLikelySecret(value) {
		return invalidf("owner_id is invalid")
	}
	return nil
}

func validateSignerKeyID(value string) error {
	if !keyIDPattern.MatchString(value) || security.ContainsLikelySecret(value) {
		return invalidf("signer_key_id is invalid")
	}
	return nil
}

func validateHostname(name, value string, wildcardAllowed bool) error {
	if value != strings.TrimSpace(value) || value == "" || len(value) > 253 || security.ContainsLikelySecret(value) || strings.HasSuffix(value, ".") {
		return invalidf("%s is invalid", name)
	}
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard && !wildcardAllowed {
		return invalidf("%s cannot be a wildcard", name)
	}
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	if value == "localhost" || strings.Count(value, ".") == 0 {
		return invalidf("%s must be a public DNS hostname", name)
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return invalidf("%s cannot be an IP address", name)
	}
	for _, label := range strings.Split(value, ".") {
		if !hostLabelPattern.MatchString(label) {
			return invalidf("%s is invalid", name)
		}
	}
	return nil
}

func certificateCovers(hostname, san string) bool {
	if hostname == san {
		return true
	}
	if !strings.HasPrefix(san, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(san, "*")
	if !strings.HasSuffix(hostname, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(hostname, suffix)
	return prefix != "" && !strings.Contains(strings.TrimSuffix(prefix, "."), ".")
}

func validateHealthPath(value string) error {
	if value != strings.TrimSpace(value) || len(value) < 2 || len(value) > 256 || security.ContainsLikelySecret(value) || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#\\@") || strings.Contains(value, "//") || path.Clean(value) != value {
		return invalidf("health path is invalid")
	}
	return nil
}

func (value PlanV1) Validate() error {
	if value.SchemaVersion != PlanSchemaV1 || value.Revision == 0 || !validPlanStatus(value.Status) {
		return invalidf("entry plan schema, revision, or status is invalid")
	}
	if err := validateUUID("entry_plan_id", value.EntryPlanID); err != nil {
		return err
	}
	if err := value.Scope.Validate(); err != nil {
		return err
	}
	digest, err := ScopeDigest(value.Scope)
	if err != nil {
		return err
	}
	if value.ScopeDigest != digest {
		return invalidf("entry plan scope digest does not match scope")
	}
	return nil
}

func validPlanStatus(value PlanStatus) bool {
	switch value {
	case PlanDraft, PlanReadyForApproval, PlanApproved, PlanExpired, PlanSuperseded:
		return true
	default:
		return false
	}
}

func (value ChallengeV1) Validate() error {
	for name, identifier := range map[string]string{
		"operation_id":  value.OperationID,
		"challenge_id":  value.ChallengeID,
		"approval_id":   value.ApprovalID,
		"entry_plan_id": value.EntryPlanID,
	} {
		if err := validateUUID(name, identifier); err != nil {
			return err
		}
	}
	if value.EntryPlanRevision == 0 || value.Revision != 1 || !digestPattern.MatchString(value.PlanHash) || !digestPattern.MatchString(value.ScopeDigest) || value.IssuedAt.IsZero() || value.ExpiresAt.IsZero() || !value.IssuedAt.Before(value.ExpiresAt) || value.ExpiresAt.Sub(value.IssuedAt) > ChallengeValidity {
		return invalidf("entry challenge is invalid")
	}
	return validateSignerKeyID(value.SignerKeyID)
}

func (value SignatureV1) Validate() error {
	for name, identifier := range map[string]string{
		"signature.approval_id":   value.ApprovalID,
		"signature.challenge_id":  value.ChallengeID,
		"signature.entry_plan_id": value.EntryPlanID,
	} {
		if err := validateUUID(name, identifier); err != nil {
			return err
		}
	}
	if value.EntryPlanRevision == 0 || !digestPattern.MatchString(value.PlanHash) || !digestPattern.MatchString(value.ScopeDigest) || value.ExpiresAt.IsZero() || len(value.Signature) != ed25519.SignatureSize {
		return invalidf("entry signature is invalid")
	}
	return validateSignerKeyID(value.SignerKeyID)
}

func (value OperationV1) Validate() error {
	if err := value.Challenge.Validate(); err != nil {
		return err
	}
	if value.Revision < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || len(value.ErrorSummary) > 512 || security.ContainsLikelySecret(value.ErrorSummary) {
		return invalidf("entry operation metadata is invalid")
	}
	if value.ApprovedAt != nil && value.ApprovedAt.IsZero() {
		return invalidf("entry operation approval time is invalid")
	}
	if value.ApprovedAt != nil && (value.ApprovedAt.Before(value.CreatedAt) || value.ApprovedAt.After(value.UpdatedAt) || !value.ApprovedAt.Before(value.Challenge.ExpiresAt)) {
		return invalidf("entry operation approval time is outside the challenge lifetime")
	}
	switch value.Status {
	case StatusAwaitingApproval:
		if value.Signature != nil || value.ApprovedAt != nil || value.ErrorCode != ErrorCodeNone || value.ErrorSummary != "" {
			return invalidf("awaiting entry operation cannot have approval or errors")
		}
	case StatusApproved, StatusProvisioning, StatusVerifying, StatusActive, StatusDestroying, StatusDestroyed:
		if value.Signature == nil || value.ApprovedAt == nil || value.ErrorCode != ErrorCodeNone || value.ErrorSummary != "" {
			return invalidf("approved entry operation state is invalid")
		}
		if err := value.Signature.Validate(); err != nil {
			return err
		}
		if !signatureMatchesChallenge(value.Challenge, *value.Signature) {
			return ErrApprovalRequired
		}
	case StatusFailed, StatusDestroyBlocked:
		if value.Signature == nil || value.ApprovedAt == nil || !validErrorCode(value.Status, value.ErrorCode) || value.ErrorSummary == "" {
			return invalidf("failed entry operation state is invalid")
		}
		if err := value.Signature.Validate(); err != nil {
			return err
		}
		if !signatureMatchesChallenge(value.Challenge, *value.Signature) {
			return ErrApprovalRequired
		}
	default:
		return invalidf("entry operation status is invalid")
	}
	return nil
}

func validErrorCode(status Status, code ErrorCode) bool {
	switch status {
	case StatusFailed:
		switch code {
		case ErrorCodeWorkerNotReady, ErrorCodeReadBackMismatch, ErrorCodeCertificateInvalid, ErrorCodeQuoteExpired, ErrorCodeProvisioningFailed, ErrorCodeVerificationFailed:
			return true
		}
	case StatusDestroyBlocked:
		return code == ErrorCodeDestroyBlocked
	}
	return false
}

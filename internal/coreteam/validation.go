package coreteam

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrInvalid             = errors.New("invalid team plan")
	ErrRuntimeUnavailable  = errors.New("team runtime unavailable")
	ErrQuoteUnavailable    = errors.New("team quote unavailable")
	ErrIdentityUnavailable = errors.New("team identity unavailable")

	roleIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	imageDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	amiIDPattern       = regexp.MustCompile(`^ami-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
	zonePattern        = regexp.MustCompile(`^ap-northeast-3[a-z]$`)
	decimalPattern     = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$`)
)

var validCapabilities = map[Capability]struct{}{
	CapabilityRepositoryRead:   {},
	CapabilityRepositoryWrite:  {},
	CapabilityCodeReview:       {},
	CapabilityShell:            {},
	CapabilityGit:              {},
	CapabilityTest:             {},
	CapabilityWebResearch:      {},
	CapabilityBrowser:          {},
	CapabilityMCPClient:        {},
	CapabilityStructuredResult: {},
}

func (p Plan) Valid() bool { return p.Validate() == nil }

// ValidateAt combines durable structural validation with the time-sensitive
// quote fence used before approval or launch. Validate intentionally remains
// time-independent so an expired historical Plan is not treated as corrupt.
func (p Plan) ValidateAt(now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if now.IsZero() || !p.Quote.ExpiresAt.After(now.UTC()) {
		return ErrQuoteUnavailable
	}
	return nil
}

func (p Plan) Validate() error {
	if !validUUID(p.PlanID) || !validUUID(p.TaskID) || !validUUID(p.ConversationID) ||
		!validUUID(p.CredentialID) || !validUUID(p.ConfirmationID) ||
		!validOwner(p.OwnerID) || p.AccountGeneration <= 0 || p.Revision == 0 ||
		p.CredentialRevision == 0 || !validBoundedText(p.Goal, MaxGoalBytes) ||
		!validPlanStatus(p.Status) || validateRuntime(p.Runtime, p.Runtime.RuntimeID) != nil ||
		validateQuote(p.Quote) != nil || validateCanonicalRoles(p.Roles) != nil {
		return ErrInvalid
	}
	want, err := p.SemanticDigest()
	if err != nil || p.Digest != want {
		return ErrInvalid
	}
	return nil
}

func (p Plan) SemanticDigest() (string, error) {
	if !validOwner(p.OwnerID) || p.AccountGeneration <= 0 || p.Revision == 0 ||
		!validUUID(p.ConversationID) || !validUUID(p.CredentialID) || p.CredentialRevision == 0 ||
		!validBoundedText(p.Goal, MaxGoalBytes) || validateRuntime(p.Runtime, p.Runtime.RuntimeID) != nil ||
		validateQuote(p.Quote) != nil || validateRoles(p.Roles) != nil {
		return "", ErrInvalid
	}
	roles := canonicalRoles(p.Roles)
	payload := struct {
		OwnerID            string
		AccountGeneration  int64
		Revision           uint64
		ConversationID     string
		CredentialID       string
		CredentialRevision uint64
		Goal               string
		Runtime            RuntimeBinding
		Quote              QuoteBinding
		Roles              []Role
	}{
		OwnerID: p.OwnerID, AccountGeneration: p.AccountGeneration, Revision: p.Revision,
		ConversationID: p.ConversationID, CredentialID: p.CredentialID,
		CredentialRevision: p.CredentialRevision, Goal: p.Goal, Runtime: p.Runtime,
		Quote: normalizedQuote(p.Quote), Roles: roles,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func validateCompileCommand(c CompileCommand) error {
	runtimeID := c.RuntimeID
	if runtimeID == "" {
		runtimeID = OfficialRuntimeID
	}
	if !validOwner(c.OwnerID) || c.AccountGeneration <= 0 ||
		!validBoundedText(strings.TrimSpace(c.Goal), MaxGoalBytes) ||
		!validUUID(c.ConversationID) || !validUUID(c.CredentialID) ||
		c.CredentialRevision == 0 || runtimeID != OfficialRuntimeID {
		return ErrInvalid
	}
	roles := make([]Role, len(c.Roles))
	for i, role := range c.Roles {
		roles[i] = Role{RoleID: role.RoleID, Goal: strings.TrimSpace(role.Goal), DependsOn: append([]string(nil), role.DependsOn...), Capabilities: append([]Capability(nil), role.Capabilities...)}
	}
	return validateRoles(roles)
}

func validateRuntime(runtime RuntimeBinding, requestedID string) error {
	if requestedID == "" {
		requestedID = OfficialRuntimeID
	}
	if runtime.RuntimeID != requestedID || runtime.RuntimeID != OfficialRuntimeID || runtime.Adapter != AdapterPiV1 ||
		!imageDigestPattern.MatchString(runtime.ImageDigest) || !amiIDPattern.MatchString(runtime.AMIID) ||
		runtime.OutputTokens == 0 || runtime.OutputTokens > MaxOutputTokens {
		return ErrRuntimeUnavailable
	}
	return nil
}

func validateQuote(quote QuoteBinding) error {
	amount, amountOK := parseDecimal(quote.Amount)
	budget, budgetOK := parseDecimal(quote.HardBudget)
	if quote.Region != OsakaRegion || quote.InstanceType != MVPInstanceType ||
		!zonePattern.MatchString(quote.AvailabilityZone) || quote.Currency != "USD" ||
		!amountOK || !budgetOK || amount.Sign() < 0 || budget.Sign() <= 0 || amount.Cmp(budget) > 0 || quote.ExpiresAt.IsZero() {
		return ErrQuoteUnavailable
	}
	return nil
}

func validateCanonicalRoles(roles []Role) error {
	if err := validateRoles(roles); err != nil {
		return err
	}
	canonical := canonicalRoles(roles)
	encoded, _ := json.Marshal(roles)
	want, _ := json.Marshal(canonical)
	if string(encoded) != string(want) {
		return ErrInvalid
	}
	return nil
}

func validateRoles(roles []Role) error {
	if len(roles) == 0 || len(roles) > MaxRoles {
		return ErrInvalid
	}
	byID := make(map[string]Role, len(roles))
	for _, role := range roles {
		if !roleIDPattern.MatchString(role.RoleID) || !validBoundedText(strings.TrimSpace(role.Goal), MaxRoleGoalBytes) || len(role.Capabilities) == 0 {
			return ErrInvalid
		}
		if _, exists := byID[role.RoleID]; exists {
			return ErrInvalid
		}
		seenCapabilities := make(map[Capability]struct{}, len(role.Capabilities))
		for _, capability := range role.Capabilities {
			if _, ok := validCapabilities[capability]; !ok {
				return ErrInvalid
			}
			if _, duplicate := seenCapabilities[capability]; duplicate {
				return ErrInvalid
			}
			seenCapabilities[capability] = struct{}{}
		}
		seenDependencies := make(map[string]struct{}, len(role.DependsOn))
		for _, dependency := range role.DependsOn {
			if !roleIDPattern.MatchString(dependency) || dependency == role.RoleID {
				return ErrInvalid
			}
			if _, duplicate := seenDependencies[dependency]; duplicate {
				return ErrInvalid
			}
			seenDependencies[dependency] = struct{}{}
		}
		byID[role.RoleID] = role
	}
	for _, role := range roles {
		for _, dependency := range role.DependsOn {
			if _, exists := byID[dependency]; !exists {
				return ErrInvalid
			}
		}
	}
	visiting := make(map[string]bool, len(roles))
	visited := make(map[string]bool, len(roles))
	var visit func(string) bool
	visit = func(id string) bool {
		if visiting[id] {
			return false
		}
		if visited[id] {
			return true
		}
		visiting[id] = true
		for _, dependency := range byID[id].DependsOn {
			if !visit(dependency) {
				return false
			}
		}
		visiting[id] = false
		visited[id] = true
		return true
	}
	for id := range byID {
		if !visit(id) {
			return ErrInvalid
		}
	}
	return nil
}

func canonicalRoles(roles []Role) []Role {
	result := cloneRoles(roles)
	for i := range result {
		sort.Strings(result[i].DependsOn)
		sort.Slice(result[i].Capabilities, func(a, b int) bool { return result[i].Capabilities[a] < result[i].Capabilities[b] })
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RoleID < result[j].RoleID })
	return result
}

func cloneRoles(roles []Role) []Role {
	result := make([]Role, len(roles))
	for i, role := range roles {
		result[i] = role
		result[i].DependsOn = append([]string(nil), role.DependsOn...)
		result[i].Capabilities = append([]Capability(nil), role.Capabilities...)
	}
	return result
}

func normalizedQuote(quote QuoteBinding) QuoteBinding {
	quote.ExpiresAt = quote.ExpiresAt.UTC()
	return quote
}

func parseDecimal(value string) (*big.Rat, bool) {
	if !decimalPattern.MatchString(value) {
		return nil, false
	}
	result, ok := new(big.Rat).SetString(value)
	return result, ok
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validOwner(value string) bool {
	return value == strings.TrimSpace(value) && validBoundedText(value, MaxOwnerIDBytes) &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}

func validBoundedText(value string, maxBytes int) bool {
	return value != "" && utf8.ValidString(value) && len(value) <= maxBytes
}

func validPlanStatus(status PlanStatus) bool {
	return status == PlanWaitingUser || status == PlanApproved || status == PlanExpired
}

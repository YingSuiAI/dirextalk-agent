package healthprobe

import (
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	dnsPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	httpPath      = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
)

type digestDocumentV1 struct {
	SchemaVersion         string   `json:"schema_version"`
	DeploymentID          string   `json:"deployment_id"`
	PlanHash              string   `json:"plan_hash"`
	RecipeDigest          string   `json:"recipe_digest"`
	Purpose               Purpose  `json:"purpose"`
	Protocol              Protocol `json:"protocol"`
	Target                string   `json:"target"`
	TimeoutMillis         uint32   `json:"timeout_millis"`
	MaxAttempts           uint32   `json:"max_attempts"`
	RetryDelayMillis      uint32   `json:"retry_delay_millis"`
	ExpectedStatusCode    uint32   `json:"expected_status_code,omitempty"`
	ExpectedSummaryDigest string   `json:"expected_summary_digest,omitempty"`
}

// Bind computes the deterministic probe digest after validating every other
// field. It never trims or otherwise normalizes caller input.
func Bind(spec SpecV1) (SpecV1, error) {
	if spec.Binding.ProbeDigest != "" {
		return SpecV1{}, ErrInvalidSpec
	}
	if err := validateWithoutDigest(spec); err != nil {
		return SpecV1{}, err
	}
	digest, err := probeDigest(spec)
	if err != nil {
		return SpecV1{}, ErrInvalidSpec
	}
	spec.Binding.ProbeDigest = digest
	return spec, nil
}

func (spec SpecV1) Validate() error {
	if err := validateWithoutDigest(spec); err != nil || !digestPattern.MatchString(spec.Binding.ProbeDigest) {
		return ErrInvalidSpec
	}
	digest, err := probeDigest(spec)
	if err != nil || digest != spec.Binding.ProbeDigest {
		return ErrInvalidSpec
	}
	return nil
}

func validateWithoutDigest(spec SpecV1) error {
	deployment, err := uuid.Parse(spec.Binding.DeploymentID)
	if spec.SchemaVersion != SchemaV1 || err != nil || deployment == uuid.Nil || deployment.String() != spec.Binding.DeploymentID ||
		!digestPattern.MatchString(spec.Binding.PlanHash) || !digestPattern.MatchString(spec.Binding.RecipeDigest) ||
		(spec.Purpose != PurposeLiveness && spec.Purpose != PurposeReadiness && spec.Purpose != PurposeSemantic) ||
		(spec.Protocol != ProtocolHTTPS && spec.Protocol != ProtocolTCP) ||
		spec.TimeoutMillis < 250 || spec.TimeoutMillis > 60_000 || spec.MaxAttempts < 1 || spec.MaxAttempts > 5 ||
		spec.RetryDelayMillis > 30_000 || len(spec.Target) == 0 || len(spec.Target) > 512 || strings.TrimSpace(spec.Target) != spec.Target ||
		security.ContainsLikelySecret(spec.Target) {
		return ErrInvalidSpec
	}
	if spec.Purpose == PurposeSemantic {
		if !digestPattern.MatchString(spec.ExpectedSummaryDigest) {
			return ErrInvalidSpec
		}
	} else if spec.ExpectedSummaryDigest != "" {
		return ErrInvalidSpec
	}
	if spec.Protocol == ProtocolHTTPS {
		// An exact health contract remains a successful HTTP result. Allowing a
		// 4xx/5xx status to be marked healthy would turn the status field into an
		// availability bypass rather than a narrower 2xx contract.
		if spec.ExpectedStatusCode != 0 && (spec.ExpectedStatusCode < 200 || spec.ExpectedStatusCode > 299) {
			return ErrInvalidSpec
		}
		return validateHTTPS(spec.Target)
	}
	if spec.ExpectedStatusCode != 0 {
		return ErrInvalidSpec
	}
	return validateTCP(spec.Target)
}

func probeDigest(spec SpecV1) (string, error) {
	return canonical.Digest(digestDocumentV1{
		SchemaVersion: spec.SchemaVersion, DeploymentID: spec.Binding.DeploymentID,
		PlanHash: spec.Binding.PlanHash, RecipeDigest: spec.Binding.RecipeDigest,
		Purpose: spec.Purpose, Protocol: spec.Protocol, Target: spec.Target,
		TimeoutMillis: spec.TimeoutMillis, MaxAttempts: spec.MaxAttempts, RetryDelayMillis: spec.RetryDelayMillis,
		ExpectedStatusCode:    spec.ExpectedStatusCode,
		ExpectedSummaryDigest: spec.ExpectedSummaryDigest,
	})
}

func healthyHTTPStatus(spec SpecV1, statusCode int) bool {
	if spec.ExpectedStatusCode != 0 {
		return statusCode == int(spec.ExpectedStatusCode)
	}
	return statusCode >= 200 && statusCode <= 299
}

func validateHTTPS(target string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path == "" ||
		!httpPath.MatchString(parsed.Path) || path.Clean(parsed.Path) != parsed.Path {
		return ErrInvalidSpec
	}
	host := parsed.Hostname()
	if host == "" || strings.ToLower(host) != host || validateHost(host) != nil {
		return ErrInvalidSpec
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return validatePort(port)
}

func validateTCP(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || strings.ToLower(host) != host || strings.Contains(host, "%") || validateHost(host) != nil {
		return ErrInvalidSpec
	}
	return validatePort(port)
}

func validateHost(host string) error {
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if ip := net.ParseIP(host); ip != nil {
		if !publicIP(ip) {
			return ErrInvalidSpec
		}
		return nil
	}
	if len(host) > 253 || !dnsPattern.MatchString(host) || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") {
		return ErrInvalidSpec
	}
	return nil
}

func validatePort(raw string) error {
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != raw {
		return ErrInvalidSpec
	}
	return nil
}

func publicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func (suite SuiteV1) Validate() error {
	if suite.SchemaVersion != SuiteSchemaV1 || len(suite.Probes) < 1 || len(suite.Probes) > 3 {
		return ErrInvalidSpec
	}
	seen := make(map[Purpose]struct{}, len(suite.Probes))
	var deploymentID, planHash, recipeDigest string
	for index, spec := range suite.Probes {
		if err := spec.Validate(); err != nil {
			return err
		}
		if _, exists := seen[spec.Purpose]; exists {
			return ErrInvalidSpec
		}
		seen[spec.Purpose] = struct{}{}
		if index == 0 {
			deploymentID, planHash, recipeDigest = spec.Binding.DeploymentID, spec.Binding.PlanHash, spec.Binding.RecipeDigest
		} else if spec.Binding.DeploymentID != deploymentID || spec.Binding.PlanHash != planHash || spec.Binding.RecipeDigest != recipeDigest {
			return ErrInvalidSpec
		}
	}
	return nil
}

func sortedSpecs(input []SpecV1) []SpecV1 {
	output := append([]SpecV1(nil), input...)
	order := map[Purpose]int{PurposeLiveness: 0, PurposeReadiness: 1, PurposeSemantic: 2}
	sort.Slice(output, func(i, j int) bool { return order[output[i].Purpose] < order[output[j].Purpose] })
	return output
}

func timeout(spec SpecV1) time.Duration { return time.Duration(spec.TimeoutMillis) * time.Millisecond }
func retryDelay(spec SpecV1) time.Duration {
	return time.Duration(spec.RetryDelayMillis) * time.Millisecond
}

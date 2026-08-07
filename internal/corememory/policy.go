package corememory

import (
	"regexp"
	"strings"
)

var (
	canonicalKeyPattern    = regexp.MustCompile(`^(?:profile|preference|goal|project)\.[a-z0-9](?:[a-z0-9_.-]{0,117}[a-z0-9])?$`)
	explicitMemoryPattern  = regexp.MustCompile(`(?i)(?:\bremember\b|\bforget\b|\bupdate (?:my|the)\b|\bcorrect (?:my|the)\b|记住|记下来|忘记|不要记|删除.*记忆|改成|更正)`)
	durableLocationPattern = regexp.MustCompile(`(?i)(?:我.{0,8}(?:住在|居住在|常住|搬到|家在)|\bI\s+(?:live|moved)\s+(?:in|to)\b|\bmy\s+home\s+is\b)`)
	secretPattern          = regexp.MustCompile(`(?i)(?:\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|passwd|recovery[_ -]?code|private[_ -]?key)\b\s*[:=]?\s*\S+|\bBearer\s+[A-Za-z0-9._~+/=-]+|\bsk-[A-Za-z0-9_-]{8,}|\bAKIA[0-9A-Z]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)`)
	sensitivePattern       = regexp.MustCompile(`(?i)(?:病史|诊断|药物|收入|工资|银行|银行卡|身份证|护照|宗教|政治立场|性取向|详细地址|门牌号|medical|diagnosis|salary|bank account|passport|religion|political view|sexual orientation|street address)`)
	transientPattern       = regexp.MustCompile(`(?i)(?:\b(?:today|tomorrow|right now|currently|this week)\b|今天|明天|现在|此刻|这周|本周)`)
)

type Policy struct {
	Version       int
	MinConfidence float64
	MinImportance float64
}

func DefaultPolicy() Policy {
	return Policy{Version: PolicyVersion, MinConfidence: 0.75, MinImportance: 0.60}
}

func (p Policy) Validate() error {
	if p.Version != PolicyVersion || p.MinConfidence < 0 || p.MinConfidence > 1 || p.MinImportance < 0 || p.MinImportance > 1 {
		return ErrInvalid
	}
	return nil
}

type PolicyContext struct {
	LatestUserMessage string
	ExplicitRequest   bool
}

type PolicyDecision struct {
	Accepted  bool
	Reason    string
	Candidate Candidate
}

func IsExplicitMemoryInstruction(value string) bool {
	return explicitMemoryPattern.MatchString(value)
}

// EvaluateCandidate applies deterministic privacy, grounding, and value
// rules after model extraction and before canonical reconciliation.
func EvaluateCandidate(candidate Candidate, context PolicyContext, policy Policy) PolicyDecision {
	candidate = candidate.Normalize()
	reject := func(reason string) PolicyDecision {
		return PolicyDecision{Accepted: false, Reason: reason, Candidate: candidate}
	}
	if policy.Validate() != nil || candidate.Validate() != nil {
		return reject("invalid_candidate")
	}
	if !canonicalKeyPattern.MatchString(candidate.Key) {
		return reject("unsupported_key")
	}
	if candidate.Operation == OperationNoop {
		return reject("model_noop")
	}
	if !evidenceMatches(candidate.Evidence, context.LatestUserMessage) {
		return reject("ungrounded_evidence")
	}
	if secretPattern.MatchString(context.LatestUserMessage+"\n"+candidate.Text) || candidate.Sensitivity == SensitivitySecret {
		return reject("secret_detected")
	}
	explicit := context.ExplicitRequest || IsExplicitMemoryInstruction(context.LatestUserMessage)
	if (candidate.Sensitivity == SensitivitySensitive || sensitivePattern.MatchString(candidate.Text+"\n"+candidate.Evidence)) && !explicit {
		return reject("sensitive_without_explicit_request")
	}
	if candidate.Operation != OperationDelete && strings.HasPrefix(candidate.Key, "profile.location.") && !durableLocationPattern.MatchString(context.LatestUserMessage) {
		return reject("location_not_durable")
	}
	if candidate.Operation != OperationDelete && transientPattern.MatchString(candidate.Text+"\n"+candidate.Evidence) && !explicit {
		return reject("transient_fact")
	}
	if !explicit && candidate.Confidence < policy.MinConfidence {
		return reject("low_confidence")
	}
	if !explicit && candidate.Importance < policy.MinImportance {
		return reject("low_importance")
	}
	return PolicyDecision{Accepted: true, Reason: "accepted", Candidate: candidate}
}

func evidenceMatches(evidence, latest string) bool {
	evidence = normalizeEvidence(evidence)
	return len([]rune(evidence)) >= 2 && strings.Contains(normalizeEvidence(latest), evidence)
}

func normalizeEvidence(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

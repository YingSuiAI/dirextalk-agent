package healthprobe

import (
	"context"
	"time"
)

// ExternalEvidence is intentionally opaque outside this package. Only an
// Engine result that validates against the persisted Suite can cross the
// lifecycle repository boundary.
type ExternalEvidence struct {
	value SuiteEvidence
	valid bool
}

func newExternalEvidence(suite SuiteV1, value SuiteEvidence) (ExternalEvidence, error) {
	if err := validateSuiteEvidence(suite, value); err != nil {
		return ExternalEvidence{}, err
	}
	return ExternalEvidence{value: cloneSuiteEvidence(value), valid: true}, nil
}

// RunExternalSuite is the only constructor path for opaque independent
// evidence consumed by resource lifecycle persistence.
func (engine *Engine) RunExternalSuite(ctx context.Context, suite SuiteV1) (ExternalEvidence, error) {
	value, err := engine.RunSuite(ctx, suite)
	if err != nil {
		return ExternalEvidence{}, err
	}
	return newExternalEvidence(suite, value)
}

func (value ExternalEvidence) SnapshotFor(suite SuiteV1) (SuiteEvidence, error) {
	if !value.valid || validateSuiteEvidence(suite, value.value) != nil {
		return SuiteEvidence{}, ErrInvalidEvidence
	}
	return cloneSuiteEvidence(value.value), nil
}

// ValidateSuiteEvidence validates a decoded persistence/event snapshot. It
// does not grant independent trust or construct ExternalEvidence.
func ValidateSuiteEvidence(suite SuiteV1, evidence SuiteEvidence) error {
	return validateSuiteEvidence(suite, evidence)
}

func validateSuiteEvidence(suite SuiteV1, evidence SuiteEvidence) error {
	if suite.Validate() != nil || evidence.SchemaVersion != EvidenceV1 || len(evidence.Probes) != len(suite.Probes) ||
		evidence.ObservedAt.IsZero() {
		return ErrInvalidEvidence
	}
	specs := sortedSpecs(suite.Probes)
	if evidence.DeploymentID != specs[0].Binding.DeploymentID || evidence.PlanHash != specs[0].Binding.PlanHash ||
		evidence.RecipeDigest != specs[0].Binding.RecipeDigest {
		return ErrInvalidEvidence
	}
	for index, spec := range specs {
		if err := validateProbeEvidence(spec, evidence.Probes[index]); err != nil {
			return err
		}
		if evidence.Probes[index].ObservedAt.After(evidence.ObservedAt) {
			return ErrInvalidEvidence
		}
	}
	status, healthy := aggregate(evidence.Probes)
	if evidence.Status != status || evidence.Healthy != healthy {
		return ErrInvalidEvidence
	}
	return nil
}

func validateProbeEvidence(spec SpecV1, evidence ProbeEvidence) error {
	if spec.Validate() != nil || evidence.SchemaVersion != EvidenceV1 || evidence.Binding != spec.Binding ||
		evidence.Purpose != spec.Purpose || evidence.Protocol != spec.Protocol || evidence.Target != spec.Target ||
		evidence.Trust != TrustIndependentControlPlane || evidence.ObservedAt.IsZero() ||
		len(evidence.Attempts) > int(spec.MaxAttempts) {
		return ErrInvalidEvidence
	}
	if evidence.Status != StatusHealthy && evidence.Status != StatusUnhealthy && evidence.Status != StatusCanceled {
		return ErrInvalidEvidence
	}
	if evidence.Healthy != (evidence.Status == StatusHealthy) {
		return ErrInvalidEvidence
	}
	if len(evidence.Attempts) == 0 {
		if evidence.Status != StatusCanceled {
			return ErrInvalidEvidence
		}
		return nil
	}
	var previous time.Time
	for index, attempt := range evidence.Attempts {
		if attempt.Attempt != uint32(index+1) || attempt.ObservedAt.IsZero() || attempt.LatencyMillis < 0 ||
			(!previous.IsZero() && attempt.ObservedAt.Before(previous)) || attempt.ObservedAt.After(evidence.ObservedAt) {
			return ErrInvalidEvidence
		}
		previous = attempt.ObservedAt
		switch attempt.Status {
		case StatusHealthy:
			if attempt.FailureCode != FailureNone || !digestPattern.MatchString(attempt.SummaryDigest) ||
				(spec.Protocol == ProtocolHTTPS && !healthyHTTPStatus(spec, attempt.StatusCode)) ||
				(spec.Protocol == ProtocolTCP && attempt.StatusCode != 0) ||
				(spec.Purpose == PurposeSemantic && attempt.SummaryDigest != spec.ExpectedSummaryDigest) {
				return ErrInvalidEvidence
			}
		case StatusUnhealthy:
			if attempt.FailureCode == FailureNone || attempt.FailureCode == FailureCanceled || !validPersistedFailure(attempt.FailureCode) {
				return ErrInvalidEvidence
			}
			switch attempt.FailureCode {
			case FailureHTTPStatus:
				if spec.Protocol != ProtocolHTTPS || attempt.StatusCode < 100 || attempt.StatusCode > 599 ||
					healthyHTTPStatus(spec, attempt.StatusCode) || !digestPattern.MatchString(attempt.SummaryDigest) {
					return ErrInvalidEvidence
				}
			case FailureSemanticMismatch:
				if spec.Purpose != PurposeSemantic || !digestPattern.MatchString(attempt.SummaryDigest) ||
					attempt.SummaryDigest == spec.ExpectedSummaryDigest ||
					(spec.Protocol == ProtocolHTTPS && !healthyHTTPStatus(spec, attempt.StatusCode)) ||
					(spec.Protocol == ProtocolTCP && attempt.StatusCode != 0) {
					return ErrInvalidEvidence
				}
			default:
				if attempt.StatusCode != 0 || attempt.SummaryDigest != "" {
					return ErrInvalidEvidence
				}
			}
		case StatusCanceled:
			if attempt.FailureCode != FailureCanceled || attempt.StatusCode != 0 || attempt.SummaryDigest != "" {
				return ErrInvalidEvidence
			}
		default:
			return ErrInvalidEvidence
		}
	}
	last := evidence.Attempts[len(evidence.Attempts)-1]
	if evidence.Status == StatusCanceled {
		if last.Status != StatusCanceled && last.Status != StatusUnhealthy {
			return ErrInvalidEvidence
		}
		if evidence.ObservedAt.Before(last.ObservedAt) {
			return ErrInvalidEvidence
		}
	} else if !last.ObservedAt.Equal(evidence.ObservedAt) || last.Status != evidence.Status {
		return ErrInvalidEvidence
	}
	return nil
}

func validPersistedFailure(code FailureCode) bool {
	switch code {
	case FailureCanceled, FailureTimeout, FailureTargetRejected, FailureResolve, FailureConnect, FailureTLS,
		FailureHTTPStatus, FailureResponseTooLarge, FailureSemanticMismatch, FailureTransport:
		return true
	default:
		return false
	}
}

func cloneSuiteEvidence(value SuiteEvidence) SuiteEvidence {
	value.Probes = append([]ProbeEvidence(nil), value.Probes...)
	for index := range value.Probes {
		value.Probes[index].Attempts = append([]AttemptEvidence(nil), value.Probes[index].Attempts...)
	}
	return value
}

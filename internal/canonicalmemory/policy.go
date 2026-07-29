package canonicalmemory

import "time"

const (
	maximumPreferenceLifetime = 5 * 365 * 24 * time.Hour
	maximumProjectLifetime    = 365 * 24 * time.Hour
	maximumExternalLifetime   = 30 * 24 * time.Hour
)

// ValidatePromotion applies the server-owned retention policy. A valid device
// signature is still required for every promotion; this function determines
// which independent evidence must accompany each memory class.
func ValidatePromotion(candidate Candidate, validUntil, now time.Time) error {
	if candidate.Validate() != nil || now.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	validUntil = normalizeOptionalTime(validUntil)
	if !candidate.PendingAt(now) ||
		(!validUntil.IsZero() && !now.Before(validUntil)) {
		return ErrState
	}

	var (
		validatedTurns = make(map[string]struct{})
		resultTasks    = make(map[string]struct{})
	)
	for _, evidence := range candidate.Evidence {
		if !evidence.ValidAt(now) {
			return ErrEvidence
		}
		switch evidence.Kind {
		case EvidenceTurnValidation:
			validatedTurns[evidence.TurnID] = struct{}{}
			if evidence.TaskID != "" {
				validatedTurns[evidence.TurnID+"\x00"+evidence.TaskID] =
					struct{}{}
			}
		case EvidenceTaskResult:
			resultTasks[evidence.TurnID+"\x00"+evidence.TaskID] =
				struct{}{}
		}
	}

	switch candidate.Kind {
	case KindUserPreference, KindDecision:
		if !validUntil.IsZero() &&
			validUntil.Sub(now) > maximumPreferenceLifetime {
			return ErrEvidence
		}
	case KindProjectFact:
		if validUntil.IsZero() ||
			validUntil.Sub(now) > maximumProjectLifetime ||
			len(validatedTurns) == 0 {
			return ErrEvidence
		}
	case KindProcedure:
		if validUntil.IsZero() ||
			validUntil.Sub(now) > maximumProjectLifetime {
			return ErrEvidence
		}
		matched := false
		for binding := range resultTasks {
			if _, ok := validatedTurns[binding]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return ErrEvidence
		}
	case KindExternalFact:
		if validUntil.IsZero() ||
			validUntil.Sub(now) > maximumExternalLifetime ||
			len(validatedTurns) == 0 {
			return ErrEvidence
		}
	default:
		return ErrInvalid
	}
	return nil
}

package healthprobe

import (
	"context"
	"errors"
	"time"
)

type Engine struct {
	transport Transport
	clock     clock
}

func NewEngine(transport Transport) (*Engine, error) {
	return newEngine(transport, realClock{})
}

func newEngine(transport Transport, current clock) (*Engine, error) {
	if transport == nil || current == nil {
		return nil, ErrInvalidTransport
	}
	return &Engine{transport: transport, clock: current}, nil
}

// Run records operational failure as de-sensitive evidence. Invalid specs are
// the only ordinary errors; cancellation is a durable StatusCanceled result.
func (engine *Engine) Run(ctx context.Context, spec SpecV1) (ProbeEvidence, error) {
	if engine == nil || engine.transport == nil || engine.clock == nil || ctx == nil || spec.Validate() != nil {
		return ProbeEvidence{}, ErrInvalidSpec
	}
	evidence := ProbeEvidence{
		SchemaVersion: EvidenceV1, Binding: spec.Binding, Purpose: spec.Purpose,
		Protocol: spec.Protocol, Target: spec.Target, Trust: TrustIndependentControlPlane, Status: StatusUnhealthy,
		Attempts: make([]AttemptEvidence, 0, spec.MaxAttempts),
	}
	for attempt := uint32(1); attempt <= spec.MaxAttempts; attempt++ {
		if ctx.Err() != nil {
			evidence.Status = StatusCanceled
			evidence.ObservedAt = engine.clock.Now().UTC()
			return evidence, nil
		}
		started := engine.clock.Now().UTC()
		attemptContext, cancel := context.WithTimeout(ctx, timeout(spec))
		observation, probeErr := engine.transport.Probe(attemptContext, Request{
			Protocol: spec.Protocol, Target: spec.Target, Timeout: timeout(spec),
		})
		contextErr := attemptContext.Err()
		cancel()
		observedAt := engine.clock.Now().UTC()
		if observation.Latency == 0 && !observedAt.Before(started) {
			observation.Latency = observedAt.Sub(started)
		}
		attemptEvidence := classifyAttempt(spec, attempt, observedAt, observation, probeErr, contextErr)
		evidence.Attempts = append(evidence.Attempts, attemptEvidence)
		evidence.ObservedAt = observedAt
		if attemptEvidence.Status == StatusHealthy {
			evidence.Status = StatusHealthy
			evidence.Healthy = true
			return evidence, nil
		}
		if attemptEvidence.Status == StatusCanceled {
			evidence.Status = StatusCanceled
			return evidence, nil
		}
		if attempt == spec.MaxAttempts || !retryable(attemptEvidence.FailureCode) {
			return evidence, nil
		}
		if err := engine.clock.Sleep(ctx, retryDelay(spec)); err != nil {
			evidence.Status = StatusCanceled
			evidence.ObservedAt = engine.clock.Now().UTC()
			return evidence, nil
		}
	}
	return evidence, nil
}

func (engine *Engine) RunSuite(ctx context.Context, suite SuiteV1) (SuiteEvidence, error) {
	if engine == nil || ctx == nil || suite.Validate() != nil {
		return SuiteEvidence{}, ErrInvalidSpec
	}
	probes := sortedSpecs(suite.Probes)
	first := probes[0]
	evidence := SuiteEvidence{
		SchemaVersion: EvidenceV1, DeploymentID: first.Binding.DeploymentID,
		PlanHash: first.Binding.PlanHash, RecipeDigest: first.Binding.RecipeDigest,
		Probes: make([]ProbeEvidence, 0, len(probes)),
	}
	for _, spec := range probes {
		probeEvidence, err := engine.Run(ctx, spec)
		if err != nil {
			return SuiteEvidence{}, err
		}
		evidence.Probes = append(evidence.Probes, probeEvidence)
		if probeEvidence.ObservedAt.After(evidence.ObservedAt) {
			evidence.ObservedAt = probeEvidence.ObservedAt
		}
	}
	evidence.Status, evidence.Healthy = aggregate(evidence.Probes)
	return evidence, nil
}

func classifyAttempt(spec SpecV1, attempt uint32, observedAt time.Time, observation Observation, probeErr, contextErr error) AttemptEvidence {
	result := AttemptEvidence{
		Attempt: attempt, Status: StatusUnhealthy, StatusCode: observation.StatusCode,
		SummaryDigest: observation.SummaryDigest, LatencyMillis: observation.Latency.Milliseconds(), ObservedAt: observedAt,
	}
	if probeErr != nil || contextErr != nil {
		result.StatusCode = 0
		result.SummaryDigest = ""
		result.FailureCode = failureCode(probeErr, contextErr)
		if result.FailureCode == FailureCanceled {
			result.Status = StatusCanceled
		}
		return result
	}
	if observation.Latency < 0 || !digestPattern.MatchString(observation.SummaryDigest) ||
		(spec.Protocol == ProtocolHTTPS && (observation.StatusCode < 100 || observation.StatusCode > 599)) ||
		(spec.Protocol == ProtocolTCP && observation.StatusCode != 0) {
		result.StatusCode = 0
		result.SummaryDigest = ""
		result.FailureCode = FailureTransport
		return result
	}
	if spec.Protocol == ProtocolHTTPS && !healthyHTTPStatus(spec, observation.StatusCode) {
		result.FailureCode = FailureHTTPStatus
		return result
	}
	if spec.Purpose == PurposeSemantic && observation.SummaryDigest != spec.ExpectedSummaryDigest {
		result.FailureCode = FailureSemanticMismatch
		return result
	}
	result.Status = StatusHealthy
	return result
}

func failureCode(probeErr, contextErr error) FailureCode {
	if errors.Is(contextErr, context.Canceled) || errors.Is(probeErr, context.Canceled) {
		return FailureCanceled
	}
	if errors.Is(contextErr, context.DeadlineExceeded) || errors.Is(probeErr, context.DeadlineExceeded) {
		return FailureTimeout
	}
	var transportErr *TransportError
	if errors.As(probeErr, &transportErr) && validFailureCode(transportErr.Code) {
		return transportErr.Code
	}
	return FailureTransport
}

func validFailureCode(code FailureCode) bool {
	switch code {
	case FailureTimeout, FailureTargetRejected, FailureResolve, FailureConnect, FailureTLS, FailureResponseTooLarge, FailureTransport:
		return true
	default:
		return false
	}
}

func retryable(code FailureCode) bool {
	return code != FailureCanceled && code != FailureTargetRejected
}

func aggregate(probes []ProbeEvidence) (AggregateStatus, bool) {
	allHealthy := len(probes) > 0
	livenessHealthy := false
	livenessPresent := false
	for _, probe := range probes {
		if probe.Status == StatusCanceled {
			return AggregateCanceled, false
		}
		allHealthy = allHealthy && probe.Healthy
		if probe.Purpose == PurposeLiveness {
			livenessPresent = true
			livenessHealthy = probe.Healthy
		}
	}
	if allHealthy {
		return AggregateHealthy, true
	}
	if livenessPresent && livenessHealthy {
		return AggregateDegraded, false
	}
	return AggregateUnhealthy, false
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func (realClock) Sleep(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

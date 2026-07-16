package resource

import (
	"context"
	"fmt"
	"time"
)

const ProbeTrustIndependent = "independent_external_probe"

type ProbeService struct {
	runner ProbeRunner
	now    func() time.Time
}

func NewProbeService(runner ProbeRunner) (*ProbeService, error) {
	if runner == nil {
		return nil, fmt.Errorf("%w: external probe runner is required", ErrInvalid)
	}
	return &ProbeService{runner: runner, now: time.Now}, nil
}

func (service *ProbeService) Run(ctx context.Context, spec ProbeSpec) (ProbeEvidence, error) {
	if err := spec.Validate(); err != nil {
		return ProbeEvidence{}, err
	}
	observation, err := service.runner.Run(ctx, spec)
	if err != nil {
		return ProbeEvidence{}, err
	}
	if observation.ObservedAt.IsZero() {
		observation.ObservedAt = service.now().UTC()
	}
	if !sha256Pattern.MatchString(observation.SummaryDigest) {
		return ProbeEvidence{}, fmt.Errorf("%w: probe runner returned an invalid summary digest", ErrInvalid)
	}
	healthy := observation.Healthy
	if spec.Kind == ProbeSemantic && observation.SummaryDigest != spec.ExpectedDigest {
		healthy = false
	}
	return ProbeEvidence{
		DeploymentID: spec.DeploymentID, Kind: spec.Kind, Endpoint: spec.Endpoint,
		Healthy: healthy, StatusCode: observation.StatusCode, SummaryDigest: observation.SummaryDigest,
		Trust: ProbeTrustIndependent, ObservedAt: observation.ObservedAt.UTC(),
	}, nil
}

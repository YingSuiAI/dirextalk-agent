package postgres

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
)

// TeamOrchestrationRepository is the narrow application adapter. RPC and
// dialogue surfaces receive the orchestration service, never the raw Store.
type TeamOrchestrationRepository struct {
	store *Store
}

func NewTeamOrchestrationRepository(
	store *Store,
) (*TeamOrchestrationRepository, error) {
	if store == nil {
		return nil, teamorchestration.ErrInvalid
	}
	return &TeamOrchestrationRepository{store: store}, nil
}

func (repository *TeamOrchestrationRepository) FindPreparedPlan(
	ctx context.Context,
	scope task.MutationScope,
	command teamorchestration.FindPreparedPlanCommand,
) (teamorchestration.PreparedPlanFact, bool, error) {
	if repository == nil || repository.store == nil {
		return teamorchestration.PreparedPlanFact{},
			false,
			teamorchestration.ErrInvalid
	}
	record, found, err := repository.store.FindPreparedTeamPlan(
		ctx,
		scope,
		FindPreparedTeamPlanCommand{
			IdempotencyKey: command.IdempotencyKey,
			Intent:         orchestrationPreparationIntent(command.Intent),
		},
	)
	if err != nil {
		return teamorchestration.PreparedPlanFact{}, false, err
	}
	if !found {
		return teamorchestration.PreparedPlanFact{}, false, nil
	}
	prepared, err := orchestrationPreparedPlanFact(record)
	return prepared, err == nil, err
}

func (repository *TeamOrchestrationRepository) PersistPreparedPlan(
	ctx context.Context,
	scope task.MutationScope,
	command teamorchestration.PersistPreparedPlanCommand,
) (teamorchestration.PreparedPlanFact, error) {
	if repository == nil || repository.store == nil {
		return teamorchestration.PreparedPlanFact{},
			teamorchestration.ErrInvalid
	}
	record, err := repository.store.PrepareTeamPlan(
		ctx,
		scope,
		PrepareTeamPlanCommand{
			IdempotencyKey: command.IdempotencyKey,
			Intent:         orchestrationPreparationIntent(command.Intent),
			Snapshot:       command.Offers,
			Plan:           command.Plan,
		},
	)
	if err != nil {
		return teamorchestration.PreparedPlanFact{}, err
	}
	return orchestrationPreparedPlanFact(record)
}

func (repository *TeamOrchestrationRepository) GetOffer(
	ctx context.Context,
	ownerID,
	snapshotID string,
) (teamorchestration.OfferFact, error) {
	if repository == nil || repository.store == nil {
		return teamorchestration.OfferFact{}, teamorchestration.ErrInvalid
	}
	record, err := repository.store.GetTeamOfferSnapshot(
		ctx,
		ownerID,
		snapshotID,
	)
	if err != nil {
		return teamorchestration.OfferFact{}, err
	}
	return teamorchestration.OfferFact{
		OwnerID:   record.OwnerID,
		Document:  record.Document,
		Digest:    record.Digest,
		CreatedAt: record.CreatedAt,
	}, nil
}

func (repository *TeamOrchestrationRepository) GetPlan(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (teamorchestration.PlanFact, error) {
	if repository == nil || repository.store == nil {
		return teamorchestration.PlanFact{}, teamorchestration.ErrInvalid
	}
	record, err := repository.store.GetTeamPlan(
		ctx,
		ownerID,
		planID,
		planRevision,
	)
	if err != nil {
		return teamorchestration.PlanFact{}, err
	}
	return orchestrationPlanFact(record)
}

func (repository *TeamOrchestrationRepository) PersistChallenge(
	ctx context.Context,
	scope task.MutationScope,
	command teamorchestration.PersistChallengeCommand,
) (teamorchestration.ChallengeFact, error) {
	if repository == nil || repository.store == nil {
		return teamorchestration.ChallengeFact{}, teamorchestration.ErrInvalid
	}
	record, err := repository.store.CreateTeamApprovalChallenge(
		ctx,
		scope,
		CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             command.IdempotencyKey,
			OwnerID:                    command.OwnerID,
			PlanID:                     command.PlanID,
			PlanRevision:               command.PlanRevision,
			ExpectedPlanRecordRevision: command.ExpectedPlanRecordRevision,
			ApprovalID:                 command.ApprovalID,
			ChallengeID:                command.ChallengeID,
			SignerKeyID:                command.SignerKeyID,
		},
	)
	if err != nil {
		return teamorchestration.ChallengeFact{}, err
	}
	return orchestrationChallengeFact(record), nil
}

func (repository *TeamOrchestrationRepository) PersistApproval(
	ctx context.Context,
	scope task.MutationScope,
	command teamorchestration.PersistApprovalCommand,
) (teamorchestration.PlanFact, error) {
	if repository == nil || repository.store == nil {
		return teamorchestration.PlanFact{}, teamorchestration.ErrInvalid
	}
	record, err := repository.store.ApproveTeamPlan(
		ctx,
		scope,
		ApproveTeamPlanCommand{
			IdempotencyKey: command.IdempotencyKey,
			OwnerID:        command.OwnerID,
			ExpectedPlanRecordRevision: command.
				ExpectedPlanRecordRevision,
			ExpectedChallengeRecordRevision: command.
				ExpectedChallengeRecordRevision,
			Signature: command.Signature,
		},
	)
	if err != nil {
		return teamorchestration.PlanFact{}, err
	}
	return orchestrationPlanFact(record)
}

func (repository *TeamOrchestrationRepository) GetApprovalForPlan(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (teamorchestration.ApprovalFact, error) {
	if repository == nil || repository.store == nil {
		return teamorchestration.ApprovalFact{}, teamorchestration.ErrInvalid
	}
	record, err := repository.store.GetTeamApprovalForPlan(
		ctx,
		ownerID,
		planID,
		planRevision,
	)
	if err != nil {
		return teamorchestration.ApprovalFact{}, err
	}
	return teamorchestration.ApprovalFact{
		Signature:  record.Signature,
		ApprovedAt: record.ApprovedAt,
		CreatedAt:  record.CreatedAt,
	}, nil
}

func orchestrationPlanFact(
	record TeamPlanRecord,
) (teamorchestration.PlanFact, error) {
	status := teamorchestration.PlanStatus(record.Status)
	switch status {
	case teamorchestration.PlanReadyForConfirmation,
		teamorchestration.PlanApproved,
		teamorchestration.PlanExpired,
		teamorchestration.PlanSuperseded,
		teamorchestration.PlanExecuting,
		teamorchestration.PlanCompleted,
		teamorchestration.PlanFailed,
		teamorchestration.PlanCanceled:
	default:
		return teamorchestration.PlanFact{}, ErrTeamFactCorrupt
	}
	return teamorchestration.PlanFact{
		TaskID:         record.TaskID,
		Plan:           record.Plan,
		PlanDigest:     record.PlanDigest,
		Status:         status,
		RecordRevision: record.RecordRevision,
		CreatedAt:      record.CreatedAt,
		UpdatedAt:      record.UpdatedAt,
	}, nil
}

func orchestrationPreparationIntent(
	intent teamorchestration.PreparationIntent,
) TeamPlanPreparationIntent {
	return TeamPlanPreparationIntent{
		OwnerID:                  intent.OwnerID,
		TaskID:                   intent.TaskID,
		PlanID:                   intent.PlanID,
		Revision:                 intent.Revision,
		ExpectedPreviousRevision: intent.ExpectedPreviousRevision,
		GoalDigest:               intent.GoalDigest,
		Proposal:                 intent.Proposal,
	}
}

func orchestrationPreparedPlanFact(
	record PreparedTeamPlanRecord,
) (teamorchestration.PreparedPlanFact, error) {
	plan, err := orchestrationPlanFact(record.Plan)
	if err != nil {
		return teamorchestration.PreparedPlanFact{}, err
	}
	return teamorchestration.PreparedPlanFact{
		Offer: teamorchestration.OfferFact{
			OwnerID:   record.Offer.OwnerID,
			Document:  record.Offer.Document,
			Digest:    record.Offer.Digest,
			CreatedAt: record.Offer.CreatedAt,
		},
		Plan:     plan,
		Replayed: record.Replayed,
	}, nil
}

func orchestrationChallengeFact(
	record TeamApprovalChallengeRecord,
) teamorchestration.ChallengeFact {
	var consumedAt *time.Time
	if record.ConsumedAt != nil {
		value := record.ConsumedAt.UTC()
		consumedAt = &value
	}
	return teamorchestration.ChallengeFact{
		Challenge:      record.Challenge,
		ConsumedAt:     consumedAt,
		RecordRevision: record.RecordRevision,
		CreatedAt:      record.CreatedAt,
		UpdatedAt:      record.UpdatedAt,
	}
}

var _ teamorchestration.Repository = (*TeamOrchestrationRepository)(nil)

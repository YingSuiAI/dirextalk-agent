package teamexecution

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type Service struct {
	plans      ApprovedPlanVerifier
	repository Repository
}

func NewService(
	plans ApprovedPlanVerifier,
	repository Repository,
) (*Service, error) {
	if plans == nil || repository == nil {
		return nil, ErrInvalid
	}
	return &Service{plans: plans, repository: repository}, nil
}

// Materialize is the only application entry point. The request identifies an
// already-approved Plan; it cannot override roles, models, images, compute, or
// budget.
func (service *Service) Materialize(
	ctx context.Context,
	scope task.MutationScope,
	request MaterializeRequest,
) (Fact, error) {
	if service == nil ||
		service.plans == nil ||
		service.repository == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		!validMaterializeRequest(request) {
		return Fact{}, ErrInvalid
	}
	replayed, found, err := service.repository.FindMaterializedExecution(
		ctx,
		scope,
		request,
	)
	if err != nil {
		return Fact{}, err
	}
	if found {
		if !factMatchesMaterializeRequest(replayed, request) {
			return Fact{}, ErrFactMismatch
		}
		return replayed, nil
	}
	authorization, err := service.plans.GetApprovedPlanForMaterialization(
		ctx,
		request.OwnerID,
		request.PlanID,
		request.PlanRevision,
	)
	if err != nil {
		return Fact{}, err
	}
	execution, err := Materialize(authorization)
	if err != nil {
		return Fact{}, err
	}
	fact, err := service.repository.PersistExecution(
		ctx,
		scope,
		PersistCommand{
			IdempotencyKey: request.IdempotencyKey,
			Authorization:  authorization,
			Execution:      execution,
		},
	)
	if err != nil {
		return Fact{}, err
	}
	if !validFact(fact) ||
		fact.Execution.ValidateAgainst(authorization) != nil {
		return Fact{}, ErrFactMismatch
	}
	return fact, nil
}

func (service *Service) RecoverPendingMaterializations(
	ctx context.Context,
	scope task.MutationScope,
	limit uint32,
) (uint32, error) {
	if service == nil ||
		service.repository == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		limit == 0 ||
		limit > 256 {
		return 0, ErrInvalid
	}
	var (
		recovered uint32
		cursor    *PendingMaterialization
		batchErr  error
	)
	for {
		pending, err := service.repository.ListPendingMaterializations(
			ctx,
			cursor,
			limit,
		)
		if err != nil {
			return recovered, errors.Join(batchErr, err)
		}
		for _, item := range pending {
			planID, parseErr := uuid.Parse(item.PlanID)
			if parseErr != nil ||
				planID == uuid.Nil ||
				item.PlanRevision == 0 ||
				item.UpdatedAt.IsZero() {
				batchErr = errors.Join(
					batchErr,
					fmt.Errorf(
						"%w: invalid pending materialization cursor",
						ErrFactMismatch,
					),
				)
				continue
			}
			idempotencyKey := uuid.NewSHA1(
				planID,
				[]byte(
					"team-execution-recovery/v1\x00"+
						strconv.FormatUint(item.PlanRevision, 10),
				),
			).String()
			if _, err := service.Materialize(
				ctx,
				scope,
				MaterializeRequest{
					IdempotencyKey: idempotencyKey,
					OwnerID:        item.OwnerID,
					PlanID:         item.PlanID,
					PlanRevision:   item.PlanRevision,
				},
			); err != nil {
				batchErr = errors.Join(
					batchErr,
					fmt.Errorf(
						"materialize approved Team Plan %s/%d: %w",
						item.PlanID,
						item.PlanRevision,
						err,
					),
				)
				continue
			}
			recovered++
		}
		if len(pending) == 0 {
			break
		}
		next := pending[len(pending)-1]
		cursor = &next
		if len(pending) < int(limit) {
			break
		}
	}
	return recovered, batchErr
}

// BeginDispatch is the spend boundary. A successful historical replay is
// returned before current offer verification so retries remain deterministic
// after the Plan advances or its original quote expires.
func (service *Service) BeginDispatch(
	ctx context.Context,
	scope task.MutationScope,
	request BeginDispatchRequest,
) (Fact, error) {
	if service == nil ||
		service.plans == nil ||
		service.repository == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		!validBeginDispatchRequest(request) {
		return Fact{}, ErrInvalid
	}
	replayed, found, err := service.repository.FindDispatch(
		ctx,
		scope,
		request,
	)
	if err != nil {
		return Fact{}, err
	}
	if found {
		if !factMatchesDispatchRequest(replayed, request) {
			return Fact{}, ErrFactMismatch
		}
		return replayed, nil
	}
	current, err := service.repository.GetTeamExecution(
		ctx,
		request.OwnerID,
		request.ExecutionID,
	)
	if err != nil {
		return Fact{}, err
	}
	if !factMatchesDispatchRequest(current, request) {
		return Fact{}, ErrFactMismatch
	}
	command := BeginDispatchCommand{
		IdempotencyKey: request.IdempotencyKey,
		OwnerID:        request.OwnerID,
		ExecutionID:    request.ExecutionID,
	}
	if current.Status == StatusMaterialized {
		authorization, verifyErr :=
			service.plans.VerifyApprovedPlanForExecution(
				ctx,
				current.Execution.OwnerID,
				current.Execution.PlanID,
				current.Execution.PlanRevision,
			)
		if verifyErr != nil {
			return Fact{}, verifyErr
		}
		if current.Execution.ValidateAgainst(authorization) != nil {
			return Fact{}, ErrFactMismatch
		}
		command.Authorization = &authorization
	}
	fact, err := service.repository.BeginDispatch(ctx, scope, command)
	if err != nil {
		return Fact{}, err
	}
	if !factMatchesDispatchRequest(fact, request) ||
		fact.Status == StatusMaterialized {
		return Fact{}, ErrFactMismatch
	}
	return fact, nil
}

func validFact(fact Fact) bool {
	actualDigest, err := fact.Execution.Digest()
	return err == nil &&
		fact.ExecutionDigest == actualDigest &&
		validStatus(fact.Status) &&
		fact.RecordRevision > 0 &&
		!fact.CreatedAt.IsZero() &&
		!fact.UpdatedAt.IsZero()
}

func factMatchesMaterializeRequest(
	fact Fact,
	request MaterializeRequest,
) bool {
	return validFact(fact) &&
		fact.Execution.OwnerID == request.OwnerID &&
		fact.Execution.PlanID == request.PlanID &&
		fact.Execution.PlanRevision == request.PlanRevision
}

func factMatchesDispatchRequest(
	fact Fact,
	request BeginDispatchRequest,
) bool {
	return validFact(fact) &&
		fact.Execution.OwnerID == request.OwnerID &&
		fact.Execution.ExecutionID == request.ExecutionID
}

func validStatus(status Status) bool {
	switch status {
	case StatusMaterialized,
		StatusDispatching,
		StatusRunning,
		StatusVerifying,
		StatusCompleted,
		StatusFailed,
		StatusCanceled:
		return true
	default:
		return false
	}
}

func validMaterializeRequest(request MaterializeRequest) bool {
	idempotencyKey, idempotencyErr := uuid.Parse(
		request.IdempotencyKey,
	)
	planID, planErr := uuid.Parse(request.PlanID)
	return idempotencyErr == nil &&
		idempotencyKey != uuid.Nil &&
		idempotencyKey.String() == request.IdempotencyKey &&
		planErr == nil &&
		planID != uuid.Nil &&
		planID.String() == request.PlanID &&
		request.OwnerID != "" &&
		request.OwnerID == strings.TrimSpace(request.OwnerID) &&
		len(request.OwnerID) <= 255 &&
		request.PlanRevision > 0 &&
		request.PlanRevision <= uint64(math.MaxInt64)
}

func validBeginDispatchRequest(request BeginDispatchRequest) bool {
	idempotencyKey, idempotencyErr := uuid.Parse(request.IdempotencyKey)
	executionID, executionErr := uuid.Parse(request.ExecutionID)
	return idempotencyErr == nil &&
		idempotencyKey != uuid.Nil &&
		idempotencyKey.String() == request.IdempotencyKey &&
		executionErr == nil &&
		executionID != uuid.Nil &&
		executionID.String() == request.ExecutionID &&
		request.OwnerID != "" &&
		request.OwnerID == strings.TrimSpace(request.OwnerID) &&
		len(request.OwnerID) <= 255
}

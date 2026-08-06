package coreteam

import "context"

const MaxExecutionPageSize = 100

type CancelExecutionRequest struct {
	Scope            Scope
	ExecutionID      string
	ExpectedRevision uint64
	IdempotencyKey   string
}

type CancellationPort interface {
	CancelExecution(context.Context, CancelExecutionRequest) (Execution, error)
}

// Service is the closed read and cancellation boundary published to Core
// capabilities. Provisioning and cleanup remain owned by the Team controller.
type Service struct {
	repository   Repository
	cancellation CancellationPort
}

func NewService(repository Repository, cancellation CancellationPort) *Service {
	return &Service{repository: repository, cancellation: cancellation}
}

func (s *Service) ReadyForPublication() bool {
	return s != nil && s.repository != nil && s.cancellation != nil
}

func (s *Service) GetPlan(ctx context.Context, scope Scope, planID string) (PlanRecord, error) {
	if s == nil || s.repository == nil {
		return PlanRecord{}, ErrRuntimeUnavailable
	}
	if scope.Validate() != nil || !validUUID(planID) {
		return PlanRecord{}, ErrInvalid
	}
	record, err := s.repository.GetPlan(ctx, scope, planID)
	if err != nil {
		return PlanRecord{}, err
	}
	if record.CreatedAt.IsZero() || record.Plan.Validate() != nil || record.Plan.PlanID != planID || !sameScope(scope, record.Plan.OwnerID, record.Plan.AccountGeneration) {
		return PlanRecord{}, ErrInvalid
	}
	record.Plan = record.Plan.Clone()
	return record, nil
}

func (s *Service) GetExecution(ctx context.Context, scope Scope, executionID string) (Execution, error) {
	if s == nil || s.repository == nil {
		return Execution{}, ErrRuntimeUnavailable
	}
	if scope.Validate() != nil || !validUUID(executionID) {
		return Execution{}, ErrInvalid
	}
	execution, err := s.repository.GetExecution(ctx, scope, executionID)
	if err != nil {
		return Execution{}, err
	}
	if execution.Validate() != nil || execution.ExecutionID != executionID || !sameScope(scope, execution.OwnerID, execution.AccountGeneration) {
		return Execution{}, ErrInvalid
	}
	return execution, nil
}

func (s *Service) ListExecutions(ctx context.Context, query ListQuery) (Page, error) {
	if s == nil || s.repository == nil {
		return Page{}, ErrRuntimeUnavailable
	}
	if err := validateListQuery(query); err != nil {
		return Page{}, err
	}
	query.Statuses = append([]ExecutionStatus(nil), query.Statuses...)
	page, err := s.repository.ListExecutions(ctx, query)
	if err != nil {
		return Page{}, err
	}
	if len(page.Executions) > int(query.Limit) || (page.NextID != "" && !validUUID(page.NextID)) {
		return Page{}, ErrInvalid
	}
	seen := make(map[string]struct{}, len(page.Executions))
	for _, execution := range page.Executions {
		if execution.Validate() != nil || !sameScope(query.Scope, execution.OwnerID, execution.AccountGeneration) {
			return Page{}, ErrInvalid
		}
		if _, duplicate := seen[execution.ExecutionID]; duplicate {
			return Page{}, ErrInvalid
		}
		seen[execution.ExecutionID] = struct{}{}
	}
	page.Executions = append([]Execution(nil), page.Executions...)
	return page, nil
}

func (s *Service) CancelExecution(ctx context.Context, request CancelExecutionRequest) (Execution, error) {
	if s == nil || s.cancellation == nil {
		return Execution{}, ErrRuntimeUnavailable
	}
	if request.Scope.Validate() != nil || !validUUID(request.ExecutionID) || request.ExpectedRevision == 0 || !validUUID(request.IdempotencyKey) {
		return Execution{}, ErrInvalid
	}
	execution, err := s.cancellation.CancelExecution(ctx, request)
	if err != nil {
		return Execution{}, err
	}
	if execution.Validate() != nil || execution.ExecutionID != request.ExecutionID || !sameScope(request.Scope, execution.OwnerID, execution.AccountGeneration) {
		return Execution{}, ErrInvalid
	}
	return execution, nil
}

func validateListQuery(query ListQuery) error {
	if query.Scope.Validate() != nil || query.Limit == 0 || query.Limit > MaxExecutionPageSize || (query.AfterID != "" && !validUUID(query.AfterID)) {
		return ErrInvalid
	}
	seen := make(map[ExecutionStatus]struct{}, len(query.Statuses))
	for _, status := range query.Statuses {
		if validateExecutionStatus(status) != nil {
			return ErrInvalid
		}
		if _, duplicate := seen[status]; duplicate {
			return ErrInvalid
		}
		seen[status] = struct{}{}
	}
	return nil
}

func sameScope(scope Scope, ownerID string, generation int64) bool {
	return scope.OwnerID == ownerID && scope.AccountGeneration == generation
}

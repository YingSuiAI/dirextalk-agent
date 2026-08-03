package teamdispatch

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

const maximumScheduleBatch = 64

type Service struct {
	authorizations AuthorizationReader
	progress       ProgressReader
	repository     Repository
	now            func() time.Time
}

func NewService(
	authorizations AuthorizationReader,
	progress ProgressReader,
	repository Repository,
	now func() time.Time,
) (*Service, error) {
	if authorizations == nil ||
		progress == nil ||
		repository == nil ||
		now == nil {
		return nil, ErrInvalid
	}
	return &Service{
		authorizations: authorizations,
		progress:       progress,
		repository:     repository,
		now:            now,
	}, nil
}

// Schedule reserves every currently ready role up to the signed concurrency
// ceiling. ClaimRole rechecks the ceiling atomically, so this optimistic read
// remains safe with concurrent dispatchers.
func (service *Service) Schedule(
	ctx context.Context,
	scope task.MutationScope,
	ownerID,
	executionID string,
) ([]Fact, error) {
	if service == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		ownerID == "" ||
		executionID == "" {
		return nil, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	authorized, err := service.authorizations.LoadAuthorizedExecution(
		ctx,
		ownerID,
		executionID,
	)
	if err != nil {
		return nil, err
	}
	if authorized.ValidateForLaunch(now) != nil {
		return nil, ErrNotReady
	}
	progress, err := service.progress.LoadRoleProgress(
		ctx,
		ownerID,
		executionID,
	)
	if err != nil {
		return nil, err
	}
	operations, err := service.repository.ListExecutionOperations(
		ctx,
		ownerID,
		executionID,
	)
	if err != nil {
		return nil, err
	}
	roleIDs, err := ReadyRoleIDs(authorized, progress, operations)
	if err != nil {
		return nil, err
	}
	claimed := make([]Fact, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		intent, buildErr := NewIntent(authorized, roleID, now)
		if buildErr != nil {
			return nil, buildErr
		}
		key, keyErr := ClaimIdempotencyKey(intent)
		if keyErr != nil {
			return nil, keyErr
		}
		fact, _, claimErr := service.repository.ClaimRole(
			ctx,
			scope,
			ClaimCommand{
				IdempotencyKey: key,
				Intent:         intent,
				MaxConcurrentRoles: authorized.Execution.Execution.
					MaxConcurrentWorkers,
			},
		)
		if errors.Is(claimErr, ErrConcurrencyLimit) {
			break
		}
		if claimErr != nil {
			return nil, claimErr
		}
		if fact.Validate() != nil ||
			fact.Intent.ValidateAgainst(authorized) != nil {
			return nil, ErrFactMismatch
		}
		claimed = append(claimed, fact)
	}
	return claimed, nil
}

func ReadyRoleIDs(
	authorized AuthorizedExecution,
	progress []RoleProgress,
	operations []Fact,
) ([]string, error) {
	if authorized.Validate() != nil {
		return nil, ErrNotReady
	}
	execution := authorized.Execution.Execution
	if len(progress) != len(execution.Roles) ||
		len(operations) > len(execution.Roles) {
		return nil, ErrFactMismatch
	}
	progressByRole := make(map[string]RoleProgress, len(progress))
	for _, item := range progress {
		if !roleIDPattern.MatchString(item.RoleID) {
			return nil, ErrFactMismatch
		}
		if _, duplicate := progressByRole[item.RoleID]; duplicate {
			return nil, ErrFactMismatch
		}
		progressByRole[item.RoleID] = item
	}
	operationsByRole := make(map[string]Fact, len(operations))
	var reserved uint32
	for _, operation := range operations {
		if operation.Validate() != nil ||
			operation.Intent.ValidateAgainst(authorized) != nil {
			return nil, ErrFactMismatch
		}
		if _, duplicate := operationsByRole[operation.Intent.RoleID]; duplicate {
			return nil, ErrFactMismatch
		}
		operationsByRole[operation.Intent.RoleID] = operation
		if operation.Phase != PhaseCompleted {
			reserved++
		}
	}
	if reserved >= execution.MaxConcurrentWorkers {
		return []string{}, nil
	}
	available := execution.MaxConcurrentWorkers - reserved
	result := make([]string, 0, available)
	for _, role := range execution.Roles {
		current, found := progressByRole[role.RoleID]
		if !found ||
			current.RoleID != role.RoleID ||
			!validProgress(current) {
			return nil, ErrFactMismatch
		}
		if _, exists := operationsByRole[role.RoleID]; exists ||
			current.ExecutionStatus != task.ExecutionQueued ||
			current.OutcomeStatus != task.OutcomePending {
			continue
		}
		dependenciesReady := true
		for _, dependencyID := range role.DependsOnRoleIDs {
			dependency, found := progressByRole[dependencyID]
			if !found ||
				dependency.ExecutionStatus != task.ExecutionFinished ||
				dependency.OutcomeStatus != task.OutcomeSucceeded {
				dependenciesReady = false
				break
			}
		}
		if !dependenciesReady {
			continue
		}
		result = append(result, role.RoleID)
		if uint32(len(result)) == available {
			break
		}
	}
	if len(result) > maximumScheduleBatch {
		result = result[:maximumScheduleBatch]
	}
	return slices.Clone(result), nil
}

func validProgress(value RoleProgress) bool {
	switch value.ExecutionStatus {
	case task.ExecutionQueued:
		return value.OutcomeStatus == task.OutcomePending
	case task.ExecutionRunning:
		return value.OutcomeStatus == task.OutcomePending
	case task.ExecutionFinished:
		switch value.OutcomeStatus {
		case task.OutcomeSucceeded,
			task.OutcomeFailed,
			task.OutcomeCanceled,
			task.OutcomeTimedOut,
			task.OutcomeInterrupted:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

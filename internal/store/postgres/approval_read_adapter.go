package postgres

import (
	"context"
	"errors"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
)

var errReadOnlyApprovalRepository = errors.New("approval coordinator repository is read-only")

// ApprovalReadRepository supplies only the reads used by DraftChallenge and
// Verify. Durable create/consume transitions must go through CloudAdapter so
// they remain caller-idempotent and transactionally coupled to Plan facts.
type ApprovalReadRepository struct{ store *Store }

func NewApprovalReadRepository(store *Store) (*ApprovalReadRepository, error) {
	if store == nil {
		return nil, errReadOnlyApprovalRepository
	}
	return &ApprovalReadRepository{store: store}, nil
}

func (repository *ApprovalReadRepository) GetDeviceKey(ctx context.Context, keyID string) (cloudapproval.DeviceKeyV1, error) {
	return repository.store.GetDeviceKey(ctx, keyID)
}

func (*ApprovalReadRepository) CreateChallenge(context.Context, cloudapproval.ChallengeV1) error {
	return errReadOnlyApprovalRepository
}

func (repository *ApprovalReadRepository) GetChallenge(ctx context.Context, challengeID string) (cloudapproval.ChallengeV1, error) {
	return repository.store.GetChallenge(ctx, challengeID)
}

func (*ApprovalReadRepository) ConsumeChallenge(context.Context, string, uint64, time.Time) error {
	return errReadOnlyApprovalRepository
}

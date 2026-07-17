package helperkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"
)

type Repository interface {
	CreateIdempotent(context.Context, Record, string, [32]byte) (Record, error)
	Get(context.Context, string) (Record, error)
	UpdateIdempotent(context.Context, string, State, string, [32]byte, func(*Record) error) (Record, error)
	DiscoverCurrent(context.Context, DiscoveryScope) (Record, error)
}

// DiscoveryScope contains only facts recovered from an authenticated Worker
// session. Repositories bind WorkerID to its current provider-verified
// instance and principal before returning a delivery.
type DiscoveryScope struct {
	DeploymentID string
	OwnerID      string
	WorkerID     string
}

type SecretPublisher interface {
	CreateRootHelperKey(context.Context, DeviceBinding, []byte) (SecretCoordinate, error)
	GrantRootHelperKey(context.Context, DeviceBinding) error
}

type SecretRevoker interface {
	DenyRootHelperKey(context.Context, DeviceBinding) error
	ReadBackRootHelperKeyDenied(context.Context, DeviceBinding) (bool, error)
}

type Service struct {
	repository Repository
	publisher  SecretPublisher
	revoker    SecretRevoker
	approvals  ApprovedBindingReader
	deriver    KeyDeriver
	now        func() time.Time
}

type ServiceOption func(*Service) error

type ApprovedBindingReader interface {
	GetApproved(context.Context, string) (ApprovalChallenge, error)
}

func WithApprovedKeyDelivery(approvals ApprovedBindingReader, deriver KeyDeriver) ServiceOption {
	return func(service *Service) error {
		if approvals == nil || deriver == nil {
			return ErrInvalid
		}
		service.approvals, service.deriver = approvals, deriver
		return nil
	}
}

func NewService(repository Repository, publisher SecretPublisher, revoker SecretRevoker, now func() time.Time, options ...ServiceOption) (*Service, error) {
	if repository == nil || publisher == nil || revoker == nil || now == nil {
		return nil, ErrInvalid
	}
	service := &Service{repository: repository, publisher: publisher, revoker: revoker, now: now}
	for _, option := range options {
		if option == nil || option(service) != nil {
			return nil, ErrInvalid
		}
	}
	return service, nil
}

type DraftRequest struct {
	Binding        DeviceBinding
	IdempotencyKey string
}

func (s *Service) Draft(ctx context.Context, request DraftRequest) (Record, error) {
	if ctx == nil || s.approvals == nil || s.deriver == nil || !validUUID(request.IdempotencyKey) ||
		request.Binding.Secret != (SecretCoordinate{}) {
		return Record{}, ErrInvalid
	}
	approved, err := s.approvals.GetApproved(ctx, request.Binding.DeliveryID)
	if err != nil {
		return Record{}, ErrNotReady
	}
	if !samePreparedBinding(request.Binding, approved.Binding) {
		return Record{}, ErrConflict
	}
	if current, err := s.repository.Get(ctx, request.Binding.DeliveryID); err == nil {
		if current.State == StateDraft && sameDraftRequest(current.Binding, request.Binding) {
			return current, nil
		}
		return Record{}, ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return Record{}, err
	}
	base := approved.Binding
	base.PublicKeyDigest, base.NonceDigest = "", ""
	publicKey, privateKey, nonce, err := s.deriver.Derive(base)
	if err != nil {
		return Record{}, err
	}
	defer clear(privateKey)
	if !bytes.Equal(publicKey, approved.PublicKey) || !bytes.Equal(nonce, approved.Nonce) {
		return Record{}, ErrConflict
	}
	request.Binding = approved.Binding
	coordinate, err := s.publisher.CreateRootHelperKey(ctx, request.Binding, privateKey)
	if err != nil {
		return Record{}, ErrUnavailable
	}
	request.Binding.Secret = coordinate
	now := s.now().UTC().Truncate(time.Microsecond)
	record := Record{Binding: request.Binding, PublicKey: publicKey, Nonce: nonce, State: StateDraft, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	hash := sha256.Sum256([]byte(request.IdempotencyKey + "\x00" + request.Binding.DeliveryID))
	return s.repository.CreateIdempotent(ctx, record, request.IdempotencyKey, hash)
}

func samePreparedBinding(requested, approved DeviceBinding) bool {
	requested.PublicKeyDigest, requested.NonceDigest = approved.PublicKeyDigest, approved.NonceDigest
	requested.Secret = approved.Secret
	return requested == approved
}

func sameDraftRequest(stored, requested DeviceBinding) bool {
	requested.PublicKeyDigest, requested.NonceDigest = stored.PublicKeyDigest, stored.NonceDigest
	requested.Secret = stored.Secret
	return requested == stored
}

type GrantRequest struct {
	DeliveryID, IdempotencyKey string
	DeviceSignature            []byte
}

func (s *Service) Grant(ctx context.Context, request GrantRequest) (Record, error) {
	current, err := s.repository.Get(ctx, request.DeliveryID)
	if err != nil || s.approvals == nil || !validUUID(request.IdempotencyKey) {
		return Record{}, ErrInvalid
	}
	approved, approvalErr := s.approvals.GetApproved(ctx, request.DeliveryID)
	if approvalErr != nil || !samePreparedBinding(current.Binding, approved.Binding) {
		return Record{}, ErrNotReady
	}
	if current.State != StateDraft {
		if current.State == StateGrant || current.State == StateProof || current.State == StateRevoking ||
			current.State == StateVerifiedRevoked || current.State == StateReady {
			return current, nil
		}
		return Record{}, ErrConflict
	}
	if err := s.publisher.GrantRootHelperKey(ctx, current.Binding); err != nil {
		return Record{}, ErrUnavailable
	}
	hash := sha256.Sum256(append([]byte(request.DeliveryID+"\x00"), request.DeviceSignature...))
	now := s.now().UTC().Truncate(time.Microsecond)
	return s.repository.UpdateIdempotent(ctx, request.DeliveryID, StateDraft, request.IdempotencyKey, hash, func(record *Record) error {
		record.State, record.UpdatedAt = StateGrant, now
		record.Revision++
		return nil
	})
}

func (s *Service) Get(ctx context.Context, deliveryID string) (Record, error) {
	return s.repository.Get(ctx, deliveryID)
}

func (s *Service) DiscoverCurrent(ctx context.Context, scope DiscoveryScope) (Record, error) {
	if !validUUID(scope.DeploymentID) || !validUUID(scope.WorkerID) || !validOwner(scope.OwnerID) {
		return Record{}, ErrInvalid
	}
	value, err := s.repository.DiscoverCurrent(ctx, scope)
	if err != nil {
		return Record{}, err
	}
	if value.Validate() != nil || value.Binding.DeploymentID != scope.DeploymentID ||
		value.Binding.OwnerID != scope.OwnerID || !discoverableState(value.State) {
		return Record{}, ErrInvalid
	}
	return value.Clone(), nil
}

func discoverableState(state State) bool {
	switch state {
	case StateGrant, StateProof, StateRevoking, StateVerifiedRevoked, StateReady:
		return true
	default:
		return false
	}
}

type ProofRequest struct {
	DeliveryID, InstanceID, PrincipalID, IdempotencyKey string
	Signature                                           []byte
}

func (s *Service) SubmitProof(ctx context.Context, request ProofRequest, nonce []byte) (Record, error) {
	current, err := s.repository.Get(ctx, request.DeliveryID)
	if err != nil {
		return Record{}, err
	}
	payload, err := PossessionPayload(current.Binding, nonce)
	if err != nil || request.InstanceID != current.Binding.InstanceID || request.PrincipalID != current.Binding.WorkerPrincipalID ||
		!ed25519.Verify(current.PublicKey, payload, request.Signature) || !validUUID(request.IdempotencyKey) {
		return Record{}, ErrInvalid
	}
	if current.State != StateGrant {
		if current.State == StateProof || current.State == StateRevoking || current.State == StateVerifiedRevoked || current.State == StateReady {
			return current, nil
		}
		return Record{}, ErrConflict
	}
	hash := sha256.Sum256(append([]byte(request.InstanceID+"\x00"+request.PrincipalID+"\x00"), request.Signature...))
	now := s.now().UTC().Truncate(time.Microsecond)
	return s.repository.UpdateIdempotent(ctx, request.DeliveryID, StateGrant, request.IdempotencyKey, hash, func(record *Record) error {
		record.State, record.ProofObservedAt, record.UpdatedAt = StateProof, now, now
		record.Revision++
		return nil
	})
}

func (s *Service) ReconcileRevocation(ctx context.Context, deliveryID, idempotencyKey string) (Record, error) {
	current, err := s.repository.Get(ctx, deliveryID)
	if err != nil {
		return Record{}, err
	}
	if current.State == StateVerifiedRevoked || current.State == StateReady {
		return current, nil
	}
	if current.State != StateProof && current.State != StateRevoking {
		return Record{}, ErrNotReady
	}
	hash := sha256.Sum256([]byte(deliveryID + "\x00revoke"))
	if current.State == StateProof {
		current, err = s.repository.UpdateIdempotent(ctx, deliveryID, StateProof, idempotencyKey, hash, func(record *Record) error {
			record.State, record.UpdatedAt = StateRevoking, s.now().UTC().Truncate(time.Microsecond)
			record.Revision++
			return nil
		})
		if err != nil {
			return Record{}, err
		}
	}
	if err := s.revoker.DenyRootHelperKey(ctx, current.Binding); err != nil {
		return Record{}, ErrUnavailable
	}
	denied, err := s.revoker.ReadBackRootHelperKeyDenied(ctx, current.Binding)
	if err != nil || !denied {
		return Record{}, ErrUnavailable
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	return s.repository.UpdateIdempotent(ctx, deliveryID, StateRevoking, idempotencyKey, hash, func(record *Record) error {
		record.State, record.RevokedAt, record.UpdatedAt = StateVerifiedRevoked, now, now
		record.Revision++
		return nil
	})
}

type CanaryRequest struct {
	DeliveryID, InstanceID, PrincipalID, ErrorCode, IdempotencyKey string
	ObservedAt                                                     time.Time
	Signature                                                      []byte
}

func (s *Service) ConfirmCanary(ctx context.Context, request CanaryRequest) (Record, error) {
	current, err := s.repository.Get(ctx, request.DeliveryID)
	if err != nil {
		return Record{}, err
	}
	payload, err := CanaryPayload(current.Binding, request.ObservedAt)
	if err != nil || request.InstanceID != current.Binding.InstanceID ||
		request.PrincipalID != current.Binding.WorkerPrincipalID || request.ErrorCode != "AccessDeniedException" ||
		!ed25519.Verify(current.PublicKey, payload, request.Signature) || !validUUID(request.IdempotencyKey) {
		return Record{}, ErrInvalid
	}
	if current.State == StateReady {
		return current, nil
	}
	if current.State != StateVerifiedRevoked {
		return Record{}, ErrConflict
	}
	hash := sha256.Sum256(append([]byte(request.InstanceID+"\x00"+request.PrincipalID+"\x00"+request.ErrorCode), request.Signature...))
	now := s.now().UTC().Truncate(time.Microsecond)
	return s.repository.UpdateIdempotent(ctx, request.DeliveryID, StateVerifiedRevoked, request.IdempotencyKey, hash, func(record *Record) error {
		record.State, record.ReadyAt, record.UpdatedAt = StateReady, now, now
		record.Revision++
		return nil
	})
}

func (s *Service) Revoke(ctx context.Context, deliveryID, idempotencyKey string) (Record, error) {
	current, err := s.repository.Get(ctx, deliveryID)
	if err != nil {
		return Record{}, err
	}
	if current.State == StateRevoked {
		return current, nil
	}
	if current.State != StateReady || !validUUID(idempotencyKey) {
		return Record{}, ErrNotReady
	}
	hash := sha256.Sum256([]byte(deliveryID + "\x00final-revoke"))
	if err := s.revoker.DenyRootHelperKey(ctx, current.Binding); err != nil {
		return Record{}, ErrUnavailable
	}
	denied, err := s.revoker.ReadBackRootHelperKeyDenied(ctx, current.Binding)
	if err != nil || !denied {
		return Record{}, ErrUnavailable
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	return s.repository.UpdateIdempotent(ctx, deliveryID, StateReady, idempotencyKey, hash, func(record *Record) error {
		record.State, record.ReadyAt, record.RevokedAt, record.UpdatedAt = StateRevoked, time.Time{}, now, now
		record.Revision++
		return nil
	})
}

func (s *Service) Fail(ctx context.Context, deliveryID, failureCode, idempotencyKey string) (Record, error) {
	current, err := s.repository.Get(ctx, deliveryID)
	if err != nil {
		return Record{}, err
	}
	if current.State == StateFailed {
		if current.FailureCode == failureCode {
			return current, nil
		}
		return Record{}, ErrConflict
	}
	if current.State == StateReady || current.State == StateRevoked || !identifierPattern.MatchString(failureCode) || !validUUID(idempotencyKey) {
		return Record{}, ErrInvalid
	}
	hash := sha256.Sum256([]byte(deliveryID + "\x00failed\x00" + failureCode))
	now := s.now().UTC().Truncate(time.Microsecond)
	return s.repository.UpdateIdempotent(ctx, deliveryID, current.State, idempotencyKey, hash, func(record *Record) error {
		record.State, record.FailureCode, record.ReadyAt, record.UpdatedAt = StateFailed, failureCode, time.Time{}, now
		record.Revision++
		return nil
	})
}

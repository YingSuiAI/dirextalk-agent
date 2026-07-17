package helperkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const ApprovalSchemaV1 = "dirextalk.agent.root-helper-key-approval/v1"

type ApprovalStatus string

const (
	ApprovalAwaiting ApprovalStatus = "awaiting_approval"
	ApprovalApproved ApprovalStatus = "approved"
)

type ApprovalChallenge struct {
	SchemaVersion      string
	ChallengeID        string
	DeviceSignerKeyID  string
	Binding            DeviceBinding
	PublicKey          []byte
	Nonce              []byte
	SigningPayloadCBOR []byte
	Status             ApprovalStatus
	Revision           int64
	DeviceSignature    []byte
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (value ApprovalChallenge) Clone() ApprovalChallenge {
	value.PublicKey = bytes.Clone(value.PublicKey)
	value.Nonce = bytes.Clone(value.Nonce)
	value.SigningPayloadCBOR = bytes.Clone(value.SigningPayloadCBOR)
	value.DeviceSignature = bytes.Clone(value.DeviceSignature)
	return value
}

func (value ApprovalChallenge) Validate() error {
	payload, err := value.Binding.SigningPayload()
	if err != nil || value.SchemaVersion != ApprovalSchemaV1 || !validUUID(value.ChallengeID) ||
		!identifierPattern.MatchString(value.DeviceSignerKeyID) ||
		ValidateApprovalBinding(value.Binding, value.PublicKey) != nil ||
		len(value.Nonce) != 32 || digest(value.Nonce) != value.Binding.NonceDigest ||
		!bytes.Equal(payload, value.SigningPayloadCBOR) || value.Revision < 1 ||
		value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return ErrInvalid
	}
	switch value.Status {
	case ApprovalAwaiting:
		if len(value.DeviceSignature) != 0 {
			return ErrInvalid
		}
	case ApprovalApproved:
		if len(value.DeviceSignature) != ed25519.SignatureSize {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type KeyDeriver interface {
	Derive(DeviceBinding) (ed25519.PublicKey, ed25519.PrivateKey, []byte, error)
}

// DeterministicKeyDeriver keeps replay material out of PostgreSQL. Its root is
// mounted secret material; derived private bytes exist only for the duration
// of an approved publish or signing operation.
type DeterministicKeyDeriver struct{ root []byte }

func NewDeterministicKeyDeriver(root []byte) (*DeterministicKeyDeriver, error) {
	if len(root) != sha256.Size {
		return nil, ErrInvalid
	}
	return &DeterministicKeyDeriver{root: bytes.Clone(root)}, nil
}

func (deriver *DeterministicKeyDeriver) Close() {
	if deriver != nil {
		clear(deriver.root)
		deriver.root = nil
	}
}

func (deriver *DeterministicKeyDeriver) Derive(binding DeviceBinding) (ed25519.PublicKey, ed25519.PrivateKey, []byte, error) {
	if deriver == nil || len(deriver.root) != sha256.Size || !validPreparedBase(binding) {
		return nil, nil, nil, ErrInvalid
	}
	contextValue := strings.Join([]string{
		binding.SchemaVersion, binding.AgentInstanceID, binding.OwnerID, binding.DeliveryID,
		binding.DeploymentID, binding.InstanceID, binding.HelperID, binding.SignerKeyID,
		strconv.FormatInt(binding.BindingRevision, 10),
	}, "\x00")
	seed := deriveBytes(deriver.root, "root-helper-private/v1", contextValue)
	nonce := deriveBytes(deriver.root, "root-helper-nonce/v1", contextValue)
	privateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	publicKey := bytes.Clone(privateKey[ed25519.SeedSize:])
	return publicKey, privateKey, nonce, nil
}

func deriveBytes(root []byte, domain, value string) []byte {
	mac := hmac.New(sha256.New, root)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func validPreparedBase(binding DeviceBinding) bool {
	return binding.SchemaVersion == SchemaV1 && validUUID(binding.AgentInstanceID) && validOwner(binding.OwnerID) &&
		validUUID(binding.DeliveryID) && validUUID(binding.DeploymentID) && binding.BindingRevision > 0 &&
		instancePattern.MatchString(binding.InstanceID) && binding.WorkerRoleARN != "" &&
		strings.HasSuffix(binding.WorkerPrincipalID, ":"+binding.InstanceID) &&
		identifierPattern.MatchString(binding.HelperID) && identifierPattern.MatchString(binding.SignerKeyID) &&
		binding.PublicKeyDigest == "" && binding.NonceDigest == "" && binding.Secret == (SecretCoordinate{}) &&
		validSecretPlan(binding.SecretPlan, binding)
}

type ApprovalMutation struct {
	IdempotencyKey   string
	ExpectedRevision int64
	RequestHash      [32]byte
}

type ApprovalRepository interface {
	CreateApprovalIdempotent(context.Context, ApprovalChallenge, ApprovalMutation) (ApprovalChallenge, error)
	GetApproval(context.Context, string) (ApprovalChallenge, error)
	ApproveIdempotent(context.Context, string, ApprovalMutation, func(*ApprovalChallenge) error) (ApprovalChallenge, error)
}

type ApprovalDeviceVerifier interface {
	VerifyRootHelperKeyApproval(context.Context, string, string, []byte, []byte) error
}

type ApprovalService struct {
	repository ApprovalRepository
	devices    ApprovalDeviceVerifier
	deriver    KeyDeriver
	now        func() time.Time
}

func NewApprovalService(repository ApprovalRepository, devices ApprovalDeviceVerifier, deriver KeyDeriver, now func() time.Time) (*ApprovalService, error) {
	if repository == nil || devices == nil || deriver == nil || now == nil {
		return nil, ErrInvalid
	}
	return &ApprovalService{repository: repository, devices: devices, deriver: deriver, now: now}, nil
}

type PrepareApprovalRequest struct {
	Binding           DeviceBinding
	DeviceSignerKeyID string
	IdempotencyKey    string
}

func (service *ApprovalService) Prepare(ctx context.Context, request PrepareApprovalRequest) (ApprovalChallenge, error) {
	if ctx == nil || !validUUID(request.IdempotencyKey) || !identifierPattern.MatchString(request.DeviceSignerKeyID) {
		return ApprovalChallenge{}, ErrInvalid
	}
	publicKey, privateKey, nonce, err := service.deriver.Derive(request.Binding)
	clear(privateKey)
	if err != nil {
		return ApprovalChallenge{}, err
	}
	request.Binding.PublicKeyDigest, request.Binding.NonceDigest = digest(publicKey), digest(nonce)
	payload, err := request.Binding.SigningPayload()
	if err != nil {
		return ApprovalChallenge{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	challenge := ApprovalChallenge{
		SchemaVersion:     ApprovalSchemaV1,
		ChallengeID:       uuid.NewSHA1(uuid.NameSpaceOID, []byte(request.Binding.DeliveryID+"\x00root-helper-key-approval/v1")).String(),
		DeviceSignerKeyID: request.DeviceSignerKeyID, Binding: request.Binding, PublicKey: publicKey, Nonce: nonce,
		SigningPayloadCBOR: payload, Status: ApprovalAwaiting, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	hash := sha256.Sum256(append([]byte(request.IdempotencyKey+"\x00"), payload...))
	return service.repository.CreateApprovalIdempotent(ctx, challenge, ApprovalMutation{request.IdempotencyKey, 0, hash})
}

type ApproveBindingRequest struct {
	DeliveryID       string
	IdempotencyKey   string
	ExpectedRevision int64
	DeviceSignature  []byte
}

func (service *ApprovalService) Approve(ctx context.Context, request ApproveBindingRequest) (ApprovalChallenge, error) {
	return service.ApproveWithVerifier(ctx, request, nil)
}

// ApproveWithVerifier runs the mutable authority check only inside the durable
// repository update callback. Exact idempotency replay is therefore returned
// before deployment/device freshness is consulted.
func (service *ApprovalService) ApproveWithVerifier(ctx context.Context, request ApproveBindingRequest,
	verify func(ApprovalChallenge) error) (ApprovalChallenge, error) {
	if ctx == nil || !validUUID(request.DeliveryID) || !validUUID(request.IdempotencyKey) ||
		request.ExpectedRevision < 1 || len(request.DeviceSignature) != ed25519.SignatureSize {
		return ApprovalChallenge{}, ErrInvalid
	}
	hash := sha256.Sum256(append([]byte(request.DeliveryID+"\x00"), request.DeviceSignature...))
	return service.repository.ApproveIdempotent(ctx, request.DeliveryID,
		ApprovalMutation{request.IdempotencyKey, request.ExpectedRevision, hash},
		func(challenge *ApprovalChallenge) error {
			if challenge.Status != ApprovalAwaiting || (verify != nil && verify(challenge.Clone()) != nil) ||
				service.devices.VerifyRootHelperKeyApproval(ctx, challenge.Binding.OwnerID, challenge.DeviceSignerKeyID,
					challenge.SigningPayloadCBOR, request.DeviceSignature) != nil {
				return ErrInvalid
			}
			challenge.Status = ApprovalApproved
			challenge.DeviceSignature = bytes.Clone(request.DeviceSignature)
			challenge.Revision++
			challenge.UpdatedAt = service.now().UTC().Truncate(time.Microsecond)
			return nil
		})
}

func (service *ApprovalService) GetApproved(ctx context.Context, deliveryID string) (ApprovalChallenge, error) {
	value, err := service.Get(ctx, deliveryID)
	if err != nil {
		return ApprovalChallenge{}, err
	}
	if value.Status != ApprovalApproved {
		return ApprovalChallenge{}, ErrNotReady
	}
	return value, nil
}

func (service *ApprovalService) Get(ctx context.Context, deliveryID string) (ApprovalChallenge, error) {
	if service == nil || ctx == nil || !validUUID(deliveryID) {
		return ApprovalChallenge{}, ErrInvalid
	}
	value, err := service.repository.GetApproval(ctx, deliveryID)
	if err != nil {
		return ApprovalChallenge{}, err
	}
	if value.Validate() != nil {
		return ApprovalChallenge{}, ErrInvalid
	}
	return value, nil
}

type approvalReplay struct {
	hash  [32]byte
	value ApprovalChallenge
}

type MemoryApprovalRepository struct {
	mu      sync.Mutex
	values  map[string]ApprovalChallenge
	replays map[string]approvalReplay
}

func NewMemoryApprovalRepository() *MemoryApprovalRepository {
	return &MemoryApprovalRepository{values: map[string]ApprovalChallenge{}, replays: map[string]approvalReplay{}}
}

func (repository *MemoryApprovalRepository) CreateApprovalIdempotent(_ context.Context, value ApprovalChallenge, mutation ApprovalMutation) (ApprovalChallenge, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := value.Binding.DeliveryID + "\x00prepare\x00" + mutation.IdempotencyKey
	if replay, ok := repository.replays[key]; ok {
		if subtle.ConstantTimeCompare(replay.hash[:], mutation.RequestHash[:]) != 1 {
			return ApprovalChallenge{}, ErrConflict
		}
		return replay.value.Clone(), nil
	}
	if _, exists := repository.values[value.Binding.DeliveryID]; exists || value.Validate() != nil {
		return ApprovalChallenge{}, ErrConflict
	}
	repository.values[value.Binding.DeliveryID] = value.Clone()
	repository.replays[key] = approvalReplay{mutation.RequestHash, value.Clone()}
	return value.Clone(), nil
}

func (repository *MemoryApprovalRepository) GetApproval(_ context.Context, deliveryID string) (ApprovalChallenge, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	value, ok := repository.values[deliveryID]
	if !ok {
		return ApprovalChallenge{}, ErrNotFound
	}
	return value.Clone(), nil
}

func (repository *MemoryApprovalRepository) ApproveIdempotent(_ context.Context, deliveryID string, mutation ApprovalMutation, update func(*ApprovalChallenge) error) (ApprovalChallenge, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := deliveryID + "\x00approve\x00" + mutation.IdempotencyKey
	if replay, ok := repository.replays[key]; ok {
		if subtle.ConstantTimeCompare(replay.hash[:], mutation.RequestHash[:]) != 1 {
			return ApprovalChallenge{}, ErrConflict
		}
		return replay.value.Clone(), nil
	}
	current, ok := repository.values[deliveryID]
	if !ok {
		return ApprovalChallenge{}, ErrNotFound
	}
	if current.Revision != mutation.ExpectedRevision {
		return ApprovalChallenge{}, ErrConflict
	}
	next := current.Clone()
	if update == nil || update(&next) != nil || next.Validate() != nil {
		return ApprovalChallenge{}, ErrInvalid
	}
	repository.values[deliveryID] = next.Clone()
	repository.replays[key] = approvalReplay{mutation.RequestHash, next.Clone()}
	return next.Clone(), nil
}

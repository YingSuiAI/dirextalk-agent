package modelrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/google/uuid"
)

const relayTokenPrefix = "cwmg1_"

type Service struct {
	store       Store
	profiles    ProfileBindingReader
	credentials ExactCredentialResolver
	backend     ProviderBackend
	now         func() time.Time
	random      func([]byte) error
}

func NewService(
	store Store,
	profiles ProfileBindingReader,
	credentials ExactCredentialResolver,
	backend ProviderBackend,
) (*Service, error) {
	if store == nil || profiles == nil || credentials == nil || backend == nil {
		return nil, ErrInvalid
	}
	return &Service{
		store: store, profiles: profiles, credentials: credentials, backend: backend,
		now: func() time.Time { return time.Now().UTC() },
		random: func(value []byte) error {
			_, err := rand.Read(value)
			return err
		},
	}, nil
}

// Activate creates a fresh bearer for one verified WorkerControl session.
// A lost response is recovered by activating another grant; Store atomically
// fences the previous active grant for the execution.
func (s *Service) Activate(ctx context.Context, activation Activation) (IssuedGrant, error) {
	if s == nil || ctx == nil {
		return IssuedGrant{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Second)
	if activation.validate(now) != nil {
		return IssuedGrant{}, ErrInvalid
	}
	activation.ExpiresAt = activation.ExpiresAt.UTC().Truncate(time.Second)
	binding, credential, err := s.resolveExact(ctx, activation.Profile)
	credential.Destroy()
	if err != nil || !binding.Matches(activation.Profile) {
		return IssuedGrant{}, ErrProfileDrift
	}
	randomValue := make([]byte, 48)
	if err := s.random(randomValue); err != nil {
		clear(randomValue)
		return IssuedGrant{}, ErrConflict
	}
	tokenText := relayTokenPrefix + base64.RawURLEncoding.EncodeToString(randomValue)
	clear(randomValue)
	token := []byte(tokenText)
	tokenText = ""
	grant := Grant{
		GrantID: uuid.NewString(), Fence: activation.Fence, Profile: activation.Profile,
		AudienceDigest: activation.AudienceDigest, LimitDigest: activation.LimitDigest,
		RelayURL: activation.RelayURL, RelayBindingDigest: activation.RelayBindingDigest,
		MaxTokens: activation.MaxTokens, State: GrantActive,
		ExpiresAt: activation.ExpiresAt, ActivatedAt: now, UpdatedAt: now, Revision: 1,
	}
	if grant.Validate() != nil {
		clear(token)
		return IssuedGrant{}, ErrInvalid
	}
	stored, err := s.store.Activate(ctx, ActivationMutation{
		Grant: grant, TokenDigest: digestBytes(token),
	})
	if err != nil {
		clear(token)
		return IssuedGrant{}, err
	}
	if stored.Validate() != nil || !sameGrantAuthorization(stored, grant) || stored.State != GrantActive {
		clear(token)
		return IssuedGrant{}, ErrConflict
	}
	return IssuedGrant{Grant: stored, BearerToken: token}, nil
}

func (s *Service) FenceExecution(ctx context.Context, fence Fence, reasonCode string, terminal bool) error {
	if s == nil || ctx == nil || fence.Validate() != nil || !validReason(reasonCode) || reasonCode == "" {
		return ErrInvalid
	}
	return s.store.FenceExecution(ctx, FenceMutation{
		Fence: fence, ReasonCode: reasonCode, Terminal: terminal,
		At: s.now().UTC(),
	})
}

func (s *Service) resolveExact(
	ctx context.Context,
	reference ProfileReference,
) (ProfileBinding, ResolvedCredential, error) {
	if s == nil || ctx == nil || reference.Validate() != nil {
		return ProfileBinding{}, ResolvedCredential{}, ErrInvalid
	}
	binding, err := s.profiles.ResolveExactProfileBinding(ctx, reference)
	if err != nil || !binding.Matches(reference) {
		return ProfileBinding{}, ResolvedCredential{}, ErrProfileDrift
	}
	credential, err := s.credentials.ResolveExactCredential(ctx, binding)
	if err != nil {
		credential.Destroy()
		return ProfileBinding{}, ResolvedCredential{}, ErrCredentialUnavailable
	}
	if credential.ValidateFor(reference) != nil {
		credential.Destroy()
		return ProfileBinding{}, ResolvedCredential{}, ErrCredentialUnavailable
	}
	return binding, credential, nil
}

func (issued IssuedGrant) RuntimeModelGrant() (cloudruntime.ModelGrant, error) {
	if issued.Grant.Validate() != nil || issued.Grant.State != GrantActive ||
		len(issued.BearerToken) < len(relayTokenPrefix)+32 ||
		!bytes.HasPrefix(issued.BearerToken, []byte(relayTokenPrefix)) {
		return cloudruntime.ModelGrant{}, ErrInvalid
	}
	return cloudruntime.ModelGrant{
		GrantID: issued.Grant.GrantID, BearerToken: bytes.Clone(issued.BearerToken),
		ModelBindingSHA256: issued.Grant.Profile.ModelBindingDigest,
		AudienceSHA256:     issued.Grant.AudienceDigest,
		ExpiresAtUnix:      issued.Grant.ExpiresAt.Unix(),
		LimitSHA256:        issued.Grant.LimitDigest,
		RelayBaseURL:       issued.Grant.RelayURL,
		RelayBindingSHA256: issued.Grant.RelayBindingDigest,
		MaxOutputTokens:    issued.Grant.MaxTokens,
	}, nil
}

func sameGrantAuthorization(left, right Grant) bool {
	return left.GrantID == right.GrantID && left.Fence == right.Fence &&
		left.Profile == right.Profile && left.AudienceDigest == right.AudienceDigest &&
		left.LimitDigest == right.LimitDigest && left.RelayURL == right.RelayURL &&
		left.RelayBindingDigest == right.RelayBindingDigest && left.MaxTokens == right.MaxTokens &&
		left.ExpiresAt.Equal(right.ExpiresAt) && left.ActivatedAt.Equal(right.ActivatedAt)
}

func durableMutationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), 5*time.Second)
	}
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

func isRelayAuthorizationError(err error) bool {
	return errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrExpired) ||
		errors.Is(err, ErrFenced) || errors.Is(err, ErrTerminal) ||
		errors.Is(err, ErrStaleFence)
}

// Package secretresolver binds an encrypted bootstrap session to one approved
// deployment-secret slot without ever returning plaintext to cloudexecution.
package secretresolver

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
)

const referencePrefix = "secret_ref:bootstrap/"

var ErrUnavailable = errors.New("deployment secret is unavailable")

type manager interface {
	Get(context.Context, string, string) (secretbootstrap.SessionV1, error)
	Inspect(context.Context, string, string, uint64, secretbootstrap.SecretConsumer) (secretbootstrap.SessionV1, error)
	Consume(context.Context, string, string, uint64, secretbootstrap.SecretConsumer) (secretbootstrap.SessionV1, error)
}

type Resolver struct{ manager manager }

func New(manager manager) (*Resolver, error) {
	if manager == nil {
		return nil, ErrUnavailable
	}
	return &Resolver{manager: manager}, nil
}

func (resolver *Resolver) Resolve(ctx context.Context, request cloudexecution.InstallerSecretResolveRequest) (cloudexecution.InstallerSecretContent, error) {
	if resolver == nil || resolver.manager == nil || ctx == nil || strings.TrimSpace(request.CallerClientID) == "" ||
		strings.TrimSpace(request.OwnerID) == "" || strings.TrimSpace(request.Purpose) == "" {
		return nil, ErrUnavailable
	}
	sessionID := strings.TrimPrefix(request.SecretRef, referencePrefix)
	if request.SecretRef == sessionID {
		return nil, ErrUnavailable
	}
	parsed, err := uuid.Parse(sessionID)
	if err != nil || parsed == uuid.Nil || parsed.String() != sessionID {
		return nil, ErrUnavailable
	}
	session, err := resolver.manager.Get(ctx, request.CallerClientID, sessionID)
	if err != nil || session.SessionID != sessionID || session.OwnerID != request.OwnerID || session.Purpose != request.Purpose ||
		session.TargetID != request.RecipeDigest || (session.Status != secretbootstrap.StatusUploaded && session.Status != secretbootstrap.StatusConsumed) {
		return nil, ErrUnavailable
	}
	return &content{manager: resolver.manager, callerClientID: request.CallerClientID, sessionID: sessionID}, nil
}

type content struct {
	manager        manager
	callerClientID string
	sessionID      string
}

func (value *content) Materialize(ctx context.Context, write func([]byte) error) error {
	if value == nil || value.manager == nil || ctx == nil || write == nil {
		return ErrUnavailable
	}
	session, err := value.manager.Get(ctx, value.callerClientID, value.sessionID)
	if err != nil {
		return ErrUnavailable
	}
	if session.Status == secretbootstrap.StatusConsumed {
		// A previous attempt completed the irreversible write. The publisher
		// must reconcile it by read-back in Commit and never needs plaintext.
		return nil
	}
	if session.Status != secretbootstrap.StatusUploaded {
		return ErrUnavailable
	}
	if _, err := value.manager.Inspect(ctx, value.callerClientID, value.sessionID, session.Revision, write); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (value *content) Commit(ctx context.Context, verify func() error) error {
	if value == nil || value.manager == nil || ctx == nil || verify == nil {
		return ErrUnavailable
	}
	session, err := value.manager.Get(ctx, value.callerClientID, value.sessionID)
	if err != nil {
		return ErrUnavailable
	}
	if session.Status == secretbootstrap.StatusConsumed {
		if verify() != nil {
			return ErrUnavailable
		}
		return nil
	}
	if session.Status != secretbootstrap.StatusUploaded {
		return ErrUnavailable
	}
	if _, err := value.manager.Consume(ctx, value.callerClientID, value.sessionID, session.Revision, func(_ []byte) error {
		return verify()
	}); err != nil {
		return ErrUnavailable
	}
	return nil
}

var _ cloudexecution.InstallerSecretResolver = (*Resolver)(nil)

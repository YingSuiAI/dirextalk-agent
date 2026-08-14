package coreaws

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	repo                          Repository
	sts                           STSProvider
	now                           func() time.Time
	credentialTestFinalizeTimeout time.Duration
	credentialDeleteGuard         CredentialDeleteGuard
}

type CredentialDeleteGuard interface {
	DeleteCredentialIfUnused(context.Context, string, func() error) (bool, error)
}

func (service *Service) SetCredentialDeleteGuard(guard CredentialDeleteGuard) {
	if service != nil {
		service.credentialDeleteGuard = guard
	}
}

func NewService(repo Repository, sts STSProvider, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{repo: repo, sts: sts, now: now, credentialTestFinalizeTimeout: credentialTestFinalizeTimeout}
}

func newUUID() string { return uuid.NewString() }

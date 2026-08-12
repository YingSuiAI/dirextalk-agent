package corestaticsite

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalid    = errors.New("invalid static-site request")
	ErrNotFound   = errors.New("static-site release not found")
	ErrConflict   = errors.New("static-site state conflict")
	ErrRepository = errors.New("static-site repository unavailable")
)

const MaxHTMLBytes = 192 << 10

type Authority struct {
	OwnerID           string
	AccountGeneration int64
}

func (a Authority) Validate() error {
	if strings.TrimSpace(a.OwnerID) == "" || a.AccountGeneration <= 0 {
		return ErrInvalid
	}
	return nil
}

type Release struct {
	SiteID         string    `json:"site_id"`
	ReleaseID      string    `json:"release_id"`
	ConversationID string    `json:"conversation_id"`
	PublicURL      string    `json:"public_url"`
	PublicPath     string    `json:"public_path"`
	SizeBytes      int64     `json:"size_bytes"`
	CreatedAt      time.Time `json:"created_at"`
}

func (r Release) Validate() error {
	if uuid.Validate(r.SiteID) != nil || uuid.Validate(r.ReleaseID) != nil || uuid.Validate(r.ConversationID) != nil ||
		r.PublicPath != "/.sites/"+r.SiteID+"/"+r.ReleaseID+"/" || r.SizeBytes < 1 || r.SizeBytes > MaxHTMLBytes || r.CreatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type ListQuery struct {
	PageSize  int
	PageToken string
}

type Page struct {
	Releases      []Release
	NextPageToken string
}

type Repository interface {
	ListReleases(context.Context, Authority, ListQuery, string) (Page, error)
	DeleteRelease(context.Context, Authority, DeleteCommand, string, func(Release, func() error) error) (DeleteResult, error)
}

type FileStore interface {
	DeleteRelease(context.Context, Release, func() error) error
}

type Service struct {
	repository   Repository
	files        FileStore
	publicOrigin string
}

func NewService(repository Repository, files FileStore, publicOrigin string) (*Service, error) {
	origin := strings.TrimRight(strings.TrimSpace(publicOrigin), "/")
	if repository == nil || files == nil || origin == "" {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, files: files, publicOrigin: origin}, nil
}

func (s *Service) List(ctx context.Context, authority Authority, query ListQuery) (Page, error) {
	if s == nil || authority.Validate() != nil || query.PageSize < 0 || query.PageSize > 100 || len(query.PageToken) > 4096 {
		return Page{}, ErrInvalid
	}
	if query.PageSize == 0 {
		query.PageSize = 50
	}
	return s.repository.ListReleases(ctx, authority, query, s.publicOrigin)
}

type DeleteResult struct {
	ReleaseID string `json:"release_id"`
	Deleted   bool   `json:"deleted"`
	Replayed  bool   `json:"replayed"`
}

type DeleteCommand struct {
	ReleaseID      string
	IdempotencyKey string
	Fingerprint    string
}

func NewDeleteCommand(authority Authority, releaseID, idempotencyKey string) (DeleteCommand, error) {
	if authority.Validate() != nil || uuid.Validate(releaseID) != nil || uuid.Validate(idempotencyKey) != nil {
		return DeleteCommand{}, ErrInvalid
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(authority.OwnerID+":"+fmt.Sprint(authority.AccountGeneration)+":"+releaseID)))
	return DeleteCommand{ReleaseID: releaseID, IdempotencyKey: idempotencyKey, Fingerprint: fingerprint}, nil
}

func (s *Service) Delete(ctx context.Context, authority Authority, releaseID, idempotencyKey string) (DeleteResult, error) {
	if s == nil {
		return DeleteResult{}, ErrInvalid
	}
	command, err := NewDeleteCommand(authority, releaseID, idempotencyKey)
	if err != nil {
		return DeleteResult{}, err
	}
	return s.repository.DeleteRelease(ctx, authority, command, s.publicOrigin, func(release Release, commit func() error) error {
		return s.files.DeleteRelease(ctx, release, commit)
	})
}

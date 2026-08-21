package coreserver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

type Config struct {
	PrimaryName   string
	PrimaryOrigin string
	PrimaryRegion string
}

type Service struct {
	repository Repository
	workers    WorkerInventory
	deleter    ArtifactDeleter
	config     Config
}

func NewService(repository Repository, workers WorkerInventory, deleter ArtifactDeleter, config Config) (*Service, error) {
	if repository == nil || strings.TrimSpace(config.PrimaryName) == "" {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, workers: workers, deleter: deleter, config: config}, nil
}

func (s *Service) ListServers(ctx context.Context, authority Authority) ([]Server, error) {
	if s == nil || !authority.Valid() {
		return nil, ErrInvalid
	}
	instance, err := s.repository.Instance(ctx)
	if err != nil {
		return nil, err
	}
	if err = s.repository.EnsurePrimaryArtifact(ctx, authority, instance, s.config.PrimaryOrigin); err != nil {
		return nil, err
	}
	counts, err := s.repository.CountByServer(ctx, authority)
	if err != nil {
		return nil, err
	}
	primaryArtifactCount := counts[instance.ID]
	if primaryArtifactCount > 0 {
		// The primary catalog always contains one immutable backend-service row.
		// It identifies the Agent node but is not a user-created deliverable.
		primaryArtifactCount--
	}
	primary := Server{ServerID: instance.ID, ServerKind: ServerPrimary, Name: s.config.PrimaryName, Status: "healthy", Address: s.config.PrimaryOrigin, Region: s.config.PrimaryRegion, ArtifactCount: primaryArtifactCount, CanDestroy: false, CreatedAt: instance.CreatedAt.UTC()}
	result := []Server{primary}
	if s.workers != nil {
		workers, listErr := s.workers.List(ctx, authority)
		if listErr != nil {
			return nil, listErr
		}
		for index := range workers {
			workers[index].ArtifactCount = counts[workers[index].ServerID]
			workers[index].ServerKind = ServerWorker
			workers[index].CanDestroy = true
		}
		sort.Slice(workers, func(i, j int) bool {
			if workers[i].CreatedAt.Equal(workers[j].CreatedAt) {
				return workers[i].ServerID < workers[j].ServerID
			}
			return workers[i].CreatedAt.Before(workers[j].CreatedAt)
		})
		result = append(result, workers...)
	}
	return result, nil
}

func (s *Service) GetServer(ctx context.Context, authority Authority, serverID string) (Server, error) {
	servers, err := s.ListServers(ctx, authority)
	if err != nil {
		return Server{}, err
	}
	for _, server := range servers {
		if server.ServerID == serverID {
			return server, nil
		}
	}
	return Server{}, ErrNotFound
}

func (s *Service) ListArtifacts(ctx context.Context, authority Authority, serverID string, pageSize int, pageToken string) (Page, error) {
	if s == nil || !authority.Valid() || uuidInvalid(serverID) || pageSize < 1 || pageSize > 100 {
		return Page{}, ErrInvalid
	}
	server, err := s.GetServer(ctx, authority, serverID)
	if err != nil {
		return Page{}, err
	}
	page, err := s.repository.ListArtifacts(ctx, authority, serverID, pageSize, pageToken)
	if err != nil {
		return Page{}, err
	}
	for index := range page.Artifacts {
		page.Artifacts[index].AccountGeneration = authority.AccountGeneration
		if page.Artifacts[index].ArtifactKind == ArtifactStaticPage && strings.HasPrefix(page.Artifacts[index].PublicURL, "/") {
			page.Artifacts[index].PublicURL = strings.TrimRight(s.config.PrimaryOrigin, "/") + page.Artifacts[index].PublicURL
		}
		if page.Artifacts[index].ArtifactKind == ArtifactDeployedService && page.Artifacts[index].PublicIPv4 == "" {
			page.Artifacts[index].PublicIPv4 = server.Address
			if page.Artifacts[index].PublicURL == "" && server.Address != "" && page.Artifacts[index].Port > 0 {
				page.Artifacts[index].PublicURL = "http://" + server.Address + ":" + fmt.Sprint(page.Artifacts[index].Port)
			}
		}
	}
	return page, nil
}

func (s *Service) DeleteArtifact(ctx context.Context, authority Authority, artifactID, idempotencyKey string) error {
	if s == nil || !authority.Valid() || uuidInvalid(artifactID) || uuidInvalid(idempotencyKey) || s.deleter == nil {
		return ErrInvalid
	}
	artifact, err := s.repository.GetArtifact(ctx, authority, artifactID)
	if err != nil {
		return err
	}
	if artifact.ArtifactKind != ArtifactStaticPage && artifact.ArtifactKind != ArtifactExecutionFile {
		return ErrConflict
	}
	if err = s.deleter.DeleteArtifact(ctx, authority, artifact, idempotencyKey); err != nil {
		return err
	}
	return s.repository.DeleteBySource(ctx, authority, artifact.SourceKind, artifact.SourceID)
}

func (s *Service) DestroyServer(ctx context.Context, authority Authority, serverID, operationID string) error {
	if s == nil || !authority.Valid() || uuidInvalid(serverID) || uuidInvalid(operationID) || s.workers == nil {
		return ErrInvalid
	}
	instance, err := s.repository.Instance(ctx)
	if err != nil {
		return err
	}
	if serverID == instance.ID {
		return ErrPrimary
	}
	server, err := s.workers.Get(ctx, authority, serverID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			artifacts, listErr := s.repository.ListServerArtifactsForCleanup(ctx, authority, serverID)
			if listErr != nil {
				return listErr
			}
			if len(artifacts) == 0 {
				return ErrNotFound
			}
			if err = s.repository.MarkServerDeleting(ctx, authority, serverID); err != nil {
				return err
			}
			if err = s.deleteExecutionArtifacts(ctx, authority, artifacts, operationID); err != nil {
				return err
			}
			return s.repository.DeleteServer(ctx, authority, serverID)
		}
		return err
	}
	if server.Busy && server.Status != "destroying" {
		return ErrBusy
	}
	if err = s.repository.MarkServerDeleting(ctx, authority, serverID); err != nil {
		return err
	}
	artifacts, err := s.repository.ListServerArtifactsForCleanup(ctx, authority, serverID)
	if err != nil {
		return err
	}
	if err = s.deleteExecutionArtifacts(ctx, authority, artifacts, operationID); err != nil {
		return err
	}
	if err = s.workers.Destroy(ctx, authority, serverID, operationID); err != nil {
		return err
	}
	if _, err = s.workers.Get(ctx, authority, serverID); err == nil {
		return ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return s.repository.DeleteServer(ctx, authority, serverID)
}

func (s *Service) deleteExecutionArtifacts(ctx context.Context, authority Authority, artifacts []Artifact, operationID string) error {
	for _, artifact := range artifacts {
		if artifact.ArtifactKind != ArtifactExecutionFile {
			continue
		}
		if s.deleter == nil {
			return ErrConflict
		}
		deleteKey := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:destroy-server-artifact:"+operationID+":"+artifact.ArtifactID)).String()
		if err := s.deleter.DeleteArtifact(ctx, authority, artifact, deleteKey); err != nil {
			return err
		}
	}
	return nil
}

func uuidInvalid(value string) bool {
	return uuid.Validate(value) != nil
}

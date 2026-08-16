// Package sshworkload persists service and optional domain state owned by one
// exact SSH Worker identity. Live runtime status is observed separately over
// SSH; this repository stores only the durable management facts.
package sshworkload

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
)

var (
	ErrInvalid  = errors.New("invalid SSH workload")
	ErrIdentity = errors.New("SSH workload identity mismatch")
	ErrNotFound = errors.New("SSH workload not found")
)

type Service struct {
	Worker        sshworker.WorkerIdentity `json:"worker"`
	TaskID        string                   `json:"task_id"`
	WorkloadID    string                   `json:"workload_id"`
	Port          uint16                   `json:"port"`
	HealthPath    string                   `json:"health_path"`
	Hostname      string                   `json:"hostname,omitempty"`
	Domain        *Domain                  `json:"domain,omitempty"`
	PendingDomain *Domain                  `json:"pending_domain,omitempty"`
}

type Domain struct {
	ZoneID    string `json:"zone_id"`
	Hostname  string `json:"hostname"`
	TTL       uint32 `json:"ttl"`
	BoundIPv4 string `json:"bound_ipv4"`
}

type Repository struct {
	root string
	mu   sync.Mutex
}

func NewRepository(root string) (*Repository, error) {
	if !filepath.IsAbs(root) {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Repository{root: root}, nil
}

func (repository *Repository) PutService(_ context.Context, service Service) error {
	if repository == nil || validateService(service) != nil {
		return ErrInvalid
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	services, err := repository.readLocked(service.Worker)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	for index := range services {
		if services[index].WorkloadID == service.WorkloadID {
			if services[index].Port != service.Port || services[index].HealthPath != service.HealthPath {
				return ErrIdentity
			}
			if services[index].Hostname != "" && services[index].Hostname != service.Hostname {
				return ErrIdentity
			}
			if service.Hostname == "" {
				service.Hostname = services[index].Hostname
			}
			service.Domain = services[index].Domain
			service.PendingDomain = services[index].PendingDomain
			services[index] = service
			return repository.writeLocked(service.Worker, services)
		}
	}
	services = append(services, service)
	return repository.writeLocked(service.Worker, services)
}

func (repository *Repository) List(_ context.Context, identity sshworker.WorkerIdentity) ([]Service, error) {
	if repository == nil || validateWorker(identity) != nil {
		return nil, ErrInvalid
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	services, err := repository.readLocked(identity)
	if errors.Is(err, ErrNotFound) {
		return []Service{}, nil
	}
	return services, err
}

func (repository *Repository) Get(ctx context.Context, identity sshworker.WorkerIdentity, workloadID string) (Service, error) {
	services, err := repository.List(ctx, identity)
	if err != nil {
		return Service{}, err
	}
	for _, service := range services {
		if service.WorkloadID == workloadID {
			return service, nil
		}
	}
	return Service{}, ErrNotFound
}

func (repository *Repository) SetDomain(_ context.Context, identity sshworker.WorkerIdentity, workloadID string, domain *Domain) error {
	if repository == nil || validateWorker(identity) != nil || !validID(workloadID) || (domain != nil && validateDomain(*domain) != nil) {
		return ErrInvalid
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	services, err := repository.readLocked(identity)
	if err != nil {
		return err
	}
	for index := range services {
		if services[index].WorkloadID == workloadID {
			next := services[index]
			next.Domain = domain
			next.PendingDomain = nil
			if validateService(next) != nil {
				return ErrIdentity
			}
			services[index] = next
			return repository.writeLocked(identity, services)
		}
	}
	return ErrNotFound
}

func (repository *Repository) StageDomain(_ context.Context, identity sshworker.WorkerIdentity, workloadID string, domain *Domain) error {
	if repository == nil || validateWorker(identity) != nil || !validID(workloadID) || domain == nil || validateDomain(*domain) != nil {
		return ErrInvalid
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	services, err := repository.readLocked(identity)
	if err != nil {
		return err
	}
	for index := range services {
		if services[index].WorkloadID != workloadID {
			continue
		}
		next := services[index]
		if next.PendingDomain != nil && *next.PendingDomain != *domain {
			return ErrIdentity
		}
		next.PendingDomain = domain
		if validateService(next) != nil {
			return ErrIdentity
		}
		services[index] = next
		return repository.writeLocked(identity, services)
	}
	return ErrNotFound
}

func (repository *Repository) CommitDomain(_ context.Context, identity sshworker.WorkerIdentity, workloadID string) error {
	if repository == nil || validateWorker(identity) != nil || !validID(workloadID) {
		return ErrInvalid
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	services, err := repository.readLocked(identity)
	if err != nil {
		return err
	}
	for index := range services {
		if services[index].WorkloadID != workloadID {
			continue
		}
		if services[index].PendingDomain == nil {
			return ErrIdentity
		}
		services[index].Domain = services[index].PendingDomain
		services[index].PendingDomain = nil
		return repository.writeLocked(identity, services)
	}
	return ErrNotFound
}

func (repository *Repository) RemoveWorker(_ context.Context, identity sshworker.WorkerIdentity) error {
	if repository == nil || validateWorker(identity) != nil {
		return ErrInvalid
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	services, err := repository.readLocked(identity)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(services) > 0 && services[0].Worker != identity {
		return ErrIdentity
	}
	return os.Remove(repository.path(identity.WorkerID))
}

func (repository *Repository) readLocked(identity sshworker.WorkerIdentity) ([]Service, error) {
	body, err := os.ReadFile(repository.path(identity.WorkerID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var services []Service
	if json.Unmarshal(body, &services) != nil {
		return nil, ErrIdentity
	}
	for _, service := range services {
		if service.Worker != identity || validateService(service) != nil {
			return nil, ErrIdentity
		}
	}
	sort.Slice(services, func(i, j int) bool { return services[i].WorkloadID < services[j].WorkloadID })
	return services, nil
}

func (repository *Repository) writeLocked(identity sshworker.WorkerIdentity, services []Service) error {
	body, err := json.Marshal(services)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(repository.root, ".workloads-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(body)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, repository.path(identity.WorkerID))
}

func (repository *Repository) path(workerID string) string {
	return filepath.Join(repository.root, "worker-"+workerID+".json")
}

func validateService(service Service) error {
	if validateWorker(service.Worker) != nil || !validID(service.TaskID) || !validID(service.WorkloadID) || service.Port == 0 ||
		!validHealthPath(service.HealthPath) || (service.Hostname != "" && !remoteservice.ValidHostname(service.Hostname)) ||
		!validServiceDomain(service.Hostname, service.Domain) || !validServiceDomain(service.Hostname, service.PendingDomain) {
		return ErrInvalid
	}
	return nil
}

func validServiceDomain(hostname string, domain *Domain) bool {
	return domain == nil || (validateDomain(*domain) == nil &&
		(hostname == "" || remoteservice.CanonicalHostname(domain.Hostname) == remoteservice.CanonicalHostname(hostname)))
}

func validateWorker(identity sshworker.WorkerIdentity) error {
	if !validID(identity.WorkerID) || strings.TrimSpace(identity.InstanceID) == "" || strings.TrimSpace(identity.KeyPairID) == "" ||
		strings.TrimSpace(identity.SecurityGroupID) == "" || strings.TrimSpace(identity.Credential.CredentialID) == "" ||
		identity.Credential.CredentialRevision == 0 || len(identity.Credential.AccountID) != 12 || strings.TrimSpace(identity.Credential.Region) == "" {
		return ErrInvalid
	}
	return nil
}

func validateDomain(domain Domain) error {
	if strings.TrimSpace(domain.ZoneID) == "" || strings.TrimSpace(domain.Hostname) == "" || strings.TrimSpace(domain.BoundIPv4) == "" ||
		domain.TTL < 60 || domain.TTL > 86400 {
		return ErrInvalid
	}
	return nil
}

func validID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, current := range value {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') && current != '-' {
			return false
		}
	}
	return true
}

func validHealthPath(value string) bool {
	return len(value) <= 2048 && strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && !strings.ContainsAny(value, " \t\r\n#")
}

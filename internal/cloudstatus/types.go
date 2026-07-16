package cloudstatus

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
)

var (
	ErrInvalid  = errors.New("invalid cloud status query")
	ErrNotFound = errors.New("cloud status entity not found")
)

type ListQuery struct {
	OwnerID      string
	DeploymentID string
	PageSize     int
	PageToken    string
}

func (query ListQuery) Validate() error {
	if err := ValidateOwnerID(query.OwnerID); err != nil {
		return err
	}
	if query.PageSize < 0 || query.PageSize > 100 || len(query.PageToken) > 2048 {
		return ErrInvalid
	}
	return nil
}

func ValidateOwnerID(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 255 || security.ContainsLikelySecret(value) {
		return ErrInvalid
	}
	return nil
}

type WorkerPage struct {
	Workers       []worker.Deployment
	NextPageToken string
}

type ResourcePage struct {
	Resources     []resource.ResourceV1
	NextPageToken string
}

type Reader interface {
	GetWorker(context.Context, string, string) (worker.Deployment, error)
	ListWorkers(context.Context, ListQuery) (WorkerPage, error)
	GetResource(context.Context, string, string) (resource.ResourceV1, error)
	ListResources(context.Context, ListQuery) (ResourcePage, error)
	ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error)
}

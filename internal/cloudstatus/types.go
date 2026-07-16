package cloudstatus

import (
	"context"
	"errors"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
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

// Connection is the persisted AWS control-plane read model. Status, revision,
// credential generation, and timestamps are read from cloud_connections; none
// of them are inferred from an in-memory coordinator or provider response.
type Connection struct {
	ConnectionID         string
	OwnerID              string
	AccountID            string
	Region               string
	ControlRoleARN       string
	FoundationStackID    string
	CredentialGeneration int64
	Status               string
	Revision             int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type ConnectionPage struct {
	Connections   []Connection
	NextPageToken string
}

type PlanPage struct {
	Plans         []cloudapproval.PlanV1
	NextPageToken string
}

// Deployment is the durable cloud-control relationship for one exclusive
// Worker. PlanID and ConnectionID come from the immutable launch intent; they
// are deliberately not inferred from Worker or resource state.
type Deployment struct {
	Worker       worker.Deployment
	PlanID       string
	ConnectionID string
}

type DeploymentPage struct {
	Deployments   []Deployment
	NextPageToken string
}

type ResourcePage struct {
	Resources     []resource.ResourceV1
	NextPageToken string
}

type Reader interface {
	ListPlans(context.Context, ListQuery) (PlanPage, error)
	GetConnection(context.Context, string, string) (Connection, error)
	ListConnections(context.Context, ListQuery) (ConnectionPage, error)
	GetDeployment(context.Context, string, string) (Deployment, error)
	ListDeployments(context.Context, ListQuery) (DeploymentPage, error)
	GetWorker(context.Context, string, string) (worker.Deployment, error)
	ListWorkers(context.Context, ListQuery) (WorkerPage, error)
	GetResource(context.Context, string, string) (resource.ResourceV1, error)
	ListResources(context.Context, ListQuery) (ResourcePage, error)
	ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error)
}

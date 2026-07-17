// Package awsprovider defines the closed, typed AWS control boundary. No
// interface in this package exposes an AWS client, arbitrary operation name,
// raw request payload, or user-provided IAM policy to an Agent/Skill.
package awsprovider

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidRequest                      = errors.New("invalid typed AWS request")
	ErrPermissionDenied                    = errors.New("AWS permission denied")
	ErrProviderUnavailable                 = errors.New("AWS provider unavailable")
	ErrReadBackMismatch                    = errors.New("AWS read-back did not match the persisted intent")
	ErrSourceCredentialRemediationRequired = errors.New("AWS source credential requires fresh-admin remediation")
	ErrFoundationStackFailed               = errors.New("AWS foundation stack reached a failed terminal state")
)

const FoundationStackReadyStatus = "CREATE_COMPLETE"
const FoundationStackUpdatedStatus = "UPDATE_COMPLETE"
const FoundationStackDeletedStatus = "DELETE_COMPLETE"

type CallerIdentity struct {
	Partition string
	AccountID string
	ARN       string
	UserID    string
	Region    string
}

type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

type PolicyStatement struct {
	SID       string                       `json:"Sid,omitempty"`
	Effect    string                       `json:"Effect"`
	Action    []string                     `json:"Action"`
	Resource  []string                     `json:"Resource,omitempty"`
	Principal map[string][]string          `json:"Principal,omitempty"`
	Condition map[string]map[string]string `json:"Condition,omitempty"`
}

type BootstrapIdentitySpec struct {
	AgentInstanceID string
	AccountID       string
	Partition       string
	Region          string

	SourceUserName     string
	ControlRoleName    string
	FoundationRoleName string
	WorkerRoleName     string
	WorkerProfileName  string
	ReaperRoleName     string
	StackName          string
	ArtifactBucketName string
	ManifestTableName  string
	WorkerLogGroupName string
	ReaperLogGroupName string
	ReaperFunctionName string
	ReaperScheduleName string
	ReaperAlarmName    string
	SecretNamespace    string

	SourceUserPolicy          PolicyDocument
	ControlTrustPolicy        PolicyDocument
	ControlBaselinePolicy     PolicyDocument
	FoundationTrustPolicy     PolicyDocument
	FoundationExecutionPolicy PolicyDocument
	Tags                      []Tag
}

type SourceCredentials struct {
	AccessKeyID     []byte
	SecretAccessKey []byte
}

func (credentials *SourceCredentials) Wipe() {
	if credentials == nil {
		return
	}
	zero(credentials.AccessKeyID)
	zero(credentials.SecretAccessKey)
	credentials.AccessKeyID = nil
	credentials.SecretAccessKey = nil
}

type FoundationStackRequest struct {
	StackName          string
	Region             string
	AccountID          string
	FoundationRoleARN  string
	ClientToken        string
	TemplateBody       string
	TemplateSHA256     string
	Parameters         map[string]string
	Tags               []Tag
	TerminationProtect bool
}

type FoundationStackReceipt struct {
	StackID    string
	Status     string
	ObservedAt time.Time
}

// BootstrapProvider is deliberately narrow. It is constructed from a single
// uploaded admin/root credential and discarded after the bootstrap call.
type BootstrapProvider interface {
	GetCallerIdentity(context.Context) (CallerIdentity, error)
	EnsureBootstrapIdentity(context.Context, BootstrapIdentitySpec) (SourceCredentials, error)
	CreateFoundationStack(context.Context, FoundationStackRequest) (FoundationStackReceipt, error)
}

type BootstrapProviderFactory interface {
	NewBootstrapProvider(context.Context, string, *Credentials) (BootstrapProvider, error)
}

// FoundationLifecycleProvider is available only to a fresh admin-bootstrap
// operation. Daily Control Role sessions never implement this interface.
type FoundationLifecycleProvider interface {
	BootstrapProvider
	UpdateFoundationStack(context.Context, FoundationStackRequest) (FoundationStackReceipt, error)
	DeleteFoundationStack(context.Context, FoundationStackRequest) (FoundationStackReceipt, error)
	UpdateBootstrapPolicies(context.Context, BootstrapIdentitySpec) error
	DeleteBootstrapIdentity(context.Context, BootstrapIdentitySpec) error
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

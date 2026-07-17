// Package workeridentity proves that an enrollment caller currently holds the
// temporary IAM credentials of the fixed EC2 Worker role. Proofs are consumed
// in memory and are never suitable for logging or persistence.
package workeridentity

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
)

var (
	ErrInvalidProof       = errors.New("invalid EC2 Worker identity proof")
	ErrProofExpired       = errors.New("EC2 Worker identity proof expired")
	ErrSTSUnavailable     = errors.New("AWS STS identity verification unavailable")
	ErrIdentityRejected   = errors.New("EC2 Worker identity is not authorized for the deployment")
	ErrSensitiveProofJSON = errors.New("EC2 Worker identity proof cannot be JSON encoded")
)

const TrustSTSAndEC2ReadBack = "aws_sts_sigv4_and_ec2_readback"

// ProofV1 contains one SigV4-signed STS GetCallerIdentity request. The
// Authorization and session token fields are sensitive bearer-equivalent
// material during their short validity window. Verify consumes and destroys
// the proof on every success or failure path.
type ProofV1 struct {
	SchemaVersion int
	Region        string
	Endpoint      string
	Method        string
	Host          string
	ContentType   string
	ContentSHA256 string
	AmzDate       string
	ChallengeID   string
	Body          []byte
	Authorization []byte
	SessionToken  []byte
}

func (proof *ProofV1) Destroy() {
	if proof == nil {
		return
	}
	wipeBytes(proof.Body)
	wipeBytes(proof.Authorization)
	wipeBytes(proof.SessionToken)
	proof.Body = nil
	proof.Authorization = nil
	proof.SessionToken = nil
	proof.SchemaVersion = 0
	proof.Region = ""
	proof.Endpoint = ""
	proof.Method = ""
	proof.Host = ""
	proof.ContentType = ""
	proof.ContentSHA256 = ""
	proof.AmzDate = ""
	proof.ChallengeID = ""
}

func wipeBytes(value []byte) {
	if value != nil {
		clear(value[:cap(value)])
	}
}

func (ProofV1) String() string   { return "[redacted-worker-identity-proof]" }
func (ProofV1) GoString() string { return "workeridentity.ProofV1{[redacted]}" }
func (ProofV1) LogValue() slog.Value {
	return slog.StringValue("[redacted-worker-identity-proof]")
}
func (ProofV1) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveProofJSON }

var _ json.Marshaler = ProofV1{}

type GenerateRequest struct {
	Region      string
	ChallengeID string
}

type VerificationRequest struct {
	Proof        *ProofV1
	ChallengeID  string
	AccountID    string
	Region       string
	OwnerID      string
	DeploymentID string
}

type DeploymentClaim struct {
	AgentInstanceID string
	OwnerID         string
	DeploymentID    string
	Partition       string
	AccountID       string
	Region          string
	WorkerRoleName  string
	InstanceID      string
	// PrincipalID is the complete, provider-verified STS UserId. For an EC2
	// role session AWS emits <role-id>:<instance-id>. S3 uses that exact value;
	// the CloudWatch stream uses the same components separated by '/' because
	// CloudWatch Logs forbids ':' in stream names.
	PrincipalID string
}

// DeploymentEvidence is an independent typed EC2/tag read-back. An
// authorizer must populate every field from provider evidence rather than
// echoing untrusted request data.
type DeploymentEvidence struct {
	Authorized      bool
	Exists          bool
	TagsVerified    bool
	AgentInstanceID string
	OwnerID         string
	DeploymentID    string
	AccountID       string
	Region          string
	WorkerRoleName  string
	InstanceID      string
	TagDigest       string
	ObservedAt      time.Time
}

type DeploymentResourceAuthorizer interface {
	AuthorizeDeployment(context.Context, DeploymentClaim) (DeploymentEvidence, error)
}

type VerifiedIdentity struct {
	Partition      string
	AccountID      string
	Region         string
	WorkerRoleName string
	InstanceID     string
	PrincipalID    string
	DeploymentID   string
	OwnerID        string
	Trust          string
	VerifiedAt     time.Time
}

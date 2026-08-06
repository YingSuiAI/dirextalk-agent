package coreteam

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

const (
	TeamExecutionOperationDomain = "team_execution"
	TeamPlanTargetKind           = "team_plan"
	TeamExecutionSelectedTool    = "team_execution"
	ErrorCodeTeamExecutionActive = "team_execution_active"
)

// TeamNetworkPolicy is the closed MVP Worker network authority. Workers have
// no inbound surface and cannot receive AWS control credentials; outbound
// internet access is used only by the role runtime and its Agent callback.
type TeamNetworkPolicy struct {
	Version             string
	PublicIP            bool
	PublicInbound       bool
	OutboundPolicy      string
	ManagementTransport string
	WorkerAWSControl    bool
}

func OfficialTeamNetworkPolicy() TeamNetworkPolicy {
	return TeamNetworkPolicy{
		Version:             "official-pi-network-v1",
		PublicIP:            true,
		PublicInbound:       false,
		OutboundPolicy:      "internet-egress",
		ManagementTransport: "worker-callback-v1",
		WorkerAWSControl:    false,
	}
}

func (policy TeamNetworkPolicy) Grants() []string {
	grants := []string{
		"management:" + policy.ManagementTransport,
		"outbound:" + policy.OutboundPolicy,
		"public_inbound:" + strconv.FormatBool(policy.PublicInbound),
		"public_ip:" + strconv.FormatBool(policy.PublicIP),
		"worker_aws_control:" + strconv.FormatBool(policy.WorkerAWSControl),
	}
	sort.Strings(grants)
	return grants
}

func ConfirmationExpiresAt(plan Plan) time.Time { return plan.Quote.ExpiresAt.UTC() }

func ConfirmationBinding(plan Plan) (coreconfirmation.Binding, error) {
	if err := plan.Validate(); err != nil {
		return coreconfirmation.Binding{}, ErrInvalid
	}
	manifest := confirmationDigest(struct {
		RuntimeID, Adapter, ImageDigest, AMIID string
		OutputTokens                           uint32
	}{plan.Runtime.RuntimeID, plan.Runtime.Adapter, plan.Runtime.ImageDigest, plan.Runtime.AMIID, plan.Runtime.OutputTokens})
	execution := confirmationDigest(struct {
		ConversationID string
		Goal           string
		Roles          []Role
	}{plan.ConversationID, plan.Goal, cloneRoles(plan.Roles)})
	type permissionRole struct {
		RoleID       string
		Capabilities []Capability
	}
	permissions := make([]permissionRole, len(plan.Roles))
	for i, role := range plan.Roles {
		permissions[i] = permissionRole{RoleID: role.RoleID, Capabilities: append([]Capability(nil), role.Capabilities...)}
	}
	permission := confirmationDigest(permissions)
	parameters := confirmationDigest(struct {
		PlanRevision       uint64
		CredentialRevision uint64
		Quote              QuoteBinding
	}{plan.Revision, plan.CredentialRevision, normalizedQuote(plan.Quote)})
	policy := OfficialTeamNetworkPolicy()
	network := confirmationDigest(policy)
	secret := confirmationDigest(struct {
		OwnerID            string
		AccountGeneration  int64
		CredentialID       string
		CredentialRevision uint64
	}{plan.OwnerID, plan.AccountGeneration, plan.CredentialID, plan.CredentialRevision})
	binding := coreconfirmation.Binding{
		OwnerID: plan.OwnerID, OperationDomain: TeamExecutionOperationDomain,
		TargetID: plan.PlanID, TargetRevision: int64(plan.Revision), TargetKind: TeamPlanTargetKind,
		SourceVersion: plan.Runtime.RuntimeID, SourceCommit: plan.Runtime.ImageDigest,
		ContentDigest: coreconfirmation.Digest(plan.Digest), ManifestDigest: manifest,
		ExecutionDigest: execution, PermissionDigest: permission, ParameterDigest: parameters,
		NetworkDigest: network, SecretGrantDigest: secret, SelectedTool: TeamExecutionSelectedTool,
		NetworkGrants: policy.Grants(),
		SecretGrants: []coreconfirmation.SecretGrant{{
			ReferenceID: plan.CredentialID, Purpose: coreconfirmation.SecretPurposeAWSCredential, BindingDigest: secret,
		}},
	}
	normalized, err := binding.Normalize()
	if err != nil {
		return coreconfirmation.Binding{}, ErrInvalid
	}
	return normalized, nil
}

func confirmationDigest(value any) coreconfirmation.Digest {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return coreconfirmation.Digest(hex.EncodeToString(sum[:]))
}

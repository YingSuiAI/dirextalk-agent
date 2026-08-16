package coreconfirmation

import (
	"encoding/json"
	"strings"
	"time"
)

// PublicSecretGrant is domain-sensitive. Cloud Worker confirmations expose
// only Purpose; existing MCP, Skill and extension confirmations retain their
// reference and per-reference digest descriptors.
type PublicSecretGrant struct {
	ReferenceID   string        `json:"reference_id,omitempty"`
	Purpose       SecretPurpose `json:"purpose"`
	BindingDigest Digest        `json:"binding_digest,omitempty"`
}

type PublicBinding struct {
	OwnerID           string              `json:"owner_id"`
	AccountGeneration uint64              `json:"account_generation,omitempty"`
	OperationDomain   string              `json:"operation_domain"`
	TargetID          string              `json:"target_id"`
	TargetRevision    int64               `json:"target_revision"`
	TargetKind        string              `json:"target_kind"`
	SourceVersion     string              `json:"source_version"`
	SourceCommit      string              `json:"source_commit"`
	ContentDigest     Digest              `json:"content_digest"`
	ManifestDigest    Digest              `json:"manifest_digest"`
	ExecutionDigest   Digest              `json:"execution_digest"`
	PermissionDigest  Digest              `json:"permission_digest"`
	ParameterDigest   Digest              `json:"parameter_digest"`
	NetworkDigest     Digest              `json:"network_digest"`
	SecretGrantDigest Digest              `json:"secret_grant_digest"`
	SelectedTool      string              `json:"selected_tool"`
	SelectedCommand   []string            `json:"selected_command"`
	NetworkGrants     []string            `json:"network_grants"`
	SecretGrants      []PublicSecretGrant `json:"secret_grants"`
	ExecutionID       string              `json:"execution_id,omitempty"`
	PlanID            string              `json:"plan_id,omitempty"`
	PlanRevision      int64               `json:"plan_revision,omitempty"`
	PlanDigest        Digest              `json:"plan_digest,omitempty"`
	RunID             string              `json:"run_id,omitempty"`
	RunRevision       int64               `json:"run_revision,omitempty"`
	RunDigest         Digest              `json:"run_digest,omitempty"`
	QuoteDigest       Digest              `json:"quote_digest,omitempty"`
	Quote             *PublicQuote        `json:"quote,omitempty"`
	Digest            Digest              `json:"digest,omitempty"`
}

type PublicQuote struct {
	AmountMicros                *int64    `json:"amount_micros,omitempty"`
	ComputeMicrosPerHour        uint64    `json:"compute_micros_per_hour"`
	Currency                    string    `json:"currency"`
	SourceTime                  time.Time `json:"source_time"`
	ExpiresAt                   time.Time `json:"expires_at"`
	MaximumAuthorizedCostMicros *int64    `json:"maximum_authorized_cost_micros,omitempty"`
}

func (b PublicBinding) MarshalJSON() ([]byte, error) {
	if b.OperationDomain != "cloud_worker.execute" {
		type bindingAlias PublicBinding
		return json.Marshal(bindingAlias(b))
	}
	return json.Marshal(struct {
		OwnerID           string       `json:"owner_id"`
		AccountGeneration uint64       `json:"account_generation"`
		OperationDomain   string       `json:"operation_domain"`
		TargetID          string       `json:"target_id"`
		TargetRevision    int64        `json:"target_revision"`
		TargetKind        string       `json:"target_kind"`
		ExecutionID       string       `json:"execution_id"`
		PlanID            string       `json:"plan_id"`
		PlanRevision      int64        `json:"plan_revision"`
		Quote             *PublicQuote `json:"quote"`
	}{b.OwnerID, b.AccountGeneration, b.OperationDomain, b.TargetID, b.TargetRevision, b.TargetKind,
		b.ExecutionID, b.PlanID, b.PlanRevision, b.Quote})
}

func (b Binding) Public() PublicBinding {
	if b.OperationDomain == "cloud_worker.execute" {
		var quote *PublicQuote
		if b.Quote != nil {
			quote = &PublicQuote{ComputeMicrosPerHour: b.Quote.ComputeMicrosPerHour, Currency: b.Quote.Currency,
				SourceTime: b.Quote.SourceTime, ExpiresAt: b.Quote.ExpiresAt}
			if b.TargetKind != TargetKindPersistentService {
				amount, maximum := b.Quote.AmountMicros, b.Quote.MaximumAuthorizedCostMicros
				quote.AmountMicros, quote.MaximumAuthorizedCostMicros = &amount, &maximum
			}
		}
		return PublicBinding{
			OwnerID: strings.TrimSpace(b.OwnerID), AccountGeneration: b.AccountGeneration,
			OperationDomain: b.OperationDomain, TargetID: b.TargetID, TargetRevision: b.TargetRevision,
			TargetKind:  b.TargetKind,
			ExecutionID: b.ExecutionID, PlanID: b.PlanID, PlanRevision: b.PlanRevision,
			Quote: quote,
		}
	}
	grants := make([]PublicSecretGrant, 0, len(b.SecretGrants))
	for _, grant := range b.SecretGrants {
		grants = append(grants, PublicSecretGrant{ReferenceID: grant.ReferenceID, Purpose: grant.Purpose, BindingDigest: grant.BindingDigest})
	}
	return PublicBinding{
		OwnerID: strings.TrimSpace(b.OwnerID), AccountGeneration: b.AccountGeneration,
		OperationDomain: b.OperationDomain, TargetID: b.TargetID, TargetRevision: b.TargetRevision,
		TargetKind: b.TargetKind, SourceVersion: b.SourceVersion, SourceCommit: b.SourceCommit,
		ContentDigest: b.ContentDigest, ManifestDigest: b.ManifestDigest, ExecutionDigest: b.ExecutionDigest,
		PermissionDigest: b.PermissionDigest, ParameterDigest: b.ParameterDigest, NetworkDigest: b.NetworkDigest,
		SecretGrantDigest: b.SecretGrantDigest, SelectedTool: b.SelectedTool,
		SelectedCommand: append(make([]string, 0, len(b.SelectedCommand)), b.SelectedCommand...),
		NetworkGrants:   append(make([]string, 0, len(b.NetworkGrants)), b.NetworkGrants...),
		SecretGrants:    grants, ExecutionID: b.ExecutionID, PlanID: b.PlanID, PlanRevision: b.PlanRevision,
		PlanDigest: b.PlanDigest, RunID: b.RunID, RunRevision: b.RunRevision, RunDigest: b.RunDigest,
		QuoteDigest: b.QuoteDigest, Digest: b.Digest,
	}
}

type PublicConfirmation struct {
	ConfirmationID string        `json:"confirmation_id"`
	OwnerID        string        `json:"owner_id"`
	Binding        PublicBinding `json:"binding"`
	TaskID         string        `json:"task_id"`
	State          State         `json:"state"`
	Revision       int64         `json:"revision"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	ExpiresAt      time.Time     `json:"expires_at"`
	TerminalCode   string        `json:"terminal_code"`
	TerminalNote   string        `json:"terminal_note"`
	TerminalReason string        `json:"terminal_reason"`
}

func (c Confirmation) Public() PublicConfirmation {
	return PublicConfirmation{ConfirmationID: c.ConfirmationID, OwnerID: c.OwnerID, Binding: c.Binding.Public(),
		TaskID: c.TaskID, State: c.State, Revision: c.Revision, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
		ExpiresAt: c.ExpiresAt, TerminalCode: c.TerminalCode, TerminalNote: c.TerminalNote, TerminalReason: c.TerminalReason}
}

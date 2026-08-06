package coreteam

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

func confirmationTestPlan(t *testing.T) Plan {
	t.Helper()
	plan, err := testCompiler(
		fakeRuntimeCatalog{binding: validRuntime()},
		fakeQuoteProvider{quote: validQuote()},
	).Compile(t.Context(), validCommand())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func confirmationTestDigest(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func TestTeamConfirmationBindsExactPlanAuthority(t *testing.T) {
	plan := confirmationTestPlan(t)
	binding, err := ConfirmationBinding(plan)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := binding.Normalize()
	if err != nil || !binding.Equal(normalized) {
		t.Fatalf("binding did not normalize: binding=%#v normalized=%#v err=%v", binding, normalized, err)
	}
	if binding.OwnerID != plan.OwnerID || binding.OperationDomain != TeamExecutionOperationDomain ||
		binding.TargetID != plan.PlanID || binding.TargetRevision != int64(plan.Revision) ||
		binding.TargetKind != TeamPlanTargetKind || binding.SourceVersion != plan.Runtime.RuntimeID ||
		binding.SourceCommit != plan.Runtime.ImageDigest || string(binding.ContentDigest) != plan.Digest ||
		binding.SelectedTool != TeamExecutionSelectedTool {
		t.Fatalf("top-level authority is incomplete: %#v", binding)
	}

	wantManifest := confirmationTestDigest(t, struct {
		RuntimeID, Adapter, ImageDigest, AMIID string
		OutputTokens                           uint32
	}{plan.Runtime.RuntimeID, plan.Runtime.Adapter, plan.Runtime.ImageDigest, plan.Runtime.AMIID, plan.Runtime.OutputTokens})
	wantExecution := confirmationTestDigest(t, struct {
		ConversationID string
		Goal           string
		Roles          []Role
	}{plan.ConversationID, plan.Goal, plan.Roles})
	type permissionRole struct {
		RoleID       string
		Capabilities []Capability
	}
	permissions := make([]permissionRole, len(plan.Roles))
	for i, role := range plan.Roles {
		permissions[i] = permissionRole{RoleID: role.RoleID, Capabilities: role.Capabilities}
	}
	wantPermission := confirmationTestDigest(t, permissions)
	wantParameters := confirmationTestDigest(t, struct {
		PlanRevision       uint64
		CredentialRevision uint64
		Quote              QuoteBinding
	}{plan.Revision, plan.CredentialRevision, plan.Quote})
	wantNetwork := confirmationTestDigest(t, OfficialTeamNetworkPolicy())
	wantSecret := confirmationTestDigest(t, struct {
		OwnerID            string
		AccountGeneration  int64
		CredentialID       string
		CredentialRevision uint64
	}{plan.OwnerID, plan.AccountGeneration, plan.CredentialID, plan.CredentialRevision})

	if string(binding.ManifestDigest) != wantManifest || string(binding.ExecutionDigest) != wantExecution ||
		string(binding.PermissionDigest) != wantPermission || string(binding.ParameterDigest) != wantParameters ||
		string(binding.NetworkDigest) != wantNetwork || string(binding.SecretGrantDigest) != wantSecret {
		t.Fatalf("exact digests missing: binding=%#v", binding)
	}
	policy := OfficialTeamNetworkPolicy()
	if !reflect.DeepEqual(binding.NetworkGrants, policy.Grants()) {
		t.Fatalf("network grants=%v want=%v", binding.NetworkGrants, policy.Grants())
	}
	if len(binding.SecretGrants) != 1 || binding.SecretGrants[0].ReferenceID != plan.CredentialID ||
		binding.SecretGrants[0].Purpose != "aws_credential" || string(binding.SecretGrants[0].BindingDigest) != wantSecret {
		t.Fatalf("credential grant is incomplete: %#v", binding.SecretGrants)
	}
	if !ConfirmationExpiresAt(plan).Equal(plan.Quote.ExpiresAt) {
		t.Fatalf("confirmation expiry=%s quote expiry=%s", ConfirmationExpiresAt(plan), plan.Quote.ExpiresAt)
	}
}

func TestTeamConfirmationDigestsChangeWithBoundFacts(t *testing.T) {
	base := confirmationTestPlan(t)
	baseBinding, err := ConfirmationBinding(base)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		mutate func(*Plan)
		read   func(coreBinding confirmationBindingView) string
	}{
		"owner": {
			mutate: func(plan *Plan) { plan.OwnerID = "@other-team-owner:example.test" },
			read:   func(view confirmationBindingView) string { return view.owner + view.secret },
		},
		"account generation": {
			mutate: func(plan *Plan) { plan.AccountGeneration++ },
			read:   func(view confirmationBindingView) string { return view.secret },
		},
		"runtime image": {
			mutate: func(plan *Plan) {
				plan.Runtime.ImageDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			},
			read: func(view confirmationBindingView) string { return view.manifest + view.sourceCommit },
		},
		"runtime ami": {
			mutate: func(plan *Plan) { plan.Runtime.AMIID = "ami-fedcba9876543210f" },
			read:   func(view confirmationBindingView) string { return view.manifest },
		},
		"credential revision": {
			mutate: func(plan *Plan) { plan.CredentialRevision++ },
			read:   func(view confirmationBindingView) string { return view.parameters + view.secret },
		},
		"quote and budget": {
			mutate: func(plan *Plan) { plan.Quote.Amount = "0.0300"; plan.Quote.HardBudget = "2.00" },
			read:   func(view confirmationBindingView) string { return view.parameters },
		},
		"input": {
			mutate: func(plan *Plan) { plan.Goal = "research, verify, and synthesize" },
			read:   func(view confirmationBindingView) string { return view.execution },
		},
		"permissions": {
			mutate: func(plan *Plan) { plan.Roles[0].Capabilities = []Capability{CapabilityBrowser} },
			read:   func(view confirmationBindingView) string { return view.permission },
		},
	}
	baseView := teamBindingView(baseBinding)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			changed := base.Clone()
			test.mutate(&changed)
			changed.Digest, err = changed.SemanticDigest()
			if err != nil {
				t.Fatal(err)
			}
			binding, bindErr := ConfirmationBinding(changed)
			if bindErr != nil {
				t.Fatal(bindErr)
			}
			if test.read(teamBindingView(binding)) == test.read(baseView) {
				t.Fatalf("%s did not change its authoritative digest", name)
			}
		})
	}
}

type confirmationBindingView struct {
	owner, manifest, execution, permission, parameters, secret, sourceCommit string
}

func teamBindingView(binding coreconfirmation.Binding) confirmationBindingView {
	return confirmationBindingView{
		owner:    binding.OwnerID,
		manifest: string(binding.ManifestDigest), execution: string(binding.ExecutionDigest),
		permission: string(binding.PermissionDigest), parameters: string(binding.ParameterDigest),
		secret: string(binding.SecretGrantDigest), sourceCommit: binding.SourceCommit,
	}
}

func TestTeamConfirmationRejectsInvalidPlan(t *testing.T) {
	plan := confirmationTestPlan(t)
	plan.Digest = ""
	if _, err := ConfirmationBinding(plan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid plan binding err=%v", err)
	}
}
